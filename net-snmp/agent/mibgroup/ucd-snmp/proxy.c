#include <config.h>

#include <sys/types.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "mibincl.h"
#include "proxy.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_parse_args.h"
#include "system.h"

/* the registration point. */
struct variable2 simple_proxy_variables[] = {
    /* bogus entry.  Only some of it is actually used. */
    {0, ASN_INTEGER, RWRITE, var_simple_proxy, 0, {0}},
};

static struct simple_proxy *proxies=NULL;

oid testoid[] = { 1,3,6,1,4,1,2021,8888,1 };

/* this must be standardized somewhere, right? */
#define MAX_ARGS 128

void
proxy_parse_config(const char *token, char *line) {
    /* proxy args [base-oid] [remap-to-remote-oid] */

    struct snmp_session session, *ss;
    struct simple_proxy *newp, **listpp;
    char args[MAX_ARGS][SPRINT_MAX_LEN], *argv[MAX_ARGS];
    int argn, arg;
    char *cp;
    
    DEBUGMSGTL(("proxy_config","entering\n"));

    /* create the argv[] like array */
    strcpy(argv[0] = args[0], "snmpd-proxy"); /* bogus entry for getopt() */
    for(argn = 1, cp = line; cp && argn < MAX_ARGS;
        cp = copy_word(cp, argv[argn] = args[argn++])) {
    }

    for(arg = 0; arg < argn; arg++) {
        DEBUGMSGTL(("proxy_args","final args: %d = %s\n", arg, argv[arg]));
    }
    
    DEBUGMSGTL(("proxy_config","parsing args: %d\n", argn));
    arg = snmp_parse_args(argn, argv, &session, NULL, NULL);
    DEBUGMSGTL(("proxy_config","done parsing args\n"));

    if (arg >= argn) {
        config_perror("missing base oid");
        return;
    }

    SOCK_STARTUP;
/*    usm_set_reportErrorOnUnknownID(0); */ /* hack, stupid v3 ASIs. */
    /* XXX: on a side note, we don't really need to be a reference
    platform any more so the proper thing to do would be to fix
    snmplib/snmpusm.c to pass in the pdu type to usm_process_incoming
    so this isn't needed. */
    ss = snmp_open(&session);
/*    usm_set_reportErrorOnUnknownID(1); */
    if (ss == NULL){
        /* diagnose snmp_open errors with the input struct snmp_session pointer */
        snmp_sess_perror("snmpget", &session);
        SOCK_CLEANUP;
        return;
    }

    newp = (struct simple_proxy *) calloc(1, sizeof(struct simple_proxy));

    newp->sess = ss;
    DEBUGMSGTL(("proxy_init","name = %s\n",args[arg]));
    newp->name_len = MAX_OID_LEN;
    if (!snmp_parse_oid(args[arg++], newp->name, &newp->name_len)) {
        snmp_perror("proxy");
        config_perror("illegal proxy oid specified\n");
        return;
    }

    if (arg < argn) {
        DEBUGMSGTL(("proxy_init","base = %s\n",args[arg]));
        newp->base_len = MAX_OID_LEN;
        if (!snmp_parse_oid(args[arg++], newp->base, &newp->base_len)) {
            snmp_perror("proxy");
            config_perror("illegal variable name specified (base oid)\n");
            return;
        }
    }

    DEBUGMSGTL(("proxy_init","registering at: "));
    DEBUGMSGOID(("proxy_init",newp->name, newp->name_len));
    DEBUGMSG(("proxy_init","\n"));

    /* add to our chain */
    /* must be sorted! */
    listpp = &proxies;
    while (*listpp &&
           snmp_oid_compare(newp->name, newp->name_len,
                            (*listpp)->name, (*listpp)->name_len) > 0) {
        listpp = &((*listpp)->next);
    }

    /* listpp should be next in line from us. */
    if (*listpp) {
        /* make our next in the link point to the current link */
        newp->next = *listpp;
    }
    /* replace current link with us */
    *listpp = newp;

    memdup((u_char **) &newp->variables, (u_char *) simple_proxy_variables,
           sizeof(*simple_proxy_variables));

    /* register our node */
    register_mib("proxy", (struct variable *) newp->variables,
                 sizeof(struct variable2), 1, newp->name, newp->name_len);
}

void
proxy_free_config (void) 
{
    struct simple_proxy *rm;

    /* XXX: finish me (needs unregister_mib()) */
    return;

    while(proxies) {
        rm = proxies;
        proxies = rm->next;
        SNMP_FREE(rm->variables);
        snmp_close(rm->sess);
        SNMP_FREE(rm);
    }
}

void
init_proxy(void) {
    snmpd_register_config_handler("proxy", proxy_parse_config,
                                  proxy_free_config,
                                  "[snmpcmd args] host oid [remoteoid]");
}

u_char *var_simple_proxy(struct variable *vp,
			 oid *name,
			 size_t *length,
			 int exact,
			 size_t *var_len,
			 WriteMethod **write_method)
{

    static u_char *ret_str = NULL;
    static int ret_str_len = 0;
    static oid  objid[MAX_OID_LEN];
    struct simple_proxy *sp;
    u_char *ret = NULL;
    struct snmp_pdu *pdu, *response;
    int status;
    int ourlength;
    oid *ourname;
  
  
    DEBUGMSGTL(("proxy_var","--- entering: "));
    DEBUGMSGOID(("proxy_var", name, *length));
    DEBUGMSG(("proxy_var","\n"));
    for(sp = proxies; sp != NULL; sp = sp->next) {

        if (sp->name_len <= vp->namelen &&
            snmp_oid_compare(sp->name, sp->name_len,
                             vp->name, sp->name_len) == 0) {
          
            DEBUGMSGTL(("proxy_var","searching:"));
            DEBUGMSGOID(("proxy_var", vp->name, vp->namelen));
            DEBUGMSG(("proxy_var","\n"));
            if (snmp_oid_compare(name, *length, sp->name, sp->name_len) < 0) {
                /* match name up with current request if it occurs before our tree */
                DEBUGMSGTL(("proxy_var","  early\n"));
                memcpy(objid, sp->name, sizeof(oid)*sp->name_len);
                ourname = objid;
                ourlength = sp->name_len;
            } else {
                ourname = name;
                ourlength = *length;
            }
      
            if (snmp_oid_compare(ourname, sp->name_len, sp->name, sp->name_len) == 0) {
  
                DEBUGMSGTL(("proxy_var","found it\n"));

                /* translate oid to another base? */
                if (sp->base_len > 0) {
                    if ((ourlength - sp->name_len + sp->base_len) > MAX_OID_LEN) {
                        /* too large */
                        snmp_log(LOG_ERR, "proxy oid request length is too long\n");
                        return NULL;
                    }
                    /* suffix appended? */
                    DEBUGMSGTL(("proxy_var","length=%d, base_len=%d, name_len=%d\n", ourlength, sp->base_len, sp->name_len));
                    if (ourlength > (int)sp->name_len)
                        memcpy(&(sp->base[sp->base_len]), &(ourname[sp->name_len]),
                               sizeof(oid)*(ourlength - sp->name_len));
                    ourlength = ourlength - sp->name_len + sp->base_len;
                    ourname = sp->base;
                }

                /* create the request pdu */
                DEBUGMSGTL(("proxy_var","requesting (exact=%d, len=%d):",exact, ourlength));
                DEBUGMSGOID(("proxy_var", ourname, ourlength));
                DEBUGMSG(("proxy_var","\n"));
                if (exact) {
                    pdu = snmp_pdu_create(SNMP_MSG_GET);
                } else {
                    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
                }
                snmp_add_null_var(pdu, ourname, ourlength);

                /* fetch the info */
                DEBUGMSGTL(("proxy_var","sending pdu \n"));
                status = snmp_synch_response(sp->sess, pdu, &response);

                /* copy the information out of it. */
                if (status == STAT_SUCCESS && response) {
                    /* "there can be only one" */
                    struct variable_list *var = response->variables;

                    DEBUGIF("proxy_var") {
                        char buf[SPRINT_MAX_LEN];
                        sprint_variable(buf, var->name, var->name_length, var);
                        DEBUGMSGTL(("proxy_var","success: %s\n", buf));
                    }
              
                    /* copy the oid it belongs to */
                    if (sp->base_len &&
                        (var->name_length < sp->base_len ||
                         snmp_oid_compare(var->name, sp->base_len, sp->base, sp->base_len) != 0)) {
                        DEBUGMSGTL(("proxy_var","out of registered range... "));
                        DEBUGMSGOID(("proxy_var", var->name, sp->base_len));
                        DEBUGMSG(("proxy_var"," (%d) != ", sp->base_len));
                        DEBUGMSGOID(("proxy_var", sp->base, sp->base_len));
                        DEBUGMSG(("proxy_var","\n"));
                  
                        /* or not if its out of our search range */
                        ret = NULL;
                        goto free_and_exit;
                    } else if (!sp->base_len &&
                               (var->name_length < sp->name_len ||
                                snmp_oid_compare(var->name, sp->name_len, sp->name, sp->name_len) != 0)) {
                        DEBUGMSGTL(("proxy_var","out of registered base range...\n"));
                        /* or not if its out of our search range */
                        ret = NULL;
                        goto free_and_exit;
                    }
          

                    if (sp->base_len) {
                        /* XXX: oid size maxed? */
                        memcpy(name, sp->name, sizeof(oid)*sp->name_len);
                        if (var->name_length > sp->base_len)
                            memcpy(&name[sp->name_len], &var->name[sp->base_len],
                                   sizeof(oid)*(var->name_length - sp->base_len));
                        *length = sp->name_len + var->name_length - sp->base_len;
                    } else {
                        memcpy(name, var->name, sizeof(oid)*var->name_length);
                        *length = var->name_length;
                    }

                    /* copy the value */
		    if (!ret_str || ret_str_len < (int)var->val_len) {
			ret_str_len = var->val_len;
			if (!ret_str_len) ret_str_len = 1;
			if (ret_str) free(ret_str);
			ret_str = (u_char *)malloc(ret_str_len);
                    }
		    memcpy(ret_str, var->val.string, var->val_len);
                    *var_len = var->val_len;
                    vp->type = var->type;
		    ret = ret_str;

                    DEBUGIF("proxy_var") {
                        char buf[SPRINT_MAX_LEN];
                        sprint_variable(buf, name, *length, var);
                        DEBUGMSGTL(("proxy_var","returning: %s\n", buf));
                    }
                }

              free_and_exit:
                /* free the response */
                if (response)
                    snmp_free_pdu(response);

                DEBUGMSGTL(("proxy_var","--- exiting: %x\n", ret));
                *write_method=proxy_set;
                return ret;
            }
        }
    }
  
    DEBUGMSGTL(("proxy_var","--- exiting: NULL\n"));
    return(NULL);
}

int
proxy_set(int action, u_char *var_val, u_char var_val_type,
          size_t var_val_len, u_char *statP, oid *name, size_t name_len) {
    
    struct snmp_pdu *pdu, *response;
    struct simple_proxy *sp;
    int status;

    DEBUGMSGTL(("proxy_set","searching for ownership\n"));
    for(sp = proxies; sp != NULL; sp = sp->next) {
        if (sp->name_len <= name_len &&
            snmp_oid_compare(sp->name, sp->name_len,
                             name, sp->name_len) == 0) {
            DEBUGMSGTL(("proxy_set","found it\n"));

            /* translate oid to another base? */
            if (sp->base_len > 0) {
                if ((name_len - sp->name_len + sp->base_len) > MAX_OID_LEN) {
                    /* too large */
                    snmp_log(LOG_ERR, "proxy oid request length is too long\n");
                    return SNMP_ERR_GENERR;
                }
                /* suffix appended? */
                DEBUGMSGTL(("proxy_set","length=%d, base_len=%d, name_len=%d\n", name, sp->base_len, sp->name_len));
                if (name_len > sp->name_len)
                    memcpy(&(sp->base[sp->base_len]), &(name[sp->name_len]),
                           sizeof(oid)*(name_len - sp->name_len));
                name_len = name_len - sp->name_len + sp->base_len;
                name = sp->base;
            }
            /* we're set to rock, but don't do it yet */
            /* intentionally here rather than above to avoid oid
               length problems during the COMMIT phase */
            if (action != COMMIT)
                return SNMP_ERR_NOERROR;
            
            /* create the request pdu */
            DEBUGMSGTL(("proxy_set","performing set on: "));
            DEBUGMSGOID(("proxy_set", name, name_len));
            DEBUGMSG(("proxy_set","\n"));
            pdu = snmp_pdu_create(SNMP_MSG_SET);
            snmp_pdu_add_variable(pdu, name, name_len,
                                  var_val_type, var_val, var_val_len);

            /* send the set request */
            DEBUGMSGTL(("proxy_set","sending pdu \n"));
            status = snmp_synch_response(sp->sess, pdu, &response);
            DEBUGMSGTL(("proxy_set", "set returned: %d\n", response->errstat));

            /* copy the information out of it. */
            if (status == STAT_SUCCESS && response) {
                return response->errstat;
            } else {
                char *err;
                snmp_error(sp->sess, NULL, NULL, &err);
                DEBUGMSGTL(("proxy_set", "failed set request: %s\n",err));
                free(err);
                return SNMP_ERR_GENERR;
            }
        }
    }
    return SNMP_ERR_NOSUCHNAME;
}
 
        
