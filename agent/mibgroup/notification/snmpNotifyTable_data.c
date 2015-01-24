/*
 * This file was created to separate data storage from  MIB implementation.
 */


/*
 * This should always be included first before anything else
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>

#include <sys/types.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * minimal include directives
 */
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "header_complex.h"
#include "snmpNotifyTable_data.h"
#include "notification/snmpNotifyFilterProfileTable_data.h"
#include "target/snmpTargetParamsEntry_data.h"
#include "target/snmpTargetAddrEntry_data.h"
#include "target/target.h"
#include "snmp-notification-mib/snmpNotifyFilterTable/snmpNotifyFilterTable_data_storage.h"
#include <net-snmp/agent/agent_callbacks.h>
#include <net-snmp/agent/agent_trap.h>
#include <net-snmp/agent/mib_module_config.h>
#include "net-snmp/agent/sysORTable.h"

#ifdef USING_NOTIFICATION_LOG_MIB_NOTIFICATION_LOG_MODULE
#   include "notification-log-mib/notification_log.h"
#endif


/*
 * global storage of our data, saved in and configured by header_complex()
 */
static struct header_complex_index *snmpNotifyTableStorage = NULL;

static int
_checkFilter(const char* paramName, netsnmp_pdu *pdu)
{
    /*
     * find appropriate filterProfileEntry
     */
    netsnmp_variable_list *var, *trap_var = NULL;
    char                  *profileName;
    size_t                 profileNameLen;
    struct vacm_viewEntry *vp, *head;
    int                    vb_oid_excluded = 0, free_trapvar = 0;;
    extern const oid       snmptrap_oid[];
    extern const size_t    snmptrap_oid_len;

    netsnmp_assert(NULL != paramName);
    netsnmp_assert(NULL != pdu);

    DEBUGMSGTL(("send_notifications", "checking filters...\n"));

    /*
   A notification originator uses the snmpNotifyFilterTable to filter
   notifications.  A notification filter profile may be associated with
   a particular entry in the snmpTargetParamsTable.  The associated
   filter profile is identified by an entry in the
   snmpNotifyFilterProfileTable whose index is equal to the index of the
   entry in the snmpTargetParamsTable.  If no such entry exists in the
   snmpNotifyFilterProfileTable, no filtering is performed for that
   management target.
    */
    profileName = get_FilterProfileName(paramName, strlen(paramName),
                                        &profileNameLen);
    if (NULL == profileName) /* try default */
        profileName = get_FilterProfileName("default", 7, &profileNameLen);
    if (NULL == profileName) {
        DEBUGMSGTL(("send_notifications", "  no matching profile\n"));
        return 0;
    }

    /*
   If such an entry does exist, the value of snmpNotifyFilterProfileName
   of the entry is compared with the corresponding portion of the index
   of all active entries in the snmpNotifyFilterTable.  All such entries
   for which this comparison results in an exact match are used for
   filtering a notification generated using the associated
   snmpTargetParamsEntry.  If no such entries exist, no filtering is
   performed, and a notification may be sent to the management target.
    */
    head = snmpNotifyFilter_vacm_view_subtree(profileName);
    if (NULL == head) {
        DEBUGMSGTL(("send_notifications", "  no matching filters\n"));
        return 0;
    }

    /*
   Otherwise, if matching entries do exist, a notification may be sent
   if the NOTIFICATION-TYPE OBJECT IDENTIFIER of the notification (this
   is the value of the element of the variable bindings whose name is
   snmpTrapOID.0, i.e., the second variable binding) is specifically
   included, and none of the object instances to be included in the
   variable-bindings of the notification are specifically excluded by
   the matching entries.
     */
    if (NULL != pdu->variables) {
        trap_var = find_varbind_in_list( pdu->variables,
                                         snmptrap_oid, snmptrap_oid_len);
    }
#if !defined(NETSNMP_DISABLE_SNMPV1)
    else {
        /** snmpv1 pdus have no varbinds. build trapoid */
        oid                    enterprise[MAX_OID_LEN];
        size_t                 enterprise_len;
        enterprise_len = OID_LENGTH(enterprise);
        if ((netsnmp_build_trap_oid(pdu, enterprise, &enterprise_len)
             != SNMPERR_SUCCESS) ||
            !snmp_varlist_add_variable(&trap_var, snmptrap_oid,
                                       snmptrap_oid_len,
                                       ASN_OBJECT_ID, (u_char*)enterprise,
                                       enterprise_len*sizeof(oid))) {
            snmp_log(LOG_WARNING,
                     "checkFilter: failed to build snmpTrapOID varbind\n");
        } else
            free_trapvar = 1;
    }
#endif /* NETSNMP_DISABLE_SNMPV1 */

    if (NULL != trap_var) {
        /*
                             For a notification name, if none match,
   then the notification name is considered excluded, and the
   notification should not be sent to this management target.
         */
        vp = netsnmp_view_get(head, profileName, trap_var->val.objid,
                              trap_var->val_len / sizeof(oid), VACM_MODE_FIND);
        if ((NULL == vp) || (SNMP_VIEW_INCLUDED != vp->viewType)) {
            DEBUGMSGTL(("send_notifications", "  filtered (snmpTrapOID.0 "));
            DEBUGMSGOID(("send_notifications",trap_var->val.objid,
                         trap_var->val_len / sizeof(oid)));
            DEBUGMSG(("send_notifications", " not included)\n"));
            free(head);
            if (free_trapvar)
                snmp_free_varbind(trap_var);
            return 1;
        }
    }
    if (free_trapvar) {
        snmp_free_varbind(trap_var);
        trap_var = NULL;
    }

    /*
     * check varbinds
     */
    for(var = pdu->variables; var; var = var->next_variable) {
        /*
                                                               For an
   object instance, if none match, the object instance is considered
   included, and the notification may be sent to this management target.
         */

        if (var == trap_var) {
            continue;
        }

        vp = netsnmp_view_get(head, profileName, var->name,
                              var->name_length, VACM_MODE_FIND);
        if ((NULL != vp) && (SNMP_VIEW_EXCLUDED == vp->viewType)) {
            DEBUGMSGTL(("send_notifications","  filtered (varbind "));
            DEBUGMSGOID(("send_notifications",var->name, var->name_length));
            DEBUGMSG(("send_notifications", " excluded)\n"));
            vb_oid_excluded = 1;
            break;
        }
    }

    free(head);

    return vb_oid_excluded;
}

int
send_notifications(int major, int minor, void *serverarg, void *clientarg)
{
    struct header_complex_index *hptr;
    struct snmpNotifyTable_data *nptr;
    netsnmp_session *sess, *sptr;
    netsnmp_pdu    *template_pdu = (netsnmp_pdu *) serverarg;
    int             count = 0;

    DEBUGMSGTL(("send_notifications", "starting: pdu=%p, vars=%p\n",
                template_pdu, template_pdu->variables));

    for (hptr = snmpNotifyTableStorage; hptr; hptr = hptr->next) {
        nptr = (struct snmpNotifyTable_data *) hptr->data;
        if (nptr->snmpNotifyRowStatus != RS_ACTIVE)
            continue;
        if (!nptr->snmpNotifyTag)
            continue;

        sess = get_target_sessions(nptr->snmpNotifyTag, NULL, NULL);

        /*
         * filter appropriately, per section 6 of RFC 3413
         */

        for (sptr = sess; sptr; sptr = sptr->next) {
#ifndef NETSNMP_DISABLE_SNMPV1
            if (sptr->version == SNMP_VERSION_1 &&
                minor != SNMPD_CALLBACK_SEND_TRAP1) {
                continue;
            } else
#endif
            if (sptr->version == SNMP_VERSION_3
#ifndef NETSNMP_DISABLE_SNMPV2C
                 || sptr->version == SNMP_VERSION_2c
#endif
                    ) {
                if(minor != SNMPD_CALLBACK_SEND_TRAP2)
                    continue;
                if (nptr->snmpNotifyType == SNMPNOTIFYTYPE_INFORM) {
                    template_pdu->command = SNMP_MSG_INFORM;
                } else {
                    template_pdu->command = SNMP_MSG_TRAP2;
                }
            }
            if (sess->paramName) {
                int filter = _checkFilter(sess->paramName, template_pdu);
                if (filter)
                    continue;
            }
            send_trap_to_sess(sptr, template_pdu);
            ++count;
        } /* for(sptr) */
    } /* for(hptr) */

    DEBUGMSGTL(("send_notifications", "sent %d notifications\n", count));

#ifdef USING_NOTIFICATION_LOG_MIB_NOTIFICATION_LOG_MODULE
    if (count)
        log_notification(template_pdu, NULL);
#endif

    return 0;
}

#define MAX_ENTRIES 1024

int
notifyTable_register_notifications(int major, int minor,
                                   void *serverarg, void *clientarg)
{
    struct targetAddrTable_struct *ptr;
    struct targetParamTable_struct *pptr;
    struct snmpNotifyTable_data *nptr;
    int             confirm, i;
    char            buf[SNMP_MAXBUF_SMALL];
    netsnmp_transport *t = NULL;
    struct agent_add_trap_args *args =
        (struct agent_add_trap_args *) serverarg;
    netsnmp_session *ss;
    char            *name, *tag, *notifyProfile;

    if (!args || !(args->ss)) {
        return (0);
    }
    confirm = args->confirm;
    ss = args->ss;
    name = args->name;
    tag = args->tag;
    notifyProfile = args->profile;

    /*
     * XXX: START move target creation to target code 
     */
    if (NULL == name) {
        for (i = 0; i < MAX_ENTRIES; i++) {
            sprintf(buf, "internal%d", i);
            if (get_addrForName(buf) == NULL && get_paramEntry(buf) == NULL)
                break;
        }
        if (i == MAX_ENTRIES) {
            snmp_log(LOG_ERR,
                     "Can't register new trap destination: max limit reached: %d",
                     MAX_ENTRIES);
            snmp_sess_close(ss);
            return (0);
        }
        name = buf;
        if (NULL == tag)
            tag = buf;
    } else {
        if (NULL == tag)
            tag = name;
    }

    /*
     * address
     */
    t = snmp_sess_transport(snmp_sess_pointer(ss));
    if (!t) {
        snmp_log(LOG_ERR,
                "Cannot add new trap destination, transport is closed.");
        snmp_sess_close(ss);
        return 0;
    }
    ptr = snmpTargetAddrTable_create();
    ptr->name = strdup(name);
    memcpy(ptr->tDomain, t->domain, t->domain_length * sizeof(oid));
    ptr->tDomainLen = t->domain_length;
    ptr->tAddressLen = t->remote_length;
    ptr->tAddress = t->remote;

    ptr->timeout = ss->timeout / 1000;
    ptr->retryCount = ss->retries;
    SNMP_FREE(ptr->tagList);
    ptr->tagList = strdup(tag);
    ptr->params = strdup(ptr->name); /* link to target param table */
    ptr->storageType = ST_READONLY;
    ptr->rowStatus = RS_ACTIVE;
    ptr->sess = ss;
    DEBUGMSGTL(("trapsess", "adding to trap table\n"));
    snmpTargetAddrTable_add(ptr);

    /*
     * param
     */
    pptr = snmpTargetParamTable_create();
    pptr->paramName = ptr->params; /* link from target addr table */
    pptr->mpModel = ss->version;
    if (ss->version == SNMP_VERSION_3) {
        pptr->secModel = ss->securityModel;
        pptr->secLevel = ss->securityLevel;
        pptr->secName = (char *) malloc(ss->securityNameLen + 1);
        if (pptr->secName == NULL) {
            snmpTargetParamTable_dispose(pptr);
            return 0;
        }
        memcpy((void *) pptr->secName, (void *) ss->securityName,
               ss->securityNameLen);
        pptr->secName[ss->securityNameLen] = 0;
    }
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
       else {
        pptr->secModel =
#ifndef NETSNMP_DISABLE_SNMPV1
            ss->version == SNMP_VERSION_1 ?  SNMP_SEC_MODEL_SNMPv1 :
#endif
                                             SNMP_SEC_MODEL_SNMPv2c;
        pptr->secLevel = SNMP_SEC_LEVEL_NOAUTH;
        pptr->secName = NULL;
        if (ss->community && (ss->community_len > 0)) {
            pptr->secName = (char *) malloc(ss->community_len + 1);
            if (pptr->secName == NULL) {
                snmpTargetParamTable_dispose(pptr);
                return 0;
            }
            memcpy((void *) pptr->secName, (void *) ss->community,
                   ss->community_len);
            pptr->secName[ss->community_len] = 0;
        }
    }
#endif
    pptr->storageType = ST_READONLY;
    pptr->rowStatus = RS_ACTIVE;
    snmpTargetParamTable_add(pptr);
    /*
     * XXX: END move target creation to target code
     */

    /*
     * notify table
     */
    nptr = SNMP_MALLOC_STRUCT(snmpNotifyTable_data);
    if (nptr == NULL)
        return 0;
    nptr->snmpNotifyName = strdup(name);
    nptr->snmpNotifyNameLen = strlen(name);
    nptr->snmpNotifyTag = strdup(tag); /* selects target addr */
    nptr->snmpNotifyTagLen = strlen(nptr->snmpNotifyTag);
    nptr->snmpNotifyType = confirm ?
        SNMPNOTIFYTYPE_INFORM : SNMPNOTIFYTYPE_TRAP;
    nptr->snmpNotifyStorageType = ST_READONLY;
    nptr->snmpNotifyRowStatus = RS_ACTIVE;

    snmpNotifyTable_add(nptr);

    /*
     * filter profile
     */
    if (NULL != notifyProfile) {
        struct snmpNotifyFilterProfileTable_data *profile;
        profile = snmpNotifyFilterProfileTable_create(ptr->params,
                                                      strlen(ptr->params),
                                                      notifyProfile,
                                                      strlen(notifyProfile));
        if (NULL == profile)
            snmp_log(LOG_ERR, "couldn't create notify filter profile\n");
        else {
            profile->snmpNotifyFilterProfileRowStatus = RS_ACTIVE;
            profile->snmpNotifyFilterProfileStorType = ST_READONLY;

            if (snmpNotifyFilterProfileTable_add(profile) != SNMPERR_SUCCESS) {
                snmp_log(LOG_ERR, "couldn't add notify filter profile\n");
                snmpNotifyFilterProfileTable_free(profile);
            }
        }
    }

    return 0;
}


/*
 * XXX: this really needs to be done for the target mib entries too.
 * But we can only trust that we've added stuff here and we don't want
 * to destroy other valid entries in the target tables, so...  Don't
 * do too many kill -HUPs to your agent as re reading the config file
 * will be a slow memory leak in the target mib.
 */
int
notifyTable_unregister_notifications(int major, int minor,
                                     void *serverarg, void *clientarg)
{
    struct header_complex_index *hptr, *nhptr;

    for (hptr = snmpNotifyTableStorage; hptr; hptr = nhptr) {
        struct snmpNotifyTable_data *nptr = hptr->data;
        nhptr = hptr->next;
        if (nptr->snmpNotifyStorageType == ST_READONLY) {
            header_complex_extract_entry(&snmpNotifyTableStorage, hptr);
            free(nptr->snmpNotifyName);
            free(nptr->snmpNotifyTag);
            free(nptr);
        }
    }
    snmpNotifyTableStorage = NULL;
    return (0);
}

/*
 * init_snmpNotifyTable_data():
 *   Initialization routine.  This is called when the agent starts up.
 */
void
init_snmpNotifyTable_data(void)
{
    DEBUGMSGTL(("snmpNotifyTable_data", "initializing...  "));

#ifndef DISABLE_SNMPV1
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_SEND_TRAP1, send_notifications,
                           NULL);
#endif
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_SEND_TRAP2, send_notifications,
                           NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_REGISTER_NOTIFICATIONS,
                           notifyTable_register_notifications, NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_PRE_UPDATE_CONFIG,
                           notifyTable_unregister_notifications, NULL);

    DEBUGMSGTL(("snmpNotifyTable_data", "done.\n"));
}

void
shutdown_snmpNotifyTable_data(void)
{
    DEBUGMSGTL(("snmpNotifyTable_data", "shutting down ... "));

    notifyTable_unregister_notifications(SNMP_CALLBACK_APPLICATION,
                                         SNMPD_CALLBACK_PRE_UPDATE_CONFIG,
                                         NULL,
                                         NULL);

    snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                             SNMPD_CALLBACK_PRE_UPDATE_CONFIG,
                             notifyTable_unregister_notifications, NULL, FALSE);
    snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                             SNMPD_CALLBACK_REGISTER_NOTIFICATIONS,
                             notifyTable_register_notifications, NULL, FALSE);
    snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                             SNMPD_CALLBACK_SEND_TRAP2, send_notifications,
                             NULL, FALSE);
#ifndef DISABLE_SNMPV1
    snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                             SNMPD_CALLBACK_SEND_TRAP1, send_notifications,
                             NULL, FALSE);
#endif
    DEBUGMSGTL(("snmpNotifyTable_data", "done.\n"));
}

/*
 * snmpNotifyTable_add(): adds a structure node to our data set
 */
int
snmpNotifyTable_add(struct snmpNotifyTable_data *thedata)
{
    netsnmp_variable_list *vars = NULL;
    int retVal;

    DEBUGMSGTL(("snmpNotifyTable_data", "adding data...  "));
    /*
     * add the index variables to the varbind list, which is
     * used by header_complex to index the data
     */
    snmp_varlist_add_variable(&vars, NULL, 0, ASN_PRIV_IMPLIED_OCTET_STR, (u_char *) thedata->snmpNotifyName, thedata->snmpNotifyNameLen);      /* snmpNotifyName */

    if (header_complex_maybe_add_data(&snmpNotifyTableStorage, vars, thedata, 1)
        != NULL){
        DEBUGMSGTL(("snmpNotifyTable", "registered an entry\n"));
        retVal = SNMPERR_SUCCESS;
    }else{
        retVal = SNMPERR_GENERR;
    }


    DEBUGMSGTL(("snmpNotifyTable", "done.\n"));
    return retVal;
}
