#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "instance.h"
#include "serialize.h"
#include "read_only.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup instance instance: process scalars and other instances easily.
 *  @ingroup handler
 *  @{
 */
mib_handler *
get_instance_handler(void) {
    return create_handler("instance", instance_helper_handler);
}

int
register_instance(handler_registration *reginfo) {
    inject_handler(reginfo, get_instance_handler());
    return register_serialize(reginfo);
}

int
register_read_only_instance(handler_registration *reginfo) {
    inject_handler(reginfo, get_instance_handler());
    inject_handler(reginfo, get_read_only_handler());
    return register_serialize(reginfo);
}

int
register_read_only_ulong_instance(const char *name,
                                  oid *reg_oid, size_t reg_oid_len,
                                  u_long *it) 
{
    handler_registration *myreg =
        create_handler_registration(name,
                                    instance_ulong_handler,
                                    reg_oid, reg_oid_len,
                                    HANDLER_CAN_RONLY);
    myreg->handler->myvoid = (void *) it;
    return register_read_only_instance(myreg);
}

int
register_ulong_instance(const char *name,
                        oid *reg_oid, size_t reg_oid_len,
                        u_long *it) 
{
    handler_registration *myreg =
        create_handler_registration(name,
                                    instance_ulong_handler,
                                    reg_oid, reg_oid_len,
                                    HANDLER_CAN_RWRITE);
    myreg->handler->myvoid = (void *) it;
    return register_instance(myreg);
}

int
register_read_only_counter32_instance(const char *name,
                                      oid *reg_oid, size_t reg_oid_len,
                                      u_long *it) 
{
    handler_registration *myreg =
        create_handler_registration(name,
                                    instance_counter32_handler,
                                    reg_oid, reg_oid_len,
                                    HANDLER_CAN_RONLY);
    myreg->handler->myvoid = (void *) it;
    return register_read_only_instance(myreg);
}

int
register_read_only_long_instance(const char *name,
                                 oid *reg_oid, size_t reg_oid_len,
                                 long *it) 
{
    handler_registration *myreg =
        create_handler_registration(name,
                                    instance_long_handler,
                                    reg_oid, reg_oid_len,
                                    HANDLER_CAN_RONLY);
    myreg->handler->myvoid = (void *) it;
    return register_read_only_instance(myreg);
}

int
register_long_instance(const char *name,
                       oid *reg_oid, size_t reg_oid_len,
                       long *it) 
{
    handler_registration *myreg =
        create_handler_registration(name,
                                    instance_long_handler,
                                    reg_oid, reg_oid_len,
                                    HANDLER_CAN_RWRITE);
    myreg->handler->myvoid = (void *) it;
    return register_instance(myreg);
}

int
instance_ulong_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    u_long *it = (u_long *) handler->myvoid;
    u_long *it_save;
    
    DEBUGMSGTL(("instance_ulong_handler", "Got request:  %d\n", reqinfo->mode));

    switch(reqinfo->mode) {
        /* data requests */
        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED,
                                     (u_char *) it,
                                     sizeof(*it));
            break;

        /* SET requests.  Should only get here if registered RWRITE */
        case MODE_SET_RESERVE1:
            if (requests->requestvb->type != ASN_UNSIGNED)
                set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
            break;

        case MODE_SET_RESERVE2:
            /* store old info for undo later */
            memdup((u_char **) &it_save,
                   (u_char *) it, sizeof(u_long));
            if (it_save == NULL) {
                set_request_error(reqinfo, requests,
                                  SNMP_ERR_RESOURCEUNAVAILABLE);
                return SNMP_ERR_NOERROR;
            }
            request_add_list_data(requests,
                                  create_data_list(INSTANCE_HANDLER_NAME,
                                                   it_save, free));
            break;

        case MODE_SET_ACTION:
            /* update current */
            DEBUGMSGTL(("testhandler","updated u_long %ul -> %ul\n", *it,
                        *(requests->requestvb->val.integer)));
            *it = *(requests->requestvb->val.integer);
            break;
            
        case MODE_SET_UNDO:
            *it =
                *((u_long *) request_get_list_data(requests,
                                                   INSTANCE_HANDLER_NAME));
            break;

        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
                /* nothing to do */
            break;
    }
    return SNMP_ERR_NOERROR;
}

int
instance_counter32_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    u_long *it = (u_long *) handler->myvoid;
    u_long *it_save;
    
    DEBUGMSGTL(("instance_ulong_handler", "Got request:  %d\n", reqinfo->mode));

    switch(reqinfo->mode) {
        /* data requests */
        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                                     (u_char *) it,
                                     sizeof(*it));
            break;

        /* SET requests.  Should only get here if registered RWRITE */
        default:
            snmp_log(LOG_ERR,"instance_counter32_handler: illegal mode\n");
            set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
            return SNMP_ERR_NOERROR;
    }
    return SNMP_ERR_NOERROR;
}

int
instance_long_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    long *it = (u_long *) handler->myvoid;
    long *it_save;
    
    DEBUGMSGTL(("instance_ulong_handler", "Got request:  %d\n", reqinfo->mode));

    switch(reqinfo->mode) {
        /* data requests */
        case MODE_GET:
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                                     (u_char *) it,
                                     sizeof(*it));
            break;

        /* SET requests.  Should only get here if registered RWRITE */
        case MODE_SET_RESERVE1:
            if (requests->requestvb->type != ASN_UNSIGNED)
                set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
            break;

        case MODE_SET_RESERVE2:
            /* store old info for undo later */
            memdup((u_char **) &it_save,
                   (u_char *) it, sizeof(u_long));
            if (it_save == NULL) {
                set_request_error(reqinfo, requests,
                                  SNMP_ERR_RESOURCEUNAVAILABLE);
                return SNMP_ERR_NOERROR;
            }
            request_add_list_data(requests,
                                  create_data_list(INSTANCE_HANDLER_NAME,
                                                   it_save, free));
            break;

        case MODE_SET_ACTION:
            /* update current */
            DEBUGMSGTL(("testhandler","updated u_long %ul -> %ul\n", *it,
                        *(requests->requestvb->val.integer)));
            *it = *(requests->requestvb->val.integer);
            break;
            
        case MODE_SET_UNDO:
            *it =
                *((u_long *) request_get_list_data(requests,
                                                   INSTANCE_HANDLER_NAME));
            break;

        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
                /* nothing to do */
            break;
    }
    return SNMP_ERR_NOERROR;
}

int
instance_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    struct variable_list *var = requests->requestvb;

    int ret, cmp;
    
    DEBUGMSGTL(("helper:instance", "Got request:\n"));
    cmp = snmp_oid_compare(requests->requestvb->name,
                           requests->requestvb->name_length,
                           reginfo->rootoid,
                           reginfo->rootoid_len);
        
    DEBUGMSGTL(("helper:instance", "  oid:", cmp));
    DEBUGMSGOID(("helper:instance", var->name, var->name_length));
    DEBUGMSG(("helper:instance", "\n"));

    switch(reqinfo->mode) {
        case MODE_GET:
            if (cmp != 0) {
                var->type = SNMP_NOSUCHOBJECT;
                return SNMP_ERR_NOERROR;
            } else {
                return call_next_handler(handler, reginfo, reqinfo, requests);
            }
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_UNDO:
        case MODE_SET_FREE:
            if (cmp != 0) {
                set_request_error(reqinfo, requests, SNMP_ERR_NOSUCHNAME);
                return SNMP_ERR_NOERROR;
            } else {
                return call_next_handler(handler, reginfo, reqinfo, requests);
            }
            break;
            
        case MODE_GETNEXT:
            if (cmp < 0) {
                reqinfo->mode = MODE_GET;
                snmp_set_var_objid(requests->requestvb, reginfo->rootoid,
                                   reginfo->rootoid_len);
                ret = call_next_handler(handler, reginfo, reqinfo, requests);
                reqinfo->mode = MODE_GETNEXT;
                return ret;
            } else {
                return SNMP_ERR_NOERROR;
            }
            break;
    }
    /* got here only if illegal mode found */
    return SNMP_ERR_GENERR;
}

/* @} */
