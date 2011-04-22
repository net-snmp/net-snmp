#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "deliverByNotify.h"

void parse_deliver_config(const char *, char *);
void parse_deliver_maxsize_config(const char *, char *);
void free_deliver_config(void);

deliver_by_notify test_notify;
oid test_oid[] = {1, 3, 6, 1, 2, 1, 1}; 
oid data_notification_oid[] = {1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 123, 0};
oid objid_snmptrap[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

#define DEFAULT_MAX_DELIVER_SIZE -1;
static int default_max_size;

/** Initializes the mteTrigger module */
void
init_deliverByNotify(void)
{
    snmpd_register_config_handler("deliverByNotify",
                                  &parse_deliver_config, &free_deliver_config,
                                  "[-s maxsize] OID");

    snmpd_register_config_handler("deliverByNotifyMaxPacketSize",
                                  &parse_deliver_maxsize_config, NULL,
                                  "sizeInBytes");
    
    test_notify.frequency = 5;
    test_notify.last_run = time(NULL);
    test_notify.target = malloc(sizeof(test_oid));
    memcpy(test_notify.target, test_oid, sizeof(test_oid));
    test_notify.target_size = OID_LENGTH(test_oid);
    test_notify.max_packet_size = -1;

    snmp_alarm_register(calculate_time_until_next_run(&test_notify, NULL), 0, 
                        &deliver_execute, NULL);

    default_max_size = DEFAULT_MAX_DELIVER_SIZE;
}

void
parse_deliver_config(const char *token, char *line) {
}

void
parse_deliver_maxsize_config(const char *token, char *line) {
    default_max_size = atoi(line);
}

void
free_deliver_config(void) {
    default_max_size = DEFAULT_MAX_DELIVER_SIZE;
}

void
deliver_execute(unsigned int clientreg, void *clientarg) {
    netsnmp_pdu pdu;
    netsnmp_variable_list *vars, *walker, *delivery_notification;
    netsnmp_session *sess;
    int rc;

    snmp_log(LOG_ERR, "got here: deliver by notify\n");

    vars = SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
    snmp_set_var_objid( vars, test_notify.target,
                        test_notify.target_size );
    vars->type = ASN_NULL;

    sess = netsnmp_query_get_default_session();

    rc = netsnmp_query_walk(vars, sess);
    if (rc != SNMP_ERR_NOERROR) {
        snmp_log(LOG_ERR, "deliveryByNotify: failed to issue the query");
        return;
    }

    delivery_notification = NULL;
    /* add in the notification type */
    snmp_varlist_add_variable(&delivery_notification,
                              objid_snmptrap, OID_LENGTH(objid_snmptrap),
                              ASN_OBJECT_ID,
                              data_notification_oid,
                              sizeof(data_notification_oid));
    
    /* copy in the collected data */
    walker = vars;
    while(walker) {
        //print_variable(walker->name, walker->name_length, walker);

        snmp_varlist_add_variable(&delivery_notification,
                                  walker->name, walker->name_length,
                                  walker->type,
                                  walker->val.string, walker->val_len);

        walker = walker->next_variable;
    }
    snmp_free_varbind(vars);

    /* send out the notification */
    send_v2trap(delivery_notification);

    /* record this as the time processed */
    /* XXX: this may creep by a few seconds when processing and maybe we want
       to do the time stamp at the beginning? */
    test_notify.last_run = time(NULL);

    /* calculate the next time to sleep for */
    snmp_alarm_register(calculate_time_until_next_run(&test_notify, NULL), 0, 
                        &deliver_execute, NULL);
}

int
calculate_time_until_next_run(deliver_by_notify *it, time_t *now) {
    time_t          local_now;
    int             time_since_last;

    /* if we weren't passed a valid time, fake it */
    if (NULL == now) {
        now = &local_now;
        time(&local_now);
    }

    time_since_last = local_now - it->last_run;

    return it->frequency - time_since_last;
}

