#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <limits.h>

netsnmp_feature_require(container_fifo)

#include "deliverByNotify.h"

void parse_deliver_config(const char *, char *);
void parse_deliver_maxsize_config(const char *, char *);
void free_deliver_config(void);

static void _schedule_next_execute_time(void);

oid data_notification_oid[] = {1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 123, 0};
oid objid_snmptrap[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

#define DEFAULT_MAX_DELIVER_SIZE -1;
static int default_max_size;
unsigned int alarm_reg;
static netsnmp_container *deliver_container;

static int
_deliver_compare(deliver_by_notify *lhs, deliver_by_notify *rhs) {
    /* sort by the next_run time */
    if (lhs->next_run < rhs->next_run)
        return -1;
    else
        return 1;
}

/** Initializes the mteTrigger module */
void
init_deliverByNotify(void)
{
    /* register the config tokens */
    snmpd_register_config_handler("deliverByNotify",
                                  &parse_deliver_config, &free_deliver_config,
                                  "[-f frequency] [-s maxsize] FREQUENCY OID");

    snmpd_register_config_handler("deliverByNotifyMaxPacketSize",
                                  &parse_deliver_maxsize_config, NULL,
                                  "sizeInBytes");

    /* create the container to store the config objects*/
    deliver_container = netsnmp_container_find("deliverByNotify:fifo");
    if (NULL == deliver_container) {
        snmp_log(LOG_ERR,
                 "deliverByNotify: failed to initialize our data container\n");
        return;
    }
    deliver_container->container_name = strdup("deliverByNotify");
    deliver_container->compare = (netsnmp_container_compare *) _deliver_compare;

    /* set the defaults */
    default_max_size = DEFAULT_MAX_DELIVER_SIZE;

    alarm_reg = 0;
}

void
parse_deliver_config(const char *token, char *line) {
    const char *cp = line;
    int max_size = DEFAULT_MAX_DELIVER_SIZE;
    int frequency;
    oid target_oid[MAX_OID_LEN];
    size_t target_oid_len = MAX_OID_LEN;
    deliver_by_notify *new_notify = NULL;

    while(cp && *cp == '-') {
        switch (*(cp+1)) {
        case 's':
            cp = skip_token_const(cp);
            if (!cp) {
                config_perror("no argument given to -s");
                return;
            }
            max_size = atoi(cp);
            cp = skip_token_const(cp);
            break;
        default:
            config_perror("unknown flag");
            return;
        }
    }

    if (!cp) {
        config_perror("no frequency given");
        return;
    }
    frequency = atoi(cp);
    cp = skip_token_const(cp);

    if (frequency <= 0) {
        config_perror("illegal frequency given");
        return;
    }

    if (!cp) {
        config_perror("no OID given");
        return;
    }

    /* parse the OID given */
    if (!snmp_parse_oid(cp, target_oid, &target_oid_len)) {
        config_perror("unknown deliverByNotify OID");
        DEBUGMSGTL(("deliverByNotify", "The OID with the problem: %s\n", cp));
        return;
    }

    /* set up the object to store all the data */
    new_notify = SNMP_MALLOC_TYPEDEF(deliver_by_notify);
    new_notify->frequency = frequency;
    new_notify->max_packet_size = max_size;
    new_notify->last_run = time(NULL);
    new_notify->next_run = new_notify->last_run + frequency;

    new_notify->target = malloc(target_oid_len * sizeof(oid));
    new_notify->target_len = target_oid_len;
    memcpy(new_notify->target, target_oid, target_oid_len*sizeof(oid));

    /* XXX: need to do the whole container */
    snmp_alarm_register(calculate_time_until_next_run(new_notify, NULL), 0, 
                        &deliver_execute, NULL);

    /* add it to the container */
    CONTAINER_INSERT(deliver_container, new_notify);
    _schedule_next_execute_time();
}

void
parse_deliver_maxsize_config(const char *token, char *line) {
    default_max_size = atoi(line);
}

static void
_free_deliver_obj(deliver_by_notify *obj, void *context) {
    netsnmp_assert_or_return(obj != NULL, );
    SNMP_FREE(obj->target);
    SNMP_FREE(obj);
}

void
free_deliver_config(void) {
    default_max_size = DEFAULT_MAX_DELIVER_SIZE;
    CONTAINER_CLEAR(deliver_container,
                    (netsnmp_container_obj_func *) _free_deliver_obj, NULL);
    if (alarm_reg) {
        snmp_alarm_unregister(alarm_reg);
        alarm_reg = 0;
    }
}

void
deliver_execute(unsigned int clientreg, void *clientarg) {
    netsnmp_variable_list *vars, *walker, *deliver_notification;
    netsnmp_session *sess;
    int rc;
    deliver_by_notify *obj;
    netsnmp_iterator *iterator;
    time_t            now = time(NULL);

    DEBUGMSGTL(("deliverByNotify", "Starting the execute routine\n"));

    /* XXX: need to do the whole container */
    iterator = CONTAINER_ITERATOR(deliver_container);
    netsnmp_assert_or_return(iterator != NULL,);

    sess = netsnmp_query_get_default_session();

    for(obj = ITERATOR_FIRST(iterator); obj;
        obj = ITERATOR_NEXT(iterator)) {

        /* check if we need to run this one yet */
        if (obj->next_run > now)
            continue;

        /* fill the varbind list with the target object */
        vars = SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
        snmp_set_var_objid( vars, obj->target, obj->target_len );
        vars->type = ASN_NULL;

        /* walk the OID tree for the data */
        rc = netsnmp_query_walk(vars, sess);
        if (rc != SNMP_ERR_NOERROR) {
            snmp_log(LOG_ERR, "deliverByNotify: failed to issue the query");
            return;
        }

        /* Set up the notification itself */
        deliver_notification = NULL;
        /* add in the notification type */
        snmp_varlist_add_variable(&deliver_notification,
                                  objid_snmptrap, OID_LENGTH(objid_snmptrap),
                                  ASN_OBJECT_ID,
                                  data_notification_oid,
                                  sizeof(data_notification_oid));
    
        /* copy in the collected data */
        walker = vars;
        while(walker) {
            //print_variable(walker->name, walker->name_length, walker);

            snmp_varlist_add_variable(&deliver_notification,
                                      walker->name, walker->name_length,
                                      walker->type,
                                      walker->val.string, walker->val_len);

            walker = walker->next_variable;
        }
        snmp_free_varbind(vars);

        /* send out the notification */
        send_v2trap(deliver_notification);

        /* record this as the time processed */
        /* XXX: this may creep by a few seconds when processing and maybe we want
           to do the time stamp at the beginning? */
        obj->last_run = time(NULL);
    }

    /* calculate the next time to sleep for */
    _schedule_next_execute_time();
}

int
calculate_time_until_next_run(deliver_by_notify *it, time_t *now) {
    time_t          local_now;

    /* if we weren't passed a valid time, fake it */
    if (NULL == now) {
        now = &local_now;
        time(&local_now);
    }

    netsnmp_assert_or_return(it->last_run != 0, -1);

    /* set the timestamp for the next run */
    it->next_run = it->last_run + it->frequency;

    /* how long until the next run? */
    return it->next_run - *now;
}

static void
_schedule_next_execute_time(void) {
    time_t             local_now = time(NULL);
    int                sleep_for = INT_MAX;
    int                next_time;
    netsnmp_iterator  *iterator;
    deliver_by_notify *obj;

    DEBUGMSGTL(("deliverByNotify", "Calculating scheduling needed\n"));

    if (alarm_reg) {
        snmp_alarm_unregister(alarm_reg);
        alarm_reg = 0;
    }

    iterator = CONTAINER_ITERATOR(deliver_container);
    if (NULL == iterator)
        return;

    for(obj = ITERATOR_FIRST(iterator); obj;
        obj = ITERATOR_NEXT(iterator)) {
        next_time = calculate_time_until_next_run(obj, &local_now);
        DEBUGMSGTL(("deliverByNotify", "  obj: %d (last=%d, next_run=%d)\n", next_time, obj->last_run, obj->next_run));
        if (next_time < sleep_for)
            sleep_for = next_time;
    }

    if (sleep_for != INT_MAX) {
        if (sleep_for < 1)
            sleep_for = 1; /* give at least a small pause */
        DEBUGMSGTL(("deliverByNotify", "Next execution in %d (max = %d) seconds\n",
                    sleep_for, INT_MAX));
        alarm_reg = snmp_alarm_register(sleep_for, 0, &deliver_execute, NULL);
    }
}

