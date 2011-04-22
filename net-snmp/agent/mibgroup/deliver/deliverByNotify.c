#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "deliveryByNotify.h"

void parse_deliver_config(const char *, char *);
void free_deliver_config(void);

/** Initializes the mteTrigger module */
void
init_mteTrigger(void)
{
    snmpd_register_config_handler("deliver",
                                  &parse_deliver_config, &free_deliver_config,
                                  "foo");
}

void
parse_deliver_config(const char *token, char *line) {
}

void
free_deliver_config(void) {
}

void
deliver_execute(unsigned int clientreg, void *clientarg) {
    
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

    return time_since_last - it->frequency;
}
