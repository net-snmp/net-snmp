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
deliver_execute(void) {
}
