/* HEADER Testing the alarms and the deferred free of DISMAN-EVENT-MIB triggers */

#include <net-snmp/agent/mib_module_config.h>

#ifndef USING_DISMAN_EVENT_MTETRIGGER_MODULE
printf("1..0 # skip disman/event/mteTrigger not enabled\n");
__did_plan = 1;
return 0;
#else
#include "disman/event/mteTrigger.h"

/*
 * snmp_alarm_reset() fails for an alarm id that is not registered (and
 * restarts the interval of one that is, which does not matter here).
 */
#define REGISTERED(id) ((id) != 0 && snmp_alarm_reset(id) == 0)

struct mteTrigger *entry;
unsigned int first, periodic;
int i;

/* Run alarms only from run_alarms() below, as snmpd does. */
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_ALARM_DONT_USE_SIG, 1);

entry = SNMP_MALLOC_TYPEDEF(struct mteTrigger);
OK(entry != NULL, "trigger allocated");

entry->mteTriggerFrequency = 600;
mteTrigger_enable(entry);
first = entry->first_alarm;
periodic = entry->alarm;
OK(REGISTERED(first), "enable registers the first run");
OK(REGISTERED(periodic), "enable registers the periodic run");

mteTrigger_enable(entry);
OK(!REGISTERED(first) && !REGISTERED(periodic),
   "enable again cancels the earlier alarms");
first = entry->first_alarm;
periodic = entry->alarm;
mteTrigger_disable(entry);
OK(entry->first_alarm == 0 && entry->alarm == 0,
   "disable clears both alarm ids");
OK(!REGISTERED(first) && !REGISTERED(periodic),
   "disable cancels both alarms");

mteTrigger_enable(entry);
first = entry->first_alarm;
for (i = 0; entry->first_alarm != 0 && i < 1000000; i++)
    run_alarms();
OK(entry->first_alarm == 0 && !REGISTERED(first),
   "the first run clears its alarm id");
periodic = entry->alarm;
mteTrigger_disable(entry);
OK(!REGISTERED(periodic), "disable after the first run cancels the alarm");

SNMP_FREE(entry);
#endif
