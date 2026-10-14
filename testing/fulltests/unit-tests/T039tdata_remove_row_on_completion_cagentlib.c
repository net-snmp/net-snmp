/* HEADER Testing netsnmp_tdata_remove_row_on_completion() */

#if !defined(USING_DISMAN_SCHEDULE_SCHEDCORE_MODULE) || \
    defined(NETSNMP_NO_WRITE_SUPPORT)
printf("1..0 # skip disman/schedule not enabled\n");
__did_plan = 1;
return 0;
#else
#include "disman/schedule/schedCore.h"

netsnmp_agent_request_info *reqinfo;
netsnmp_tdata_row          *row1, *row2;

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");
init_schedule_container();

row1 = schedTable_createEntry("owner", "name1");
row2 = schedTable_createEntry("owner", "name2");
OK(row1 && row2, "created two rows");
OK(netsnmp_tdata_row_count(schedule_table) == 2, "table has two rows");

/* 1. The row is removed only once the request has been processed. */
reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
OK(reqinfo != NULL, "allocated request info");
reqinfo->mode = MODE_SET_COMMIT;
netsnmp_tdata_remove_row_on_completion(reqinfo, schedule_table, row1,
                                       schedTable_removeEntry);
OK(netsnmp_tdata_row_get(schedule_table, row1) == row1,
   "row is still in the table while the request is being processed");

/* 2. Asking twice for the removal of the same row is harmless. */
reqinfo->mode = MODE_SET_FREE;
netsnmp_tdata_remove_row_on_completion(reqinfo, schedule_table, row1,
                                       schedTable_removeEntry);
netsnmp_free_agent_request_info(reqinfo);
OK(netsnmp_tdata_row_count(schedule_table) == 1,
   "row has been removed once the request has been processed");
OK(netsnmp_tdata_row_first(schedule_table) == row2,
   "the other row is still in the table");

/* 3. A row that has already left the table is not removed again. */
reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);
OK(reqinfo != NULL, "allocated request info");
reqinfo->mode = MODE_SET_COMMIT;
netsnmp_tdata_remove_row_on_completion(reqinfo, schedule_table, row2,
                                       schedTable_removeEntry);
schedTable_removeEntry(row2);
OK(netsnmp_tdata_row_count(schedule_table) == 0, "table is empty");
netsnmp_free_agent_request_info(reqinfo);
OK(netsnmp_tdata_row_count(schedule_table) == 0, "table is still empty");

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif
