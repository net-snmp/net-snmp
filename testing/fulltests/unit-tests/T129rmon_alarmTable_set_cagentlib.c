/* HEADER Testing RMON alarmTable SETs that remove a row */

#include <net-snmp/agent/mib_module_config.h>

#if !defined(USING_RMON_ALARMTABLE_MODULE) || \
    !defined(USING_UTILITIES_IQUERY_MODULE) || \
    defined(NETSNMP_NO_WRITE_SUPPORT) || \
    defined(NETSNMP_DISABLE_SET_SUPPORT)
printf("1..0 # skip Rmon/alarmTable or iquery not enabled\n");
__did_plan = 1;
return 0;
#else
#include "Rmon/alarmTable.h"
#include "utilities/iquery.h"

/* alarmStatus.8 and alarmOwner.8 */
static const oid status_oid[] = { 1, 3, 6, 1, 2, 1, 16, 3, 1, 1,
                                  COLUMN_ALARMSTATUS, 8 };
static const oid owner_oid[] = { 1, 3, 6, 1, 2, 1, 16, 3, 1, 1,
                                 COLUMN_ALARMOWNER, 8 };
netsnmp_session *sess;
netsnmp_variable_list *vars;
char rwuser_line[] = "rwuser internal";
long status;
int rc;

SOCK_STARTUP;

netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_ALARM_DONT_USE_SIG, 1);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
init_agent("snmpd");
init_alarmTable();
init_snmp("snmpd");
netsnmp_config(rwuser_line);
sess = netsnmp_iquery_user_session("internal");
OK(sess != NULL, "internal query session created");

/* alarmStatus = createRequest(2) and alarmOwner for a new row */
vars = NULL;
status = 2;
snmp_varlist_add_variable(&vars, status_oid, OID_LENGTH(status_oid),
                          ASN_INTEGER, &status, sizeof(status));
snmp_varlist_add_variable(&vars, owner_oid, OID_LENGTH(owner_oid),
                          ASN_OCTET_STR, "o", 1);
rc = netsnmp_query_set(vars, sess);
OKF(rc == SNMP_ERR_NOERROR, ("SET creating alarm row 8 succeeds (%d)", rc));
snmp_free_varbind(vars);

vars = NULL;
snmp_varlist_add_variable(&vars, owner_oid, OID_LENGTH(owner_oid),
                          ASN_NULL, NULL, 0);
rc = netsnmp_query_get(vars, sess);
OKF(rc == SNMP_ERR_NOERROR && vars->type == ASN_OCTET_STR &&
    vars->val_len == 1 && vars->val.string[0] == 'o',
    ("alarm row 8 exists with its owner (%d, type %d)", rc, vars->type));
snmp_free_varbind(vars);

/* alarmStatus = invalid(4) followed by alarmOwner for the same row */
vars = NULL;
status = 4;
snmp_varlist_add_variable(&vars, status_oid, OID_LENGTH(status_oid),
                          ASN_INTEGER, &status, sizeof(status));
snmp_varlist_add_variable(&vars, owner_oid, OID_LENGTH(owner_oid),
                          ASN_OCTET_STR, "x", 1);
rc = netsnmp_query_set(vars, sess);
OKF(rc == SNMP_ERR_NOERROR,
    ("SET removing alarm row 8 and writing its owner succeeds (%d)", rc));
snmp_free_varbind(vars);

vars = NULL;
snmp_varlist_add_variable(&vars, owner_oid, OID_LENGTH(owner_oid),
                          ASN_NULL, NULL, 0);
rc = netsnmp_query_get(vars, sess);
OKF(rc == SNMP_ERR_NOERROR &&
    (vars->type == SNMP_NOSUCHINSTANCE || vars->type == SNMP_NOSUCHOBJECT),
    ("alarm row 8 is removed (%d, type %d)", rc, vars->type));
snmp_free_varbind(vars);

snmp_close(sess);
snmp_shutdown("snmpd");
shutdown_agent();
SOCK_CLEANUP;
#endif
