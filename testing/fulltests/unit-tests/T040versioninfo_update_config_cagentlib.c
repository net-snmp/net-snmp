/* HEADER Testing that versionUpdateConfig reloads the configuration after the request */

#ifndef USING_UCD_SNMP_VERSIONINFO_MODULE
printf("1..0 # skip ucd-snmp/versioninfo not enabled\n");
__did_plan = 1;
return 0;
#else
#include "ucd-snmp/versioninfo.h"

#define RELOADED NETSNMP_DS_APPLICATION_ID, 40 /* unused by the agent */

long one = 1, zero = 0;
oid name[] = { 1, 3, 6, 1, 4, 1, 2021, 100, VERUPDATECONFIG, 0 };
const char *dir = "/tmp/snmp-versioninfo-unit-test";
char path[64];
FILE *fp;

SOCK_STARTUP;

/*
 * Run the agent with a configuration file that sets a token which is only
 * set again when the configuration is read again.
 */
OK(mkdirhier(dir, 0700, 0) == SNMPERR_SUCCESS, "temporary directory created");
snprintf(path, sizeof(path), "%s/snmpd.conf", dir);
fp = fopen(path, "w");
OK(fp != NULL, "configuration file created");
if (fp) {
    fputs("testReloaded true\n", fp);
    fclose(fp);
}
netsnmp_setenv("SNMPCONFPATH", dir, 1);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE, 1);

netsnmp_ds_register_config(ASN_BOOLEAN, "snmpd", "testReloaded", RELOADED);
init_agent("snmpd");
init_snmp("snmpd");
OK(netsnmp_ds_get_boolean(RELOADED), "configuration file read at startup");

/* 1. Setting the object to 1 reloads the configuration after the request. */
netsnmp_ds_set_boolean(RELOADED, 0);
OK(update_hook(COMMIT, (u_char *)&one, ASN_INTEGER, sizeof(one), NULL,
               name, OID_LENGTH(name)) == SNMP_ERR_NOERROR,
   "update_hook() accepts 1 in COMMIT");
OK(!netsnmp_ds_get_boolean(RELOADED),
   "the configuration is not reloaded while the request is processed");
run_alarms();
OK(netsnmp_ds_get_boolean(RELOADED),
   "the configuration is reloaded once the request has been processed");
netsnmp_ds_set_boolean(RELOADED, 0);
run_alarms();
OK(!netsnmp_ds_get_boolean(RELOADED), "the configuration is reloaded only once");

/* 2. Other values and other SET modes do not reload the configuration. */
OK(update_hook(COMMIT, (u_char *)&zero, ASN_INTEGER, sizeof(zero), NULL,
               name, OID_LENGTH(name)) == SNMP_ERR_NOERROR,
   "update_hook() accepts 0 in COMMIT");
OK(update_hook(RESERVE1, (u_char *)&one, ASN_INTEGER, sizeof(one), NULL,
               name, OID_LENGTH(name)) == SNMP_ERR_NOERROR,
   "update_hook() accepts 1 in RESERVE1");
run_alarms();
OK(!netsnmp_ds_get_boolean(RELOADED),
   "the configuration is not reloaded for 0 or before COMMIT");

snmp_shutdown("snmpd");
shutdown_agent();

remove(path);
remove(dir);

SOCK_CLEANUP;
#endif
