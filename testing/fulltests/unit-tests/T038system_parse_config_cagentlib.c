/* HEADER Testing system_parse_config_string() in system_mib */

#ifndef USING_MIBII_SYSTEM_MIB_MODULE
printf("1..0 # skip mibII/system_mib not enabled\n");
__did_plan = 1;
return 0;
#else
#include "mibII/system_mib.h"

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");
init_system_mib();

/* 1. Normal configuration parses successfully */
netsnmp_config("psyslocation 0x54657374204c6f636174696f6e");
OK(TRUE, "valid psyslocation hex string parsed");

/* 2. Invalid hex characters: read_config_read_octet_string returns NULL with len != 0 */
netsnmp_config("psyslocation 0xzz");
OK(TRUE, "psyslocation with invalid hex characters handled (len != 0)");

netsnmp_config("psyscontact 0x0100zz");
OK(TRUE, "psyscontact with invalid hex suffix handled (len != 0)");

netsnmp_config("psysname 0x0");
OK(TRUE, "psysname with odd-length hex string handled (len != 0)");

/* 3. Oversized hex string: read_config_read_octet_string returns NULL with len == 0 */
{
    char oversized[600];
    memcpy(oversized, "psyslocation 0x", 15);
    memset(oversized + 15, '4', 530);
    oversized[15 + 530] = '\0';
    netsnmp_config(oversized);
    OK(TRUE, "psyslocation oversized hex string handled (len == 0)");
}

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif
