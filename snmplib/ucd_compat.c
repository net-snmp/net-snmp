/*
 * For compatibility with applications built using
 * previous versions of the UCD library only.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/types.h>
#include <net-snmp/session_api.h>
#include <net-snmp/config_api.h>

/* use <netsnmp_session *)->s_snmp_errno instead */
int  snmp_get_errno   (void)  { return SNMPERR_SUCCESS; }

/* synch_reset and synch_setup are no longer used. */
void snmp_synch_reset (netsnmp_session * notused) {}
void snmp_synch_setup (netsnmp_session * notused) {}


void
snmp_set_dump_packet(int x) {
    ds_set_boolean(DS_LIBRARY_ID, DS_LIB_DUMP_PACKET, x);
}

int
snmp_get_dump_packet(void) {
    return ds_get_boolean(DS_LIBRARY_ID, DS_LIB_DUMP_PACKET);
}

void
snmp_set_quick_print(int x) {
    ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, x);
}
  
int
snmp_get_quick_print(void) {
    return ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT);
}
 

void
snmp_set_suffix_only(int x) {
    ds_set_int(DS_LIBRARY_ID, DS_LIB_PRINT_SUFFIX_ONLY, x);
}
  
int
snmp_get_suffix_only(void) {
    return ds_get_int(DS_LIBRARY_ID, DS_LIB_PRINT_SUFFIX_ONLY);
}
 
void
snmp_set_full_objid(int x) {
      ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_FULL_OID, x);
}

int
snmp_get_full_objid(void) {
    return ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_FULL_OID);
}
 
void
snmp_set_random_access(int x) {
    ds_set_boolean(DS_LIBRARY_ID, DS_LIB_RANDOM_ACCESS, x);
}
 
int
snmp_get_random_access(void) {
    return ds_get_boolean(DS_LIBRARY_ID, DS_LIB_RANDOM_ACCESS);
}

void snmp_set_mib_errors(int err)
{
  ds_set_boolean(DS_LIBRARY_ID, DS_LIB_MIB_ERRORS, err);
}

void snmp_set_mib_warnings(int warn)
{
  ds_set_int(DS_LIBRARY_ID, DS_LIB_MIB_WARNINGS, warn);
}

void snmp_set_save_descriptions(int save)
{
  ds_set_boolean(DS_LIBRARY_ID, DS_LIB_SAVE_MIB_DESCRS, save);
}

void snmp_set_mib_comment_term(int save)
{
  /* 0=strict, 1=EOL terminated */
  ds_set_boolean(DS_LIBRARY_ID, DS_LIB_MIB_COMMENT_TERM, save);
}

void snmp_set_mib_parse_label(int save)
{
  /* 0=strict, 1=underscore OK in label */
  ds_set_boolean(DS_LIBRARY_ID, DS_LIB_MIB_PARSE_LABEL, save);
}

