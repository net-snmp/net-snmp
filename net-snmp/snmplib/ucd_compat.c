/*
 * For compatibility with applications built using
 * previous versions of the UCD library only.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/types.h>
#include <net-snmp/session_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/library/mib.h>	/* for OID O/P format enums */

/*
 * use <netsnmp_session *)->s_snmp_errno instead 
 */
int
snmp_get_errno(void)
{
    return SNMPERR_SUCCESS;
}

/*
 * synch_reset and synch_setup are no longer used. 
 */
void
snmp_synch_reset(netsnmp_session * notused)
{
}
void
snmp_synch_setup(netsnmp_session * notused)
{
}


void
snmp_set_dump_packet(int x)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_DUMP_PACKET, x);
}

int
snmp_get_dump_packet(void)
{
    return netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, 
				  NETSNMP_DS_LIB_DUMP_PACKET);
}

void
snmp_set_quick_print(int x)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_QUICK_PRINT, x);
}

int
snmp_get_quick_print(void)
{
    return netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, 
				  NETSNMP_DS_LIB_QUICK_PRINT);
}


void
snmp_set_suffix_only(int x)
{
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
		       NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, x);
}

int
snmp_get_suffix_only(void)
{
    return netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
			      NETSNMP_DS_LIB_OID_OUTPUT_FORMAT);
}

void
snmp_set_full_objid(int x)
{
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
                                              NETSNMP_OID_OUTPUT_FULL);
}

int
snmp_get_full_objid(void)
{
    return (NETSNMP_OID_OUTPUT_FULL ==
        netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT));
}

void
snmp_set_random_access(int x)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_RANDOM_ACCESS, x);
}

int
snmp_get_random_access(void)
{
    return netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, 
				  NETSNMP_DS_LIB_RANDOM_ACCESS);
}

void
snmp_set_mib_errors(int err)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_MIB_ERRORS, err);
}

void
snmp_set_mib_warnings(int warn)
{
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, 
		       NETSNMP_DS_LIB_MIB_WARNINGS, warn);
}

void
snmp_set_save_descriptions(int save)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_SAVE_MIB_DESCRS, save);
}

void
snmp_set_mib_comment_term(int save)
{
    /*
     * 0=strict, 1=EOL terminated 
     */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_MIB_COMMENT_TERM, save);
}

void
snmp_set_mib_parse_label(int save)
{
    /*
     * 0=strict, 1=underscore OK in label 
     */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, 
			   NETSNMP_DS_LIB_MIB_PARSE_LABEL, save);
}
