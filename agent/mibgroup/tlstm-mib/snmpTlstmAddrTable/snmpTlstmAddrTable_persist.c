/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * include our parent header 
 */
#include "tlstmAddrTable.h"

#include <net-snmp/agent/table_container.h>
#include <net-snmp/library/container.h>
#include <ctype.h>

#include "tlstmAddrTable_internal.h"

/**********************************************************************
 **********************************************************************
 ***
 *** Table 
 ***
 **********************************************************************
 **********************************************************************/
/***********************************************************************
 *
 * PERSISTENCE
 *
 ***********************************************************************/

static int  _tlstmAddrTable_container_save_rows(int majorID, int minorID,
                                                void *serverarg,
                                                void *clientarg);
static void _tlstmAddrTable_container_row_restore_system(const char *token,
                                                         char *buf);
static void _tlstmAddrTable_container_row_restore_user(const char *token,
                                                       char *buf);
static int  _tlstmAddrTable_container_row_save(netsnmp_tdata_row * row,
                                               void *type);

static const char system_token[] = "tlstmAddrTable";
static const char user_token[] = "tlstmAddrEntry";
static netsnmp_tdata  *_table_data = NULL;

/************************************************************
 * *_init_persistence should be called from the main table
 * init routine.
 *
 * If your table depends on rows in another table,
 * you should register your callback after the other table,
 * which should ensure the rows on which you depend are saved
 * (and re-created) before the dependent rows.
 */
void
_tlstmAddr_container_init_persistence(netsnmp_tdata *table_data)
{
    int             rc;
    const char     *user_help = 
        "tlstmAddrEntry targetName fingerPrintLen hashType:fingerPrint "
        "serverIdentityLen serverIdentity";

    /** save table for use during row restore */
    _table_data = table_data;

    register_config_handler(NULL, system_token,
                            _tlstmAddrTable_container_row_restore_system, NULL,
                            NULL);
    register_config_handler(NULL, user_token,
                            _tlstmAddrTable_container_row_restore_user, NULL,
                            user_help);
    rc = snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                                SNMP_CALLBACK_STORE_DATA,
                                _tlstmAddrTable_container_save_rows,
                                table_data->container);

    if (rc != SNMP_ERR_NOERROR)
        snmp_log(LOG_ERR, "error registering for STORE_DATA callback "
                 "in _tlstmAddrTable_container_init_persistence\n");
}

static int
_tlstmAddrTable_container_save_rows(int majorID, int minorID, void *serverarg,
                      void *clientarg)
{
    char            sep[] =
        "##############################################################";
    char            buf[] = "#\n" "# tlstmAddr persistent data\n" "#";
    char           *type = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                                 NETSNMP_DS_LIB_APPTYPE);

    read_config_store((char *) type, sep);
    read_config_store((char *) type, buf);

    /*
     * save all rows
     */
    CONTAINER_FOR_EACH((netsnmp_container *) clientarg,
                       (netsnmp_container_obj_func *)
                       _tlstmAddrTable_container_row_save,
                       type);

    read_config_store((char *) type, sep);
    read_config_store((char *) type, "\n");

    /*
     * never fails 
     */
    return SNMPERR_SUCCESS;
}



/************************************************************
 * _tlstmAddrTable_container_row_save
 */
static int
_tlstmAddrTable_container_row_save(netsnmp_tdata_row * row, void *type)
{
    tlstmAddrTable_entry *entry;
    char                  buf[sizeof(system_token) + (256 * 4) + (2 * 13) + 10];
    char                 *pos = buf;

    netsnmp_assert(row && row->data);
    entry = (tlstmAddrTable_entry *)row->data;

    /** don't store values from conf files */
    if ((ST_PERMANENT == entry->tlstmAddrStorageType) ||
        (ST_READONLY == entry->tlstmAddrStorageType) ||
        (ST_VOLATILE == entry->tlstmAddrStorageType)) {
        DEBUGMSGT(("tlstmAddrTable:row:save", 
                   "skipping RO/permanent/volatile row\n"));
        return SNMP_ERR_NOERROR;
    }

    /*
     * build the line
     */
    snprintf(buf, sizeof(buf), "%s ", system_token);
    buf[sizeof(buf)-1] = 0;
    pos = &buf[strlen(buf)];

    pos =
        read_config_save_octet_string(pos, (u_char *)entry->snmpTargetAddrName,
                                      entry->snmpTargetAddrName_len);
    *pos++ = ' ';
    pos =
        read_config_save_octet_string(pos, (u_char *)
                                      entry->tlstmAddrServerFingerprint,
                                      entry->tlstmAddrServerFingerprint_len);
    *pos++ = ' ';
    pos =
        read_config_save_octet_string(pos, (u_char *)
                                      entry->tlstmAddrServerIdentity,
                                      entry->tlstmAddrServerIdentity_len);
    *pos++ = ' ';

    snprintf(pos, sizeof(buf), "%d %d ", entry->tlstmAddrStorageType,
             entry->tlstmAddrRowStatus);
    buf[sizeof(buf)-1] = 0;
    pos = &buf[strlen(buf)];

    read_config_store(type, buf);
    DEBUGMSGTL(("tlstmAddrTable:row:save", "saving line '%s'\n", buf));

    return SNMP_ERR_NOERROR;
}


static tlstmAddrTable_entry *
_tlstmAddrTable_container_row_restore_common(char *buf)
{
    netsnmp_tdata_row    *row;
    tlstmAddrTable_entry  entry, *new_entry;
    char                 *tmp;

    /** need somewhere to save rows */
    netsnmp_assert(_table_data && _table_data->container); 

    entry.snmpTargetAddrName_len = sizeof(entry.snmpTargetAddrName);
    tmp = entry.snmpTargetAddrName;
    buf = read_config_read_octet_string(buf, (u_char **)&tmp,
                                        &entry.snmpTargetAddrName_len);

    entry.tlstmAddrServerFingerprint_len =
        sizeof(entry.tlstmAddrServerFingerprint);
    tmp = entry.tlstmAddrServerFingerprint;
    buf = read_config_read_octet_string(buf, (u_char **)&tmp,
                                        &entry.tlstmAddrServerFingerprint_len);
    if (tmp[1] != ':' || !isdigit(tmp[0])) {
        /** xxx: could assume some default here instead of bailing */
        config_perror("fingerprint must include hash type");
        return NULL;
    }
    
    entry.tlstmAddrServerIdentity_len =
        sizeof(entry.tlstmAddrServerIdentity);
    tmp = entry.tlstmAddrServerIdentity;
    buf = read_config_read_octet_string(buf, (u_char **)&tmp,
                                        &entry.tlstmAddrServerIdentity_len);

    row = tlstmAddrTable_createEntry(_table_data,
                                     entry.snmpTargetAddrName,
                                     entry.snmpTargetAddrName_len);
    if (!row)
        return NULL;

    new_entry = row->data;

    new_entry->tlstmAddrStorageType = entry.tlstmAddrStorageType;
    new_entry->tlstmAddrRowStatus = entry.tlstmAddrRowStatus;
    entry.tlstmAddrServerFingerprint[1] = '\0';
    new_entry->hashType = atoi(entry.tlstmAddrServerFingerprint);
    netsnmp_fp_lowercase_and_strip_colon(&entry.tlstmAddrServerFingerprint[2]);
    memcpy(new_entry->tlstmAddrServerFingerprint,
           &entry.tlstmAddrServerFingerprint[2],
           entry.tlstmAddrServerFingerprint_len);
    new_entry->tlstmAddrServerFingerprint_len =
        strlen(new_entry->tlstmAddrServerFingerprint);
    memcpy(new_entry->tlstmAddrServerIdentity,
           entry.tlstmAddrServerIdentity,
           entry.tlstmAddrServerIdentity_len);
    new_entry->tlstmAddrServerIdentity_len = entry.tlstmAddrServerIdentity_len;

    return new_entry;
}

static void
_tlstmAddrTable_container_row_restore_system(const char *token, char *buf)
{
    tlstmAddrTable_entry  *entry =
        _tlstmAddrTable_container_row_restore_common(buf);

    if (!entry)
        return;

    entry->tlstmAddrStorageType = atoi(buf);
    buf = skip_token(buf);

    entry->tlstmAddrRowStatus = atoi(buf);
    buf = skip_token(buf);
}

static void
_tlstmAddrTable_container_row_restore_user(const char *token, char *buf)
{
    tlstmAddrTable_entry  *entry =
        _tlstmAddrTable_container_row_restore_common(buf);

    if (!entry)
        return;

    entry->tlstmAddrStorageType = ST_PERMANENT;
    entry->tlstmAddrRowStatus = RS_ACTIVE;
}
