/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 * include our parent header 
 */
#include "snmpTlstmAddrTable.h"

#include <net-snmp/agent/table_container.h>
#include <net-snmp/library/container.h>
#include <ctype.h>

#include <openssl/x509.h>
#include <net-snmp/library/cert_util.h>

#include "snmpTlstmAddrTable_internal.h"

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
static void _tlstmAddrTable_container_row_restore_mib(const char *token,
                                                       char *buf);
static int  _tlstmAddrTable_container_row_save(netsnmp_tdata_row * row,
                                               void *type);

static const char mib_token[] = "snmpTlstmAddrEntry";
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

    /** save table for use during row restore */
    _table_data = table_data;

    register_config_handler(NULL, mib_token,
                            _tlstmAddrTable_container_row_restore_mib, NULL,
                            NULL);
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
    netsnmp_container *addrs = (netsnmp_container *) clientarg;

    if ((NULL == addrs) || (CONTAINER_SIZE(addrs) == 0))
        return SNMPERR_SUCCESS;

    read_config_store((char *) type, sep);
    read_config_store((char *) type, buf);

    /*
     * save all rows
     */
    CONTAINER_FOR_EACH(addrs, (netsnmp_container_obj_func *)
                       _tlstmAddrTable_container_row_save, type);

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
    char                  buf[sizeof(mib_token) + (256 * 4) + (2 * 13) + 10];

    netsnmp_assert(row && row->data);
    entry = (tlstmAddrTable_entry *)row->data;

    /** don't store values from conf files */
    if (ST_NONVOLATILE != entry->tlstmAddrStorageType) {
        DEBUGMSGT(("tlstmAddrTable:row:save", 
                   "skipping RO/permanent/volatile (%d) row\n",
                   entry->tlstmAddrStorageType));
        return SNMP_ERR_NOERROR;
    }

    /*
     * build the line
     */
    netsnmp_assert(0 == entry->snmpTargetAddrName[
                       entry->snmpTargetAddrName_len]);
    netsnmp_assert(0 == entry->tlstmAddrServerFingerprint[
                       entry->tlstmAddrServerFingerprint_len]);
    netsnmp_assert(0 == entry->tlstmAddrServerIdentity[
                       entry->tlstmAddrServerIdentity_len]);
    snprintf(buf, sizeof(buf), "%s %s %d:0x%s %s %d", mib_token,
             entry->snmpTargetAddrName, entry->hashType,
             entry->tlstmAddrServerFingerprint, entry->tlstmAddrServerIdentity,
             entry->tlstmAddrRowStatus);
    buf[sizeof(buf)-1] = 0;

    read_config_store(type, buf);
    DEBUGMSGTL(("tlstmAddrTable:row:save", "saving line '%s'\n", buf));

    return SNMP_ERR_NOERROR;
}


static void
_tlstmAddrTable_container_row_restore_mib(const char *token, char *buf)
{
    char                   name[SNMPADMINLENGTH + 1], id[SNMPADMINLENGTH + 1],
                           fingerprint[SNMPTLSFINGERPRINT_MAX_LEN + 1];
    u_int                  name_len = sizeof(name), id_len = sizeof(id),
                           fp_len = sizeof(fingerprint);
    u_char                 hashType, rowStatus;
    int                    rc;

    /** need somewhere to save rows */
    netsnmp_assert(_table_data && _table_data->container); 

    rc = netsnmp_tlstmAddr_restore_common(&buf, name, &name_len, id, &id_len,
                                          fingerprint, &fp_len, &hashType);
    if (rc < 0)
        return;

    if (NULL == buf) {
        config_perror("incomplete line");
        return;
    }
    rowStatus = atoi(buf);

    /*
     * if row is active, add it to the addrs container so it is available
     * for use. Do not add it to the table, since it will be added
     * during cache_load.
     */
    if (RS_ACTIVE == rowStatus) {
        snmpTlstmAddr *addr;

        addr = netsnmp_tlstmAddr_create(name);
        if (!addr)
            return;

        if (fp_len)
            addr->fingerprint = strndup(fingerprint, fp_len);
        if (id_len)
            addr->identity = strndup(id, id_len);
        addr->hashType = hashType;
        addr->flags = TLSTM_ADDR_FROM_MIB | TLSTM_ADDR_NONVOLATILE;

        if (netsnmp_tlstmAddr_add(addr) != 0)
            netsnmp_tlstmAddr_free(addr);
    }
    else {
        netsnmp_tdata_row     *row;
        tlstmAddrTable_entry  *entry;

        row = tlstmAddrTable_createEntry(_table_data, name, name_len);
        if (!row)
            return;

        entry = row->data;
        
        entry->hashType = hashType;
        memcpy(entry->tlstmAddrServerFingerprint,fingerprint, fp_len);
        entry->tlstmAddrServerFingerprint_len = fp_len;
        memcpy(entry->tlstmAddrServerIdentity, id, id_len);
        entry->tlstmAddrServerIdentity_len = id_len;
        entry->tlstmAddrStorageType = ST_NONVOLATILE;
        entry->tlstmAddrRowStatus = rowStatus;
    }
}
