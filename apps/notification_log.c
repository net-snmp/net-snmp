#include <config.h>

#include "mibincl.h"
#include "snmp_transport.h"
#include "helpers/instance.h"
#include "helpers/table.h"
#include "helpers/table_data.h"
#include "helpers/table_dataset.h"
#include "notification_log.h"

extern u_long num_received;
u_long num_deleted = 0;

u_long max_logged = 0;
u_long max_age = 1440;

table_data_set *nlmLogTable;

/** Initialize the nlmLogTable table by defining it's contents and how it's structured */
void
initialize_table_nlmLogTable(void)
{
    static oid      nlmLogTable_oid[] = { 1, 3, 6, 1, 2, 1, 92, 1, 3, 1 };
    size_t          nlmLogTable_oid_len = OID_LENGTH(nlmLogTable_oid);

    /*
     * create the table structure itself 
     */
    nlmLogTable = create_table_data_set("nlmLogTable");

    /***************************************************
     * Adding indexes
     */
    /*
     * declaring the nlmLogIndex index
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding index nlmLogName of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_dataset_add_index(nlmLogTable, ASN_OCTET_STR);

    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding index nlmLogIndex of type ASN_UNSIGNED to table nlmLogTable\n"));
    table_dataset_add_index(nlmLogTable, ASN_UNSIGNED);

    /*
     * adding column nlmLogTime of type ASN_TIMETICKS and access of
     * ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogTime (#2) of type ASN_TIMETICKS to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGTIME, ASN_TIMETICKS,
                              0);
    /*
     * adding column nlmLogDateAndTime of type ASN_OCTET_STR and access of 
     * ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogDateAndTime (#3) of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGDATEANDTIME,
                              ASN_OCTET_STR, 0);
    /*
     * adding column nlmLogEngineID of type ASN_OCTET_STR and access of
     * ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogEngineID (#4) of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGENGINEID,
                              ASN_OCTET_STR, 0);
    /*
     * adding column nlmLogEngineTAddress of type ASN_OCTET_STR and access 
     * of ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogEngineTAddress (#5) of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGENGINETADDRESS,
                              ASN_OCTET_STR, 0);
    /*
     * adding column nlmLogEngineTDomain of type ASN_OBJECT_ID and access
     * of ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogEngineTDomain (#6) of type ASN_OBJECT_ID to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGENGINETDOMAIN,
                              ASN_OBJECT_ID, 0);
    /*
     * adding column nlmLogContextEngineID of type ASN_OCTET_STR and
     * access of ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogContextEngineID (#7) of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGCONTEXTENGINEID,
                              ASN_OCTET_STR, 0);
    /*
     * adding column nlmLogContextName of type ASN_OCTET_STR and access of 
     * ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogContextName (#8) of type ASN_OCTET_STR to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGCONTEXTNAME,
                              ASN_OCTET_STR, 0);
    /*
     * adding column nlmLogNotificationID of type ASN_OBJECT_ID and access 
     * of ReadOnly 
     */
    DEBUGMSGTL(("initialize_table_nlmLogTable",
                "adding column nlmLogNotificationID (#9) of type ASN_OBJECT_ID to table nlmLogTable\n"));
    table_set_add_default_row(nlmLogTable, COLUMN_NLMLOGNOTIFICATIONID,
                              ASN_OBJECT_ID, 0);

    /*
     * registering the table with the master agent 
     */
    /*
     * note: if you don't need a subhandler to deal with any aspects of
     * the request, change nlmLogTable_handler to "NULL" 
     */
    register_table_data_set(create_handler_registration
                            ("nlmLogTable", nlmLogTable_handler,
                             nlmLogTable_oid, nlmLogTable_oid_len,
                             HANDLER_CAN_RWRITE), nlmLogTable, NULL);
}

void
init_notification_log(void) 
{
    static oid my_nlmStatsGlobalNotificationsLogged_oid[] = {1,3,6,1,2,1,92,1,2,1,0};
    static oid my_nlmStatsGlobalNotificationsBumped_oid[] = {1,3,6,1,2,1,92,1,2,2,0};
    static oid my_nlmConfigGlobalEntryLimit_oid[] = {1,3,6,1,2,1,92,1,1,1,0};
    static oid my_nlmConfigGlobalAgeOut_oid[] = {1,3,6,1,2,1,92,1,1,2,0};

    /* static variables */
    register_read_only_counter32_instance("nlmStatsGlobalNotificationsLogged",
                                          my_nlmStatsGlobalNotificationsLogged_oid, OID_LENGTH(my_nlmStatsGlobalNotificationsLogged_oid),
                                          &num_received);

    register_read_only_counter32_instance("nlmStatsGlobalNotificationsBumped",
                                          my_nlmStatsGlobalNotificationsBumped_oid, OID_LENGTH(my_nlmStatsGlobalNotificationsBumped_oid),
                                          &num_deleted);

    register_ulong_instance("nlmConfigGlobalEntryLimit",
                            my_nlmConfigGlobalEntryLimit_oid, OID_LENGTH(my_nlmConfigGlobalEntryLimit_oid),
                            &max_logged);

    register_ulong_instance("nlmConfigGlobalAgeOut",
                            my_nlmConfigGlobalAgeOut_oid, OID_LENGTH(my_nlmConfigGlobalAgeOut_oid),
                            &max_age);

    /* tables */
    initialize_table_nlmLogTable();
}

u_long default_num = 0;

void
log_notification(struct hostent *host, struct snmp_pdu *pdu,
                 snmp_transport *transport) 
{
    long tmpl;
    struct timeval now;
    table_row *row;

    static oid snmptrapoid[] = {1,3,6,1,6,3,1,1,4,1,0};
    size_t snmptrapoid_len = OID_LENGTH(snmptrapoid);
    struct variable_list *vptr;
    
    DEBUGMSGTL(("log_notification","logging something\n"));
    row = create_table_data_row();

    default_num++;

    /* indexes to the table */
    table_row_add_index(row, ASN_OCTET_STR, "default",
                        strlen("default"));
    table_row_add_index(row, ASN_UNSIGNED, &default_num,
                        sizeof(default_num));

    /* add the data */
    gettimeofday(&now, NULL);
    tmpl = timeval_uptime( &now );
    set_row_column(row, COLUMN_NLMLOGTIME, ASN_TIMETICKS,
                   (u_char *) &tmpl, sizeof(tmpl));
/* XXX: do after merge to main line
    set_row_column(row, COLUMN_NLMLOGDATEANDTIME, , );
*/
    set_row_column(row, COLUMN_NLMLOGENGINEID, ASN_OCTET_STR,
                   pdu->securityEngineID, pdu->securityEngineIDLen);
    if (transport &&
        transport->domain == snmpUDPDomain) {
        /* lame way to check for the udp domain */
        struct sockaddr_in *addr =
            (struct sockaddr_in *)pdu->transport_data;
        if (addr) {
            char buf[sizeof(in_addr_t) + sizeof(addr->sin_port)];
            in_addr_t locaddr = htonl(addr->sin_addr.s_addr);
            in_port_t portnum = htons(addr->sin_port);
            memcpy(buf, &locaddr, sizeof(in_addr_t));
            memcpy(buf + sizeof(in_addr_t), &portnum,
                   sizeof(addr->sin_port));
            set_row_column(row, COLUMN_NLMLOGENGINETADDRESS, ASN_OCTET_STR,
                           buf, sizeof(in_addr_t) + sizeof(addr->sin_port));
        }
    }
    set_row_column(row, COLUMN_NLMLOGENGINETDOMAIN, ASN_OBJECT_ID,
                   (const u_char *) transport->domain,
                   sizeof(oid)*transport->domain_length);
    set_row_column(row, COLUMN_NLMLOGCONTEXTENGINEID, ASN_OCTET_STR,
                   pdu->contextEngineID, pdu->contextEngineIDLen);
    set_row_column(row, COLUMN_NLMLOGCONTEXTNAME, ASN_OCTET_STR,
                   pdu->contextName, pdu->contextNameLen);
    for(vptr = pdu->variables; vptr; vptr = vptr->next_variable) {
        if (snmp_oid_compare(snmptrapoid, snmptrapoid_len,
                             vptr->name, vptr->name_length) == 0) {
            set_row_column(row, COLUMN_NLMLOGNOTIFICATIONID, ASN_OBJECT_ID,
                           vptr->val.string, vptr->val_len);

            break;
        }
    }

    /* store the row */
    table_dataset_add_row(nlmLogTable, row);
    DEBUGMSGTL(("log_notification","done logging something\n"));
}

/** handles requests for the nlmLogTable table, if anything else needs to be done */
int
nlmLogTable_handler(mib_handler * handler,
                    handler_registration * reginfo,
                    agent_request_info * reqinfo, request_info * requests)
{
    /*
     * perform anything here that you need to do.  The requests have
     * already been processed by the master table_dataset handler, but
     * this gives you chance to act on the request in some other way if
     * need be. 
     */
    return SNMP_ERR_NOERROR;
}
