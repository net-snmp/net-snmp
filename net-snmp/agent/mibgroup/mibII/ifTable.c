/*
 *  Interface MIB ifTable (and ifXTable) implementation - ifTable.c
 *
 */

#include <net-snmp/net-snmp-config.h>
#include "mibII_common.h"

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/auto_nlist.h>

#include "ifTable.h"
#include "ifTable_columns.h"
#include "ifXTable_columns.h"

        /*
         * Head of linked list, or root of table 
         */
netsnmp_ifentry *if_head = NULL;
int             if_size = 0;

unsigned long long get_ifspeed(netsnmp_ifentry * entry);
int             get_iftype(netsnmp_ifentry * entry);
int             ifTable_info(netsnmp_ifentry * entry);

        /*
         *
         * Initialization and handler routines are common to all architectures
         *
         */
#ifndef MIB_STATS_CACHE_TIMEOUT
#define MIB_STATS_CACHE_TIMEOUT	5
#endif
#ifndef IF_STATS_CACHE_TIMEOUT
#define IF_STATS_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif

oid             ifTable_oid[] = { SNMP_OID_MIB2, 2, 2 };
oid             ifXTable_oid[] = { SNMP_OID_MIB2, 31, 1, 1 };

void
init_ifTable(void)
{
    netsnmp_table_registration_info *table_info;
    netsnmp_iterator_info *iinfo;
    netsnmp_handler_registration *reginfo;

    DEBUGMSGTL(("mibII/ifTable", "Initialising Interface Table\n"));
    /*
     * Create the table data structure, and define the indexing....
     */
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!table_info) {
        return;
    }
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER, 0);
    table_info->min_column = COLUMN_IFINDEX;
    table_info->max_column = COLUMN_IFSPECIFIC;


    /*
     * .... and iteration information ....
     */
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        return;
    }
    iinfo->get_first_data_point = ifTable_first_entry;
    iinfo->get_next_data_point = ifTable_next_entry;
    iinfo->table_reginfo = table_info;
#ifdef DO_WE_SORT_THIS
    iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
#endif                          /* WIN32 || solaris2 */


    /*
     * .... and register the table with the agent.
     */
    reginfo = netsnmp_create_handler_registration("ifTable",
                                                  ifTable_handler,
                                                  ifTable_oid,
                                                  OID_LENGTH(ifTable_oid),
                                                  HANDLER_CAN_RONLY),
        netsnmp_register_table_iterator(reginfo, iinfo);

    /*
     * .... with a local cache
     *    (except for Solaris, which uses a different approach)
     */
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_cache_handler
                           (IF_STATS_CACHE_TIMEOUT, ifTable_load,
                            ifTable_free, ifTable_oid,
                            OID_LENGTH(ifTable_oid)));
#define ENTENDED_IF_TABLE
#ifdef ENTENDED_IF_TABLE
    /*
     * Now do exactly the same thing with the extension table
     */
    DEBUGMSGTL(("mibII/ifTable",
                "Initialising Interface Extension Table\n"));
    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!table_info) {
        return;
    }
    netsnmp_table_helper_add_indexes(table_info, ASN_INTEGER, 0);
    table_info->min_column = COLUMN_IFNAME;
    table_info->max_column = COLUMN_IFCOUNTERDISCONTINUITYTIME;
    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        return;
    }
    /*
     * Note that we re-use the same iteration hook routines
     * This is sufficient to link the two tables together
     */
    iinfo->get_first_data_point = ifTable_first_entry;
    iinfo->get_next_data_point = ifTable_next_entry;
    iinfo->table_reginfo = table_info;
#ifdef DO_WE_SORT_THIS
    iinfo->flags |= NETSNMP_ITERATOR_FLAG_SORTED;
#endif                          /* WIN32 || solaris2 */

    reginfo = netsnmp_create_handler_registration("ifXTable",
                                                  ifXTable_handler,
                                                  ifXTable_oid,
                                                  OID_LENGTH(ifXTable_oid),
                                                  HANDLER_CAN_RONLY),
        netsnmp_register_table_iterator(reginfo, iinfo);
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_cache_handler
                           (IF_STATS_CACHE_TIMEOUT, ifTable_load,
                            ifTable_free, ifXTable_oid,
                            OID_LENGTH(ifXTable_oid)));
#endif                          /* ENTENDED_IF_TABLE */
}


        /*
         *  Iteration hook routines are common to both tables
         */

netsnmp_variable_list *
ifTable_first_entry(void **loop_context,
                    void **data_context,
                    netsnmp_variable_list * index,
                    netsnmp_iterator_info * data)
{
    if (if_size == 0)
        return NULL;

    /*
     * Point to the first entry, and use the
     * 'next_entry' hook to retrieve this row
     */
    *loop_context = (void *) if_head;
    return ifTable_next_entry(loop_context, data_context, index, data);
}

netsnmp_variable_list *
ifTable_next_entry(void **loop_context,
                   void **data_context,
                   netsnmp_variable_list * index,
                   netsnmp_iterator_info * data)
{
    netsnmp_ifentry *entry = (netsnmp_ifentry *) * loop_context;
    netsnmp_variable_list *idx;

    while (entry && !(entry->flags & NETSNMP_IF_FLAGS_ACTIVE))
        entry = entry->next;
    if (!entry)
        return NULL;

    /*
     * Set up the indexing for the specified row...
     */
    idx = index;
    snmp_set_var_value(idx, (u_char *) & (entry->index),
                       sizeof(entry->index));

    /*
     * ... return the data structure for this row,
     * and update the loop context ready for the next one.
     */
    *data_context = (void *) entry;
    *loop_context = (void *) entry->next;
    return index;
}

        /*
         *  Don't actually release the list
         *  (since it contains static information)
         *  Just mark the entries as inactive.
         */
void
ifTable_free(netsnmp_cache * cache, void *magic)
{
    netsnmp_ifentry *p;
    for (p = if_head; p; p = p->next) {
        p->flags &= ~NETSNMP_IF_FLAGS_ACTIVE;
    }

    if_size = 0;
}

        /************
	 *
 	 *  Handler for the original ifTable
 	 *
	 ************/

int
ifTable_handler(netsnmp_mib_handler * handler,
                netsnmp_handler_registration * reginfo,
                netsnmp_agent_request_info * reqinfo,
                netsnmp_request_info * requests)
{
    netsnmp_request_info *request;
    netsnmp_variable_list *requestvb;
    netsnmp_table_request_info *table_info;
    netsnmp_ifentry *entry;
    oid             subid;
    long            val;

    DEBUGMSGTL(("mibII/ifTable", "Handler - mode %s\n",
                se_find_label_in_slist("agent_mode", reqinfo->mode)));
    switch (reqinfo->mode) {
    case MODE_GET:
        for (request = requests; request; request = request->next) {
            requestvb = request->requestvb;
            DEBUGMSGTL(("mibII/ifTable", "oid: "));
            DEBUGMSGOID(("mibII/ifTable", requestvb->name,
                         requestvb->name_length));
            DEBUGMSG(("mibII/ifTable", "\n"));

            entry =
                (netsnmp_ifentry *)
                netsnmp_extract_iterator_context(request);
            if (!entry)
                continue;
            table_info = netsnmp_extract_table_info(request);
            subid = table_info->colnum;

            switch (subid) {
            case COLUMN_IFINDEX:
                snmp_set_var_typed_value(requestvb, ASN_INTEGER,
                                         (u_char *) & entry->index,
                                         sizeof(entry->index));
                break;
            case COLUMN_IFDESCR:
                snmp_set_var_typed_value(requestvb, ASN_OCTET_STR,
                                         (u_char *) entry->if_descr,
                                         (entry->if_descr ?
                                          strlen(entry->if_descr) : 0));
                break;
            case COLUMN_IFTYPE:
                snmp_set_var_typed_value(requestvb, ASN_INTEGER,
                                         (u_char *) & entry->if_type,
                                         sizeof(entry->if_type));
                break;
            case COLUMN_IFMTU:
                snmp_set_var_typed_value(requestvb, ASN_INTEGER,
                                         (u_char *) & entry->if_mtu,
                                         sizeof(entry->if_mtu));
                break;
            case COLUMN_IFSPEED:
                if (entry->flags & NETSNMP_IF_FLAGS_DYNAMIC_SPEED)
                    val = get_ifspeed(entry) & 0xffffffff;
                else
                    val = entry->if_speed;
                snmp_set_var_typed_value(requestvb, ASN_GAUGE,
                                         (u_char *) & val, sizeof(val));
                break;
            case COLUMN_IFPHYSADDRESS:
                snmp_set_var_typed_value(requestvb, ASN_OCTET_STR,
                                         (u_char *) entry->if_paddr,
                                         entry->if_paddr_len);
                break;
            case COLUMN_IFADMINSTATUS:
            case COLUMN_IFOPERSTATUS:
                /*
                 * XXX 
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            case COLUMN_IFLASTCHANGE:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_LASTCHANGE)
                    snmp_set_var_typed_value(requestvb, ASN_INTEGER,
                                             (u_char *) & entry->
                                             if_lastchange,
                                             sizeof(entry->if_lastchange));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFINOCTETS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_BYTES)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                             (u_char *) & entry->if_ibytes.
                                             low,
                                             sizeof(entry->if_ibytes.low));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFINUCASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_iucast.low,
                                         sizeof(entry->if_iucast.low));
                break;
            case COLUMN_IFINNUCASTPKTS:
                /*
                 * Deprecated object 
                 */
                val = entry->if_imcast.low + entry->if_ibcast.low;
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & val, sizeof(val));
                break;
            case COLUMN_IFINDISCARDS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_idiscards,
                                         sizeof(entry->if_idiscards));
                break;
            case COLUMN_IFINERRORS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_ierrors,
                                         sizeof(entry->if_ierrors));
                break;
            case COLUMN_IFINUNKNOWNPROTOS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->
                                         if_iunknown_protos,
                                         sizeof(entry->
                                                if_iunknown_protos));
                break;

            case COLUMN_IFOUTOCTETS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_BYTES)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                             (u_char *) & entry->if_obytes.
                                             low,
                                             sizeof(entry->if_obytes.low));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFOUTUCASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_oucast.low,
                                         sizeof(entry->if_oucast.low));
                break;
            case COLUMN_IFOUTNUCASTPKTS:
                /*
                 * Deprecated object 
                 */
                val = entry->if_omcast.low + entry->if_obcast.low;
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & val, sizeof(val));
                break;
            case COLUMN_IFOUTDISCARDS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_odiscards,
                                         sizeof(entry->if_odiscards));
                break;
            case COLUMN_IFOUTERRORS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_oerrors,
                                         sizeof(entry->if_oerrors));
                break;
            case COLUMN_IFOUTQLEN:
                /*
                 * Deprecated object 
                 */
                snmp_set_var_typed_value(requestvb, ASN_GAUGE,
                                         (u_char *) & entry->if_oqlen,
                                         sizeof(entry->if_oqlen));
                break;
            case COLUMN_IFSPECIFIC:
                /*
                 * Deprecated object 
                 */
                snmp_set_var_typed_value(requestvb, ASN_OBJECT_ID,
                                         (u_char *) nullOid, nullOidLen);
                break;
            default:
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            }
        }
        break;

    case MODE_GETNEXT:
    case MODE_GETBULK:
    case MODE_SET_RESERVE1:
    case MODE_SET_RESERVE2:
    case MODE_SET_ACTION:
    case MODE_SET_COMMIT:
    case MODE_SET_FREE:
    case MODE_SET_UNDO:
        snmp_log(LOG_WARNING, "mibII/ifTable: Unsupported mode (%d)\n",
                 reqinfo->mode);
        break;
    default:
        snmp_log(LOG_WARNING, "mibII/ifTable: Unrecognised mode (%d)\n",
                 reqinfo->mode);
        break;
    }

    return SNMP_ERR_NOERROR;
}


        /************
	 *
 	 *  Handler for the extension ifXTable
 	 *
	 ************/


int
ifXTable_handler(netsnmp_mib_handler * handler,
                 netsnmp_handler_registration * reginfo,
                 netsnmp_agent_request_info * reqinfo,
                 netsnmp_request_info * requests)
{
    netsnmp_request_info *request;
    netsnmp_variable_list *requestvb;
    netsnmp_table_request_info *table_info;
    netsnmp_ifentry *entry;
    oid             subid;
    long            val;

    DEBUGMSGTL(("mibII/ifTable", "XHandler - mode %s\n",
                se_find_label_in_slist("agent_mode", reqinfo->mode)));
    switch (reqinfo->mode) {
    case MODE_GET:
        for (request = requests; request; request = request->next) {
            requestvb = request->requestvb;
            DEBUGMSGTL(("mibII/ifTable", "oid: "));
            DEBUGMSGOID(("mibII/ifTable", requestvb->name,
                         requestvb->name_length));
            DEBUGMSG(("mibII/ifTable", "\n"));

            entry =
                (netsnmp_ifentry *)
                netsnmp_extract_iterator_context(request);
            if (!entry)
                continue;
            table_info = netsnmp_extract_table_info(request);
            subid = table_info->colnum;

            switch (subid) {
            case COLUMN_IFNAME:
                snmp_set_var_typed_value(requestvb, ASN_OCTET_STR,
                                         (u_char *) entry->if_name,
                                         (entry->if_name ?
                                          strlen(entry->if_name) : 0));
                break;
            case COLUMN_IFINMULTICASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_imcast.low,
                                         sizeof(entry->if_imcast.low));
                break;
            case COLUMN_IFINBROADCASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_ibcast.low,
                                         sizeof(entry->if_ibcast.low));
                break;
            case COLUMN_IFOUTMULTICASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_omcast.low,
                                         sizeof(entry->if_omcast.low));
                break;
            case COLUMN_IFOUTBROADCASTPKTS:
                snmp_set_var_typed_value(requestvb, ASN_COUNTER,
                                         (u_char *) & entry->if_obcast.low,
                                         sizeof(entry->if_obcast.low));
                break;
            case COLUMN_IFHCINOCTETS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_BYTES)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_ibytes,
                                             sizeof(entry->if_ibytes));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCINUCASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_iucast,
                                             sizeof(entry->if_iucast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCINMULTICASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_imcast,
                                             sizeof(entry->if_imcast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCINBROADCASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_ibcast,
                                             sizeof(entry->if_ibcast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCOUTOCTETS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_BYTES)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_obytes,
                                             sizeof(entry->if_obytes));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCOUTUCASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_oucast,
                                             sizeof(entry->if_oucast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCOUTMULTICASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_omcast,
                                             sizeof(entry->if_omcast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFHCOUTBROADCASTPKTS:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS)
                    snmp_set_var_typed_value(requestvb, ASN_COUNTER64,
                                             (u_char *) & entry->if_obcast,
                                             sizeof(entry->if_obcast));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFLINKUPDOWNTRAPENABLE:
                /*
                 * XXX 
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            case COLUMN_IFHIGHSPEED:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_HIGH_SPEED) {
                    if (entry->flags & NETSNMP_IF_FLAGS_DYNAMIC_SPEED)
                        val = get_ifspeed(entry) >> 32;
                    else
                        val = entry->if_speed_high;
                    snmp_set_var_typed_value(requestvb, ASN_GAUGE,
                                             (u_char *) & val,
                                             sizeof(val));
                } else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            case COLUMN_IFPROMISCUOUSMODE:
                /*
                 * XXX 
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            case COLUMN_IFCONNECTORPRESENT:
                /*
                 * XXX 
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            case COLUMN_IFALIAS:
                snmp_set_var_typed_value(requestvb, ASN_OCTET_STR,
                                         (u_char *) entry->if_alias,
                                         (entry->if_alias ?
                                          strlen(entry->if_alias) : 0));
                break;
            case COLUMN_IFCOUNTERDISCONTINUITYTIME:
                if (entry->flags & NETSNMP_IF_FLAGS_HAS_DISCONTINUITY)
                    snmp_set_var_typed_value(requestvb, ASN_INTEGER,
                                             (u_char *) & entry->
                                             if_discontinuity,
                                             sizeof(entry->
                                                    if_discontinuity));
                else
                    netsnmp_set_request_error(reqinfo, request,
                                              SNMP_NOSUCHINSTANCE);
                break;
            default:
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHOBJECT);
                break;
            }
        }
        break;

    case MODE_GETNEXT:
    case MODE_GETBULK:
    case MODE_SET_RESERVE1:
    case MODE_SET_RESERVE2:
    case MODE_SET_ACTION:
    case MODE_SET_COMMIT:
    case MODE_SET_FREE:
    case MODE_SET_UNDO:
        snmp_log(LOG_WARNING, "mibII/ifTable: Unsupported mode (%d)\n",
                 reqinfo->mode);
        break;
    default:
        snmp_log(LOG_WARNING, "mibII/ifTable: Unrecognised mode (%d)\n",
                 reqinfo->mode);
        break;
    }

    return SNMP_ERR_NOERROR;
}

        /*
         * Architecture-independent routines to locate
         *  and/or create the entry for a given interface
         */
netsnmp_ifentry *
ifTable_get_entry_by_name(char *name, int create)
{
    netsnmp_ifentry *entry;
    netsnmp_ifentry *entry_prev = NULL;
    int             index;

    for (entry = if_head; entry; entry = entry->next) {
        if (!strcmp(name, entry->if_name)) {
            DEBUGMSGTL(("mibII/ifTable", "Found entry for %s (%d)\n",
                        name, entry->index));
            entry->flags &= NETSNMP_IF_FLAGS_ACTIVE;
            if_size++;
            break;
        }
        entry_prev = entry;
    }
    if (!entry && create) {
        entry = SNMP_MALLOC_TYPEDEF(netsnmp_ifentry);
        memset(entry, 0, sizeof(netsnmp_ifentry));
        entry->if_name = strdup(name);
        /*
         * If we've met this interface before, use the same index.
         * Otherwise find an unused index value and use that.
         */
        entry->index = se_find_value_in_slist("interfaces", name);
        if (entry->index == SE_DNE) {
            entry->index = se_find_free_value_in_slist("interfaces");
            if (entry->index == SE_DNE)
                entry->index = 1;       /* Completely new list! */
            se_add_pair_to_slist("interfaces", strdup(name), entry->index);
            entry->next = if_head;
            if_head = entry;    /* XXX - or sorted? */
        }
        DEBUGMSGTL(("mibII/ifTable", "Creating entry for %s (%d)\n",
                    name, entry->index));
        /*
         * XXX - initialise the "static" information
         *  a) Using the configure overrides
         *  b) Via (architecture-specific) utility routines
         */
        ifTable_info(entry);
        entry->flags &= NETSNMP_IF_FLAGS_ACTIVE;
        if_size++;
    }
    return entry;

}

netsnmp_ifentry *
ifTable_get_entry_by_index(int index)
{
    netsnmp_ifentry *entry;

    for (entry = if_head; entry; entry = entry->next) {
        if (index == entry->index)
            break;
    }
    return entry;
}

        /*
         * The cache-handler loading routines are the
         *     main place for architecture-specific code
         *
         * This is actually split into two for each architecture.
         * ifTable_load identifies the list of interfaces that
         *     are currently present, and retrieves the dynamic
         *     information for them (mostly statistic counters).
         * ifTable_info sets up the static information for a
         *     given interface, and this will typically be
         *     retained even after the interface disappears.
         */


#ifdef linux
unsigned long long
get_ifspeed(netsnmp_ifentry * entry)
{
    return 10000000;
}

int
get_iftype(netsnmp_ifentry * entry)
{
    return 6;
}

int
ifTable_info(netsnmp_ifentry * entry)
{
    if (!entry)
        return -1;
    if (!entry->if_speed)
        entry->if_speed = get_ifspeed(entry);
    if (!entry->if_type)
        entry->if_type = get_iftype(entry);

    entry->if_descr = strdup(entry->if_name);
    return 0;
}

int
ifTable_load(netsnmp_cache * cache, void *vmagic)
{
    FILE           *devin;
    char            line[256];
    const char     *scan_line_2_2 =
        "%llu %llu %llu %llu %*llu %*llu %*llu %*llu %llu %llu %llu %llu %*llu %llu";
    const char     *scan_line_2_0 =
        "%lu %lu %*lu %*lu %*lu %lu %lu %*lu %*lu %lu";
    const char     *scan_line_to_use;
    int             scan_count;
    unsigned long long int rec_pkt, rec_oct, rec_err, rec_drop;
    unsigned long long int snd_pkt, snd_oct, snd_err, snd_drop, coll;
    netsnmp_ifentry *entry;

    ifTable_free(cache, NULL);

    if (!(devin = fopen("/proc/net/dev", "r"))) {
        DEBUGMSGTL(("mibII/ifTable",
                    "Failed to load Interface Table (linux1)\n"));
        snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/dev ...\n");
        return -1;
    }

    /*
     * Read the first two lines of the file, containing the header
     * This indicates which version of the kernel we're working with,
     * and hence which statistics are actually available.
     *
     * Wes originally suggested parsing the field names in this header
     * to detect the position of individual fields directly,
     * but I suspect this is probably more trouble than it's worth.
     */
    fgets(line, sizeof(line), devin);
    fgets(line, sizeof(line), devin);
    /*
     * XXX - What's the format for the 2.6 kernel ?
     */
    if (strstr(line, "compressed")) {
        scan_line_to_use = scan_line_2_2;
        DEBUGMSGTL(("mibII/ifTable",
                    "using linux 2.2 kernel /proc/net/dev\n"));
    } else {
        scan_line_to_use = scan_line_2_0;
        DEBUGMSGTL(("mibII/ifTable",
                    "using linux 2.0 kernel /proc/net/dev\n"));
    }

    /*
     * The rest of the file provides the statistics for each interface.
     * Read in each line in turn, isolate the interface name
     *   and retrieve (or create) the corresponding data structure.
     */
    while (fgets(line, sizeof(line), devin)) {
        char           *stats, *ifstart = line;

        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        while (*ifstart && *ifstart == ' ')
            ifstart++;

        if (!*ifstart || ((stats = strrchr(ifstart, ':')) == NULL)) {
            snmp_log(LOG_ERR,
                     "/proc/net/dev data format error, line ==|%s|", line);
            continue;
        }
        if ((scan_line_to_use == scan_line_2_2) && ((stats - line) < 6)) {
            snmp_log(LOG_ERR,
                     "/proc/net/dev data format error, line ==|%s|", line);
        }
        *stats = 0;
        entry = ifTable_get_entry_by_name(ifstart, 1);
        *stats++ = ':';
        while (*stats == ' ')
            stats++;

        /*
         * OK - we've now got (or created) the data structure for
         *      this interface, including any "static" information.
         * Now parse the rest of the line (i.e. starting from 'stats')
         *      to extract the relevant statistics, and populate
         *      data structure accordingly.
         * Use the flags field to indicate which counters are valid
         */

        /*
         * XXX - may need another block for the 2.6 kernel
         */
        rec_pkt = rec_oct = rec_err = rec_drop = 0;
        snd_pkt = snd_oct = snd_err = snd_drop = coll = 0;
        if (scan_line_to_use == scan_line_2_2) {
            scan_count = sscanf(stats, scan_line_to_use,
                                &rec_oct, &rec_pkt, &rec_err, &rec_drop,
                                &snd_oct, &snd_pkt, &snd_err, &snd_drop,
                                &coll);
            if (scan_count == 9) {
                entry->flags |= NETSNMP_IF_FLAGS_ACTIVE;
                entry->flags |= NETSNMP_IF_FLAGS_HAS_BYTES;
                entry->flags |= NETSNMP_IF_FLAGS_HAS_DROPS;
                /*
                 *  2.4 kernel includes a single multicast (input) counter?
                 */
                entry->flags |= NETSNMP_IF_FLAGS_HAS_MCAST_PKTS;
                entry->flags |= NETSNMP_IF_FLAGS_HAS_HIGH_SPEED;
                entry->flags |= NETSNMP_IF_FLAGS_HAS_HIGH_BYTES;
                entry->flags |= NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS;
            }
        } else {
            scan_count = sscanf(stats, scan_line_to_use,
                                &rec_pkt, &rec_err,
                                &snd_pkt, &snd_err, &coll);
            if (scan_count == 5) {
                entry->flags |= NETSNMP_IF_FLAGS_ACTIVE;
                entry->flags &= ~NETSNMP_IF_FLAGS_HAS_MCAST_PKTS;
                rec_oct = rec_drop = 0;
                snd_oct = snd_drop = 0;
            }
        }
        /*
         * linux previous to 1.3.~13 may miss transmitted loopback pkts: 
         */
        if (!strcmp(entry->if_name, "lo") && rec_pkt > 0 && !snd_pkt)
            snd_pkt = rec_pkt;

        if (entry->flags & NETSNMP_IF_FLAGS_ACTIVE) {
            entry->if_ibytes.low = rec_oct & 0xffffffff;
            entry->if_ibytes.high = rec_oct >> 32;
            entry->if_iucast.low = rec_pkt & 0xffffffff;
            entry->if_iucast.high = rec_pkt >> 32;
            entry->if_ierrors = rec_err;
            entry->if_idiscards = rec_drop;
            entry->if_obytes.low = snd_oct & 0xffffffff;
            entry->if_obytes.high = snd_oct >> 32;
            entry->if_oucast.low = snd_pkt & 0xffffffff;
            entry->if_oucast.high = snd_pkt >> 32;
            entry->if_oerrors = snd_err;
            entry->if_odiscards = snd_drop;
            entry->if_collisions = coll;
        }
    }
    fclose(devin);
    return 0;
}
#endif                          /* linux */
