/*
 *  Interface MIB ifTable (and ifXTable) implementation - ifTable.c
 *
 */

#include <net-snmp/net-snmp-config.h>
#include "mibII_common.h"

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/auto_nlist.h>
#include <net-snmp/agent/table_container.h>
#include <net-snmp/agent/cache_handler.h>

#include "ifTable.h"
#include "ifTable_columns.h"
#include "ifXTable_columns.h"


/*
 * prototypes for architecture specific routines
 */
void            ifTable_free(netsnmp_cache * cache, void *magic);
int             ifTable_ifentry_info_init(netsnmp_ifentry * entry);
unsigned long long get_ifspeed(netsnmp_ifentry * entry);
int             get_iftype(netsnmp_ifentry * entry);

static int      ifTable_ifentry_compare_name(const void *lhs,
                                             const void *rhs);

/*
 * local statics, or useful utility routines?
 */
netsnmp_ifentry *ifTable_ifentry_get_by_index(netsnmp_cache * cache,
                                              int index);
netsnmp_ifentry *ifTable_ifentry_get_by_name(netsnmp_cache * cache,
                                             char *name, int create);


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
    netsnmp_handler_registration *reginfo;
    netsnmp_container *container;
    netsnmp_cache  *cache;

    DEBUGMSGTL(("mibII/ifTable", "Initialising Interface Table\n"));

     /*
      * get ifcontainer
      */
    container = netsnmp_dal_ifcontainer_init(0);

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
     * .... and register the table with the agent.
     */
    reginfo = netsnmp_create_handler_registration("ifTable",
                                                  ifTable_handler,
                                                  ifTable_oid,
                                                  OID_LENGTH(ifTable_oid),
                                                  HANDLER_CAN_RONLY);
    netsnmp_container_table_register(reginfo, table_info, container1,
                                     TABLE_CONTAINER_KEY_NETSNMP_INDEX);

    /*
     * .... with a local cache
     *    (except for Solaris, which uses a different approach)
     */
    cache = netsnmp_cache_create(IF_STATS_CACHE_TIMEOUT,
                                 ifTable_load, ifTable_free,
                                 ifTable_oid, OID_LENGTH(ifTable_oid));
    cache->magic = container1;
    netsnmp_inject_handler(reginfo, netsnmp_cache_handler_get(cache));

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

    reginfo = netsnmp_create_handler_registration("ifXTable",
                                                  ifXTable_handler,
                                                  ifXTable_oid,
                                                  OID_LENGTH(ifXTable_oid),
                                                  HANDLER_CAN_RONLY),
    netsnmp_container_table_register(reginfo, table_info, container1,
                                     TABLE_CONTAINER_KEY_NETSNMP_INDEX);
    netsnmp_inject_handler(reginfo, netsnmp_cache_handler_get(cache));
#endif                          /* ENTENDED_IF_TABLE */
}

NETSNMP_STATIC_INLINE netsnmp_ifentry *
ifTable_ifentry_extract(netsnmp_request_info * request)
{
    return (netsnmp_ifentry *)
        netsnmp_container_table_extract_context(request);
}

static int
ifTable_ifentry_compare_name(const void *lhs, const void *rhs)
{
    return strcmp(((const netsnmp_ifentry *) lhs)->if_name,
                  ((const netsnmp_ifentry *) rhs)->if_name);
}

static void
ifTable_ifentry_release(netsnmp_ifentry * entry, void *context)
{
    if (NULL == entry)
        return;

    if (NULL != entry->if_name)
        free(entry->if_name);

    if (NULL != entry->if_descr)
        free(entry->if_descr);

    free(entry);
}

        /*
         *  Don't actually release the list
         *  (since it contains static information)
         *  Just mark the entries as inactive.
         */
void
ifTable_free(netsnmp_cache * cache, void *magic)
{
    netsnmp_container *container;

    if ((NULL == cache) || (NULL == cache->magic)) {
        snmp_log(LOG_ERR, "invalid cache for ifTable\n");
        return;
    }
    DEBUGMSGTL(("ifTable/cache", "ifTable_free %p/%p\n",
                cache, cache->magic));

    container = (netsnmp_container *) cache->magic;

    /*
     * free all items. inefficient, but easy.
     */
    CONTAINER_CLEAR(container, ifTable_ifentry_release, NULL);


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

            entry = ifTable_ifentry_extract(request);
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

            entry = ifTable_ifentry_extract(request);
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
ifTable_ifentry_get_by_name(netsnmp_cache * cache, char *name, int create)
{
    netsnmp_ifentry tmp;
    netsnmp_ifentry *entry;
    netsnmp_container *container, *container_by_name;

    if ((NULL == cache) || (NULL == cache->magic)) {
        snmp_log(LOG_ERR, "invalid cache for ifTable\n");
        return NULL;
    }

    container = (netsnmp_container *) cache->magic;
    container_by_name = container->next;
    if (NULL == container_by_name) {
        snmp_log(LOG_ERR,
                 "invalid cache for ifTable_ifentry_get_by_name\n");
        return NULL;
    }

    tmp.if_name = name;
    entry = CONTAINER_FIND(container_by_name, &tmp);
    if ((NULL == entry) && (create)) {
        entry = SNMP_MALLOC_TYPEDEF(netsnmp_ifentry);
        entry->if_name = strdup(name);

        /*
         * XXX - initialise the "static" information
         *  a) Using the configure overrides
         *  b) Via (architecture-specific) utility routines
         */
        ifTable_ifentry_info_init(entry);

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
        }

        /*
         * inserting in container will also handle container_by_name 
         */
        CONTAINER_INSERT(container, entry);

        DEBUGMSGTL(("mibII/ifTable", "Creating entry for %s (%d)\n",
                    name, entry->index));
    }
    if (entry)
        entry->flags &= NETSNMP_IF_FLAGS_ACTIVE;

    return entry;

}

netsnmp_ifentry *
ifTable_ifentry_get_by_index(netsnmp_cache * cache, int index)
{
    netsnmp_index   tmp;
    netsnmp_container *container;

    if ((NULL == cache) || (NULL == cache->magic)) {
        snmp_log(LOG_ERR,
                 "invalid cache for ifTable_ifentry_get_by_index\n");
        return NULL;
    }

    container = (netsnmp_container *) cache->magic;

    tmp.len = 1;
    tmp.oids = (oid *) & index;

    return (netsnmp_ifentry *) CONTAINER_FIND(container, &tmp);
}

        /*
         * The cache-handler loading routines are the
         *     main place for architecture-specific code
         *
         * This is actually split into two for each architecture.
         * ifTable_load identifies the list of interfaces that
         *     are currently present, and retrieves the dynamic
         *     information for them (mostly statistic counters).
         * ifTable_info_init sets up the static information for a
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
ifTable_ifentry_info_init(netsnmp_ifentry * entry)
{
    if (!entry)
        return -1;

    entry->oid_index.len = 1;
    entry->oid_index.oids = (oid *) & entry->index;

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
    netsnmp_container *container;

    if ((NULL == cache) || (NULL == cache->magic)) {
        snmp_log(LOG_ERR, "invalid cache for ifTable_load\n");
        return -1;
    }
    DEBUGMSGTL(("ifTable/cache", "ifTable_load %p/%p\n",
                cache, cache->magic));

    container = (netsnmp_container *) cache->magic;

    if (cache->valid)
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
     *    xxx - couldn't this result be cached at startup? can the format
     *          change without a reboot??
     *
     * Wes originally suggested parsing the field names in this header
     * to detect the position of individual fields directly,
     * but I suspect this is probably more trouble than it's worth.
     *
     * Robert suggests that once we have the table index, we could store the
     * raw data and save the parsing for later. Wouldn't save much work during
     * a walk, but if there are lots of interfaces and only a few are being
     * polled, it would save some parsing...
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
        entry = ifTable_ifentry_get_by_name(cache, ifstart, 1);
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
