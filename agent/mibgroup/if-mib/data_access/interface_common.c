/*
 *  Interface MIB architecture support
 *
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"
#include "if-mib/ifTable/ifTable_constants.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>
#include "if-mib/data_access/interface.h"

/**---------------------------------------------------------------------*/
/*
 * local static vars
 */
static netsnmp_conf_if_list *conf_list = NULL;
static int need_wrap_check = -1;

/*
 * local static prototypes
 */
static int _access_interface_entry_compare_name(const void *lhs,
                                                const void *rhs);
static void _access_interface_entry_release(netsnmp_interface_entry * entry,
                                            void *unused);
static void _access_interface_entry_set_index(netsnmp_interface_entry *entry,
                                              const char *name);
static void _parse_interface_config(const char *token, char *cptr);
static void _free_interface_config(void);
static void _update_32bit(struct counter64 *prev_val, struct counter64 *new_val,
                          struct counter64 *old_prev_val);

/**---------------------------------------------------------------------*/
/*
 * external per-architecture functions prototypes
 *
 * These shouldn't be called by the general public, so they aren't in
 * the header file.
 */
extern int
netsnmp_access_interface_container_arch_load(netsnmp_container* container,
                                             u_int load_flags);

/**---------------------------------------------------------------------*/
/*
 * initialization
 */
void
interface_common_init(void)
{
    snmpd_register_config_handler("interface", _parse_interface_config,
                                  _free_interface_config,
                                  "name type speed");

    netsnmp_access_interface_arch_init();
}

/**---------------------------------------------------------------------*/
/*
 * container functions
 */
/**
 * initialize interface container
 */
netsnmp_container *
netsnmp_access_interface_container_init(u_int flags)
{
    netsnmp_container *container1;

    DEBUGMSGTL(("access:interface:container", "init\n"));

    /*
     * create the containers. one indexed by ifIndex, the other
     * indexed by ifName.
     */
    container1 = netsnmp_container_find("access_interface:table_container");
    if (NULL == container1)
        return NULL;

    if (flags & NETSNMP_ACCESS_INTERFACE_INIT_ADDL_IDX_BY_NAME) {
        netsnmp_container *container2 =
            netsnmp_container_find("access_interface_by_name:access_interface:table_container");
        if (NULL == container2)
            return NULL;

        container2->compare = _access_interface_entry_compare_name;
        
        netsnmp_container_add_index(container1, container2);
    }

    return container1;
}

/**
 * load interface information in specified container
 *
 * @param container empty container, or NULL to have one created for you
 * @param load_flags flags to modify behaviour. Examples:
 *                   NETSNMP_ACCESS_INTERFACE_INIT_ADDL_IDX_BY_NAME
 *
 * @retval NULL  error
 * @retval !NULL pointer to container
 */
netsnmp_container*
netsnmp_access_interface_container_load(netsnmp_container* container, u_int load_flags)
{
    int rc;

    DEBUGMSGTL(("access:interface:container", "load\n"));

    if (NULL == container)
        container = netsnmp_access_interface_container_init(load_flags);
    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_interface\n");
        return NULL;
    }

    rc =  netsnmp_access_interface_container_arch_load(container, load_flags);
    if (0 != rc) {
        netsnmp_access_interface_container_free(container,
                                                NETSNMP_ACCESS_INTERFACE_FREE_NOFLAGS);
        container = NULL;
    }

    return container;
}

void
netsnmp_access_interface_container_free(netsnmp_container *container, u_int free_flags)
{
    DEBUGMSGTL(("access:interface:container", "free\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR, "invalid container for netsnmp_access_interface_free\n");
        return;
    }

    if(! (free_flags & NETSNMP_ACCESS_INTERFACE_FREE_DONT_CLEAR)) {
        /*
         * free all items.
         */
        CONTAINER_CLEAR(container,
                        (netsnmp_container_obj_func*)_access_interface_entry_release,
                        NULL);
    }

    CONTAINER_FREE(container);
}

/**---------------------------------------------------------------------*/
/*
 * ifentry functions
 */
/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_index(netsnmp_container *container, oid index)
{
    netsnmp_index   tmp;

    DEBUGMSGTL(("access:interface:entry", "by_index\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR,
                 "invalid container for netsnmp_access_interface_entry_get_by_index\n");
        return NULL;
    }

    tmp.len = 1;
    tmp.oids = &index;

    return (netsnmp_interface_entry *) CONTAINER_FIND(container, &tmp);
}

/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_name(netsnmp_container *container,
                                const char *name)
{
    netsnmp_interface_entry tmp;

    DEBUGMSGTL(("access:interface:entry", "by_name\n"));

    if (NULL == container) {
        snmp_log(LOG_ERR,
                 "invalid container for netsnmp_access_interface_entry_get_by_name\n");
        return NULL;
    }

    if (NULL == container->next) {
        snmp_log(LOG_ERR,
                 "secondary index missing for netsnmp_access_interface_entry_get_by_name\n");
        return NULL;
    }

    tmp.if_name = name;
    return CONTAINER_FIND(container->next, &tmp);
}

/**
 * @retval 0  interface not found
 */
oid
netsnmp_access_interface_index_find(const char *name)
{
    oid index = se_find_value_in_slist("interfaces", name);
    if (index == SE_DNE)
        return 0;

    return index;
}

/**
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_create(const char *name)
{
    netsnmp_interface_entry *entry =
        SNMP_MALLOC_TYPEDEF(netsnmp_interface_entry);

    DEBUGMSGTL(("access:interface:entry", "create\n"));

    if(NULL == entry)
        return NULL;

    if(NULL != name)
        entry->if_name = strdup(name);

    _access_interface_entry_set_index(entry, name);

    entry->if_descr = strdup("unknown");
    // xxx-rks: if_alias? supposed to be persistent

    /*
     * make some assumptions
     */
    entry->if_connector_present = 1;
    entry->if_oper_status = IFOPERSTATUS_UP;

    entry->oid_index.len = 1;
    entry->oid_index.oids = (oid *) & entry->index;

    snmp_log(LOG_ERR, "netsnmp_access_interface_entry_create(entry);\n");

    return entry;
}

/**
 */
void
netsnmp_access_interface_entry_free(netsnmp_interface_entry * entry)
{
    DEBUGMSGTL(("access:interface:entry", "free\n"));

    if (NULL == entry)
        return;

    /*
     * SNMP_FREE not needed, for any of these, 
     * since the whole entry is about to be freed
     */

    if (NULL != entry->old_stats)
        free(entry->old_stats);

    if (NULL != entry->if_name)
        free(entry->if_name);

    if (NULL != entry->if_descr)
        free(entry->if_descr);

    if (NULL != entry->if_paddr)
        free(entry->if_paddr);

    free(entry);
}

/**
 *
 * @retval 0   : success
 * @retval < 0 : error
 */
int
netsnmp_access_interface_entry_set_admin_status(netsnmp_interface_entry * entry,
                                                int ifAdminStatus)
{
    int rc;

    DEBUGMSGTL(("access:interface:entry", "set_admin_status\n"));

    if (NULL == entry)
        return -1;

    if ((ifAdminStatus < IFADMINSTATUS_UP) ||
         (ifAdminStatus > IFADMINSTATUS_TESTING))
        return -2;

    rc = netsnmp_arch_set_admin_status(entry, ifAdminStatus);
    if (0 == rc) /* success */
        entry->if_admin_status = ifAdminStatus;

    return rc;
}

/**---------------------------------------------------------------------*/
/*
 * Utility routines
 */

/**
 */
static int
_access_interface_entry_compare_name(const void *lhs, const void *rhs)
{
    return strcmp(((const netsnmp_interface_entry *) lhs)->if_name,
                  ((const netsnmp_interface_entry *) rhs)->if_name);
}

/**
 */
static void
_access_interface_entry_release(netsnmp_interface_entry * entry, void *context)
{
    netsnmp_access_interface_entry_free(entry);
}

/**
 */
static void
_access_interface_entry_set_index(netsnmp_interface_entry *entry, const char *name)
{
    if(NULL != name) {
        entry->index = netsnmp_access_interface_index_find(name);
        if (entry->index == 0) {
            entry->index = se_find_free_value_in_slist("interfaces");
            if (entry->index == SE_DNE)
                entry->index = 1;       /* Completely new list! */
            se_add_pair_to_slist("interfaces", strdup(name), entry->index);
            DEBUGMSGTL(("access:interface:ifIndex", "new ifIndex %d for %s\n",
                        entry->index, name));
        }
    }
    else
        entry->index = 0;
}

/**
 * update stats
 *
 * @retval  0 : success
 * @retval -1 : error
 */
int
netsnmp_access_interface_entry_update_stats(netsnmp_interface_entry * prev_vals,
                                            netsnmp_interface_entry * new_vals)
{
    DEBUGMSGTL(("access:interface", "check_wrap\n"));
    
    /*
     * sanity checks
     */
    if ((NULL == prev_vals) || (NULL == new_vals) ||
        (NULL == prev_vals->if_name) || (NULL == new_vals->if_name) ||
        (0 != strncmp(prev_vals->if_name, new_vals->if_name, strlen(prev_vals->if_name))))
        return -1;

    /*
     * if we've determined that we have 64 bit counters, just copy them.
     */
    if (0 == need_wrap_check) {
        memcpy(&prev_vals->stats, &new_vals->stats, sizeof(new_vals->stats));
        return 0;
    }

    if (NULL == prev_vals->old_stats) {
        /*
         * if we don't have old stats, they can't have wrapped, so just copy
         */
        prev_vals->old_stats = SNMP_MALLOC_TYPEDEF(netsnmp_interface_stats);
        if (NULL == prev_vals->old_stats) {
            return -2;
        }
    }
    else {
        _update_32bit(&prev_vals->if_ibytes,
                      &new_vals->if_ibytes, &prev_vals->old_ibytes);
        _update_32bit(&prev_vals->if_iucast,
                      &new_vals->if_iucast, &prev_vals->old_iucast);
        _update_32bit(&prev_vals->if_imcast,
                      &new_vals->if_imcast, &prev_vals->old_imcast);
        _update_32bit(&prev_vals->if_ibcast,
                      &new_vals->if_ibcast, &prev_vals->old_ibcast);
        _update_32bit(&prev_vals->if_obytes,
                      &new_vals->if_obytes, &prev_vals->old_obytes);
        _update_32bit(&prev_vals->if_oucast,
                      &new_vals->if_oucast, &prev_vals->old_oucast);
        _update_32bit(&prev_vals->if_omcast,
                      &new_vals->if_omcast, &prev_vals->old_omcast);
        _update_32bit(&prev_vals->if_obcast,
                      &new_vals->if_obcast, &prev_vals->old_obcast);
    }
    
    /*
     * if we've decided we no longer need to check wraps, free old stats
     */
    if (0 == need_wrap_check) {
        SNMP_FREE(prev_vals->old_stats);
    }
    
    /*
     * update old stats from new stats.
     * careful - old_stats is a pointer to stats...
     */
    memcpy(prev_vals->old_stats, &new_vals->stats, sizeof(new_vals->stats));
    
    return 0;
}

/**
 * copy interface entry data (after checking for counter wraps)
 *
 * @retval -2 : malloc failed
 * @retval -1 : interfaces not the same
 * @retval  0 : no error
 */
int
netsnmp_access_interface_entry_copy(netsnmp_interface_entry * lhs,
                                    netsnmp_interface_entry * rhs)
{
    DEBUGMSGTL(("access:interface", "copy\n"));
    
    if ((NULL == lhs) || (NULL == rhs) ||
        (NULL == lhs->if_name) || (NULL == rhs->if_name) ||
        (0 != strncmp(lhs->if_name, rhs->if_name, strlen(rhs->if_name))))
        return -1;

    /*
     * update stats
     */
    netsnmp_access_interface_entry_update_stats(lhs, rhs);

    /*
     * update data
     */
    lhs->flags = rhs->flags;
    if((NULL != lhs->if_descr) && (NULL != rhs->if_descr) &&
       (0 == strcmp(lhs->if_descr, rhs->if_descr)))
        ;
    else {
        if (NULL != lhs->if_descr)
            SNMP_FREE(lhs->if_descr);
        if (rhs->if_descr) {
            lhs->if_descr = strdup(rhs->if_descr);
            if(NULL == lhs->if_descr)
                return -2;
        }
    }
    lhs->if_type = rhs->if_type;
    lhs->if_speed = rhs->if_speed;
    lhs->if_speed_high = rhs->if_speed_high;
    lhs->if_mtu = rhs->if_mtu;
    lhs->if_discontinuity = rhs->if_discontinuity;
    lhs->if_oper_status = rhs->if_oper_status;
    lhs->if_promiscuous = rhs->if_promiscuous;
    lhs->if_connector_present = rhs->if_connector_present;
    lhs->if_flags = rhs->if_flags;
    if(lhs->if_paddr_len == rhs->if_paddr_len) {
        if(rhs->if_paddr_len)
            memcpy(lhs->if_paddr,rhs->if_paddr,rhs->if_paddr_len);
    } else {
        if (NULL != lhs->if_paddr)
            SNMP_FREE(lhs->if_paddr);
        if (rhs->if_paddr) {
            lhs->if_paddr = malloc(rhs->if_paddr_len);
            if(NULL == lhs->if_paddr)
                return -2;
            memcpy(lhs->if_paddr,rhs->if_paddr,rhs->if_paddr_len);
        }
    }
    lhs->if_paddr_len = rhs->if_paddr_len;
    
    return 0;
}

void
netsnmp_access_interface_entry_guess_speed(netsnmp_interface_entry *entry)
{
    if (entry->if_type == IANAIFTYPE_ETHERNETCSMACD)
        entry->if_speed = 10000000;
    else if (entry->if_type == IANAIFTYPE_SOFTWARELOOPBACK)
        entry->if_speed = 10000000;
    else if (entry->if_type == IANAIFTYPE_ISO88025TOKENRING)
        entry->if_speed = 4000000;
    else
        entry->if_speed = 0;
}

netsnmp_conf_if_list *
netsnmp_access_interface_entry_overrides_get(const char * name)
{
    netsnmp_conf_if_list * if_ptr;

    if(NULL == name)
        return NULL;

    for (if_ptr = conf_list; if_ptr; if_ptr = if_ptr->next)
        if (!strcmp(if_ptr->name, name))
            break;

    return if_ptr;
}

void
netsnmp_access_interface_entry_overrides(netsnmp_interface_entry *entry)
{
    netsnmp_conf_if_list * if_ptr;

    if (NULL == entry)
        return;

    /*
     * enforce mib size limit
     */
    if(entry->if_descr && (strlen(entry->if_descr) > 255))
        entry->if_descr[255] = 0;

    if_ptr =
        netsnmp_access_interface_entry_overrides_get(entry->if_name);
    if (if_ptr) {
        entry->if_type = if_ptr->type;
        entry->if_speed = if_ptr->speed;
    }
}

/**---------------------------------------------------------------------*/
/*
 * interface config token
 */
/**
 */
static void
_parse_interface_config(const char *token, char *cptr)
{
    netsnmp_conf_if_list   *if_ptr, *if_new;
    char                   *name, *type, *speed, *ecp;

    name = strtok(cptr, " \t");
    if (!name) {
        config_perror("Missing NAME parameter");
        return;
    }
    type = strtok(NULL, " \t");
    if (!type) {
        config_perror("Missing TYPE parameter");
        return;
    }
    speed = strtok(NULL, " \t");
    if (!speed) {
        config_perror("Missing SPEED parameter");
        return;
    }
    if_ptr = conf_list;
    while (if_ptr)
        if (strcmp(if_ptr->name, name))
            if_ptr = if_ptr->next;
        else
            break;
    if (if_ptr)
        config_pwarn("Duplicate interface specification");
    if_new = SNMP_MALLOC_TYPEDEF(netsnmp_conf_if_list);
    if (!if_new) {
        config_perror("Out of memory");
        return;
    }
    if_new->speed = strtoul(speed, &ecp, 0);
    if (*ecp) {
        config_perror("Bad SPEED value");
        free(if_new);
        return;
    }
    if_new->type = strtol(type, &ecp, 0);
    if (*ecp || if_new->type < 0) {
        config_perror("Bad TYPE");
        free(if_new);
        return;
    }
    if_new->name = strdup(name);
    if (!if_new->name) {
        config_perror("Out of memory");
        free(if_new);
        return;
    }
    if_new->next = conf_list;
    conf_list = if_new;
}

static void
_free_interface_config(void)
{
    netsnmp_conf_if_list   *if_ptr = conf_list, *if_next;
    while (if_ptr) {
        if_next = if_ptr->next;
        free(if_ptr->name);
        free(if_ptr);
        if_ptr = if_next;
    }
    conf_list = NULL;
}

static void
_update_32bit(struct counter64 *prev_val, struct counter64 *new_val,
              struct counter64 *old_prev_val)
{
    int rc;

    /*
     * counters are 32bit or unknown (which we'll treat as 32bit).
     * update the prev values with the difference between the
     * new stats and the prev old_stats:
     *    prev->stats += (new->stats - prev->old_stats)
     */
    rc = netsnmp_c64_check_for_32bit_wrap(old_prev_val,new_val, 1);
    if (rc < 0)
        snmp_log(LOG_ERR,"c64 32 bit check failed\n");
    else {
        /*
         * update previous values
         */
        (void) u64UpdateCounter(prev_val, new_val, old_prev_val);

        /*
         * if wrap check was 32 bit, undo adjust, now that prev is updated
         */
        if (32 == rc) {
            /*
             * check wrap incremented high, so reset it. (Because
             * new is going to be copied to old later on.)
             */
            netsnmp_assert(1 == new_val->high);
            new_val->high = 0;
        }
        else if (64 == rc) {
            /*
             * if we really have 64 bit counters, the summing we've been
             * doing for prev values should be equal to the new values.
             */
            if ((prev_val->low != new_val->low) ||
                (prev_val->high != new_val->high))
                snmp_log(LOG_ERR, "looks like a 64bit wrap, but prev!=new\n");
            else
                need_wrap_check = 0;
        }
    }
}
