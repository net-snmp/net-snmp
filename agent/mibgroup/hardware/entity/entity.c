#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/snmpv3.h>
#include "entity.h"

static netsnmp_entity_info             *_ent_head = NULL;
static netsnmp_cache                   *_ent_cache = NULL;
static netsnmp_entity_contains_row     *_contains = NULL;
static int                              _contains_n = 0;
static netsnmp_entity_alias_row        *_alias = NULL;
static int                              _alias_n = 0;
static int                              _alias_cap = 0;
static netsnmp_entity_logical_row      *_log_head = NULL;

u_long entity_last_change = 0;

static oid _ent_oid[] = { 1, 3, 6, 1, 2, 1, 47 };

static int _cmp_contains(const void *a, const void *b)
{
    const netsnmp_entity_contains_row *ra = (const netsnmp_entity_contains_row *)a;
    const netsnmp_entity_contains_row *rb = (const netsnmp_entity_contains_row *)b;
    if (ra->parent_idx != rb->parent_idx)
        return ra->parent_idx - rb->parent_idx;
    return ra->child_idx - rb->child_idx;
}

void netsnmp_entity_contains_rebuild(void)
{
    netsnmp_entity_info *e;
    int count = 0;

    SNMP_FREE(_contains);
    _contains_n = 0;

    for (e = _ent_head; e; e = e->next)
        if (e->parent_idx > 0)
            count++;

    if (!count)
        return;

    _contains = (netsnmp_entity_contains_row *)
        malloc(count * sizeof(netsnmp_entity_contains_row));
    if (!_contains)
        return;

    _contains_n = 0;
    for (e = _ent_head; e; e = e->next) {
        if (e->parent_idx > 0) {
            _contains[_contains_n].parent_idx = e->parent_idx;
            _contains[_contains_n].child_idx  = e->idx;
            _contains_n++;
        }
    }

    qsort(_contains, _contains_n, sizeof(_contains[0]), _cmp_contains);
}

int netsnmp_entity_contains_count(void)
{
    return _contains_n;
}

netsnmp_entity_contains_row *netsnmp_entity_contains_get(int n)
{
    if (n < 0 || n >= _contains_n)
        return NULL;
    return &_contains[n];
}

static int _cmp_alias(const void *a, const void *b)
{
    const netsnmp_entity_alias_row *ra = (const netsnmp_entity_alias_row *)a;
    const netsnmp_entity_alias_row *rb = (const netsnmp_entity_alias_row *)b;
    if (ra->phys_idx != rb->phys_idx)
        return ra->phys_idx - rb->phys_idx;
    return ra->logical_idx - rb->logical_idx;
}

/* OID prefix for ifEntry.ifIndex — 1.3.6.1.2.1.2.2.1.1 */
static const oid _ifentry_ifindex_prefix[] = { 1,3,6,1,2,1,2,2,1,1 };
#define IFENTRY_PREFIX_LEN OID_LENGTH(_ifentry_ifindex_prefix)

void netsnmp_entity_alias_rebuild(void)
{
    netsnmp_entity_info *e;
    int count = 0;

    SNMP_FREE(_alias);
    _alias_n = 0;
    _alias_cap = 0;

    for (e = _ent_head; e; e = e->next)
        if (e->ifindex > 0)
            count++;

    if (!count)
        return;

    _alias = (netsnmp_entity_alias_row *)
        malloc(count * sizeof(netsnmp_entity_alias_row));
    if (!_alias)
        return;
    _alias_cap = count;

    _alias_n = 0;
    for (e = _ent_head; e; e = e->next) {
        if (e->ifindex > 0) {
            _alias[_alias_n].phys_idx    = e->idx;
            _alias[_alias_n].logical_idx = 0;
            memcpy(_alias[_alias_n].target_oid, _ifentry_ifindex_prefix,
                   sizeof(_ifentry_ifindex_prefix));
            _alias[_alias_n].target_oid[IFENTRY_PREFIX_LEN] = (oid)e->ifindex;
            _alias[_alias_n].target_oid_len = IFENTRY_PREFIX_LEN + 1;
            _alias_n++;
        }
    }

    qsort(_alias, _alias_n, sizeof(_alias[0]), _cmp_alias);
}

void netsnmp_entity_alias_add_oid(int phys_idx, int logical_idx,
                                   const oid *target, size_t target_len)
{
    netsnmp_entity_alias_row *row;

    if (target_len > ENTITY_ALIAS_OID_LEN)
        return;

    if (_alias_n >= _alias_cap) {
        int newcap = _alias_cap ? _alias_cap * 2 : 16;
        netsnmp_entity_alias_row *tmp =
            (netsnmp_entity_alias_row *)realloc(_alias,
                newcap * sizeof(netsnmp_entity_alias_row));
        if (!tmp)
            return;
        _alias = tmp;
        _alias_cap = newcap;
    }

    row = &_alias[_alias_n];
    row->phys_idx    = phys_idx;
    row->logical_idx = logical_idx;
    memcpy(row->target_oid, target, target_len * sizeof(oid));
    row->target_oid_len = target_len;
    _alias_n++;
}

void netsnmp_entity_alias_sort(void)
{
    if (_alias_n > 0)
        qsort(_alias, _alias_n, sizeof(_alias[0]), _cmp_alias);
}

int netsnmp_entity_alias_count(void)
{
    return _alias_n;
}

netsnmp_entity_alias_row *netsnmp_entity_alias_get(int n)
{
    if (n < 0 || n >= _alias_n)
        return NULL;
    return &_alias[n];
}

static void
_entity_cache_free(netsnmp_cache *cache, void *magic)
{
    netsnmp_entity_free_list();
    netsnmp_entity_logical_free_list();
    SNMP_FREE(_contains);
    _contains_n = 0;
    SNMP_FREE(_alias);
    _alias_n = 0;
    _alias_cap = 0;
}

void init_entity(void)
{
    _ent_cache = netsnmp_cache_create(300,
                                      netsnmp_entity_arch_load,
                                      _entity_cache_free,
                                      _ent_oid, OID_LENGTH(_ent_oid));
    if (_ent_cache)
        _ent_cache->flags |= NETSNMP_CACHE_DONT_FREE_BEFORE_LOAD
                           | NETSNMP_CACHE_AUTO_RELOAD;
}

void shutdown_entity(void)
{
    netsnmp_entity_free_list();
    netsnmp_entity_logical_free_list();
    SNMP_FREE(_contains);
    _contains_n = 0;
    SNMP_FREE(_alias);
    _alias_n = 0;
    _alias_cap = 0;
}

netsnmp_cache *netsnmp_entity_get_cache(void)
{
    return _ent_cache;
}

netsnmp_entity_info *netsnmp_entity_get_first(void)
{
    return _ent_head;
}

netsnmp_entity_info *netsnmp_entity_get_next(netsnmp_entity_info *e)
{
    return e ? e->next : NULL;
}

netsnmp_entity_info *netsnmp_entity_get_byIdx(int idx)
{
    netsnmp_entity_info *e;
    for (e = _ent_head; e; e = e->next)
        if (e->idx == idx)
            return e;
    return NULL;
}

netsnmp_entity_info *netsnmp_entity_create(int idx)
{
    netsnmp_entity_info *e, *prev;

    e = SNMP_MALLOC_TYPEDEF(netsnmp_entity_info);
    if (!e)
        return NULL;
    e->idx = idx;
    e->parent_rel_pos = -1;
    e->iana_class = IANA_PHYS_UNKNOWN;
    e->is_fru = TV_FALSE;

    if (!_ent_head || _ent_head->idx > idx) {
        e->next = _ent_head;
        _ent_head = e;
        return e;
    }
    for (prev = _ent_head; prev->next && prev->next->idx < idx; prev = prev->next)
        ;
    e->next = prev->next;
    prev->next = e;
    return e;
}

void netsnmp_entity_parent_rel_pos_rebuild(void)
{
    netsnmp_entity_info *e, *sibling;
    int pos;

    for (e = _ent_head; e; e = e->next) {
        if (e->parent_idx <= 0) {
            e->parent_idx = 0;
            e->parent_rel_pos = -1;
            continue;
        }

        if (!netsnmp_entity_get_byIdx(e->parent_idx)) {
            e->parent_idx = 0;
            e->parent_rel_pos = -1;
            continue;
        }

        pos = 1;
        for (sibling = _ent_head; sibling && sibling != e;
             sibling = sibling->next) {
            if (sibling->parent_idx == e->parent_idx &&
                sibling->iana_class == e->iana_class)
                pos++;
        }
        e->parent_rel_pos = pos;
    }
}

void netsnmp_entity_free_list(void)
{
    netsnmp_entity_info *e, *next;
    for (e = _ent_head; e; e = next) {
        next = e->next;
        SNMP_FREE(e);
    }
    _ent_head = NULL;
}

/* ---- entLogicalTable list management ------------------------------------- */

netsnmp_entity_logical_row *netsnmp_entity_logical_get_first(void)
{
    return _log_head;
}

netsnmp_entity_logical_row *
netsnmp_entity_logical_get_next(netsnmp_entity_logical_row *r)
{
    return r ? r->next : NULL;
}

netsnmp_entity_logical_row *netsnmp_entity_logical_get_byIdx(int idx)
{
    netsnmp_entity_logical_row *r;
    for (r = _log_head; r; r = r->next)
        if (r->idx == idx)
            return r;
    return NULL;
}

netsnmp_entity_logical_row *netsnmp_entity_logical_create(int idx)
{
    netsnmp_entity_logical_row *r, *prev;

    r = SNMP_MALLOC_TYPEDEF(netsnmp_entity_logical_row);
    if (!r)
        return NULL;
    r->idx = idx;

    if (!_log_head || _log_head->idx > idx) {
        r->next = _log_head;
        _log_head = r;
        return r;
    }
    for (prev = _log_head; prev->next && prev->next->idx < idx;
         prev = prev->next)
        ;
    r->next = prev->next;
    prev->next = r;
    return r;
}

void netsnmp_entity_logical_free_list(void)
{
    netsnmp_entity_logical_row *r, *next;
    for (r = _log_head; r; r = next) {
        next = r->next;
        SNMP_FREE(r);
    }
    _log_head = NULL;
}

/*
 * Populate the logical table.  One row per unique SNMP context:
 * index 1 = default (empty) context with the local engine ID.
 * Called from netsnmp_entity_arch_load() on each cache refresh.
 */
void netsnmp_entity_logical_load(void)
{
    /* snmpUDPDomain: 1.3.6.1.6.1.1 */
    static const oid _udp_domain[] = { 1,3,6,1,6,1,1 };
    /* zeroDotZero */
    static const oid _zero_dot_zero[] = { 0,0 };

    netsnmp_entity_logical_row *r;
    in_addr_t myaddr;

    netsnmp_entity_logical_free_list();

    r = netsnmp_entity_logical_create(1);
    if (!r)
        return;

    strlcpy(r->descr, "local SNMP agent", sizeof(r->descr));

    memcpy(r->type_oid, _zero_dot_zero, sizeof(_zero_dot_zero));
    r->type_oid_len = OID_LENGTH(_zero_dot_zero);

    memcpy(r->tdomain, _udp_domain, sizeof(_udp_domain));
    r->tdomain_len = OID_LENGTH(_udp_domain);

    /* TAddress for snmpUDPDomain: 4-byte IPv4 + 2-byte port (big-endian) */
    myaddr = get_myaddr();  /* returns address in network byte order */
    memcpy(r->taddress, &myaddr, 4);
    r->taddress[4] = 0;    /* port 161 high byte */
    r->taddress[5] = 161;  /* port 161 low byte  */
    r->taddress_len = 6;

    r->context_engine_id_len =
        snmpv3_get_engineID(r->context_engine_id,
                            sizeof(r->context_engine_id));

    r->context_name[0] = '\0';   /* default context */
}
