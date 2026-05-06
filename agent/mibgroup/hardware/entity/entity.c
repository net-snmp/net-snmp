#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "entity.h"

static netsnmp_entity_info        *_ent_head = NULL;
static netsnmp_cache              *_ent_cache = NULL;
static netsnmp_entity_contains_row *_contains = NULL;
static int                          _contains_n = 0;

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

static void
_entity_cache_free(netsnmp_cache *cache, void *magic)
{
    netsnmp_entity_free_list();
    SNMP_FREE(_contains);
    _contains_n = 0;
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
    SNMP_FREE(_contains);
    _contains_n = 0;
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
