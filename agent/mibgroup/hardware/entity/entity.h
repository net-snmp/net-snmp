#ifndef NETSNMP_HARDWARE_ENTITY_H
#define NETSNMP_HARDWARE_ENTITY_H

void init_entity(void);
void shutdown_entity(void);

/* IANAPhysicalClass values */
#define IANA_PHYS_OTHER         1
#define IANA_PHYS_UNKNOWN       2
#define IANA_PHYS_CHASSIS       3
#define IANA_PHYS_BACKPLANE     4
#define IANA_PHYS_CONTAINER     5
#define IANA_PHYS_POWERSUPPLY   6
#define IANA_PHYS_FAN           7
#define IANA_PHYS_SENSOR        8
#define IANA_PHYS_MODULE        9
#define IANA_PHYS_PORT         10
#define IANA_PHYS_STACK        11
#define IANA_PHYS_CPU          12

/* TruthValue */
#define TV_TRUE  1
#define TV_FALSE 2

typedef struct netsnmp_entity_info_s {
    int     idx;
    int     parent_idx;
    int     parent_rel_pos;
    int     iana_class;
    int     is_fru;
    int     ifindex;        /* >0 for port entities with an if-MIB mapping */
    char    descr[256];
    char    name[64];
    char    hw_rev[64];
    char    fw_rev[64];
    char    sw_rev[64];
    char    serial[64];
    char    mfg_name[128];
    char    model_name[128];
    char    alias[128];
    char    asset_id[64];
    char    uris[256];
    u_char  uuid[16];
    size_t  uuid_len;
    struct netsnmp_entity_info_s *next;
} netsnmp_entity_info;

/* Sorted (parent_idx, child_idx) pairs for entPhysicalContainsTable */
typedef struct {
    int parent_idx;
    int child_idx;
} netsnmp_entity_contains_row;

/* Max OID length for alias target (covers all target MIBs + one index component) */
#define ENTITY_ALIAS_OID_LEN 16

/* Sorted (phys_idx, logical_idx) pairs for entAliasMappingTable */
typedef struct {
    int    phys_idx;
    int    logical_idx;    /* 0 when no entLogicalTable is implemented */
    oid    target_oid[ENTITY_ALIAS_OID_LEN];
    size_t target_oid_len;
} netsnmp_entity_alias_row;

extern u_long entity_last_change;

netsnmp_cache *netsnmp_entity_get_cache(void);

netsnmp_entity_info *netsnmp_entity_get_first(void);
netsnmp_entity_info *netsnmp_entity_get_next(netsnmp_entity_info *);
netsnmp_entity_info *netsnmp_entity_get_byIdx(int idx);
netsnmp_entity_info *netsnmp_entity_create(int idx);
void                 netsnmp_entity_free_list(void);

int                           netsnmp_entity_contains_count(void);
netsnmp_entity_contains_row  *netsnmp_entity_contains_get(int n);
void                          netsnmp_entity_contains_rebuild(void);
void                          netsnmp_entity_parent_rel_pos_rebuild(void);

int                        netsnmp_entity_alias_count(void);
netsnmp_entity_alias_row  *netsnmp_entity_alias_get(int n);
void                       netsnmp_entity_alias_rebuild(void);
void                       netsnmp_entity_alias_add_oid(int phys_idx,
                               int logical_idx,
                               const oid *target, size_t target_len);
void                       netsnmp_entity_alias_sort(void);

int netsnmp_entity_arch_load(netsnmp_cache *, void *);

#endif /* NETSNMP_HARDWARE_ENTITY_H */
