#ifndef _MIBGROUP_IFTABLE_H
#define _MIBGROUP_IFTABLE_H

#define NETSNMP_IF_FLAGS_ACTIVE			0x01
#define NETSNMP_IF_FLAGS_HAS_BYTES		0x02
#define NETSNMP_IF_FLAGS_HAS_DROPS		0x04
#define NETSNMP_IF_FLAGS_HAS_MCAST_PKTS		0x08
#define NETSNMP_IF_FLAGS_HAS_HIGH_BYTES		0x10
#define NETSNMP_IF_FLAGS_HAS_HIGH_PACKETS	0x20
#define NETSNMP_IF_FLAGS_HAS_HIGH_SPEED		0x40
#define NETSNMP_IF_FLAGS_DYNAMIC_SPEED		0x80
#define NETSNMP_IF_FLAGS_HAS_LASTCHANGE		0x100
#define NETSNMP_IF_FLAGS_HAS_DISCONTINUITY	0x200

typedef struct netsnmp_ifentry_s {
    struct netsnmp_ifentry_s *prev, *next;
    int     flags;
    int     index;

    /*
     *  "Static" information
     *  Typically constant for a given interface
     */
    char   *if_name;
    char   *if_descr;
    char   *if_alias;
    char   *if_old_alias;
    int     if_type;
    unsigned int     if_speed;
    unsigned int     if_speed_high;
    char   *if_paddr;
    int     if_paddr_len;
    int     if_mtu;

    time_t  if_lastchange;	/* XXX - or marker ?? */
    time_t  if_discontinuity;

    /*
     *  "Dynamic" fields
     *  Cached versions of byte/packet counters, etc
     *  (saved as a 'struct counter64' even if the
     *   high order half isn't actually used)
     *
     */
    struct counter64 if_ibytes;
    struct counter64 if_iucast;
    struct counter64 if_imcast;
    struct counter64 if_ibcast;
    unsigned int     if_ierrors;
    unsigned int     if_idiscards;
    unsigned int     if_iunknown_protos;
    struct counter64 if_obytes;
    struct counter64 if_oucast;
    struct counter64 if_omcast;
    struct counter64 if_obcast;
    unsigned int     if_oerrors;
    unsigned int     if_odiscards;
    unsigned int     if_oqlen;
    unsigned int     if_collisions;

} netsnmp_ifentry;


void  init_ifTable( void );

extern Netsnmp_First_Data_Point ifTable_first_entry;
extern Netsnmp_Next_Data_Point  ifTable_next_entry;
extern NetsnmpCacheLoad         ifTable_load;
extern NetsnmpCacheFree         ifTable_free;
extern Netsnmp_Node_Handler     ifTable_handler;
extern Netsnmp_Node_Handler     ifXTable_handler;

#endif /* _MIBGROUP_IFTABLE_H */
