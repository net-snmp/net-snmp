typedef struct netsnmp_memory_info_s netsnmp_memory_info;

#define NETSNMP_MEM_TYPE_MEMORY  1
#define NETSNMP_MEM_TYPE_SWAP    2
#define NETSNMP_MEM_TYPE_BUFFERS 3

struct netsnmp_memory_info_s {
     int  idx;
     int  type;

     long units;
     long size;
     long free;
     long other;

     netsnmp_memory_info *next;
};


    /*
     * Possibly not all needed ??
     */
netsnmp_memory_info *netsnmp_memory_get_first(  int );
netsnmp_memory_info *netsnmp_memory_get_next( netsnmp_memory_info*, int );
netsnmp_memory_info *netsnmp_memory_get_byIdx(  int,   int );

netsnmp_cache *netsnmp_memory_get_cache( void );
int netsnmp_memory_load( void );
