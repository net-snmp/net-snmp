typedef struct netsnmp_cpu_info_s netsnmp_cpu_info;

struct netsnmp_cpu_info_s {
     int  idx;
                 /* For hrDeviceTable */
     char name[  SNMP_MAXBUF ];
     char descr[ SNMP_MAXBUF ];

                 /* For UCD cpu stats */
     long user_ticks;
     long nice_ticks;
     long sys_ticks;
     long idle_ticks;
     long wait_ticks;
     long kern_ticks;
     long intrpt_ticks;
     long sirq_ticks;

                 /* For paging-related UCD stats */
              /* XXX - Do these belong elsewhere ?? */
     long pageIn;
     long pageOut;
     long swapIn;
     long swapOut;
     long nInterrupts;
     long nCtxSwitches;

     netsnmp_cpu_info *next;
};


    /*
     * Possibly not all needed ??
     */
netsnmp_cpu_info *netsnmp_cpu_get_first(  void );
netsnmp_cpu_info *netsnmp_cpu_get_next( netsnmp_cpu_info* );
netsnmp_cpu_info *netsnmp_cpu_get_byIdx(  int,   int );
netsnmp_cpu_info *netsnmp_cpu_get_byName( char*, int );

netsnmp_cache *netsnmp_cpu_get_cache( void );
int netsnmp_cpu_load( void );
