
#define bsdlike

/* nlist symbols in ip.c */
#define IPSTAT_SYMBOL "ipstat"
#define IP_FORWARDING_SYMBOL "ipforwarding"
#define TCP_TTL_SYMBOL "tcpDefaultTTL"

/* nlist symbols in interfaces.c */
#define IFNET_SYMBOL "ifnet"
#define IFADDR_SYMBOL "in_ifaddr"

/* nlist symbols in at.c */
#define ARPTAB_SYMBOL "arptab"
#define ARPTAB_SIZE_SYMBOL "arptab_size"

/* load average lookup symbol */
#define LOADAVE_SYMBOL "avenrun"

/* nlist symbols in hr_proc.c and memory.c */
#define PHYSMEM_SYMBOL "physmem"
#define TOTAL_MEMORY_SYMBOL "total"
#define MBSTAT_SYMBOL "mbstat"
#define SWDEVT_SYBOL "swdevt"
#define FSWDEVT_SYBOL "fswdevt"
#define NSWAPFS_SYBOL "nswapfs"
#define NSWAPDEV_SYBOL "nswapdev"

/* process nlist symbols. */
#define NPROC_SYMBOL "nproc"
#define PROC_SYMBOL "proc"

/* icmp.c nlist symbols */
#define ICMPSTAT_SYMBOL "icmpstat"

/* tcp.c nlist symbols */
#define TCPSTAT_SYMBOL "tcpstat"
#define TCP_SYMBOL "tcp"

/* upd.c nlist symbols */
#define UDPSTAT_SYMBOL "udpstat"
#define UDB_SYMBOL "udb"

/* var_route.c nlist symbols */
#define RTTABLES_SYMBOL "rt_table"
#define RTHASHSIZE_SYMBOL "rthashsize"
#define RTHOST_SYMBOL "rthost"
#define RTNET_SYMBOL "rtnet"
