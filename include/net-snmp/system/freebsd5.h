#include "freebsd.h"

/*
 * freebsd4 is a superset of freebsd2 and freebsd3 
 */
#define freebsd2 1
#define freebsd3 1
/* freebsd5 is a superset of freebsd4 */
#define freebsd4 1

#undef IFADDR_SYMBOL
#define IFADDR_SYMBOL "in_ifaddrhead"

#undef PROC_SYMBOL
#define PROC_SYMBOL "allproc"

#undef NPROC_SYMBOL
#define NPROC_SYMBOL "nprocs"

#undef TOTAL_MEMORY_SYMBOL

/* force hr_storage.c to use getfsstat */
#undef MBSTAT_SYMBOL
#undef HAVE_STATVFS
#undef HAVE_SYS_STATVFS_H
#undef STRUCT_STATVFS_HAS_F_FRSIZE
/* force ucd-snmp/disk.c to ignore statvfs objects */
#undef STRUCT_STATFS_HAS_F_FAVAIL

