/*
 *  memory quantity mib groups
 *
 */
#ifndef _MIBGROUP_MEMORY_H
#define _MIBGROUP_MEMORY_H

#include "mibdefs.h"

int getswap __P((int));
unsigned char *var_extensible_mem __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

extern void	init_memory __P((void));

/* config file parsing routines */
void memory_parse_config __P((char *, char *));
void memory_free_config __P((void));

#define MEMTOTALSWAP 3
#define MEMAVAILSWAP 4
#define MEMTOTALREAL 5
#define MEMAVAILREAL 6
#define MEMTOTALSWAPTXT 7
#define MEMUSEDSWAPTXT 8
#define MEMTOTALREALTXT 9
#define MEMUSEDREALTXT 10
#define MEMTOTALFREE 11
#define MEMSWAPMINIMUM 12
#define MEMSHARED 13
#define MEMBUFFER 14
#define MEMCACHED 15
#define MEMSWAPERROR 16

#endif /* _MIBGROUP_MEMORY_H */
