/*
 *  memory quantity mib groups
 *
 */
#ifndef _MIBGROUP_MEMORY_H
#define _MIBGROUP_MEMORY_H

#include "mibdefs.h"

extern void	init_memory_freebsd2 (void);

/* config file parsing routines */
void memory_parse_config (const char *, char *);
void memory_free_config (void);

#endif /* _MIBGROUP_MEMORY_H */
