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
config_parse_dot_conf("swap", memory_parse_config, memory_free_config);

#define MEMTOTALSWAP 3
#define MEMUSEDSWAP 4
#define MEMTOTALREAL 5
#define MEMUSEDREAL 6
#define MEMTOTALSWAPTXT 7
#define MEMUSEDSWAPTXT 8
#define MEMTOTALREALTXT 9
#define MEMUSEDREALTXT 10
#define MEMTOTALFREE 11
#define MEMSWAPMINIMUM 12
#define MEMSWAPERROR 13

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_mem_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_mem,1,{MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_mem, 1, {ERRORNAME }},
  {MEMTOTALSWAP, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAP}},
  {MEMUSEDSWAP, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDSWAP}},
  {MEMTOTALREAL, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREAL}},
  {MEMUSEDREAL, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDREAL}},
  {MEMTOTALSWAPTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAPTXT}},
  {MEMUSEDSWAPTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDSWAPTXT}},
  {MEMTOTALREALTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREALTXT}},
  {MEMUSEDREALTXT, INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDREALTXT}},
  {MEMTOTALFREE, INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALFREE}},
  {ERRORFLAG, INTEGER, RONLY, var_extensible_mem, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_extensible_mem, 1, {ERRORMSG }}
};

config_load_mib(EXTENSIBLEMIB.MEMMIBNUM, EXTENSIBLENUM+1, extensible_mem_variables)

#endif
#endif /* _MIBGROUP_MEMORY_H */
