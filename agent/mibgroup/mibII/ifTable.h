#ifndef _MIBGROUP_IFTABLE_H
#define _MIBGROUP_IFTABLE_H

#include "mibgroup/if-mib/data-access/interface.h"

void  init_ifTable( void );

extern NetsnmpCacheLoad         ifTable_load;
extern NetsnmpCacheFree         ifTable_free;
extern Netsnmp_Node_Handler     ifTable_handler;
extern Netsnmp_Node_Handler     ifXTable_handler;

#endif /* _MIBGROUP_IFTABLE_H */
