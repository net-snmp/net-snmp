/*
 *  Template MIB group interface - disk.h
 *
 */
#ifndef _MIBGROUP_DISK_H
#define _MIBGROUP_DISK_H

config_require(util_funcs)

unsigned char *var_extensible_disk (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );

/* config file parsing routines */
void disk_free_config (void);
void disk_parse_config (char *, char *);

#include "mibdefs.h"

#define DISKDEVICE 3
#define DISKMINIMUM 4
#define DISKMINPERCENT 5
#define DISKTOTAL 6
#define DISKAVAIL 7
#define DISKUSED 8
#define DISKPERCENT 9

struct diskpart
{
   char device[STRMAX];
   char path[STRMAX];
   int minimumspace;
   int minpercent;
};

#endif /* _MIBGROUP_DISK_H */
