/*
 *  Template MIB group interface - disk.h
 *
 */
#ifndef _MIBGROUP_DISK_H
#define _MIBGROUP_DISK_H

config_require(util_funcs)

unsigned char *var_extensible_disk __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

/* config file parsing routines */
void disk_free_config __P((void));
void disk_parse_config __P((char *, char *));
config_parse_dot_conf("disk", disk_parse_config, disk_free_config,"path [ minspace | minpercent% ]");

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

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_disk_variables[] = {
  {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_disk, 1, {MIBINDEX}},
  {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_disk, 1, {ERRORNAME}},
  {DISKDEVICE, ASN_OCTET_STR, RONLY, var_extensible_disk, 1, {DISKDEVICE}},
  {DISKMINIMUM, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKMINIMUM}},
  {DISKMINPERCENT, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKMINPERCENT}},
  {DISKTOTAL, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKTOTAL}},
  {DISKAVAIL, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKAVAIL}},
  {DISKUSED, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKUSED}},
  {DISKPERCENT, ASN_INTEGER, RONLY, var_extensible_disk, 1, {DISKPERCENT}},
  {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_disk, 1, {ERRORFLAG }},
  {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_disk, 1, {ERRORMSG }}
};

config_load_mib(EXTENSIBLEMIB.DISKMIBNUM.1, EXTENSIBLENUM+2, extensible_disk_variables)

#endif
#endif /* _MIBGROUP_DISK_H */
