/*
 *  Template MIB group interface - versioninfo.h
 *
 */
#ifndef _MIBGROUP_VERSIONINFO_H
#define _MIBGROUP_VERSIONINFO_H

unsigned char *var_extensible_version __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
int update_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));
int debugging_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));

#include "mibdefs.h"

/* Version info mib */
#define VERTAG 2
#define VERDATE 3
#define VERCDATE 4
#define VERIDENT 5
#define VERCONFIG 6
#define VERCLEARCACHE 10
#define VERUPDATECONFIG 11
#define VERRESTARTAGENT 12
#define VERDEBUGGING 20

config_require(util_funcs)

#endif /* _MIBGROUP_VERSIONINFO_H */
