/*
 *  Template MIB group interface - sysORTable.h
 *
 */
#ifndef _MIBGROUP_SYSORTABLE_H
#define _MIBGROUP_SYSORTABLE_H

config_require(util_funcs)

struct sysORTable {
   char *OR_descr;
   oid  *OR_oid;
   int  OR_oidlen;
   struct timeval OR_uptime;
   struct sysORTable *next;
};

extern void     init_sysORTable (void);
extern FindVarMethod var_sysORTable;
extern FindVarMethod var_sysORLastChange;
extern void     register_sysORTable (oid *, int, char *);

#define	SYSORTABLEINDEX		        1
#define	SYSORTABLEID		        2
#define	SYSORTABLEDESCR		        3
#define	SYSORTABLEUPTIME	        4

#endif /* _MIBGROUP_SYSORTABLE_H */
