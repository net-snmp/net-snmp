/*
 *  hpux specific mib sections
 *
 */
#ifndef _MIBGROUP_HPUX_H
#define _MIBGROUP_HPUX_H

int writeHP __P((int, u_char *, u_char, int, u_char *,oid *, int));
unsigned char *var_hp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define TRAPAGENT 128.120.57.92

#define HPCONF 1
#define HPRECONFIG 2
#define HPFLAG 3
#define HPLOGMASK 4
#define HPSTATUS 6
#define HPTRAP 101

#endif /* _MIBGROUP_HPUX_H */
