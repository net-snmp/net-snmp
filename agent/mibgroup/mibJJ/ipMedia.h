/*
 *  Template MIB group interface - at.h
 *
 */

#ifndef _MIBGROUP_AT_H
#define _MIBGROUP_AT_H

config_arch_require(solaris2, kernel_sunos5)

extern void	init_ipMedia (void);
extern FindVarMethod var_atEntry;


#define ATIFINDEX	0
#define ATPHYSADDRESS	1
#define ATNETADDRESS	2

#define IPMEDIAIFINDEX          0
#define IPMEDIAPHYSADDRESS      1
#define IPMEDIANETADDRESS       2
#define IPMEDIATYPE             3

/* in case its missing: */
#ifndef ATF_PERM
# define ATF_PERM	0x04
#endif /*  ATF_PERM */
#ifndef ATF_COM
# define ATF_COM	0x02
#endif /*  ATF_COM */

#ifdef linux
/*
 * arp struct to pass flags, hw-addr and ip-addr in bsd manner:
 */
struct arptab {
		/* This is used for the I/F index.  We could define
		   with a more sensible name, but by using an unused
		   field name from the standard BSD structure, we
		   can keep things consistent */
  int	at_state;
  int	at_flags;
  char	at_enaddr[6];
  struct sockaddr at_iaddr;
};
#endif
#endif /* _MIBGROUP_AT_H */
