/*
 *  Template MIB group interface - at.h
 *
 */

#ifndef _MIBGROUP_AT_H
#define _MIBGROUP_AT_H

config_arch_require(solaris2, kernel_sunos5)

extern void	init_at __P((void));
extern u_char	*var_atEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define ATIFINDEX	0
#define ATPHYSADDRESS	1
#define ATNETADDRESS	2

#define IPMEDIAIFINDEX          0
#define IPMEDIAPHYSADDRESS      1
#define IPMEDIANETADDRESS       2
#define IPMEDIATYPE             3

#ifdef IN_SNMP_VARS_C

  /* variable4 because var_atEntry is also used by ipNetToMediaTable */
struct variable4 at_variables[] = {
    {ATIFINDEX, ASN_INTEGER, RONLY, var_atEntry, 1, {1}},
    {ATPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 1, {2}},
    {ATNETADDRESS, ASN_IPADDRESS, RONLY, var_atEntry, 1, {3}}
};

    config_load_mib(MIB.3.1.1, 9, at_variables)

#endif

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
  int at_flags;
  char at_enaddr [6];
  struct in_addr at_iaddr;
};
#endif
#endif /* _MIBGROUP_AT_H */
