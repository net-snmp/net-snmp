/*
 *  Template MIB group interface - udp.h
 *
 */
#ifndef _MIBGROUP_UDP_H
#define _MIBGROUP_UDP_H

#ifdef linux
struct udp_mib
{
 	unsigned long	UdpInDatagrams;
 	unsigned long	UdpNoPorts;
 	unsigned long	UdpInErrors;
 	unsigned long	UdpOutDatagrams;
};
#endif

config_arch_require(solaris2, kernel_sunos5)

extern void	init_udp __P((void));
extern u_char	*var_udp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_udpEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));


#define UDPINDATAGRAMS	    0
#define UDPNOPORTS	    1
#define UDPINERRORS	    2
#define UDPOUTDATAGRAMS     3
#define UDPLOCALADDRESS     4
#define UDPLOCALPORT	    5

#endif /* _MIBGROUP_UDP_H */
