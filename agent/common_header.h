#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/param.h>
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#include <sys/signal.h>
#if HAVE_SYS_USER_H
#include <sys/user.h>
#endif
#if HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif
#ifdef HAVE_SYS_DMAP_H
#include <sys/dmap.h>
#endif
#if defined(HAVE_MACHINE_PTE_H) && (!defined(bsdi2))
#include <machine/pte.h>
#endif
#if HAVE_XTI_H
#include <xti.h>
#endif
#if HAVE_SYS_VM_H
#include <sys/vm.h>
#else
#if HAVE_VM_VM_H
#include <vm/vm.h>
#else
#if HAVE_SYS_VMPARAM_H
#include <sys/vmparam.h>
#endif
#if HAVE_SYS_VMMAC_H
#include <sys/vmmac.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif
#if HAVE_SYS_VMSYSTM_H
#include <sys/vmsystm.h>
#endif
#endif /* vm/vm.h */
#endif /* sys/vm.h */
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#include <netinet/in_systm.h>
#if HAVE_SYS_HASHING_H
#include <sys/hashing.h>
#endif
#if HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif
#include <netinet/ip.h>
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#if defined(osf4) || defined(aix4) || defined(hpux10)
/* these are undefed to remove a stupid warning on osf compilers
   because they get redefined with a slightly different notation of the
   same value.  -- Wes */
#undef TCP_NODELAY
#undef TCP_MAXSEG
#endif
#include <netinet/tcp.h>
#if HAVE_NETINET_TCP_TIMER_H
#include <netinet/tcp_timer.h>
#endif
#ifdef HAVE_NETINET_TCPIP_H
# include <netinet/tcpip.h>
#endif
#if HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#if HAVE_NETINET_TCP_FSM_H
#include <netinet/tcp_fsm.h>
#endif
#include <netinet/udp.h>
#if HAVE_NETINET_UDP_VAR_H
#include <netinet/udp_var.h>
#endif
#include <netinet/ip_icmp.h>
#if HAVE_NETINET_ICMP_VAR_H
#include <netinet/icmp_var.h>
#endif
#include <nlist.h>
#if HAVE_SYS_PROTOSW_H
#include <sys/protosw.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_KVM_OPENFILES
#include <fcntl.h>
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif

#ifndef NULL
#define NULL 0
#endif
#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b)) 
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "mib.h"
#include "var_struct.h"
#include "snmp_vars.h"

#include "m2m.h"
#include "snmp_vars_m2m.h"
/* jab2 debug */
#include "snmp_vars.linux.h"
/* jab2 debug */
#include "kernel.h"
#ifdef USING_KERNEL_SUNOS5_MODULE
#include "mibgroup/kernel_sunos5.h"
#endif

#ifdef hpux
#undef OBJID
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#undef  OBJID
#define OBJID                   ASN_OBJECT_ID
#endif /* hpux */

void init_nlist __P((struct nlist *));
int compare __P((oid *, int, oid *, int));

#if !defined(USING_ERRORMIB_MODULE)
#define setPerrorstatus(x) perror(x)
#endif
