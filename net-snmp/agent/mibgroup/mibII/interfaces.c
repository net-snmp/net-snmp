/*
 *  Interfaces MIB group implementation - interfaces.c
 *
 */

#include "mib_module_config.h"

#include <config.h>

#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#if HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_IOCTLS_H
#include <ioctls.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "../mibincl.h"

#ifdef hpux
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* hpux */

#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
# if defined(CTL_NET) && !defined(freebsd2)
#  ifdef PF_ROUTE
#   ifdef NET_RT_IFLIST
#    define USE_SYSCTL_IFLIST
#   endif
#  endif
# endif
#endif

/* #include "../common_header.h" */

#include "../../../snmplib/system.h"

#ifdef HAVE_OSRELDATE_H
#include <osreldate.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#ifdef CAN_USE_SYSCTL
#include <sys/sysctl.h>
#endif
#include "interfaces.h"
#include "../struct.h"
#include "../util_funcs.h"
#include "auto_nlist.h"

static int Interface_Scan_Get_Count __P((void));

static int header_interfaces __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));
static int header_ifEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));

#ifdef USE_SYSCTL_IFLIST

static u_char * if_list = 0;
static const u_char * if_list_end;
static size_t if_list_size = 0;

void
init_interfaces __P((void))
{
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

static int
header_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define IFENTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    register int	interface;
    int result, count;
    char c_oid[1024];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_ifEntry: %s %d\n", c_oid, exact);
    }
    
    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    /* find "next" interface */
    count = Interface_Scan_Get_Count();
    for(interface = 1; interface <= count; interface++){
	newname[IFENTRY_NAME_LENGTH] = (oid)interface;
	result = compare(name, *length, newname, (int)vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (interface > count) {
        DEBUGP ("... index out of range\n");
        return MATCH_FAILED;
    }


    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    sprint_objid (c_oid, name, *length);
    DEBUGP ("... get I/F stats %s\n", c_oid);

    return interface;
};

static int
header_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define INTERFACES_NAME_LENGTH	8
  oid newname[MAX_NAME_LEN];
  int result;
  char c_oid[1024];

  if (snmp_get_do_debugging()) {
    sprint_objid (c_oid, name, *length);
    DEBUGP ("var_interfaces: %s %d\n", c_oid, exact);
  }

  memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
  newname[INTERFACES_NAME_LENGTH] = 0;
  result = compare(name, *length, newname, (int)vp->namelen + 1);
  if ((exact && (result != 0)) || (!exact && (result >= 0)))
    return MATCH_FAILED;
  memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
  *length = vp->namelen + 1;

  *write_method = 0;
  *var_len = sizeof(long);	/* default to 'long' results */
  return MATCH_SUCCEEDED;
};

u_char *
var_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int	   (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
  if (header_interfaces(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
    return NULL;

  switch (vp->magic)
    {
    case IFNUMBER:
      long_return = Interface_Scan_Get_Count ();
      return (u_char *)&long_return;
    default:
      ERROR_MSG("");
    }
  return NULL;
}

struct small_ifaddr
{
  struct in_addr	sifa_addr;
  struct in_addr	sifa_netmask;
  struct in_addr	sifa_broadcast;
};

extern const struct sockaddr * get_address (const void *, int, int);
extern const struct in_addr * get_in_address (const void *, int, int);
static int Interface_Scan_By_Index __P((int, struct if_msghdr *, char *, struct small_ifaddr *));
static int Interface_Get_Ether_By_Index __P((int, u_char *));

static int
Interface_Scan_By_Index (index, if_msg, if_name, sifa)
     int index;
     struct if_msghdr *if_msg;
     char *if_name;
     struct small_ifaddr *sifa;
{
  u_char *cp;
  struct if_msghdr *ifp;
  int have_ifinfo = 0, have_addr = 0;

  memset (sifa, 0, sizeof (*sifa));
  for (cp = if_list;
       cp < if_list_end;
       cp += ifp->ifm_msglen)
    {
      ifp = (struct if_msghdr *)cp;
      DEBUGP("ifm_type = %d, ifm_index = %d\n", ifp->ifm_type, ifp->ifm_index);

      switch (ifp->ifm_type)
	{
	case RTM_IFINFO:
	  {
	    const struct sockaddr *a;

	    if (ifp->ifm_index == index)
	      {
		a = get_address (ifp+1, ifp->ifm_addrs, RTA_IFP);
		strncpy (if_name,
			 ((struct sockaddr_in *) a)->sin_zero,
			 ((u_char *) a)[5]);
		if_name[((u_char *) a)[5]] = 0;
		*if_msg = *ifp;
		++have_ifinfo;
	      }
	  }
	  break;
	case RTM_NEWADDR:
	  {
	    struct ifa_msghdr *ifap = (struct ifa_msghdr *) cp;

	    if (ifap->ifam_index == index)
	      {
		const struct in_addr *ia;

		/* I don't know why the normal get_address() doesn't
		   work on IRIX 6.2.  Maybe this has to do with the
		   existence of struct sockaddr_new.  Hopefully, on
		   other systems we can simply use get_in_address
		   three times, with (ifap+1) as the starting
		   address. */

		sifa->sifa_netmask = *((struct in_addr *) ((char *) (ifap+1)+4));
		ia = get_in_address ((char *) (ifap+1)+8,
				     ifap->ifam_addrs &= ~RTA_NETMASK,
				     RTA_IFA);
		sifa->sifa_addr = *ia;
		ia = get_in_address ((char *) (ifap+1)+8,
				     ifap->ifam_addrs &= ~RTA_NETMASK,
				     RTA_BRD);
		sifa->sifa_broadcast = *ia;
		++have_addr;
	      }
	  }
	  break;
	default:
	  DEBUGP ("routing socket: unknown message type %d\n", ifp->ifm_type);
	}
    }
  if (have_ifinfo && have_addr)
    {
      return 0;
    }
  else if (have_ifinfo && !(if_msg->ifm_flags & IFF_UP))
      return 0;
  else
    {
      return -1;
    }
}

static int
Interface_Scan_Get_Count __P((void))
{
  u_char *cp;
  struct if_msghdr *ifp;
  long n;

  Interface_Scan_Init();

  for (cp = if_list, n = 0;
       cp < if_list_end;
       cp += ifp->ifm_msglen)
    {
      ifp = (struct if_msghdr *)cp;

      if (ifp->ifm_type == RTM_IFINFO)
	{
	  ++n;
	}
    }
  return n;
}

void
Interface_Scan_Init __P((void))
{
  int name[] = {CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST,0};
  size_t size;

  if (sysctl (name, sizeof(name)/sizeof(int),
	      0, &size, 0, 0) == -1)
    {
      ERROR_MSG("sysctl(CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST,0)\n");
    }
  else
    {
      if (if_list == 0 || if_list_size < size)
	{
	  if (if_list != 0)
	    {
	      free (if_list);
	      if_list = 0;
	    }
	  if ((if_list = malloc (size)) == 0)
	    {
	      ERROR_MSG("out of memory allocating route table\n");
	    }
	  if_list_size = size;
	}
      else
	{
	  size = if_list_size;
	}
      if (sysctl (name, sizeof (name) / sizeof (int),
		  if_list, &size, 0, 0) == -1)
	{
	  ERROR_MSG("sysctl(CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST,0)\n");
	}
      if_list_end = if_list + size;
    }
}

u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    register oid	*name;
    register int	*length;
    int			exact;
    int			*var_len;
    int                 (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
  int interface;
  struct if_msghdr if_msg;
  char if_name[100];
  struct small_ifaddr sifa;
  char * cp;

  interface = header_ifEntry(vp, name, length, exact, var_len, write_method);
  if ( interface == MATCH_FAILED )
    return NULL;

  if (Interface_Scan_By_Index(interface, &if_msg, if_name, &sifa) != 0)
    return NULL;

  switch (vp->magic) {
  case IFINDEX:
    long_return = interface;
    return (u_char *) &long_return;
  case IFDESCR:
    cp = if_name;
    *var_len = strlen (if_name);
    return (u_char *) cp;
  case IFTYPE:
    long_return = (long) if_msg.ifm_data.ifi_type;
    return (u_char *) &long_return;
  case IFMTU:
    long_return = (long) if_msg.ifm_data.ifi_mtu;
    return (u_char *) &long_return;
  case IFSPEED:
    long_return = (u_long) if_msg.ifm_data.ifi_baudrate;
    return (u_char *) &long_return;
  case IFPHYSADDRESS:
    /* XXX */
    return NULL;
  case IFADMINSTATUS:
    long_return = if_msg.ifm_flags & IFF_RUNNING ? 1 : 2;
    return (u_char *) &long_return;
  case IFOPERSTATUS:
    long_return = if_msg.ifm_flags & IFF_UP ? 1 : 2;
    return (u_char *) &long_return;
    /* ifLastChange */
  case IFINOCTETS:
    long_return = (u_long) if_msg.ifm_data.ifi_ibytes;
    return (u_char *) &long_return;
  case IFINUCASTPKTS:
    long_return = (u_long) if_msg.ifm_data.ifi_ipackets-if_msg.ifm_data.ifi_imcasts;
    return (u_char *) &long_return;
  case IFINNUCASTPKTS:
    long_return = (u_long) if_msg.ifm_data.ifi_imcasts;
    return (u_char *) &long_return;
  case IFINDISCARDS:
    long_return = (u_long) if_msg.ifm_data.ifi_iqdrops;
    return (u_char *) &long_return;
  case IFINERRORS:
    long_return = (u_long) if_msg.ifm_data.ifi_ierrors;
    return (u_char *) &long_return;
  case IFINUNKNOWNPROTOS:
    long_return = (u_long) if_msg.ifm_data.ifi_noproto;
    return (u_char *) &long_return;
  case IFOUTOCTETS:
    long_return = (u_long) if_msg.ifm_data.ifi_obytes;
    return (u_char *) &long_return;
  case IFOUTUCASTPKTS:
    long_return = (u_long) if_msg.ifm_data.ifi_opackets-if_msg.ifm_data.ifi_omcasts;
    return (u_char *) &long_return;
  case IFOUTNUCASTPKTS:
    long_return = (u_long) if_msg.ifm_data.ifi_omcasts;
    return (u_char *) &long_return;
  case IFOUTDISCARDS:
#ifdef if_odrops
    long_return = (u_long) if_msg.ifm_data.ifi_odrops;
#else
    long_return = 0;
#endif
    return (u_char *) &long_return;
  case IFOUTERRORS:
    long_return = (u_long) if_msg.ifm_data.ifi_oerrors;
    return (u_char *) &long_return;
    /* ifOutQLen */
  default:
    return 0;
  }
}

int Interface_Scan_Next(Index, Name, Retifnet, Retin_ifaddr)
short *Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
  return 0;
}

#else /* not USE_SYSCTL_IFLIST */
 
	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifndef HAVE_NET_IF_MIB_H

static int header_interfaces __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));
static int header_ifEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));
extern u_char	*var_ifEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));

#ifndef solaris2
static int Interface_Scan_By_Index __P((int, char *, struct ifnet *, struct in_ifaddr *));
static int Interface_Get_Ether_By_Index __P((int, u_char *));
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_interfaces( )
{
}

#ifdef linux
typedef struct _conf_if_list {
    char *name;
    int type;
    int speed;
    struct _conf_if_list *next;
} conf_if_list;

conf_if_list *if_list;
struct ifnet *ifnetaddr_list;
#endif /* linux */

static int
header_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define INTERFACES_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[1024];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_interfaces: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[INTERFACES_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return MATCH_FAILED;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return MATCH_SUCCEEDED;
}



static int
header_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define IFENTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    register int	interface;
    int result, count;
    char c_oid[1024];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_ifEntry: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    /* find "next" interface */
    count = Interface_Scan_Get_Count();
    for(interface = 1; interface <= count; interface++){
	newname[IFENTRY_NAME_LENGTH] = (oid)interface;
	result = compare(name, *length, newname, (int)vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (interface > count) {
        DEBUGP ("... index out of range\n");
        return MATCH_FAILED;
    }


    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("... get I/F stats %s\n", c_oid);
    }

    return interface;
}



	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char	*
var_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    if (header_interfaces(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
	case IFNUMBER:
	    long_return = Interface_Scan_Get_Count();
	    return (u_char *)&long_return;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}


#ifndef solaris2
#ifndef hpux

u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    register oid	*name;
    register int	*length;
    int			exact;
    int			*var_len;
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct ifnet ifnet;
    register int interface;
    static struct in_ifaddr in_ifaddr;
    static char Name[16];
    register char *cp;
#if STRUCT_IFNET_HAS_IF_LASTCHANGE_TV_SEC
    struct timeval now;
#endif

    interface = header_ifEntry(vp, name, length, exact, var_len, write_method);
    if ( interface == MATCH_FAILED )
	return NULL;

    Interface_Scan_By_Index(interface, Name, &ifnet, &in_ifaddr);

    switch (vp->magic){
	case IFINDEX:
	    long_return = interface;
	    return (u_char *) &long_return;
	case IFDESCR:
	    cp = Name;
	    *var_len = strlen(cp);
	    return (u_char *)cp;
	case IFTYPE:
#if STRUCT_IFNET_HAS_IF_TYPE
	    long_return = ifnet.if_type;
#else
	    long_return = 1;	/* OTHER */
#endif
	    return (u_char *) &long_return;
	case IFMTU: {
	    long_return = (long) ifnet.if_mtu;
	    return (u_char *) &long_return;
	}
	case IFSPEED:
#if STRUCT_IFNET_HAS_IF_BAUDRATE
	    long_return = ifnet.if_baudrate;
#elif STRUCT_IFNET_HAS_IF_SPEED
	    long_return = ifnet.if_speed;
#elif STRUCT_IFNET_HAS_IF_TYPE && defined(IFT_ETHER)
	    if((long_return == 0) || (long_return == 1)) {
		if(ifnet.if_type == IFT_ETHER) long_return=10000000;
		if(ifnet.if_type == IFT_P10) long_return=10000000;
		if(ifnet.if_type == IFT_P80) long_return=80000000;
		if(ifnet.if_type == IFT_ISDNBASIC) long_return=64000; /* EDSS1 only */
		if(ifnet.if_type == IFT_ISDNPRIMARY) long_return=64000*30;
	    }
#else
	    long_return = (u_long) 10000000;
#endif
	    return (u_char *) &long_return;
	case IFPHYSADDRESS:
	    Interface_Get_Ether_By_Index(interface, return_buf);
	    *var_len = 6;
	    if ((return_buf[0] == 0) && (return_buf[1] == 0) &&
		(return_buf[2] == 0) && (return_buf[3] == 0) &&
		(return_buf[4] == 0) && (return_buf[5] == 0))
		*var_len = 0;
	    return(u_char *) return_buf;
	case IFADMINSTATUS:
	    long_return = ifnet.if_flags & IFF_RUNNING ? 1 : 2;
	    return (u_char *) &long_return;
	case IFOPERSTATUS:
	    long_return = ifnet.if_flags & IFF_UP ? 1 : 2;
	    return (u_char *) &long_return;
	case IFLASTCHANGE:
#if defined(STRUCT_IFNET_HAS_IF_LASTCHANGE_TV_SEC) && !(defined(freebsd2) && __FreeBSD_version < 199607)
/* XXX - SNMP's ifLastchange is time when op. status changed
 * FreeBSD's if_lastchange is time when packet was input or output
 * (at least in 2.1.0-RELEASE. Changed in later versions of the kernel?)
 */
/* FreeBSD's if_lastchange before the 2.1.5 release is the time when
 * a packet was last input or output.  In the 2.1.5 and later releases,
 * this is fixed, thus the 199607 comparison.
 */
          if ((ifnet.if_lastchange.tv_sec == 0 ) &&
              (ifnet.if_lastchange.tv_usec == 0))
            long_return = 0;
          else {
            gettimeofday(&now, (struct timezone *)0);
            long_return = (u_long)
              ((now.tv_sec - ifnet.if_lastchange.tv_sec) * 100
               + (now.tv_usec - ifnet.if_lastchange.tv_usec) / 10000);
          }
#else
          long_return = 0; /* XXX */
#endif
          return (u_char *) &long_return;
	case IFINOCTETS:
#ifdef STRUCT_IFNET_HAS_IF_IBYTES
          long_return = (u_long)  ifnet.if_ibytes;
#else
	    long_return = (u_long)  ifnet.if_ipackets * 308; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFINUCASTPKTS:
	    {
	    long_return = (u_long)  ifnet.if_ipackets;
#if STRUCT_IFNET_HAS_IF_IMCASTS
	    long_return -= (u_long) ifnet.if_imcasts;
#endif
	    }
	    return (u_char *) &long_return;
	case IFINNUCASTPKTS:
#if STRUCT_IFNET_HAS_IF_IMCASTS
	    long_return = (u_long)  ifnet.if_imcasts;
#else
	    long_return = (u_long)  0; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFINDISCARDS:
#if STRUCT_IFNET_HAS_IF_IQDROPS
	    long_return = (u_long)  ifnet.if_iqdrops;
#else
	    long_return = (u_long)  0; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFINERRORS:
	    long_return = (u_long) ifnet.if_ierrors;
	    return (u_char *) &long_return;
	case IFINUNKNOWNPROTOS:
#if STRUCT_IFNET_HAS_IF_NOPROTO
	    long_return = (u_long)  ifnet.if_noproto;
#else
	    long_return = (u_long)  0; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFOUTOCTETS:
#ifdef STRUCT_IFNET_HAS_IF_OBYTES
          long_return = (u_long)  ifnet.if_obytes;
#else
	    long_return = (u_long)  ifnet.if_opackets * 308; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFOUTUCASTPKTS:
	    {
	    long_return = (u_long)  ifnet.if_opackets;
#if STRUCT_IFNET_HAS_IF_OMCASTS
	    long_return -= (u_long) ifnet.if_omcasts;
#endif
	    }
	    return (u_char *) &long_return;
	case IFOUTNUCASTPKTS:
#if STRUCT_IFNET_HAS_IF_OMCASTS
	    long_return = (u_long)  ifnet.if_omcasts;
#else
	    long_return = (u_long)  0; /* XXX */
#endif
	    return (u_char *) &long_return;
	case IFOUTDISCARDS:
          long_return = ifnet.if_snd.ifq_drops;
          return (u_char *) &long_return;
	case IFOUTERRORS:
          long_return = ifnet.if_oerrors;
          return (u_char *) &long_return;
	case IFOUTQLEN:
          long_return = ifnet.if_snd.ifq_len;
          return (u_char *) &long_return;
	case IFSPECIFIC:
	    *var_len = nullOidLen;
	    return (u_char *) nullOid;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}

#else /* hpux */

u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    register oid	*name;
    register int	*length;
    int			exact;
    int			*var_len;
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct ifnet ifnet;
    register int interface;
    static struct in_ifaddr in_ifaddr;
    static char Name[16];
    register char *cp;
#if STRUCT_IFNET_HAS_IF_LASTCHANGE_TV_SEC
          struct timeval now;
#endif
    struct nmparms hp_nmparms;
    static mib_ifEntry hp_ifEntry;
    int  hp_fd;
    int  hp_len=sizeof(hp_ifEntry);


    interface = header_ifEntry(vp, name, length, exact, var_len, write_method);
    if ( interface == MATCH_FAILED )
	return NULL;

    Interface_Scan_By_Index(interface, Name, &ifnet, &in_ifaddr);

	/*
	 * Additional information about the interfaces is available under
	 * HP-UX through the network management interface '/dev/netman'
	 */
    hp_ifEntry.ifIndex = interface;
    hp_nmparms.objid  = ID_ifEntry;
    hp_nmparms.buffer = &hp_ifEntry;
    hp_nmparms.len    = &hp_len;
    if ((hp_fd=open("/dev/netman", O_RDONLY)) != -1 ) {
      if (ioctl(hp_fd, NMIOGET, &hp_nmparms) != -1 ) {
          close(hp_fd);
      }
      else {
          close(hp_fd);
          hp_fd = -1;         /* failed */
      }
    }

    switch (vp->magic){
	case IFINDEX:
	    long_return = interface;
	    return (u_char *) &long_return;
	case IFDESCR:
	  if ( hp_fd != -1 )
	    cp = hp_ifEntry.ifDescr;
	  else
	    cp = Name;
	    *var_len = strlen(cp);
	    return (u_char *)cp;
	case IFTYPE:
	      if ( hp_fd != -1 )
		long_return = hp_ifEntry.ifType;
	      else
		long_return = 1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFMTU: {
	    long_return = (long) ifnet.if_mtu;
	    return (u_char *) &long_return;
	}
	case IFSPEED:
	    if ( hp_fd != -1 )
		long_return = hp_ifEntry.ifSpeed;
	    else
	        long_return = (u_long)  1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFPHYSADDRESS:
		Interface_Get_Ether_By_Index(interface, return_buf);
		*var_len = 6;
	        if ((return_buf[0] == 0) && (return_buf[1] == 0) &&
		    (return_buf[2] == 0) && (return_buf[3] == 0) &&
		    (return_buf[4] == 0) && (return_buf[5] == 0))
		    *var_len = 0;
		return(u_char *) return_buf;
	case IFADMINSTATUS:
	    long_return = ifnet.if_flags & IFF_RUNNING ? 1 : 2;
	    return (u_char *) &long_return;
	case IFOPERSTATUS:
	    long_return = ifnet.if_flags & IFF_UP ? 1 : 2;
	    return (u_char *) &long_return;
	case IFLASTCHANGE:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifLastChange;
	  else
          long_return = 0; /* XXX */
          return (u_char *) &long_return;
	case IFINOCTETS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifInOctets;
	  else
	    long_return = (u_long)  ifnet.if_ipackets * 308; /* XXX */
	  return (u_char *) &long_return;
	case IFINUCASTPKTS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifInUcastPkts;
	  else
	    long_return = (u_long)  ifnet.if_ipackets;
	  return (u_char *) &long_return;
	case IFINNUCASTPKTS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifInNUcastPkts;
	  else
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFINDISCARDS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifInDiscards;
	  else
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFINERRORS:
	    return (u_char *) &ifnet.if_ierrors;
	case IFINUNKNOWNPROTOS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifInUnknownProtos;
	  else
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTOCTETS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifOutOctets;
	  else
	    long_return = (u_long)  ifnet.if_opackets * 308; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTUCASTPKTS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifOutUcastPkts;
	  else
	    long_return = (u_long)  ifnet.if_opackets;
	    return (u_char *) &long_return;
	case IFOUTNUCASTPKTS:
	  if ( hp_fd != -1 )
	    long_return = hp_ifEntry.ifOutNUcastPkts;
	  else
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTDISCARDS:
	    return (u_char *) &ifnet.if_snd.ifq_drops;
	case IFOUTERRORS:
	    return (u_char *) &ifnet.if_oerrors;
	case IFOUTQLEN:
	    return (u_char *) &ifnet.if_snd.ifq_len;
	case IFSPECIFIC:
	    *var_len = nullOidLen;
	    return (u_char *) nullOid;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}

#endif /* hpux */
#else /* solaris2 */

static int
IF_cmp(void *addr, void *ep)
{
    DEBUGP ("... IF_cmp %d %d\n", 
    ((mib2_ifEntry_t *)ep)->ifIndex, ((mib2_ifEntry_t *)addr)->ifIndex);
    if (((mib2_ifEntry_t *)ep)->ifIndex == ((mib2_ifEntry_t *)addr)->ifIndex)
	return (0);
    else
	return (1);
}

u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    register oid        *name;
    register int        *length;
    int                 exact;
    int                 *var_len;
    int                 (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    int        interface;
    mib2_ifEntry_t      ifstat;


    interface = header_ifEntry(vp, name, length, exact, var_len, write_method);
    if ( interface == MATCH_FAILED )
	return NULL;

    if (getMibstat(MIB_INTERFACES, &ifstat, sizeof(mib2_ifEntry_t),
                   GET_EXACT, &IF_cmp, &interface) != 0) {
      DEBUGP ("... no mib stats\n");
      return NULL;
    }
    switch (vp->magic){
    case IFINDEX:
      long_return = ifstat.ifIndex;
      return (u_char *) &long_return;
    case IFDESCR:
      *var_len = ifstat.ifDescr.o_length;
      (void)memcpy(return_buf, ifstat.ifDescr.o_bytes, *var_len);
      return(u_char *)return_buf;
    case IFTYPE:
      long_return = (u_long)ifstat.ifType;
      return (u_char *) &long_return;
    case IFMTU:
      long_return = (u_long)ifstat.ifMtu;
      return (u_char *) &long_return;
    case IFSPEED:
      long_return = (u_long)ifstat.ifSpeed;
      return (u_char *) &long_return;
    case IFPHYSADDRESS:
      *var_len = ifstat.ifPhysAddress.o_length;
      (void)memcpy(return_buf, ifstat.ifPhysAddress.o_bytes, *var_len);
      return(u_char *)return_buf;
    case IFADMINSTATUS:
      long_return = (u_long)ifstat.ifAdminStatus;
      return (u_char *) &long_return;
    case IFOPERSTATUS:
      long_return = (u_long)ifstat.ifOperStatus;
      return (u_char *) &long_return;
    case IFLASTCHANGE:
      long_return = (u_long)ifstat.ifLastChange;
      return (u_char *) &long_return;
    case IFINOCTETS:
      long_return = (u_long)ifstat.ifInOctets;
      return (u_char *) &long_return;
    case IFINUCASTPKTS:
      long_return = (u_long)ifstat.ifInUcastPkts;
      return (u_char *) &long_return;
    case IFINNUCASTPKTS:
      long_return = (u_long)ifstat.ifInNUcastPkts;
      return (u_char *) &long_return;
    case IFINDISCARDS:
      long_return = (u_long)ifstat.ifInDiscards;
      return (u_char *) &long_return;
    case IFINERRORS:
      long_return = (u_long)ifstat.ifInErrors;
      return (u_char *) &long_return;
    case IFINUNKNOWNPROTOS:
      long_return = (u_long)ifstat.ifInUnknownProtos;
      return (u_char *) &long_return;
    case IFOUTOCTETS:
      long_return = (u_long)ifstat.ifOutOctets;
      return (u_char *) &long_return;
    case IFOUTUCASTPKTS:
      long_return = (u_long)ifstat.ifOutUcastPkts;
      return (u_char *) &long_return;
    case IFOUTNUCASTPKTS:
      long_return = (u_long)ifstat.ifOutNUcastPkts;
      return (u_char *) &long_return;
    case IFOUTDISCARDS:
      long_return = (u_long)ifstat.ifOutDiscards;
      return (u_char *) &long_return;
    case IFOUTERRORS:
      long_return = (u_long)ifstat.ifOutErrors;
      return (u_char *) &long_return;
     case IFOUTQLEN:
      long_return = (u_long)ifstat.ifOutQLen;
      return (u_char *) &long_return;
    default:
      ERROR_MSG("");
    }
    return NULL;
}

#endif /* solaris2 */



	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


#ifndef solaris2

#if !defined(sunV3) && !defined(linux)
static struct in_ifaddr savein_ifaddr;
#endif
static struct ifnet *ifnetaddr, saveifnet, *saveifnetaddr;
static int saveIndex=0;
static char saveName[16];

void
Interface_Scan_Init __P((void))
{
#ifdef linux
    char line [128], fullname [20], ifname_buf [20], *ifname, *ptr;
    struct ifreq ifrq;
    struct ifnet **ifnetaddr_ptr;
    FILE *devin;
    int a, b, c, d, e, i, fd;
    extern conf_if_list *if_list;
    conf_if_list *if_ptr;
#endif  

    auto_nlist(IFNET_SYMBOL, (char *)&ifnetaddr, sizeof(ifnetaddr));
    saveIndex=0;

#ifdef linux
    /* free old list: */
    while (ifnetaddr_list)
      {
	struct ifnet *old = ifnetaddr_list;
	ifnetaddr_list = ifnetaddr_list->if_next;
	free (old->if_name);
	free (old);
      }

    ifnetaddr = 0;
    ifnetaddr_ptr = &ifnetaddr_list;

    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
      {
	ERROR_MSG("cannot open inet/dgram socket - continuing...\n");
	return; /** exit (1); **/
      }

    /*
     * build up ifnetaddr list by hand: 
     */
    
    /* at least linux v1.3.53 says EMFILE without reason... */
    if (! (devin = fopen ("/proc/net/dev", "r")))
      {
	close (fd);
	ERROR_MSG("cannot open /proc/net/dev - continuing...\n");
	return; /** exit (1); **/
      }

    i = 0;
    while (fgets (line, 256, devin))
      {
	struct ifnet *nnew;

	if (6 != sscanf (line, "%[^:]: %d %d %*d %*d %*d %d %d %*d %*d %d",
			 ifname_buf, &a, &b, &c, &d, &e))
	  continue;
	
	nnew = (struct ifnet *) malloc (sizeof (struct ifnet));	    
	memset ( nnew, 0, sizeof (struct ifnet));
	
	/* chain in: */
	*ifnetaddr_ptr = nnew;
	ifnetaddr_ptr = &nnew->if_next;
	i++;
	
	/* linux previous to 1.3.~13 may miss transmitted loopback pkts: */
	if (! strcmp (ifname_buf, "lo") && a > 0 && ! c)
	  c = a;

	nnew->if_ipackets = a, nnew->if_ierrors = b, nnew->if_opackets = c,
	nnew->if_oerrors = d, nnew->if_collisions = e;
	
	/* ifnames are given as ``   eth0'': split in ``eth'' and ``0'': */
	for (ifname = ifname_buf; *ifname && *ifname == ' '; ifname++) ;
	
	/* set name and interface# : */
	nnew->if_name = (char *) strdup (ifname);
	for (ptr = nnew->if_name; *ptr && (*ptr < '0' || *ptr > '9'); 
	     ptr++) ;
	nnew->if_unit = (*ptr) ? atoi (ptr) : 0;
	*ptr = 0;

	sprintf (fullname, "%s%d", nnew->if_name, nnew->if_unit);

	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFADDR, &ifrq) < 0)
	  memset ((char *) &nnew->if_addr, 0, sizeof (nnew->if_addr));
	else
	  nnew->if_addr = ifrq.ifr_addr;

	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFBRDADDR, &ifrq) < 0)
	  memset ((char *)&nnew->ifu_broadaddr, 0, sizeof(nnew->ifu_broadaddr));
	else
	  nnew->ifu_broadaddr = ifrq.ifr_broadaddr;

	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFNETMASK, &ifrq) < 0)
 	  memset ((char *)&nnew->ia_subnetmask, 0, sizeof(nnew->ia_subnetmask));
	else
	  nnew->ia_subnetmask = ifrq.ifr_netmask;
	  
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_flags = ioctl (fd, SIOCGIFFLAGS, &ifrq) < 0 
	  		? 0 : ifrq.ifr_flags;
	
	strcpy (ifrq.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifrq) < 0)
	  memset (nnew->if_hwaddr,(0), 6);
	else
	  memcpy (nnew->if_hwaddr, ifrq.ifr_hwaddr.sa_data, 6);
	    
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_metric = ioctl (fd, SIOCGIFMETRIC, &ifrq) < 0
	  		? 0 : ifrq.ifr_metric;
	    
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_mtu = (ioctl (fd, SIOCGIFMTU, &ifrq) < 0) 
			  ? 0 : ifrq.ifr_mtu;

	for (if_ptr = if_list; if_ptr; if_ptr = if_ptr->next)
	    if (! strcmp (if_ptr->name, fullname))
	      break;

	if (if_ptr) {
	    nnew->if_type = if_ptr->type;
	    nnew->if_speed = if_ptr->speed;
	}
	else {
	  nnew->if_type = ! strcmp (nnew->if_name, "lo") ? 24 :
	    ! strcmp (nnew->if_name, "eth") ? 6 :
	      ! strcmp (nnew->if_name, "sl") ? 28 : 1;
	  
	  nnew->if_speed = nnew->if_type == 6 ? 10000000 : 
	    nnew->if_type == 24 ? 10000000 : 0;
	}

      } /* while (fgets ... */

      ifnetaddr = ifnetaddr_list;

      if (snmp_get_do_debugging()) {
        { struct ifnet *x = ifnetaddr;
        printf ("* see: known interfaces:");
        while (x)
          {
            printf (" %s", x->if_name);
            x = x->if_next;
          }
        printf ("\n");
        } /* XXX */
      }

    fclose (devin);
    close (fd);
#endif /* linux */
}



#if defined(sunV3) || defined(linux)
/*
**  4.2 BSD doesn't have ifaddr
**  
*/
int Interface_Scan_Next(Index, Name, Retifnet, dummy)
short *Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *dummy;
{
	struct ifnet ifnet;
	register char *cp;

	while (ifnetaddr) {
	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
#ifndef linux
	    klookup((unsigned long)ifnetaddr, (char *)&ifnet, sizeof ifnet);
	    klookup((unsigned long)ifnet.if_name, (char *)saveName, sizeof saveName);
#else
	    ifnet = *ifnetaddr;
	    strcpy (saveName, ifnet.if_name);
#endif
	    if (strcmp(saveName, "ip") == 0) {
		ifnetaddr = ifnet.if_next;
		continue;
	    }



 	    saveName[sizeof (saveName)-1] = '\0';
	    cp = (char *) strchr(saveName, '\0');
	    string_append_int (cp, ifnet.if_unit);
	    if (1 || strcmp(saveName,"lo0") != 0) {  /* XXX */

		if (Index)
		    *Index = ++saveIndex;
		if (Retifnet)
		    *Retifnet = ifnet;
		if (Name)
		    strcpy(Name, saveName);
		saveifnet = ifnet;
		saveifnetaddr = ifnetaddr;
		ifnetaddr = ifnet.if_next;

		return(1);	/* DONE */
	    } 
	    ifnetaddr = ifnet.if_next;
	}
	return(0);	    /* EOF */
}


#else

#if defined(netbsd1) || defined(openbsd2)
#define ia_next ia_list.tqe_next
#define if_next if_list.tqe_next
#endif

int Interface_Scan_Next(Index, Name, Retifnet, Retin_ifaddr)
short *Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	struct ifnet ifnet;
	struct in_ifaddr *ia, in_ifaddr;
#if !STRUCT_IFNET_HAS_IF_XNAME
	register char *cp;
#endif

	while (ifnetaddr) {
	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
	    klookup((unsigned long)ifnetaddr, (char *)&ifnet, sizeof ifnet);
#if STRUCT_IFNET_HAS_IF_XNAME
#if defined(netbsd1) || defined(openbsd2)
            strncpy(saveName, ifnet.if_xname, sizeof saveName);
#else
	    klookup((unsigned long)ifnet.if_xname, (char *)saveName, sizeof saveName);
#endif
	    saveName[sizeof (saveName)-1] = '\0';
#else
	    klookup((unsigned long)ifnet.if_name, (char *)saveName, sizeof saveName);

	    saveName[sizeof (saveName)-1] = '\0';
	    cp = strchr(saveName, '\0');
	    string_append_int (cp, ifnet.if_unit);
#endif
	    if (1 || strcmp(saveName,"lo0") != 0) {  /* XXX */
		/*
		 *  Try to find an address for this interface
		 */

		auto_nlist(IFADDR_SYMBOL, (char *)&ia, sizeof(ia));
		while (ia) {
		    klookup((unsigned long)ia ,  (char *)&in_ifaddr, sizeof(in_ifaddr));
		    if (in_ifaddr.ia_ifp == ifnetaddr) break;
		    ia = in_ifaddr.ia_next;
		}

#if !defined(netbsd1) && !defined(freebsd2) && !defined(openbsd2) && !defined(STRUCT_IFNET_HAS_IF_ADDRLIST)
		ifnet.if_addrlist = (struct ifaddr *)ia;     /* WRONG DATA TYPE; ONLY A FLAG */
#endif
/*		ifnet.if_addrlist = (struct ifaddr *)&ia->ia_ifa;   */  /* WRONG DATA TYPE; ONLY A FLAG */

		if (Index)
		    *Index = ++saveIndex;
		if (Retifnet)
		    *Retifnet = ifnet;
		if (Retin_ifaddr)
		    *Retin_ifaddr = in_ifaddr;
		if (Name)
		    strcpy(Name, saveName);
		saveifnet = ifnet;
		saveifnetaddr = ifnetaddr;
		savein_ifaddr = in_ifaddr;
		ifnetaddr = ifnet.if_next;

		return(1);	/* DONE */
	    }
	    ifnetaddr = ifnet.if_next;
	}
	return(0);	    /* EOF */
}


#endif sunV3

static int Interface_Scan_By_Index(Index, Name, Retifnet, Retin_ifaddr)
int Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	short i;

        Interface_Scan_Init();
        while (Interface_Scan_Next(&i, Name, Retifnet, Retin_ifaddr)) {
          if (i == Index) break;
        }
        if (i != Index) return(-1);     /* Error, doesn't exist */
	return(0);	/* DONE */
}


static int Interface_Count=0;

static int Interface_Scan_Get_Count __P((void))
{

	if (!Interface_Count) {
	    Interface_Scan_Init();
	    while (Interface_Scan_Next(NULL, NULL, NULL, NULL) != 0) {
		Interface_Count++;
	    }
	}
	return(Interface_Count);
}


static int Interface_Get_Ether_By_Index(Index, EtherAddr)
int Index;
u_char *EtherAddr;
{
	short i;
#if !(defined(linux) || defined(netbsd1) || defined(bsdi2) || defined(openbsd2))
	struct arpcom arpcom;
#else /* is linux or netbsd1 */
	struct arpcom {
	  char ac_enaddr[6];
	} arpcom;
#if defined(netbsd1) || defined(bsdi2) || defined(openbsd2)
        struct sockaddr_dl sadl;
        struct ifaddr ifaddr;
        u_long ifaddraddr;
#endif
#endif

        memset(&arpcom.ac_enaddr, 0, sizeof(arpcom.ac_enaddr));
        memset(EtherAddr, 0, sizeof(arpcom.ac_enaddr));

	if (saveIndex != Index) {	/* Optimization! */

	    Interface_Scan_Init();

	    while (Interface_Scan_Next((short *)&i, NULL, NULL, NULL) != 0) {
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	}

#ifdef freebsd2
	    if (saveifnet.if_type != IFT_ETHER)
	    {
		return(0);	/* Not an ethernet if */
	    }
#endif
	/*
	 *  the arpcom structure is an extended ifnet structure which
	 *  contains the ethernet address.
	 */
#ifndef linux
#if !(defined(netbsd1) || defined(bsdi2) || defined(openbsd2))
      klookup((unsigned long)saveifnetaddr, (char *)&arpcom, sizeof arpcom);
#else  /* netbsd1 or bsdi2 or openbsd2 */

#if defined(netbsd1) || defined(openbsd2)
#define if_addrlist if_addrlist.tqh_first
#define ifa_next    ifa_list.tqe_next
#endif

        ifaddraddr = (unsigned long)saveifnet.if_addrlist;
        while (ifaddraddr) {
          klookup(ifaddraddr, (char *)&ifaddr, sizeof ifaddr);
          klookup((unsigned long)ifaddr.ifa_addr, (char *)&sadl, sizeof sadl);
          if (sadl.sdl_family == AF_LINK &&
              (saveifnet.if_type == IFT_ETHER ||
               saveifnet.if_type == IFT_ISO88025 ||
               saveifnet.if_type == IFT_FDDI)) {
            memcpy(arpcom.ac_enaddr, sadl.sdl_data + sadl.sdl_nlen,
                   sizeof(arpcom.ac_enaddr));
          break;
          }
          ifaddraddr = (unsigned long)ifaddr.ifa_next;
        }
#endif /* netbsd1 or bsdi2 or openbsd2 */

#else /* linux */
	memcpy(arpcom.ac_enaddr, saveifnetaddr->if_hwaddr, 6);
#endif
	if (strncmp("lo", saveName, 2) == 0) {
	    /*
	     *  Loopback doesn't have a HW addr, so return 00:00:00:00:00:00
	     */
	    memset(EtherAddr, 0, sizeof(arpcom.ac_enaddr));

	} else {

#if defined(mips) || defined(hpux) || defined(osf4)
          memcpy( EtherAddr,(char *) arpcom.ac_enaddr, sizeof (arpcom.ac_enaddr));
#else
          memcpy( EtherAddr,(char *) &arpcom.ac_enaddr, sizeof (arpcom.ac_enaddr));
#endif


	}
	return(0);	/* DONE */
}

#else /* solaris2 */

static int Interface_Scan_Get_Count __P((void))
{
	int i, sd;

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	  return (0);
	if (ioctl(sd, SIOCGIFNUM, &i) == -1) {
	  close(sd);
	  return (0);
	} else {
	  close(sd);
	  return (i);
	}
}

int
Interface_Index_By_Name(Name, Len)
char *Name;
int Len;
{
	int i, sd, ret;
	char buf[1024];
	struct ifconf ifconf;
	struct ifreq *ifrp;

	if (Name == 0)
	  return (0);
	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	  return (0);
	ifconf.ifc_buf = buf;
	ifconf.ifc_len = 1024;
	if (ioctl(sd, SIOCGIFCONF, &ifconf) == -1) {
	  ret = 0;
	  goto Return;
	}
	for (i = 1, ifrp = ifconf.ifc_req, ret = 0;
	     (char *)ifrp < (char *)ifconf.ifc_buf + ifconf.ifc_len; i++, ifrp++)
	  if (strncmp(Name, ifrp->ifr_name, Len) == 0) {
	    ret = i;
	    break;
	  } else
	    ret = 0;
      Return:
	close(sd);
	return (ret);	/* DONE */
}

#endif /* solaris2 */

#else /* HAVE_NET_IF_MIB_H */

/*
 * This code attempts to do the right thing for FreeBSD.  Note that
 * the statistics could be gathered through use of of the
 * net.route.0.link.iflist.0 sysctl (which we already use to get the
 * hardware address of the interfaces), rather than using the ifmib
 * code, but eventually I will implement dot3Stats and we will have to
 * use the ifmib interface.  ifmib is also a much more natural way of
 * mapping the SNMP MIB onto sysctl(3).
 */

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_mib.h>
#include <net/route.h>

static int header_interfaces __P((struct variable *, oid *, int *, int, int *,
			   int (**write) __P((int, u_char *, u_char, int,
					      u_char *, oid *, int)) ));
static int header_ifEntry __P((struct variable *, oid *, int *, int, int *,
			int (**write) __P((int, u_char *, u_char, int, 
					   u_char *, oid *, int)) ));
u_char	*var_ifEntry __P((struct variable *, oid *, int *, int, 
			  int *, 
			  int (**write) __P((int, u_char *, u_char, int, 
					     u_char *, oid *, int)) ));

static	char *physaddrbuf;
static	int nphysaddrs;
struct	sockaddr_dl **physaddrs;

void	init_interfaces()
{
	int naddrs, ilen, bit;
	static int mib[6] 
		= { CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, 0 };
	char *cp;
	size_t len;
	struct rt_msghdr *rtm;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr *sa;

	naddrs = 0;
	if (physaddrs)
		free(physaddrs);
	if (physaddrbuf)
		free(physaddrbuf);
	physaddrbuf = 0;
	physaddrs = 0;
	nphysaddrs = 0;
	len = 0;
	if (sysctl(mib, 6, 0, &len, 0, 0) < 0)
		return;

	cp = physaddrbuf = malloc(len);
	if (physaddrbuf == 0)
		return;
	if (sysctl(mib, 6, physaddrbuf, &len, 0, 0) < 0) {
		free(physaddrbuf);
		physaddrbuf = 0;
		return;
	}

loop:
	ilen = len;
	cp = physaddrbuf;
	while (ilen > 0) {
		rtm = (struct rt_msghdr *)cp;
		if (rtm->rtm_version != RTM_VERSION 
		    || rtm->rtm_type != RTM_IFINFO) {
			free(physaddrs);
			physaddrs = 0;
			free(physaddrbuf);
			physaddrbuf = 0;
		}
		ifm = (struct if_msghdr *)rtm;
		ilen -= ifm->ifm_msglen;
		cp += ifm->ifm_msglen;
		rtm = (struct rt_msghdr *)cp;
		while (ilen > 0 && rtm->rtm_type == RTM_NEWADDR) {
			int is_alias = 0;
			ifam = (struct ifa_msghdr *)rtm;
			ilen -= sizeof(*ifam);
			cp += sizeof(*ifam);
			sa = (struct sockaddr *)cp;
#define ROUND(x) (((x) + sizeof(long) - 1) & ~sizeof(long))
			for (bit = 1; bit && ilen > 0; bit <<= 1) {
				if (!(ifam->ifam_addrs & bit))
					continue;
				ilen -= ROUND(sa->sa_len);
				cp += ROUND(sa->sa_len);

				if (bit == RTA_IFA) {
					if (physaddrs)
#define satosdl(sa) ((struct sockaddr_dl *)(sa))
						physaddrs[naddrs++] 
							= satosdl(sa);
					else
						naddrs++;
				}
				sa = (struct sockaddr *)cp;
			}
			rtm = (struct rt_msghdr *)cp;
		}
	}
	if (physaddrs) {
		nphysaddrs = naddrs;
		return;
	}
	physaddrs = malloc(naddrs * sizeof(*physaddrs));
	if (physaddrs == 0)
		return;
	naddrs = 0;
	goto loop;
	
}

static int
get_phys_address(int index, char **ap, int *len)
{
	int i;
	int once = 1;

	do {
		for (i = 0; i < nphysaddrs; i++) {
			if (physaddrs[i]->sdl_index == index)
				break;
		}
		if (i < nphysaddrs)
			break;
		init_interfaces();
	} while (once--);

	if (i < nphysaddrs) {
		*ap = LLADDR(physaddrs[i]);
		*len = physaddrs[i]->sdl_alen;
		return 0;
	}
	return -1;
}

static int
header_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define INTERFACES_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[1024];

    sprint_objid (c_oid, name, *length);
    printf ("var_interfaces: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[INTERFACES_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return MATCH_FAILED;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return MATCH_SUCCEEDED;
}

static int count_oid[5] = { CTL_NET, PF_LINK, NETLINK_GENERIC, 
			    IFMIB_SYSTEM, IFMIB_IFCOUNT };

static int
header_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define IFENTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    register int	interface;
    int result, count;
    static int count_oid[5] = { CTL_NET, PF_LINK, NETLINK_GENERIC, 
				IFMIB_SYSTEM, IFMIB_IFCOUNT };
    size_t len;
#ifdef DODEBUG
    char c_oid[1024];

    sprint_objid (c_oid, name, *length);
    printf ("var_ifEntry: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    /* find "next" interface */
    len = sizeof count;
    if (sysctl(count_oid, 5, &count, &len, (void *)0, (size_t)0) < 0)
	    return MATCH_FAILED;

    for(interface = 1; interface <= count; interface++){
	newname[IFENTRY_NAME_LENGTH] = (oid)interface;
	result = compare(name, *length, newname, (int)vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (interface > count) {
#ifdef DODEBUG
	printf ("... index out of range\n");
#endif
        return MATCH_FAILED;
    }


    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

#ifdef DODEBUG
    sprint_objid (c_oid, name, *length);
    printf ("... get I/F stats %s\n", c_oid);
#endif

    return interface;
}

u_char	*
var_interfaces(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *,
				  oid *, int));
{
    size_t len;
    int count;

    if (header_interfaces(vp, name, length, exact, var_len, write_method)
	== MATCH_FAILED)
	    return NULL;

    switch (vp->magic){
    case IFNUMBER:
	    len = sizeof count;
	    if (sysctl(count_oid, 5, &count, &len, 0, 0) < 0)
		    return NULL;
	    long_return = count;
	    return (u_char *)&long_return;
    default:
	    ERROR_MSG("");
    }
    return NULL;
}

u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    register oid	*name;
    register int	*length;
    int			exact;
    int			*var_len;
    int			(**write_method) __P((int, u_char *, u_char, int,
					      u_char *, oid *, int));
{
	int interface;
	static int sname[6] = { CTL_NET, PF_LINK, NETLINK_GENERIC,
			       IFMIB_IFDATA, 0, IFDATA_GENERAL };
	static struct ifmibdata ifmd;
	size_t len;
	char *cp;

	interface = header_ifEntry(vp, name, length, exact, var_len,
				   write_method);
	if (interface == MATCH_FAILED)
		return NULL;

	sname[4] = interface;
	len = sizeof ifmd;
	if (sysctl(sname, 6, &ifmd, &len, 0, 0) < 0)
		return NULL;
	
	switch (vp->magic) {
	case IFINDEX:
		long_return = interface;
		return (u_char *) &long_return;
	case IFDESCR:
		cp = ifmd.ifmd_name;
		*var_len = strlen(cp);
		return (u_char *)cp;
	case IFTYPE:
		long_return = ifmd.ifmd_data.ifi_type;
		return (u_char *) &long_return;
	case IFMTU:
		long_return = (long) ifmd.ifmd_data.ifi_mtu;
		return (u_char *) &long_return;
	case IFSPEED:
		long_return = ifmd.ifmd_data.ifi_baudrate;
		return (u_char *) &long_return;
	case IFPHYSADDRESS:
	{
		char *cp;
		if (get_phys_address(interface, &cp, var_len))
			return NULL;
		else
			return cp;
	}
	case IFADMINSTATUS:
		long_return = ifmd.ifmd_flags & IFF_RUNNING ? 1 : 2;
		return (u_char *) &long_return;
	case IFOPERSTATUS:
		long_return = ifmd.ifmd_flags & IFF_UP ? 1 : 2;
		return (u_char *) &long_return;
	case IFLASTCHANGE:
		if ((ifmd.ifmd_data.ifi_lastchange.tv_sec == 0 ) &&
		    (ifmd.ifmd_data.ifi_lastchange.tv_usec == 0)) {
			long_return = 0;
		} else {
			struct timeval now;

			gettimeofday(&now, (struct timezone *)0);
			long_return = (u_long)
				((now.tv_sec 
				  - ifmd.ifmd_data.ifi_lastchange.tv_sec) * 100
				 + ((now.tv_usec
				     - ifmd.ifmd_data.ifi_lastchange.tv_usec)
				    / 10000));
		}
		return (u_char *) &long_return;
	case IFINOCTETS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_ibytes;
		return (u_char *) &long_return;
	case IFINUCASTPKTS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_ipackets;
		long_return -= (u_long) ifmd.ifmd_data.ifi_imcasts;
		return (u_char *) &long_return;
	case IFINNUCASTPKTS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_imcasts;
		return (u_char *) &long_return;
	case IFINDISCARDS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_iqdrops;
		return (u_char *) &long_return;
	case IFINERRORS:
		long_return = ifmd.ifmd_data.ifi_ierrors;
		return (u_char *) &long_return;
	case IFINUNKNOWNPROTOS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_noproto;
		return (u_char *) &long_return;
	case IFOUTOCTETS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_obytes;
		return (u_char *) &long_return;
	case IFOUTUCASTPKTS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_opackets;
		long_return -= (u_long) ifmd.ifmd_data.ifi_omcasts;
		return (u_char *) &long_return;
	case IFOUTNUCASTPKTS:
		long_return = (u_long)  ifmd.ifmd_data.ifi_omcasts;
		return (u_char *) &long_return;
	case IFOUTDISCARDS:
		long_return = ifmd.ifmd_snd_drops;
		return (u_char *) &long_return;
	case IFOUTERRORS:
		long_return = ifmd.ifmd_data.ifi_oerrors;
		return (u_char *) &long_return;
	case IFOUTQLEN:
		long_return = ifmd.ifmd_snd_len;
		return (u_char *) &long_return;
	case IFSPECIFIC:
		*var_len = nullOidLen;
		return (u_char *) nullOid;
	default:
		ERROR_MSG("");
	}
	return NULL;
}

#endif /* HAVE_NET_IF_MIB_H */
#endif
