/***********************************************************
        Copyright 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * System dependent routines go here
 */
#include <config.h>
#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
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
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <net/if.h>
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <nlist.h>
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_KSTAT_H
#include <kstat.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#include "system.h"

#define NUM_NETWORKS    32   /* max number of interfaces to check */

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0
#endif
#define LOOPBACK    0x7f000001
u_long get_myaddr __P((void))
{
    int sd;
    struct ifconf ifc;
    struct ifreq conf[NUM_NETWORKS], *ifrp, ifreq;
    struct sockaddr_in *in_addr;
    int count;
    int interfaces;             /* number of interfaces returned by ioctl */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return 0;
    ifc.ifc_len = sizeof(conf);
    ifc.ifc_buf = (caddr_t)conf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0){
        close(sd);
        return 0;
    }
    ifrp = ifc.ifc_req;
    interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for(count = 0; count < interfaces; count++, ifrp++){
        ifreq = *ifrp;
        if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifreq) < 0)
            continue;
        in_addr = (struct sockaddr_in *)&ifrp->ifr_addr;
        if ((ifreq.ifr_flags & IFF_UP)
          && (ifreq.ifr_flags & IFF_RUNNING)
          && !(ifreq.ifr_flags & IFF_LOOPBACK)
          && in_addr->sin_addr.s_addr != LOOPBACK){
#ifdef freebsd2
	    if (ioctl(sd, SIOCGIFADDR, (char *)&ifreq) < 0)
		continue;
	    in_addr = (struct sockaddr_in *)&(ifreq.ifr_addr);
#endif
	    close(sd);
	    return in_addr->sin_addr.s_addr;
	}
    }
    close(sd);
    return 0;
}


/*
 * Returns uptime in centiseconds(!).
 */
long get_uptime __P((void))
{
#ifdef bsdlike
    struct timeval boottime, now, diff;
#ifndef CAN_USE_SYSCTL
    int kmem;
    static struct nlist nl[] = {
#if !defined(hpux) && !defined(solaris2)
	    { "_boottime" },
#else
	    { "boottime" },
#endif
	    { "" }
	};

    if ((kmem = open("/dev/kmem", 0)) < 0)
	return 0;
    nlist(KERNEL_LOC, nl);
    if (nl[0].n_type == 0){
	close(kmem);
	return 0;
    }

    lseek(kmem, (long)nl[0].n_value, L_SET);
    read(kmem, &boottime, sizeof(boottime));
    close(kmem);
#else /* CAN_USE_SYSCTL */
    int                 mib[2];
    size_t              len;

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;

    len = sizeof(boottime);

    sysctl(mib, 2, &boottime, &len, NULL, NULL);
#endif /* CAN_USE_SYSCTL */

    gettimeofday(&now, 0);
    now.tv_sec--;
    now.tv_usec += 1000000L;
    diff.tv_sec = now.tv_sec - boottime.tv_sec;
    diff.tv_usec = now.tv_usec - boottime.tv_usec;
    if (diff.tv_usec > 1000000L){
	diff.tv_usec -= 1000000L;
	diff.tv_sec++;
    }
    return ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
#endif /* bsdlike */

#ifdef solaris2
    kstat_ctl_t *ksc = kstat_open();
    kstat_t *ks;
    kid_t kid;
    kstat_named_t *named;
    u_long lbolt;

    if (ksc == NULL) return 0;
    ks = kstat_lookup (ksc, "unix", -1, "system_misc");
    if (ks == NULL) return 0;
    kid = kstat_read (ksc, ks, NULL);
    if (kid == -1) return 0;
    named = kstat_data_lookup(ks, "lbolt");
    if (named == NULL) return 0;
    lbolt = named->value.ul;
    kstat_close(ksc);
    return lbolt;
#endif /* solaris2 */

#ifdef linux
   FILE *in = fopen ("/proc/uptime", "r");
   long uptim = 0, a, b;
   if (in) {
       if (2 == fscanf (in, "%ld.%ld", &a, &b))
	   uptim = a * 100 + b;
       fclose (in);
   }
   return uptim;
#endif /* linux */
}
