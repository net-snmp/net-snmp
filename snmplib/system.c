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
#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <nlist.h>
#include <sys/file.h>
#include "system.h"

#define NUM_NETWORKS    32   /* max number of interfaces to check */

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0
#endif
#define LOOPBACK    0x7f000001
u_long get_myaddr(){
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
                close(sd);
                return in_addr->sin_addr.s_addr;
            }
    }
    close(sd);
    return 0;
}

struct nlist nl[] = {
    { "_boottime" },
    { "" }
};

/*
 * Returns uptime in centiseconds(!).
 */
long get_uptime(){
    struct timeval boottime, now, diff;
    int kmem;

    if ((kmem = open("/dev/kmem", 0)) < 0)
        return 0;
    nlist("/vmunix", nl);
    if (nl[0].n_type == 0){
        close(kmem);
        return 0;
    }

    lseek(kmem, (long)nl[0].n_value, L_SET);
    read(kmem, &boottime, sizeof(boottime));
    close(kmem);

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
}

