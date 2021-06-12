/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#include <net-snmp/net-snmp-config.h>

#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif


#ifdef HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include <errno.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "ip.h"
#include "route_write.h"
#include "var_route.h"

#if defined(cygwin) || defined(mingw32)
#include <windows.h>
#include <winerror.h>
#endif

#if !defined (WIN32) && !defined (cygwin)

#ifndef HAVE_STRUCT_RTENTRY_RT_DST
#define rt_dst rt_nodes->rn_key
#endif
#ifndef HAVE_STRUCT_RTENTRY_RT_HASH
#define rt_hash rt_pad1
#endif

#ifdef irix6
#define SIOCADDRT SIOCADDMULTI
#define SIOCDELRT SIOCDELMULTI
#endif

#ifdef linux
#define NETSNMP_ROUTE_WRITE_PROTOCOL PF_ROUTE
#else
#define NETSNMP_ROUTE_WRITE_PROTOCOL 0
#endif

int
addRoute(u_long dstip, u_long gwip, u_long iff, u_short flags)
{
#if defined SIOCADDRT && !(defined(irix6) || defined(__OpenBSD__) || defined(darwin))
    struct sockaddr_in dst;
    struct sockaddr_in gateway;
    int             s, rc;
    RTENTRY         route;

    s = socket(AF_INET, SOCK_RAW, NETSNMP_ROUTE_WRITE_PROTOCOL);
    if (s < 0) {
        snmp_log_perror("socket");
        return -1;
    }


    flags |= RTF_UP;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(dstip);

    memset(&gateway, 0, sizeof(gateway));
    gateway.sin_family = AF_INET;
    gateway.sin_addr.s_addr = htonl(gwip);

    memset(&route, 0, sizeof(route));
    memcpy(&route.rt_dst, &dst, sizeof(struct sockaddr_in));
    memcpy(&route.rt_gateway, &gateway, sizeof(struct sockaddr_in));

    route.rt_flags = flags;
#ifndef RTENTRY_4_4
    route.rt_hash = iff;
#endif

    rc = ioctl(s, SIOCADDRT, (caddr_t) & route);
    close(s);
    if (rc < 0)
        snmp_log_perror("ioctl");
    return rc;

#elif (defined __OpenBSD__ || defined(darwin))

       int     s, rc;
       struct {
               struct  rt_msghdr hdr;
               struct  sockaddr_in dst;
               struct  sockaddr_in gateway;
       } rtmsg;

       s = socket(PF_ROUTE, SOCK_RAW, 0);
       if (s < 0) {
            snmp_log_perror("socket");
            return -1;
       }

       shutdown(s, SHUT_RD);

       /* possible panic otherwise */
       flags |= (RTF_UP | RTF_GATEWAY);

       bzero(&rtmsg, sizeof(rtmsg));

       rtmsg.hdr.rtm_type = RTM_ADD;
       rtmsg.hdr.rtm_version = RTM_VERSION;
       rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;
       rtmsg.hdr.rtm_flags = RTF_GATEWAY;

       rtmsg.dst.sin_len = sizeof(rtmsg.dst);
       rtmsg.dst.sin_family = AF_INET;
       rtmsg.dst.sin_addr.s_addr = htonl(dstip);

       rtmsg.gateway.sin_len = sizeof(rtmsg.gateway);
       rtmsg.gateway.sin_family = AF_INET;
       rtmsg.gateway.sin_addr.s_addr = htonl(gwip);

       rc = sizeof(rtmsg);
       rtmsg.hdr.rtm_msglen = rc;

       if ((rc = write(s, &rtmsg, rc)) < 0) {
               snmp_log_perror("writing to routing socket");
               return -1;
       }
       return (rc);
#else                           /* SIOCADDRT */
    return -1;
#endif
}



int
delRoute(u_long dstip, u_long gwip, u_long iff, u_short flags)
{
#if defined SIOCADDRT && !(defined(irix6) || defined(__OpenBSD__) || defined(darwin))

    struct sockaddr_in dst;
    struct sockaddr_in gateway;
    int             s, rc;
    RTENTRY         route;

    s = socket(AF_INET, SOCK_RAW, NETSNMP_ROUTE_WRITE_PROTOCOL);
    if (s < 0) {
        snmp_log_perror("socket");
        return 0;
    }


    flags |= RTF_UP;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(dstip);

    memset(&gateway, 0, sizeof(gateway));
    gateway.sin_family = AF_INET;
    gateway.sin_addr.s_addr = htonl(gwip);

    memcpy(&route.rt_dst, &dst, sizeof(struct sockaddr_in));
    memcpy(&route.rt_gateway, &gateway, sizeof(struct sockaddr_in));

    route.rt_flags = flags;
#ifndef RTENTRY_4_4
    route.rt_hash = iff;
#endif

    rc = ioctl(s, SIOCDELRT, (caddr_t) & route);
    close(s);
    return rc;
#elif (defined __OpenBSD__ || defined(darwin))
 
       int     s, rc;
       struct {
               struct  rt_msghdr hdr;
               struct  sockaddr_in dst;
               struct  sockaddr_in gateway;
       } rtmsg;

       s = socket(PF_ROUTE, SOCK_RAW, 0);
       if (s < 0) {
            snmp_log_perror("socket");
            return -1;
       }

       shutdown(s, SHUT_RD);

       /* possible panic otherwise */
       flags |= (RTF_UP | RTF_GATEWAY);

       bzero(&rtmsg, sizeof(rtmsg));

       rtmsg.hdr.rtm_type = RTM_DELETE;
       rtmsg.hdr.rtm_version = RTM_VERSION;
       rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;
       rtmsg.hdr.rtm_flags = RTF_GATEWAY;

       rtmsg.dst.sin_len = sizeof(rtmsg.dst);
       rtmsg.dst.sin_family = AF_INET;
       rtmsg.dst.sin_addr.s_addr = htonl(dstip);

       rtmsg.gateway.sin_len = sizeof(rtmsg.gateway);
       rtmsg.gateway.sin_family = AF_INET;
       rtmsg.gateway.sin_addr.s_addr = htonl(gwip);

       rc = sizeof(rtmsg);
       rtmsg.hdr.rtm_msglen = rc;

       if ((rc = write(s, &rtmsg, rc)) < 0) {
               snmp_log_perror("writing to routing socket");
               return -1;
       }
       return (rc);
#else                           /* SIOCDELRT */
    return 0;
#endif
}


#ifndef HAVE_STRUCT_RTENTRY_RT_DST
#undef rt_dst
#endif


#define  MAX_CACHE   8

struct rtent {

    u_long          in_use;
    u_long          old_dst;
    u_long          old_nextIR;
    u_long          old_ifix;
    u_long          old_flags;

    u_long          rt_dst;     /*  main entries    */
    u_long          rt_ifix;
    u_long          rt_metric1;
    u_long          rt_nextIR;
    u_long          rt_type;
    u_long          rt_proto;


    u_long          xx_dst;     /*  shadow entries  */
    u_long          xx_ifix;
    u_long          xx_metric1;
    u_long          xx_nextIR;
    u_long          xx_type;
    u_long          xx_proto;
};

struct rtent    rtcache[MAX_CACHE];

struct rtent   *
findCacheRTE(u_long dst)
{
    int             i;

    for (i = 0; i < MAX_CACHE; i++) {

        if (rtcache[i].in_use && (rtcache[i].rt_dst == dst)) {  /* valid & match? */
            return (&rtcache[i]);
        }
    }
    return NULL;
}

struct rtent   *
newCacheRTE(void)
{

    int             i;

    for (i = 0; i < MAX_CACHE; i++) {

        if (!rtcache[i].in_use) {
            rtcache[i].in_use = 1;
            return (&rtcache[i]);
        }
    }
    return NULL;

}

int
delCacheRTE(u_long dst)
{
    struct rtent   *rt;

    rt = findCacheRTE(dst);
    if (!rt) {
        return 0;
    }

    rt->in_use = 0;
    return 1;
}


struct rtent   *
cacheKernelRTE(u_long dst)
{
    return NULL;                /* for now */
    /*
     * ...... 
     */
}

#endif                          /* WIN32 cygwin */
