#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#include <sys/socket.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif


#include <net/route.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#if STDC_HEADERS
#include <stdlib.h>
#endif
#if STDC_HEADERS
#include <string.h>
#endif



#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_vars.h"

#if defined(osf3) || defined(netbsd1) || defined(freebsd2)
#define rt_dst rt_nodes->rn_key
#endif

int  addRoute(dstip, gwip, iff, flags)
u_long  dstip;
u_long  gwip;
u_long  iff;
u_short  flags;
{


    struct sockaddr_in     dst;
    struct sockaddr_in     gateway;
    int                    s;
    RTENTRY  route;
    int  ret;

    s = socket(AF_INET, SOCK_RAW, 0);
    if (s<0) {
        perror("socket");
	return 0;
    }
    

    flags |= RTF_UP;

    dst.sin_family       = AF_INET;
    dst.sin_addr.s_addr  = htonl(dstip);


    gateway.sin_family        = AF_INET;
    gateway.sin_addr.s_addr   = htonl(gwip);

    bcopy((char*) &dst, (char *) &route.rt_dst, sizeof(struct  sockaddr_in));
    bcopy((char*) &gateway, (char *) &route.rt_gateway, sizeof(struct  sockaddr_in));

    route.rt_flags = flags;
#ifndef RTENTRY_4_4
    route.rt_hash  = iff;
#endif
    return (ioctl(s, SIOCADDRT , (caddr_t)&route));

}



int  delRoute(dstip, gwip, iff, flags)
u_long  dstip;
u_long  gwip;
u_long  iff;
u_short  flags;
{


    struct sockaddr_in     dst;
    struct sockaddr_in     gateway;
    int                    s;
    RTENTRY  route;
    int  ret;

    s = socket(AF_INET, SOCK_RAW, 0);
    if (s<0) {
        perror("socket");
	return 0;
    }
    

    flags |= RTF_UP;

    dst.sin_family       = AF_INET;
    dst.sin_addr.s_addr  = htonl(dstip);


    gateway.sin_family        = AF_INET;
    gateway.sin_addr.s_addr   = htonl(gwip);

    bcopy((char*) &dst, (char *) &route.rt_dst, sizeof(struct  sockaddr_in));
    bcopy((char*) &gateway, (char *) &route.rt_gateway, sizeof(struct  sockaddr_in));

    route.rt_flags = flags;
#ifndef RTENTRY_4_4
    route.rt_hash  = iff;
#endif

    return (ioctl(s, SIOCDELRT , (caddr_t)&route));

}


#if defined(osf3) || defined(netbsd1) || defined(freebsd2)
#undef rt_dst
#endif







#define  MAX_CACHE   8



struct rtent {

    u_long    in_use;
    u_long    old_dst;
    u_long    old_nextIR;
    u_long    old_ifix;
    u_long    old_flags;

    u_long    rt_dst;            /*  main entries    */
    u_long    rt_ifix;
    u_long    rt_metric1;
    u_long    rt_nextIR;
    u_long    rt_type;
    u_long    rt_proto;


    u_long    xx_dst;            /*  shadow entries  */
    u_long    xx_ifix;
    u_long    xx_metric1;
    u_long    xx_nextIR;
    u_long    xx_type;
    u_long    xx_proto;
};






struct  rtent  rtcache[MAX_CACHE];



struct rtent *findCacheRTE(dst)
u_long dst;
{
    int i;

    for (i = 0; i < MAX_CACHE; i++) {
	
	if (rtcache[i].in_use && (rtcache[i].rt_dst == dst)) {  /* valid & match? */
	    return (&rtcache[i]);
	}
    }
    return 0;
}



struct rtent  *newCacheRTE()
{

    int i;

    for (i = 0; i < MAX_CACHE; i++) {
	
	if (!rtcache[i].in_use) {
	    rtcache[i].in_use = 1;
	    return (&rtcache[i]);
	}
    }
    return 0;

}



int delCacheRTE(dst)
u_long dst;
{
    int i;
    struct  rtent  *rt;

    rt = findCacheRTE(dst);
    if (!rt) {
	return 0;
    }

    rt->in_use = 0;
    return 1;
}





struct  rtent  *cacheKernelRTE(dst)
u_long dst;
{

    return 0;  /* for now */


    /* ...... */

    
}






/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and ap is non-NULL, the instance exists, but not this variable.
 * If statP is NULL and ap is NULL, then neither this instance nor the variable exists.
 */

int
write_rte(action, var_val, var_val_type, var_val_len, statP, name, length)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      length;
{
    struct rtent *rp;
    int var;
    long val;
    u_long  dst;
    char    buf[8];
    int     bufsz;
    u_short  flags;
    int      oldty;

    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.X.A.B.C.D ,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */

    if (length != 14) {
	printf("length error\n");
	return SNMP_ERR_NOCREATION;
    }

    var = name[9];
    
    dst = *((u_long *) & name[10] );

    rp = findCacheRTE(dst);

    if (!rp) {
	rp = cacheKernelRTE(dst);
    }


    if (action == RESERVE1 && !rp) {

	rp = newCacheRTE();
	if (!rp) {
	    printf("newCacheRTE");
	    return SNMP_ERR_RESOURCEUNAVAILABLE;
	}
	rp->rt_type = rp->xx_type = 2;

    } else if (action == COMMIT){


    } else if (action == FREE) {
	if (rp->rt_type == 2) {  /* was invalid before */
	    delCacheRTE(dst);
	}
    }



    
    switch(var){

	case IPROUTEDEST:
	   
            if (action == RESERVE1){

		if (var_val_type != ASN_OCTET_STR) {
		    printf("not octet");
		    return SNMP_ERR_WRONGTYPE;
		}

		bufsz = 8;
		asn_parse_string(var_val, &var_val_len, &var_val_type, buf, &bufsz);

		if (var_val_type != ASN_OCTET_STR) {
		    printf("not octet2");
		    return SNMP_ERR_WRONGTYPE;
		}
		
		rp->xx_dst = *((u_long *) buf);
		

	    } else if (action == COMMIT) {
		rp->rt_dst = rp->xx_dst;
	    }
	    break;

	case IPROUTEMETRIC1:

	    if (action == RESERVE1) {
		if (var_val_type != ASN_INTEGER) {
		    printf("not int1");
		    return SNMP_ERR_WRONGTYPE;
		}
		
		asn_parse_int(var_val, &var_val_len, &var_val_type, &val, sizeof(val));

		if (val < -1) {
		    printf("not right1");
		    return SNMP_ERR_WRONGVALUE;
		}

		rp->xx_metric1 = val;

	    } else if (action == RESERVE2) {

		if ((rp->xx_metric1 == 1) && (rp->xx_type != 4)) {
		    printf("reserve2 failed\n");
		    return SNMP_ERR_WRONGVALUE;
		}

	    } else if (action == COMMIT) {
		rp->rt_metric1 = rp->xx_metric1;
	    }
	    break;

	case IPROUTEIFINDEX:

	    if (action == RESERVE1) {
		if (var_val_type != ASN_INTEGER) {
		    printf("not right2");
		  return SNMP_ERR_WRONGTYPE;
		}
		
		asn_parse_int(var_val, &var_val_len, &var_val_type, &val, sizeof(val));

		if (val <= 0) {
		    printf("not right3");
		    return SNMP_ERR_WRONGVALUE;
		}

		rp->xx_ifix = val;

	    } else if (action == COMMIT) {
		rp->rt_ifix = rp->xx_ifix;
	    }
	    break;	    
	    
	case IPROUTENEXTHOP:
	   
            if (action == RESERVE1){

		if (var_val_type != ASN_OCTET_STR) {
		    printf("not right4");
		  return SNMP_ERR_WRONGTYPE;
		}

		bufsz = 8;
		asn_parse_string(var_val, &var_val_len, &var_val_type, buf, &bufsz);

		if (var_val_type != ASN_OCTET_STR) {
		    printf("not right5");
		    return SNMP_ERR_WRONGTYPE;
		}
		
		rp->xx_nextIR = *((u_long *) buf);

	    } else if (action == COMMIT) {
		rp->rt_nextIR = rp->xx_nextIR;
	    }
	  

	case IPROUTETYPE:

	    /*
	     *  flag meaning:
	     *
	     *  IPROUTEPROTO (rt_proto): none: (cant set == 3 (netmgmt)) 
	     *
	     *  IPROUTEMETRIC1:  1 iff gateway, 0 otherwise
	     *  IPROUTETYPE:     4 iff gateway, 3 otherwise
	     */

	    if (action == RESERVE1) {
		if (var_val_type != ASN_INTEGER) {
		  return SNMP_ERR_WRONGTYPE;
		}
		
		asn_parse_int(var_val, &var_val_len, &var_val_type, &val, sizeof(val));

		if ((val < 2) || (val > 4)) { /* only accept invalid, direct, indirect */
		    printf("not right6");
		    return SNMP_ERR_WRONGVALUE;
		}

		rp->xx_type = val;

	    } else if (action == COMMIT) {
		
		oldty = rp->rt_type;
		rp->rt_type = rp->xx_type;
		
		if (rp->rt_type == 2) {  /* invalid, so delete from kernel */

		    if (delRoute(rp->rt_dst, rp->rt_nextIR, rp->rt_ifix , rp->old_flags ) < 0) {
			perror("delRoute");
		    }

		} else {

		    /* it must be valid now, so flush to kernel */
		    
		    if (oldty != 2) {   /* was the old entry valid ?  */
			if (delRoute(rp->old_dst, rp->old_nextIR, rp->old_ifix , rp->old_flags ) < 0) {
			    perror("delRoute");
			}
		    }

		    /* not invalid, so remove from cache */
		    
		    flags = (rp->rt_type == 4 ? RTF_GATEWAY : 0);

		    if (addRoute(rp->rt_dst, rp->rt_nextIR, rp->rt_ifix , flags) < 0) {
			perror("addRoute");
		    }

		    delCacheRTE( rp->rt_type );
		}
	    }
	    break;


	case IPROUTEPROTO:

	default:
                printf("err default\n");
        	return SNMP_ERR_NOCREATION;


    }


    return SNMP_ERR_NOERROR;
}




