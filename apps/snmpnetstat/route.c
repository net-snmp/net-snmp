/*****************************************************************
	Copyright 1989, 1991, 1992 by Carnegie Mellon University

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
 * Copyright (c) 1983,1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifdef SVR4
#include <string.h>
#else
#include <strings.h>
#endif

#include <stdio.h>
#include <ctype.h>

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#define	LOOPBACKNET 127

#include <netdb.h>
#include "main.h"
#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"

extern	int nflag;
extern	char *routename(), *netname(), *plural();
extern	char *malloc();
extern	struct snmp_session *Session;
extern	struct variable_list *getvarbyname();
extern	int print_errors;


struct route_entry {
    oid	    instance[4];
    struct in_addr  destination;
    int	    set_destination;
    struct in_addr  gateway;
    int	    set_gateway;
    int	    interface;
    int	    set_interface;
    int	    type;
    int	    set_type;
    int	    proto;
    int	    set_proto;
    char    ifname[64];
    int	    set_name;
};



#define RTDEST	    1
#define RTIFINDEX   2
#define RTNEXTHOP   7
#define RTTYPE	    8
#define RTPROTO	    9
static oid oid_rttable[] = {1, 3, 6, 1, 2, 1, 4, 21, 1};
static oid oid_rtdest[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 1};
static oid oid_rtifindex[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 2};
static oid oid_rtnexthop[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 7};
static oid oid_rttype[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 8};
static oid oid_rtproto[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 9};
static oid oid_ifdescr[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2};
static oid oid_ipnoroutes[] = {1, 3, 6, 1, 2, 1, 4, 12, 0};


/*
 * Print routing tables.
 */
routepr()
{
	struct route_entry route, *rp = &route;
	struct snmp_pdu *request, *response;
	struct variable_list *vp;
	char name[16], *flags;
	oid *instance, type;
	int toloopback, status;
	char ch;

	printf("Routing tables\n");
	printf("%-16.16s %-18.18s %-6.6s  %s\n",
		"Destination", "Gateway",
		"Flags", "Interface");


	request = snmp_pdu_create(GETNEXT_REQ_MSG);

	snmp_add_null_var(request, oid_rtdest, sizeof(oid_rtdest)/sizeof(oid));
	snmp_add_null_var(request, oid_rtifindex, sizeof(oid_rtifindex)/sizeof(oid));
	snmp_add_null_var(request, oid_rtnexthop, sizeof(oid_rtnexthop)/sizeof(oid));
	snmp_add_null_var(request, oid_rttype, sizeof(oid_rttype)/sizeof(oid));
	snmp_add_null_var(request, oid_rtproto, sizeof(oid_rtproto)/sizeof(oid));

	while(request){
	    status = snmp_synch_response(Session, request, &response);
	    if (status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR){
		fprintf(stderr, "SNMP request failed\n");
		break;
	    }
	    instance = NULL;
	    request = NULL;
	    rp->set_destination = 0;
	    rp->set_interface = 0;
	    rp->set_gateway = 0;
	    rp->set_type = 0;
	    rp->set_proto = 0;
	    for(vp = response->variables; vp; vp = vp->next_variable){
		if (vp->name_length != 14 ||
#ifdef SVR4
		    memcmp((char *)vp->name, (char *)oid_rttable, sizeof(oid_rttable))){
#else
		    bcmp((char *)vp->name, (char *)oid_rttable, sizeof(oid_rttable))){
#endif
		    continue;	/* if it isn't in this subtree, just continue */
		}

		if (instance != NULL){
		    oid *ip, *op;
		    int count;

		    ip = instance;
		    op = vp->name + 10;
		    for(count = 0; count < 4; count++){
			if (*ip++ != *op++)
			    break;
		    }
		    if (count < 4)
			continue;	/* not the right instance, ignore */
		} else {
		    instance = vp->name + 10;
		}
		/*
		 * At this point, this variable is known to be in the routing table
		 * subtree, and is of the right instance for this transaction.
		 */

		if (request == NULL)
		    request = snmp_pdu_create(GETNEXT_REQ_MSG);
		snmp_add_null_var(request, vp->name, vp->name_length);

		type = vp->name[9];
		switch ((char)type){
		    case RTDEST:
#ifdef SVR4
			memmove((char *)&rp->destination, (char *)vp->val.string, sizeof(u_long));
#else
			bcopy((char *)vp->val.string, (char *)&rp->destination, sizeof(u_long));
#endif
			rp->set_destination = 1;
			break;
		    case RTIFINDEX:
			rp->interface = *vp->val.integer;
			rp->set_interface = 1;
			break;
		    case RTNEXTHOP:
#ifdef SVR4
			memmove((char *)&rp->gateway, (char *)vp->val.string, sizeof(u_long));
#else
			bcopy((char *)vp->val.string, (char *)&rp->gateway, sizeof(u_long));
#endif
			rp->set_gateway = 1;
			break;
		    case RTTYPE:
			rp->type = *vp->val.integer;
			rp->set_type = 1;
			break;
		    case RTPROTO:
			rp->proto = *vp->val.integer;
			rp->set_proto = 1;
			break;
		}
	    }
	    if (!(rp->set_destination && rp->set_gateway
		&& rp->set_type && rp->set_interface)){
		    if (request)
			snmp_free_pdu(request);
		    request = 0;
		    continue;
	    }
	    toloopback = *(char *)&rp->gateway == LOOPBACKNET;
	    printf("%-16.16s ",
		(rp->destination.s_addr == 0) ? "default" :
		(toloopback) ?
		routename(rp->destination) : netname(rp->destination, 0L));
	    printf("%-18.18s ", routename(rp->gateway));
	    flags = name;
	    *flags++ = 'U'; /* route is in use */
	    /* this !toloopback shouldnt be necessary */
	    if (!toloopback && rp->type == MIB_IPROUTETYPE_REMOTE)
		*flags++ = 'G';
	    if (toloopback)
		*flags++ = 'H';
	    if (rp->proto == MIB_IPROUTEPROTO_ICMP)
		*flags++ = 'D';	/* redirect */
	    *flags = '\0';
	    printf("%-6.6s ", name);
	    get_ifname(rp->ifname, rp->interface);
	    ch = rp->ifname[strlen(rp->ifname) - 1];
	    ch = '5';   /* force the if statement */
	    if (isdigit(ch))
		printf(" %.32s\n", rp->ifname);
	    else
		printf(" %.32s%d\n", rp->ifname, rp->interface);

	}
}

struct iflist {
    int	index;
    char name[64];
    struct iflist *next;
} *Iflist = NULL;

get_ifname(name, index)
    char *name;
    int index;
{
    struct snmp_pdu *pdu, *response;
    struct variable_list *vp;
    struct iflist *ip;
    oid varname[32];
    int status;

    for(ip = Iflist; ip; ip = ip->next){
	if (ip->index == index)
	    break;
    }
    if (ip){
	strcpy(name, ip->name);
	return;
    }
    ip = (struct iflist *)malloc(sizeof(struct iflist));
    ip->next = Iflist;
    Iflist = ip;
    ip->index = index;
    pdu = snmp_pdu_create(GET_REQ_MSG);
#ifdef SVR4
    memmove((char *)varname, (char *)oid_ifdescr, sizeof(oid_ifdescr));
#else
    bcopy((char *)oid_ifdescr, (char *)varname, sizeof(oid_ifdescr));
#endif
    varname[10] = (oid)index;
    snmp_add_null_var(pdu, varname, sizeof(oid_ifdescr)/sizeof(oid) + 1);
    status = snmp_synch_response(Session, pdu, &response);
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR){
	vp = response->variables;
#ifdef SVR4
	memmove(ip->name, (char *)vp->val.string, vp->val_len);
#else
	bcopy((char *)vp->val.string, ip->name, vp->val_len);
#endif
	ip->name[vp->val_len] = '\0';
    } else {
	sprintf(ip->name, "if%d", index);
    }    
    strcpy(name, ip->name);
}

char *
routename(in)
	struct in_addr in;
{
	register char *cp;
	static char line[MAXHOSTNAMELEN + 1];
	struct hostent *hp;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;

	if (first) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
#ifdef SVR4
		    (cp = strchr(domain, '.')))
#else
		    (cp = index(domain, '.')))
#endif
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}
	cp = 0;
	if (!nflag) {
		hp = gethostbyaddr((char *)&in, sizeof (struct in_addr),
			AF_INET);
		if (hp) {
#ifdef SVR4
			if ((cp = strchr(hp->h_name, '.')) &&
#else
			if ((cp = index(hp->h_name, '.')) &&
#endif
			    !strcmp(cp + 1, domain))
				*cp = 0;
			cp = hp->h_name;
		}
	}
	if (cp)
		strncpy(line, cp, sizeof(line) - 1);
	else {
#define C(x)	((x) & 0xff)
		in.s_addr = ntohl(in.s_addr);
		sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),
			C(in.s_addr >> 16), C(in.s_addr >> 8), C(in.s_addr));
	}
	return (line);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
char *
netname(in, mask)
	struct in_addr in;
	u_long mask;
{
	char *cp = 0;
	static char line[MAXHOSTNAMELEN + 1];
	struct netent *np = 0;
	u_long net;
	register i;
	int subnetshift;

	i = ntohl(in.s_addr);
	if (!nflag && i) {
		if (mask == 0) {
			if (IN_CLASSA(i)) {
				mask = IN_CLASSA_NET;
				subnetshift = 8;
			} else if (IN_CLASSB(i)) {
				mask = IN_CLASSB_NET;
				subnetshift = 8;
			} else {
				mask = IN_CLASSC_NET;
				subnetshift = 4;
			}
			/*
			 * If there are more bits than the standard mask
			 * would suggest, subnets must be in use.
			 * Guess at the subnet mask, assuming reasonable
			 * width subnet fields.
			 */
			while (i &~ mask)
				mask = (long)mask >> subnetshift;
		}
		net = i & mask;
		while ((mask & 1) == 0)
			mask >>= 1, net >>= 1;
		np = getnetbyaddr(net, AF_INET);
		if (np)
			cp = np->n_name;
	}	
	if (cp)
		strncpy(line, cp, sizeof(line) - 1);
	else if ((i & 0xffffff) == 0)
		sprintf(line, "%u", C(i >> 24));
	else if ((i & 0xffff) == 0)
		sprintf(line, "%u.%u", C(i >> 24) , C(i >> 16));
	else if ((i & 0xff) == 0)
		sprintf(line, "%u.%u.%u", C(i >> 24), C(i >> 16), C(i >> 8));
	else
		sprintf(line, "%u.%u.%u.%u", C(i >> 24),
			C(i >> 16), C(i >> 8), C(i));
	return (line);
}

/*
 * Print routing statistics
 */
rt_stats()
{
	struct variable_list *var;

	printf("routing:\n");
	var = getvarbyname(Session, oid_ipnoroutes, sizeof(oid_ipnoroutes) / sizeof(oid));
	if (var){
	    printf("\t%u destination%s found unreachable\n",
		*var->val.integer, plural((int)*var->val.integer));
	} else {
	    printf("\tCouldn't get ipOutNoRoutes variable\n");
	}
}

/*
 * Request a variable with a GET REQUEST message on the given
 * session.  The session must have been opened as a synchronous
 * session (synch_setup_session()).  If the variable is found, a
 * pointer to a struct variable_list object will be returned.
 * Otherwise, NULL is returned.  The caller must free the returned
 * variable_list object when done with it.
 */
struct variable_list *
getvarbyname(sp, name, len)
    struct snmp_session *sp;
    oid	*name;
    int len;
{
    struct snmp_pdu *request, *response;
    struct variable_list *var = NULL, *vp;
    int status;

    request = snmp_pdu_create(GET_REQ_MSG);

    snmp_add_null_var(request, name, len);

    status = snmp_synch_response(sp, request, &response);

    if (status == STAT_SUCCESS){
	if (response->errstat == SNMP_ERR_NOERROR){
	    for(var = response->variables; var; var = var->next_variable){
#ifdef SVR4
		if (var->name_length == len && !memcmp(name, var->name, len * sizeof(oid)))
#else
		if (var->name_length == len && !bcmp(name, var->name, len * sizeof(oid)))
#endif
		    break;	/* found our match */
	    }
	    if (var != NULL){
		/*
		 * Now unlink this var from pdu chain so it doesn't get freed.
		 * The caller will free the var.
		 */
		if (response->variables == var){
		    response->variables = var->next_variable;
		} else {
		    for(vp = response->variables; vp; vp = vp->next_variable){
			if (vp->next_variable == var){
			    vp->next_variable = var->next_variable;
			    break;
			}
		    }
		}
	    }
	}
    }
    if (response)
	snmp_free_pdu(response);
    return var;
}
