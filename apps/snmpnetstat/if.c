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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <signal.h>

#include "main.h"
#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"

#define	YES	1
#define	NO	0

extern	int nflag;
extern	char *interface;
extern	char *routename(), *netname();
extern	struct snmp_session *Session;
extern	struct variable_list *getvarbyname();

oid oid_ifname[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1};
static oid oid_ifinucastpkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 11, 1};
static oid oid_cfg_nnets[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};

#define IFNAME		2
#define IFMTU		4
#define IFOPERSTATUS	8
#define INUCASTPKTS	11
#define INNUCASTPKTS	12
#define INERRORS	14
#define OUTUCASTPKTS	17
#define OUTNUCASTPKTS	18
#define OUTERRORS	20

/*
 * Print a description of the network interfaces.
 */
intpr(interval)
	int interval;
{
	oid varname[MAX_NAME_LEN], *instance, *ifentry;
	int varname_len;
	int ifnum, cfg_nnets;
	struct variable_list *var;
	char name[128];
	int mtu;
	int ipkts, ierrs, opkts, oerrs, operstatus, collisions;

	if (interval) {
		sidewaysintpr((unsigned)interval);
		return;
	}
	printf("%-11.11s %-5.5s %-11.11s %-15.15s %8.8s %5.5s %8.8s %5.5s",
		"Name", "Mtu", "Network", "Address", "Ipkts", "Ierrs",
		"Opkts", "Oerrs");
	putchar('\n');
	var = getvarbyname(Session, oid_cfg_nnets, sizeof(oid_cfg_nnets) / sizeof(oid));
	if (var)
	    cfg_nnets = *var->val.integer;
	else
	    return;
#ifdef SVR4
	memmove((char *)varname, (char *)oid_ifname, sizeof(oid_ifname));
#else
	bcopy((char *)oid_ifname, (char *)varname, sizeof(oid_ifname));
#endif
	varname_len = sizeof(oid_ifname) / sizeof(oid);
	ifentry = varname + 9;
	instance = varname + 10;
	for (ifnum = 1; ifnum <= cfg_nnets; ifnum++) {
		register char *cp;

		*name = mtu = 0;
		ipkts = ierrs = opkts = oerrs = operstatus = collisions = 0;
		*instance = ifnum;
		*ifentry = IFNAME;
		var = getvarbyname(Session, varname, varname_len);
		if (var){
#ifdef SVR4
		    memmove(name, (char *)var->val.string, var->val_len);
#else
		    bcopy((char *)var->val.string, name, var->val_len);
#endif
		    name[var->val_len] = 0;
		}
		*ifentry = IFMTU;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    mtu = *var->val.integer;
		*ifentry = IFOPERSTATUS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    operstatus = *var->val.integer;
		*ifentry = INUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ipkts = *var->val.integer;
		*ifentry = INNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ipkts += *var->val.integer;
		*ifentry = INERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ierrs = *var->val.integer;
		*ifentry = OUTUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    opkts = *var->val.integer;
		*ifentry = OUTNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    opkts += *var->val.integer;
		*ifentry = OUTERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    oerrs = *var->val.integer;

		name[15] = '\0';
		if (interface != 0 &&
		    strcmp(name, interface) != 0)
			continue;
#ifdef SVR4
		cp = strchr(name, '\0');
#else
		cp = index(name, '\0');
#endif
		if (operstatus != MIB_IFSTATUS_UP)
			*cp++ = '*';
		*cp = '\0';
		printf("%-11.11s %-5d ", name, mtu);
		printf("%-11.11s ", "none");
		printf("%-15.15s ", "none");
		printf("%8d %5d %8d %5d %5d",
		    ipkts, ierrs,
		    opkts, oerrs, collisions);
		putchar('\n');
	}
}

#define	MAXIF	128
struct	iftot {
	char	ift_name[128];		/* interface name */
	int	ift_ip;			/* input packets */
	int	ift_ie;			/* input errors */
	int	ift_op;			/* output packets */
	int	ift_oe;			/* output errors */
	int	ift_co;			/* collisions */
} iftot[MAXIF];

u_char	signalled;			/* set if alarm goes off "early" */

/*
 * Print a running summary of interface statistics.
 * Repeat display every interval seconds, showing statistics
 * collected over that interval.  Assumes that interval is non-zero.
 * First line printed at top of screen is always cumulative.
 */
sidewaysintpr(interval)
	unsigned interval;
{
	register struct iftot *ip, *total;
	register int line;
	struct iftot *lastif, *sum, *interesting, ifnow, *now = &ifnow;
	int oldmask;
	void catchalarm();
	struct variable_list *var;
	oid varname[MAX_NAME_LEN], *instance, *ifentry;
	int varname_len;
	int ifnum, cfg_nnets;

	lastif = iftot;
	sum = iftot + MAXIF - 1;
	total = sum - 1;
	interesting = iftot;
	var = getvarbyname(Session, oid_cfg_nnets, sizeof(oid_cfg_nnets) / sizeof(oid));
	if (var)
	    cfg_nnets = *var->val.integer;
	else
	    return;
#ifdef SVR4
	memmove((char *)varname, (char *)oid_ifname, sizeof(oid_ifname));
#else
	bcopy((char *)oid_ifname, (char *)varname, sizeof(oid_ifname));
#endif
	varname_len = sizeof(oid_ifname) / sizeof(oid);
	for (ifnum = 1, ip = iftot; ifnum <= cfg_nnets; ifnum++) {
		char *cp;

		ip->ift_name[0] = '(';
		varname[10] = ifnum;
		var = getvarbyname(Session, varname, varname_len);
		if (var){
#ifdef SVR4
		    memmove(ip->ift_name + 1, (char *)var->val.string, var->val_len);
#else
		    bcopy((char *)var->val.string, ip->ift_name + 1, var->val_len);
#endif
		}
		if (interface && strcmp(ip->ift_name + 1, interface) == 0)
			interesting = ip;
		ip->ift_name[15] = '\0';
#ifdef SVR4
		cp = strchr(ip->ift_name, '\0');
#else
		cp = index(ip->ift_name, '\0');
#endif
		sprintf(cp, ")");
		ip++;
		if (ip >= iftot + MAXIF - 2)
			break;
	}
	lastif = ip;

	(void)signal(SIGALRM, catchalarm);
	signalled = NO;
	(void)alarm(interval);
banner:
	printf("    input   %-6.6s    output       ", interesting->ift_name);
	if (lastif - iftot > 0)
		printf("     input  (Total)    output");
	for (ip = iftot; ip < iftot + MAXIF; ip++) {
		ip->ift_ip = 0;
		ip->ift_ie = 0;
		ip->ift_op = 0;
		ip->ift_oe = 0;
		ip->ift_co = 0;
	}
	putchar('\n');
	printf("%8.8s %5.5s %8.8s %5.5s %5.5s ",
		"packets", "errs", "packets", "errs", "colls");
	if (lastif - iftot > 0)
		printf("%8.8s %5.5s %8.8s %5.5s %5.5s ",
			"packets", "errs", "packets", "errs", "colls");
	putchar('\n');
	fflush(stdout);
	line = 0;
loop:
	sum->ift_ip = 0;
	sum->ift_ie = 0;
	sum->ift_op = 0;
	sum->ift_oe = 0;
	sum->ift_co = 0;
#ifdef SVR4
	memmove((char *)varname, (char *)oid_ifinucastpkts, sizeof(oid_ifinucastpkts));
#else
	bcopy((char *)oid_ifinucastpkts, (char *)varname, sizeof(oid_ifinucastpkts));
#endif
	varname_len = sizeof(oid_ifinucastpkts) / sizeof(oid);
	ifentry = varname + 9;
	instance = varname + 10;
	for (ifnum = 1, ip = iftot; ifnum <= cfg_nnets && ip < lastif; ip++, ifnum++) {
#ifdef SVR4
		memset((char *)now, NULL, sizeof(*now));
#else
		bzero((char *)now, sizeof(*now));
#endif
		*instance = ifnum;
		*ifentry = INUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ip = *var->val.integer;
		*ifentry = INNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ip += *var->val.integer;
		*ifentry = INERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ie = *var->val.integer;
		*ifentry = OUTUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_op = *var->val.integer;
		*ifentry = OUTNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_op += *var->val.integer;
		*ifentry = OUTERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_oe = *var->val.integer;

		if (ip == interesting)
			printf("%8d %5d %8d %5d %5d ",
				now->ift_ip - ip->ift_ip,
				now->ift_ie - ip->ift_ie,
				now->ift_op - ip->ift_op,
				now->ift_oe - ip->ift_oe,
				now->ift_co - ip->ift_co);
		ip->ift_ip = now->ift_ip;
		ip->ift_ie = now->ift_ie;
		ip->ift_op = now->ift_op;
		ip->ift_oe = now->ift_oe;
		ip->ift_co = now->ift_co;
		sum->ift_ip += ip->ift_ip;
		sum->ift_ie += ip->ift_ie;
		sum->ift_op += ip->ift_op;
		sum->ift_oe += ip->ift_oe;
		sum->ift_co += ip->ift_co;
	}
	if (lastif - iftot > 0)
		printf("%8d %5d %8d %5d %5d ",
			sum->ift_ip - total->ift_ip,
			sum->ift_ie - total->ift_ie,
			sum->ift_op - total->ift_op,
			sum->ift_oe - total->ift_oe,
			sum->ift_co - total->ift_co);
	*total = *sum;
	putchar('\n');
	fflush(stdout);
	line++;
#ifdef SVR4
	sighold(SIGALRM);
	if (! signalled) {
		sigpause(0);
	}
	sigrelse(SIGALRM);
#else
	oldmask = sigblock(sigmask(SIGALRM));
	if (! signalled) {
		sigpause(0);
	}
	sigsetmask(oldmask);
#endif
	signalled = NO;
	(void)alarm(interval);
	if (line == 21)
		goto banner;
	goto loop;
	/*NOTREACHED*/
}

/*
 * Called if an interval expires before sidewaysintpr has completed a loop.
 * Sets a flag to not wait for the alarm.
 */
void
catchalarm()
{
	signalled = YES;
}
