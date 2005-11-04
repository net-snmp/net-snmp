/*	$OpenBSD: netstat.h,v 1.31 2005/02/10 14:25:08 itojun Exp $	*/
/*	$NetBSD: netstat.h,v 1.6 1996/05/07 02:55:05 thorpej Exp $	*/

/*
 * Copyright (c) 1992, 1993
 *	Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)netstat.h	8.2 (Berkeley) 1/4/94
 */

#include <sys/cdefs.h>

/* What is the max length of a pointer printed with %p (including 0x)? */
#define PLEN	(LONG_BIT / 4 + 2)

int	Aflag;		/* show addresses of protocol control block */
int	aflag;		/* show all sockets (including servers) */
int	bflag;		/* show bytes instead of packets */
int	dflag;		/* show i/f dropped packets */
int	gflag;		/* show group (multicast) routing or stats */
int	iflag;		/* show interfaces */
int	lflag;		/* show routing table with use and ref */
int	mflag;		/* show memory stats */
int	nflag;		/* show addresses numerically */
int	pflag;		/* show given protocol */
int	qflag;		/* only display non-zero values for output */
int	rflag;		/* show routing tables (or routing stats) */
int	Sflag;		/* show source address in routing table */
int	sflag;		/* show protocol statistics */
int	tflag;		/* show i/f watchdog timers */
int	vflag;		/* be verbose */

int	interval;	/* repeat interval for i/f stats */

char	*interface;	/* desired i/f for stats, or NULL for all i/fs */

int	af;		/* address family */

extern	char *__progname; /* program name, from crt0.o */

char	*plural(int);
char	*plurales(int);

void	tcpprotopr(char *);
void	udpprotopr(char *);
void	tcp_stats( char *);
void	udp_stats( char *);
void	ip_stats(  char *);
void	icmp_stats(char *);

void	tcp6protopr(char *);
void	udp6protopr(char *);
void	ip6_stats(  char *);
void	icmp6_stats(char *);

void	pr_rthdr(int);
void	pr_encaphdr(void);
void	pr_family(int);
void	rt_stats(void);

char	*routename(in_addr_t);
char	*netname(in_addr_t, in_addr_t);
char	*ns_print(struct sockaddr *);
void	routepr();

void	intpr(int);

