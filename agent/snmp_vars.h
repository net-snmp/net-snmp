/*
 * Definitions for SNMP (RFC 1067) agent variable finder.
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#include "mibgroup/system.h"
#include "mibgroup/interfaces.h"
#include "mibgroup/ip.h"
#include "mibgroup/icmp.h"
#include "mibgroup/tcp.h"
#include "mibgroup/udp.h"
#include "mibgroup/snmp.h"

int KNLookup();

extern long long_return;
extern u_char return_buf[];

extern oid nullOid[];
extern int nullOidLen;

#define INST	0xFFFFFFFF	/* used to fill out the instance field of the variables table */

struct variable {
    u_char	    magic;	    /* passed to function as a hint */
    char	    type;	    /* type of variable */
/* See important comment in snmp_vars.c relating to acl */
    u_short	    acl;	    /* access control list for variable */
    u_char	    *(*findVar)();  /* function that finds variable */
    u_char	    namelen;	    /* length of above */
    oid		    name[32];	    /* object identifier of variable */
};
