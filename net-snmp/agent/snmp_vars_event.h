/*
 * Definitions for SNMP (RFC 1067) agent variable finder.
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/


extern long long_return;
extern u_char return_buf[];

#define INST	0xFFFFFFFF	/* used to fill out the instance field of the variables table */

/*
 * These are magic numbers for each variable.
 */

#define EVENTCLASS		    0
#define EVENTINSTANCE		    1
#define EVENTALARMTYPE		    2
#define EVENTTIME		    3
#define EVENTPROBCAUSE		    4
#define EVENTSPECIFICPROBLEM	    5
#define EVENTSEVERITY		    6
#define EVENTBACKUPSTATUS	    7
#define EVENTBACKUPINSTANCE	    8
#define EVENTTREND		    9
#define EVENTTHRESHOLD		    10
#define EVENTTHRESHOLDLEVEL	    11
#define EVENTTHRESHOLDOBSVALUE	    12
#define EVENTID			    13
#define EVENTCORRELATIONS	    14
#define EVENTOPERSTATE		    16
#define EVENTADMINSTATE		    17
#define EVENTMONATTRIBUTES	    18
#define EVENTREPAIRACTION	    19
#define EVENTDATA		    20
#define EVENTTEXT		    21
#define EVENTCREDIBILITY	    22
#define EVENTINDEX		    23
#define EVENTSTATUS		    24


struct variable {
    oid		    name[26];	    /* object identifier of variable */
    u_char	    namelen;	    /* length of above */
    char	    type;	    /* type of variable, INTEGER or (octet) STRING */
    u_char	    magic;	    /* passed to function as a hint */
    u_short	    acl;	    /* access control list for variable */
    u_char	    *(*findVar)();  /* function that finds variable */
};
