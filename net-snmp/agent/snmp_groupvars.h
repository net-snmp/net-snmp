/*
 * vars for the MIB-II snmp group
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be used in
advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT
SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/


extern int snmp_inpkts;			/*  1 - current */
extern int snmp_outpkts;		/*  2 - obsolete */
extern int snmp_inbadversions;		/*  3 - current */
extern int snmp_inbadcommunitynames;	/*  4 - current */
extern int snmp_inbadcommunityuses;	/*  5 - current */
extern int snmp_inasnparseerrors;	/*  6 - current */
extern int snmp_intoobigs;		/*  8 - obsolete */
extern int snmp_innosuchnames;		/*  9 - obsolete */
extern int snmp_inbadvalues;		/* 10 - obsolete */
extern int snmp_inreadonlys;		/* 11 - obsolete */
extern int snmp_ingenerrs;		/* 12 - obsolete */
extern int snmp_intotalreqvars;		/* 13 - obsolete */
extern int snmp_intotalsetvars;		/* 14 - obsolete */
extern int snmp_ingetrequests;		/* 15 - obsolete */
extern int snmp_ingetnexts;		/* 16 - obsolete */
extern int snmp_insetrequests;		/* 17 - obsolete */
extern int snmp_ingetresponses;		/* 18 - obsolete */
extern int snmp_intraps;		/* 19 - obsolete */
extern int snmp_outtoobigs;		/* 20 - obsolete */
extern int snmp_outnosuchnames;		/* 21 - obsolete */
extern int snmp_outbadvalues;		/* 22 - obsolete */
extern int snmp_outgenerrs;		/* 24 - obsolete */
extern int snmp_outgetrequests;		/* 25 - obsolete */
extern int snmp_outgetnexts;		/* 26 - obsolete */
extern int snmp_outsetrequests;		/* 27 - obsolete */
extern int snmp_outgetresponses;	/* 28 - obsolete */
extern int snmp_outtraps;		/* 29 - obsolete */
extern int snmp_enableauthentraps;	/* 30 - current */
extern int snmp_silentdrops;		/* 31 - current */
extern int snmp_proxydrops;		/* 32 - current */

extern char *snmp_trapsink;
extern char *snmp_trapcommunity;
