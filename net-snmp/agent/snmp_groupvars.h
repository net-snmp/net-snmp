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


extern int snmp_inpkts;
extern int snmp_outpkts;
extern int snmp_inbadversions;
extern int snmp_inbadcommunitynames;
extern int snmp_inbadcommunityuses;
extern int snmp_inasnparseerrors;
extern int snmp_intoobigs;
extern int snmp_innosuchnames;
extern int snmp_inbadvalues;
extern int snmp_inreadonlys;
extern int snmp_ingenerrs;
extern int snmp_intotalreqvars;
extern int snmp_intotalsetvars;
extern int snmp_ingetrequests;
extern int snmp_ingetnexts;
extern int snmp_insetrequests;
extern int snmp_ingetresponses;
extern int snmp_intraps;
extern int snmp_outtoobigs;
extern int snmp_outnosuchnames;
extern int snmp_outbadvalues;
extern int snmp_outgenerrs;
extern int snmp_outgetrequests;
extern int snmp_outgetnexts;
extern int snmp_outsetrequests;
extern int snmp_outgetresponses;
extern int snmp_outtraps;
extern int snmp_enableauthentraps;

extern char *snmp_trapsink;
extern char *snmp_trapcommunity;
