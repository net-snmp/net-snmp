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

/* various OIDs that are needed throughout the agent */
extern oid alarmVariableOid[];
extern int alarmVariableOidLen;
extern oid alarmSampleTypeOid[];
extern int alarmSampleTypeOidLen;
extern oid alarmValueOid[];
extern int alarmValueOidLen;
extern oid alarmFallingThreshOid[];
extern int alarmFallingThreshOidLen;
extern oid alarmRisingThreshOid[];
extern int alarmRisingThreshOidLen;
extern oid eventIdOid[];
extern int eventIdOidLen;
extern oid sysUpTimeOid[];
extern int sysUpTimeOidLen;
extern oid trapRisingAlarmOid[];
extern int trapRisingAlarmOidLen;
extern oid trapFallingAlarmOid[];
extern int trapFallingAlarmOidLen;
extern oid trapObjUnavailAlarmOid[];
extern int trapObjUnavailAlarmOidLen;

extern long long_return;
extern u_char return_buf[];

#define INST	0xFFFFFFFF	/* used to fill out the instance field of the variables table */

/*
 * These are magic numbers for each variable.
 */

#define ALARMNEXTINDEX			1
#define ALARMTABINDEX			1
#define ALARMTABVARIABLE		2
#define ALARMTABINTERVAL		3
#define ALARMTABSAMPLETYPE		4
#define ALARMTABVALUE			5
#define ALARMTABSTARTUPALARM		6
#define ALARMTABRISINGTHRESH		7
#define ALARMTABFALLINGTHRESH		8
#define ALARMTABRISINGINDEX		9
#define ALARMTABFALLINGINDEX		10
#define ALARMTABUNAVAILABLEINDEX	11
#define ALARMTABSTATUS			12

#define EVENTNEXTINDEX			1
#define EVENTTABINDEX			1
#define EVENTTABID			2
#define EVENTTABDESCRIPTION		3
#define EVENTTABEVENTS			4
#define EVENTTABLASTTIMESENT		5
#define EVENTTABSTATUS			6
#define EVENTMININTERVAL		3
#define EVENTMAXRETRANS			4
#define EVENTNOTIFYTABINTERVAL		1
#define EVENTNOTIFYTABRETRANSMISSIONS	2
#define EVENTNOTIFYTABLIFETIME		3
#define EVENTNOTIFYTABSTATUS		4
