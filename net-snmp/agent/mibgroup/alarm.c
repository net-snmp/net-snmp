/***********************************************************
	Copyright 1992 by Carnegie Mellon University

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

/* alarm.c: implement the alarm group of the RMON MIB */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#include <asn1.h>
#include <snmp_impl.h>
#include <snmp_api.h>
#include <snmp_client.h>
#include "party.h"
#include "context.h"
#include "snmp_vars.h"
#include "snmp.h"
#include "m2m.h"
#include "snmp_vars_m2m.h"
#include "event.h"
#include "alarm.h"
#include "system.h"
#include "snmpd.h"

static struct alarmEntry *alarmTab = NULL;
static long alarmNextIndex = 1;
static int write_alarmtab __P((int, u_char *, u_char, int, u_char *, oid *, int));

/* retrieve the given variable from the MIB.  Returns 0 on success,
** 1 if the request was asynchronously transmitted to another host,
** and another value on errors.
*/
static int
rmonGetValue(srcParty, srcPartyLen, dstParty, dstPartyLen,
	     context, contextLen, variable, variableLen, value, alarm)
    oid *srcParty, *dstParty, *context;
    int srcPartyLen, dstPartyLen, contextLen;
    oid *variable;
    int variableLen;                /* number of subids in variable */
    long *value;
    struct alarmEntry *alarm;
{
    oid bigVar[MAX_OID_LEN];
    int bigVarLen;
    u_char type;
    int len;
    u_short acl;
    int (*writeFunc) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    u_char *var;
    struct packet_info pinfo, *pi = &pinfo;
    int noSuchObject;
    struct partyEntry *srcp, *dstp;
    struct contextEntry *cxp;
    struct snmp_session session;
    struct snmp_pdu *pdu;
    struct variable_list *varList;
    u_long addr;
    struct get_req_state *state;
    extern int snmp_input();
    
    /* whether it's local or non-local, I have to know about the
       parties and context */
    if (((srcp = party_getEntry(srcParty, srcPartyLen)) == NULL)
	|| ((dstp = party_getEntry(dstParty, dstPartyLen)) == NULL)
	|| ((cxp = context_getEntry(context, contextLen)) == NULL))
	return 2;
    
    addr = get_myaddr();
    if (bcmp(dstp->partyTAddress, &addr, 4)) {
	/* this is a different IP address, so it must be non-local */
	if (alarm->ss == NULL) {
	    state = (struct get_req_state *)malloc(sizeof(struct get_req_state));
	    state->type = ALARM_GET_REQ;
	    state->info = (void *)alarm;
	    alarm->magic = state;
	    bzero((char *)&session, sizeof(struct snmp_session));
	    session.peername = SNMP_DEFAULT_PEERNAME;
	    session.version = SNMP_VERSION_2p;
	    session.srcParty = srcParty;
	    session.srcPartyLen = srcPartyLen;
	    session.dstParty = dstParty;
	    session.dstPartyLen = dstPartyLen;
	    session.context = context;
	    session.contextLen = contextLen;
	    session.retries = 4;
	    session.timeout = 500000L;	/* one half second */
	    session.callback = snmp_input;
	    session.callback_magic = (void *)state;
	    alarm->ss = snmp_open(&session);
	    if (!alarm->ss) {
		ERROR_MSG("");
		return 3;
	    }
	}
	
	pdu = snmp_pdu_create(GET_REQ_MSG);
	bcopy(dstp->partyTAddress, (char *)&pdu->address.sin_addr.s_addr, 4);
	bcopy(dstp->partyTAddress + 4, &pdu->address.sin_port, 2);
	pdu->address.sin_family = AF_INET;
	varList = (struct variable_list *)malloc(sizeof(struct variable_list));
	
	varList->name = (oid *)malloc(variableLen * sizeof(oid));
	bcopy(variable, varList->name, variableLen * sizeof(oid));
	varList->name_length = variableLen;
	varList->type = ASN_NULL;
	varList->val_len = 0;
	varList->val.integer = NULL;
	varList->next_variable = NULL;
	
	pdu->variables = varList;
	alarm->reqid = snmp_send(alarm->ss, pdu);
	return 1;	/* this means the request has been sent */
    }
    
    if (!has_access(GET_REQ_MSG, srcp->partyIndex, dstp->partyIndex,
		    cxp->contextIndex))
	return 5;
    if (!has_access(GET_RSP_MSG, dstp->partyIndex, srcp->partyIndex,
		    cxp->contextIndex))
	return 4;
    
    bcopy(srcParty, pi->srcParty, srcPartyLen * sizeof(oid));
    pi->srcPartyLength = srcPartyLen;
    bcopy(dstParty, pi->dstParty, dstPartyLen * sizeof(oid));
    pi->dstPartyLength = dstPartyLen;
    bcopy(context, pi->context, contextLen * sizeof(oid));
    pi->contextLength = contextLen;
    pi->srcp = srcp;
    pi->dstp = dstp;
    pi->cxp = cxp;
    
    pi->version = SNMP_VERSION_2p;
    pi->pdutype = GET_REQ_MSG;
    /* rest of pi is not needed */
    
    bcopy((char *)variable, (char *)bigVar, variableLen * sizeof(oid));
    bigVarLen = variableLen;
    
    var = getStatPtr(bigVar, &bigVarLen, &type, &len, &acl, 1, &writeFunc, pi,
		     &noSuchObject);
    if (var == NULL) {
	return 6;
    }
    
    if ((type != INTEGER) && (type != COUNTER) &&
	(type != TIMETICKS) && (type != GAUGE) &&
	(type != COUNTER64)) {
	return 7;
    }
    
    *value = *(int *)var;
    return 0;
}

/* add the time values t1 and t2, and store the sum in result.  This
** routine accounts for tv_usec overflow.
*/
static void
cmutimeradd(rresult, tt1, tt2)
	struct timeval *rresult, *tt1, *tt2;
{
	rresult->tv_usec = tt1->tv_usec + tt2->tv_usec;
	rresult->tv_sec = tt1->tv_sec + tt2->tv_sec;
	while (rresult->tv_usec > 1000000L) {
		(rresult->tv_usec) -= 1000000L;
		(rresult->tv_sec)++;
	}
}

/* insert the given row into the alarm table, ordered by index */
static void
alarmInsertRow(alarm)
    struct alarmEntry *alarm;
{
    struct alarmEntry *current;
    struct alarmEntry *prev;

    for (current = alarmTab, prev = NULL; current; current = current->next) {
	if (current->index > alarm->index) {
	    break;
	}
	prev = current;
    }

    /* put the new entry before "current" */
    alarm->next = current;
    if (prev) {
	prev->next = alarm;
    }
    else {
	/* this is first on the list */
	alarmTab = alarm;
    }
}

/* free the shadow space that was allocated to this row */
static void
alarmFreeShadow(alarm)
	struct alarmEntry *alarm;
{
    if (alarm->shadow == NULL) {
	return;
    }

    free((char *)alarm->shadow);
    alarm->shadow = NULL;
}

/* delete the given row from the alarm table, and free the memory
** associated with it.
*/
static void
alarmDeleteRow(alarm)
	struct alarmEntry *alarm;
{
    struct alarmEntry *temp;
    struct alarmEntry *prev = NULL;
    
    for (temp = alarmTab; temp; temp = temp->next) {
	if (temp == alarm) {
	    /* this is the one to remove */
	    if (prev) {
		prev->next = temp->next;
	    }
	    else {
		/* this is the first on the list */
		alarmTab = temp->next;
	    }
	    break;
	}
	prev = temp;
    }
    
    /* KLF debugging */
    if (temp == NULL) {
	printf("alarmDeleteRow: didn't find row (%d) in alarmTab\n",
	       alarm->index);
    }
    
    if (alarm->ss) {
	snmp_close(alarm->ss);
	free((char *)alarm->magic);
    }
    alarmFreeShadow(alarm);
    /* KLF alarmFreeEntries(alarm); */
    free((char *)alarm);
}

/* create a shadow structure for the given row, and copy the world-visible
** data into the shadow structure.  Returns 1 on success, 0 otherwise.
*/
static int
alarmShadowRow(alarm)
struct alarmEntry *alarm;
{
    int i = 0;
    
    if (alarm->shadow != NULL) {
	/* it's already been created */
	return 1;
    }
    
    alarm->shadow = (struct alarmEntry *)malloc(sizeof(struct alarmEntry));
    while ((alarm->shadow == NULL) && (i++ < 5)) {
	eventFreeSpace();
	alarm->shadow = (struct alarmEntry *)malloc(sizeof(struct alarmEntry));
    }
    if (alarm->shadow == NULL) {
	/* no more memory */
	return 0;
    }
    
    bcopy((char *)alarm, (char *)alarm->shadow, sizeof(struct alarmEntry));
    
    return 1;
}

/* return a pointer to the given row in the alarmTab */
static struct alarmEntry *
alarmGetRow(context, contextLen, index)
    oid *context;
    int contextLen;
    int index;
{
	struct alarmEntry *alarm;

	for (alarm = alarmTab; alarm; alarm = alarm->next) {
		if (alarm->index == index
		    && alarm->contextLength == contextLen
		    && !bcmp(alarm->contextID, context,
			     contextLen * sizeof(oid))) {
			return alarm;
		}
	}

	return NULL;
}

/* return a pointer to the given row in the alarmTab */
static struct alarmEntry *
alarmGetRowByIndex(index)
    int index;
{
    struct alarmEntry *alarm;

    for (alarm = alarmTab; alarm; alarm = alarm->next) {
	if (alarm->index == index) {
	    return alarm;
	}
    }

    return NULL;
}

/* create a new row for the alarm table, with the given index.
** Create a shadow for the row.  Put default values into the shadow.
** Return a pointer to the new row.  This routine does not check that
** the index has not already been used, and does not make the row
** visible to a management station that is doing a walk of the table.
** It makes sure the index is in the valid range.
*/
static struct alarmEntry *
alarmNewRow(context, contextLen, index)
    oid *context;
    int contextLen;
    int index;
{
    struct alarmEntry *alarm;
    int i = 0;
    
    if ((index < 1) || (index > 65535)) {
	return NULL;
    }
    
    alarm = (struct alarmEntry *)malloc(sizeof(struct alarmEntry));
    while ((alarm == NULL) && (i++ < 5)) {
	eventFreeSpace();
	alarm = (struct alarmEntry *)malloc(sizeof(struct alarmEntry));
    }
    if (alarm == NULL) {
	/* no more room */
	return NULL;
    }
    
    bzero((char *)alarm, sizeof(struct alarmEntry));
    
    alarm->index = index;
    bcopy(context, alarm->contextID, contextLen * sizeof(oid));
    alarm->contextLength = contextLen;
    alarm->status = ENTRY_DESTROY;
    
    alarm->bitmask = ALARMTABINDEXMASK;
    
    alarmInsertRow(alarm);
    
    /* this will copy the index, status, and bitmask into the shadow area */
    if (alarmShadowRow(alarm) == 0) {
	/* weren't able to allocate space for the shadow area, so
	 ** remove the entry from the list.
	 */
	alarmDeleteRow(alarm);
	return NULL;
    }
    
    /* add default entries to the shadow copy.  The variables that
     ** aren't defaulted are interval, variable, value, startupAlarm,
     ** risingThresh, fallingThresh, risingEventIndex, + fallingEventIndex,
     */
    alarm->shadow->status = ENTRY_NOTINSERVICE;
    alarm->shadow->sampleType = ALARM_DELTA_VALUE;
    
    alarm->shadow->bitmask |= (ALARMTABSAMPLETYPEMASK | ALARMTABSTATUSMASK);
    
    alarmNextIndex = random() & 0x0000ffff;
    while (alarmGetRowByIndex(alarmNextIndex) != NULL) {
	alarmNextIndex = random() & 0x0000ffff;
    }
    
    return alarm;
}

/* copy the data in the given row from the shadow copy into the world-
** visible copy, and get rid of the shadow copy.  If no shadow copy
** exists, just return.  If we are setting the row to invalid, delete it.
*/
static void
alarmCommitRow(alarm)
    struct alarmEntry *alarm;
{
    struct alarmEntry *nextPtr;
    u_long destAddr;
    
    if (alarm->shadow == NULL) {
	return;
    }
    
    /* if this entry is being set to invalid, just delete it */
    if (alarm->shadow->status == ENTRY_DESTROY) {
	alarmDeleteRow(alarm);
	return;
    }
    
    /* if the row will no longer be valid, invalidate the value field */
    if (alarm->status == ENTRY_ACTIVE &&
	alarm->shadow->status != ENTRY_ACTIVE) {
	alarm->shadow->bitmask &= (~ALARMTABVALUEMASK
				   & ~ALARMTABREALVALUEMASK);
	alarm->shadow->value = 0;
	}
    
    /* set up the intervalAdd variable */
    if (alarm->shadow->sampleType == ALARM_ABSOLUTE_VALUE) {
	alarm->shadow->intervalAdd.tv_sec = alarm->shadow->interval;
    } else {
	/* this is a delta value */
	alarm->shadow->intervalAdd.tv_sec = alarm->shadow->interval / 2;
	if ((alarm->shadow->interval & 1) == 1) {
	    /* alarm->shadow->interval is odd; therefore, another half second
	     ** must be added to its update time
	     */
	    alarm->shadow->intervalAdd.tv_usec = 500000;
	}
    }
    
    nextPtr = alarm->next;
    bcopy((char *)alarm->shadow, (char *)alarm, sizeof(struct alarmEntry));
    
    if (alarm->next != nextPtr) {
	/* KLF debugging */
	printf("alarmCommitRow(%d): next pointer was different\n",
	       alarm->index);
	alarm->next = nextPtr;
    }
    
    ((u_char *)&destAddr)[0] = (u_char)alarm->contextID[9];
    ((u_char *)&destAddr)[1] = (u_char)alarm->contextID[10];
    ((u_char *)&destAddr)[2] = (u_char)alarm->contextID[11];
    ((u_char *)&destAddr)[3] = (u_char)alarm->contextID[12];

    alarm->srcPartyLength
	= alarm->dstPartyLength = alarm->contextLength= MAX_NAME_LEN;
    ms_party_init(destAddr, alarm->srcPartyID, &(alarm->srcPartyLength),
		  alarm->dstPartyID, &(alarm->dstPartyLength),
                    alarm->contextID, &(alarm->contextLength));
#if 0
    bcopy((char *)alarm->contextID, (char *)alarm->srcPartyID,
	  alarm->contextLength * sizeof(oid));
    bcopy((char *)alarm->contextID, (char *)alarm->dstPartyID,
	  alarm->contextLength * sizeof(oid));
    alarm->srcPartyLength = alarm->contextLength;
    alarm->dstPartyLength = alarm->contextLength;
    alarm->srcPartyID[8] = 3;
    alarm->dstPartyID[8] = 3;
    alarm->srcPartyID[13] = alarm->contextID[13] * 2;
    alarm->dstPartyID[13] = (alarm->contextID[13] * 2) - 1;
#endif

    alarmFreeShadow(alarm);
    
    /* note that alarmTimer() will be called within 1/2 second of this
     ** entry becoming valid, and will do the startup alarm processing
     ** then.  This is close enough to "when this entry is first set
     ** to valid" for me.
     */
}

/* compare the new value against the old one, and send a rising or
** falling alarm if necessary.
*/
static void
alarmProcessValue(alarm, oldValue, newValue)
	struct alarmEntry *alarm;
	long oldValue;
	long newValue;
{
    if ((alarm->bitmask & ALARMTABVALUEMASK) == 0) {
	/* this is the first sample */
	if ((newValue >= alarm->risingThresh) &&
	    ((alarm->startupAlarm == ALARM_STARTUP_RISING) ||
	     (alarm->startupAlarm == ALARM_STARTUP_RISING_OR_FALLING))) {
	    /* send rising alarm */
	    eventGenerate(alarm->risingEventIndex, EVENT_TYPE_STARTUP_RISING,
			  (void *)alarm);
	}
	else if ((newValue <= alarm->fallingThresh) &&
		 ((alarm->startupAlarm == ALARM_STARTUP_FALLING) ||
		  (alarm->startupAlarm == ALARM_STARTUP_RISING_OR_FALLING))) {
	    /* send falling alarm */
	    eventGenerate(alarm->fallingEventIndex, EVENT_TYPE_STARTUP_FALLING,
			  (void *)alarm);
	}
    }
    else if ((newValue >= alarm->risingThresh) &&
	     (oldValue < alarm->risingThresh) && !alarm->cantSendRising) {
	/* send rising alarm */
	eventGenerate(alarm->risingEventIndex, EVENT_TYPE_RISING,
		      (void *)alarm);
	alarm->cantSendFalling = FALSE;
	alarm->cantSendRising = TRUE;
    }
    else if ((newValue <= alarm->fallingThresh) &&
	     (oldValue > alarm->fallingThresh) && !alarm->cantSendFalling) {
	/* send falling alarm */
	eventGenerate(alarm->fallingEventIndex, EVENT_TYPE_FALLING,
		      (void *)alarm);
	alarm->cantSendRising = FALSE;
	alarm->cantSendFalling = TRUE;
    }
}

/* update a delta counter and send an alarm if necessary */
static void
alarmUpdateDelta(alarm, realValue)
    struct alarmEntry *alarm;
    long realValue;
{
    long oldValue;

    if ((alarm->bitmask & ALARMTABREALVALUEMASK) == 0) {
	/* lastRealValue hasn't been initialized, so do it */
	alarm->lastRealValue = realValue;
	alarm->bitmask |= ALARMTABREALVALUEMASK;
	alarm->lastDeltaValue = 0;
	return;
    }

    /* this is the normal case */
    oldValue = alarm->value;
    alarm->value = alarm->lastDeltaValue + (realValue - alarm->lastRealValue);

    alarmProcessValue(alarm, oldValue, alarm->value);

    alarm->bitmask |= ALARMTABVALUEMASK;
    alarm->lastDeltaValue = realValue - alarm->lastRealValue;
    alarm->lastRealValue = realValue;
}

/* update an absolute value counter and send an alarm if necessary */
static void
alarmUpdateAbs(alarm, value)
    struct alarmEntry *alarm;
    long value;
{
    long oldValue;

    oldValue = alarm->value;
    alarm->value = value;

    alarmProcessValue(alarm, oldValue, value);

    alarm->bitmask |= ALARMTABVALUEMASK;
}

/* search the alarm table for entries whose interval has expired.  Record
** the value for the variable and take action if necessary.
*/
Export void
alarmTimer(now)
	struct timeval *now;
{
    struct alarmEntry *alarm;
    struct alarmEntry *next;
    int error;
    long value;
    
    for (alarm = alarmTab; alarm; alarm = next) {
	next = alarm->next;
	if (alarm->status == ENTRY_DESTROY) {
	    alarmDeleteRow(alarm);
	    continue;
	}

	if (alarm->status != ENTRY_ACTIVE) {
	    /* pretend these don't exist */
	    continue;
	}
	
	if (timercmp(now, &alarm->update, <)) {
	    continue;
	}
	
	error = rmonGetValue(alarm->srcPartyID, alarm->srcPartyLength,
			     alarm->dstPartyID, alarm->dstPartyLength,
			     alarm->contextID, alarm->contextLength,
			     alarm->variable, alarm->variableLen,
			     &value, alarm);
	if (error == 1) {
	    /* the request was sent out asynchronously.  snmp_input() will
	    ** call one of the alarmUpdate routines.
	    */
	    cmutimeradd(&alarm->update, now, &alarm->intervalAdd);
	    continue;
	}
	
	if (error) {
	    /* send objectUnavailable alarm event */
	    eventGenerate(alarm->unavailableEventIndex,
			  EVENT_TYPE_UNAVAILABLE, alarm);
	    alarmDeleteRow(alarm);
	    continue;
	}

	if (alarm->sampleType == ALARM_DELTA_VALUE) {
	    alarmUpdateDelta(alarm, value);
	}
	else {
	    alarmUpdateAbs(alarm, value);
	}

	cmutimeradd(&alarm->update, now, &alarm->intervalAdd);
    }
}

/* process the response to a Get request */
Export int
alarmGetResponse(pdu, state, op, session)
    struct snmp_pdu *pdu;
    struct get_req_state *state;
    int op;
    struct snmp_session *session;
{
    struct alarmEntry *alarm = (struct alarmEntry *)state->info;
    struct variable_list *vp;

    if ((alarm->ss != session) || (alarm->reqid != pdu->reqid)) {
	return 1;
    }
    
    if (op == TIMED_OUT) {
	/* got an error, so send an inform and delete
	** the alarm entry
	*/
	eventGenerate(alarm->unavailableEventIndex,
		      EVENT_TYPE_UNAVAILABLE, alarm);
	alarm->status = ENTRY_DESTROY;
	return 1;
    }	

    if (pdu->errstat == SNMP_ERR_NOERROR) {
	/* send the variable to an update routine */
	vp = pdu->variables;
	if (vp && ((vp->type == INTEGER) || (vp->type == COUNTER) ||
		   (vp->type == TIMETICKS) || (vp->type == GAUGE) ||
		   (vp->type == COUNTER64))) {
	    if (alarm->sampleType == ALARM_DELTA_VALUE) {
		alarmUpdateDelta(alarm, *vp->val.integer);
	    }
	    else {
		alarmUpdateAbs(alarm, *vp->val.integer);
	    }
	}
    }
    else {
	/* got an error, so send an inform and delete
	** the alarm entry
	*/
	eventGenerate(alarm->unavailableEventIndex,
		      EVENT_TYPE_UNAVAILABLE, alarm);
	alarm->status = ENTRY_DESTROY;
    }
    return 1;
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and alarm is non-NULL, the instance (row) exists, but not
 * this variable.
 * If statP is NULL and alarm is NULL, then neither this instance nor the
 * variable exists.
 */
/* return TRUE on success and FALSE on failure */
static int
write_alarmtab(action, var_val, var_val_type, var_val_len, statP,
		name, name_len)
    int action;			/* IN - RESERVE1, RESERVE2, COMMIT, or FREE */
    u_char *var_val;	/* IN - input or output buffer space */
    u_char var_val_type;	/* IN - type of input buffer */
    int var_val_len;	/* IN - input and output buffer len */
    u_char *statP;		/* IN - pointer to local statistic */
    oid *name;			/* IN - pointer to name requested */
    int name_len;		/* IN - number of sub-ids in the name */
{
    register int index;
    register int variable;
    register struct alarmEntry *alarm;
    int size;
    long int_value;
    oid oid_value[MAX_OID_LEN];
    u_char string_value[MAX_OWNER_STR_LEN];
    int buffersize = 1000;
    int contextlen;
    oid *context;
    
    /* .1.3.6.1.6.3.2.1.1.2.1.X.cxlen.context.index */
    
    contextlen = name[12];
    if (name_len < (13 + contextlen))
	return SNMP_ERR_NOCREATION;
    context = name + 13;
    index = name[13 + contextlen];
    alarm = alarmGetRow(context, contextlen, index);
    
    switch (action) {
      case RESERVE1:
	if (alarm == NULL) {
	    alarm = alarmNewRow(context, contextlen, index);
	    if (alarm == NULL) {
		/* no memory for row */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	else {
	    /* we have a row, but some vars will change.  Remember
	     ** the current numbers.
	     */
	    if (alarmShadowRow(alarm) == 0) {
		/* not enough memory available */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	break;
      case RESERVE2:
	if (alarm == NULL) {
	    /* this should have been created in the RESERVE1 phase */
	    return SNMP_ERR_GENERR;
	}
	break;
      case COMMIT:
	if (alarm == NULL) {
	    return SNMP_ERR_GENERR;
	}
	alarmCommitRow(alarm);
	return SNMP_ERR_NOERROR;
      case FREE:
	if (alarm == NULL) {
	    return SNMP_ERR_GENERR;
	}
	if (alarm->status == ENTRY_DESTROY) {
	    /* this row did not exist before we began this RESERVE/FREE
	     ** cycle, so delete it now.
	     */
	    alarmDeleteRow(alarm);
	}
	else {
	    /* the row existed before, so just get rid of the shadow
	     ** copy.
	     */
	    alarmFreeShadow(alarm);
	}
	return SNMP_ERR_NOERROR;
    }
    
    variable = name[11];
    
    /* interval, variable, sampleType, startupAlarm, risingThresh,
     ** fallingThresh, risingEventIndex, fallingEventIndex,
     ** and status are the user-writable variables in this table.
     */
    switch (variable) {
      case ALARMTABVARIABLE:
	if (action == RESERVE1) {
	    /* make sure it's an oid */
	    if (var_val_type != ASN_OBJECT_ID) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    size = sizeof(oid_value) / sizeof(oid);
	    if (asn_parse_objid(var_val, &buffersize, &var_val_type,
				oid_value, &size) == NULL) {
		return SNMP_ERR_WRONGENCODING;
				}
#if 0
	    /* this assures that the variable exists and resolves
	     ** to an integer value
	     */
	    if (rmonGetValue(oid_value, size, (long *)&int_value) != 0) {
		return SNMP_ERR_INCONSISTENTVALUE;
	    }
#endif
	    /* There should also be a check here that the setter
	     ** can read all variables in the MIB.  Since all
	     ** communities have read access to all variables,
	     ** this test is punted.
	     */
	    bcopy((char *)oid_value, (char *)alarm->shadow->variable,
		  size * sizeof(oid));
	    alarm->shadow->variableLen = size;
	    alarm->shadow->bitmask |= ALARMTABVARIABLEMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABINTERVAL:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    alarm->shadow->interval = int_value;
	    alarm->shadow->bitmask |= ALARMTABINTERVALMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABSAMPLETYPE:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if ((int_value < ALARM_ABSOLUTE_VALUE) ||
		(int_value > ALARM_DELTA_VALUE)) {
		return SNMP_ERR_WRONGLENGTH;
		}
	    alarm->shadow->sampleType = int_value;
	    alarm->shadow->bitmask |= ALARMTABSAMPLETYPEMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABSTARTUPALARM:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if ((int_value < ALARM_STARTUP_RISING) ||
		(int_value > ALARM_STARTUP_RISING_OR_FALLING)) {
		return SNMP_ERR_WRONGVALUE;
		}
	    alarm->shadow->startupAlarm = int_value;
	    alarm->shadow->bitmask |= ALARMTABSTARTUPALARMMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABRISINGTHRESH:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    alarm->shadow->risingThresh = int_value;
	    alarm->shadow->bitmask |= ALARMTABRISINGTHRESHMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABFALLINGTHRESH:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    alarm->shadow->fallingThresh = int_value;
	    alarm->shadow->bitmask |= ALARMTABFALLINGTHRESHMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABRISINGINDEX:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if ((int_value < 0) || (int_value > 65535)) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    alarm->shadow->risingEventIndex = int_value;
	    alarm->shadow->bitmask |= ALARMTABRISINGINDEXMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABFALLINGINDEX:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if ((int_value < 0) || (int_value > 65535)) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    alarm->shadow->fallingEventIndex = int_value;
	    alarm->shadow->bitmask |= ALARMTABFALLINGINDEXMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABUNAVAILABLEINDEX:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if ((int_value < 0) || (int_value > 65535)) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    alarm->shadow->unavailableEventIndex = int_value;
	    alarm->shadow->bitmask |= ALARMTABUNAVAILABLEINDEXMASK;
	}
	else if (action == RESERVE2) {
	    /* not allowed to change this if the entry is valid */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->status == ENTRY_ACTIVE)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      case ALARMTABSTATUS:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGENCODING;
			      }
	    if (int_value < ENTRY_ACTIVE
		|| int_value > ENTRY_DESTROY
		|| int_value == ENTRY_NOTREADY
		|| int_value == ENTRY_CREATEANDGO) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    
	    if (int_value == ENTRY_CREATEANDWAIT) {
		if (alarm->status != ENTRY_DESTROY) {
		    /* this is an entry that already existed; not
		     ** allowed to set it to underCreation
		     */
		    return SNMP_ERR_INCONSISTENTVALUE;
		}
		int_value = ENTRY_NOTINSERVICE;
	    }
	    
	    alarm->shadow->status = int_value;
	    alarm->shadow->bitmask |= ALARMTABSTATUSMASK;
	}
	else if (action == RESERVE2) {
	    /* when the entry is first created, the value field is not
	     ** valid
	     */
	    if ((alarm->shadow->status == ENTRY_ACTIVE) &&
		(alarm->shadow->bitmask !=
		 (ALARMTABCOMPLETEMASK & ~ALARMTABVALUEMASK))) {
		return SNMP_ERR_INCONSISTENTVALUE;
		 }
	}
	break;
      default:
	return SNMP_ERR_GENERR;
    }
    
    return SNMP_ERR_NOERROR;
}

Export u_char *
var_alarmnextindex(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that
				 ** points here
				 */
    register oid *name;		/* IN/OUT - input name requested,
				 ** output name found
				 */
    register int *length;	/* IN/OUT - length of input and output oid's */
    int exact;		/* IN - TRUE if an exact match was requested. */
    int *var_len;   /* OUT - length of variable or 0 if function returned. */
    int	(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    int result;

    *write_method = NULL;
    result = compare(name, *length, vp->name, (int)vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;

    bcopy((char *)vp->name, (char *)name,
	  (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *var_len = sizeof(long);
    
    switch (vp->magic) {
      case ALARMNEXTINDEX:
	return (u_char *)&alarmNextIndex;
      default:
	ERROR_MSG("");
    }

    return NULL;
}
    
/* respond to requests for variables in the alarm table */
Export u_char *
var_alarmtab(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that
				     ** points here
									*/
    register oid *name;		/* IN/OUT - input name requested,
				 ** output name found
				 */
    register int *length;	/* IN/OUT - length of input and output oid's */
    int exact;		/* IN - TRUE if an exact match was requested. */
    int *var_len;   /* OUT - length of variable or 0 if function returned. */
    int	(**write_method) __P((int, u_char *, u_char, int, u_char *,oid *, int));
{
    oid newname[MAX_NAME_LEN];
    int result;
    int mask;
    struct alarmEntry *alarm;

    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname,
	  (int)vp->namelen * sizeof(oid));
    *write_method = write_alarmtab;
    
    /* .1.3.6.1.6.3.2.1.1.2.1.X.cxlen.context.index */
    
    /* find "next" process */
    for (alarm = alarmTab; alarm; alarm = alarm->next) {
	if ((alarm->bitmask & mask) == 0) {
	    /* this variable isn't available for inspection */
	    continue;
	}
	newname[12] = (oid)alarm->contextLength;
	bcopy(alarm->contextID, newname + 13,
	      alarm->contextLength * sizeof(oid));
	newname[13 + alarm->contextLength] = (oid)alarm->index;
	result = compare(name, *length,
			 newname, 14 + alarm->contextLength);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (alarm == NULL) {
	return NULL;
    }
    
    
    bcopy((char *)newname, (char *)name,
	  (int)(14 + alarm->contextLength) * sizeof(oid));
    *length = 14 + alarm->contextLength;
    *var_len = sizeof(long);
    
    switch (vp->magic) {
      case ALARMTABVARIABLE:
	*var_len = alarm->variableLen * sizeof(oid);
	return (u_char *)alarm->variable;
      case ALARMTABINTERVAL:
	return (u_char *)&alarm->interval;
      case ALARMTABSAMPLETYPE:
	return (u_char *)&alarm->sampleType;
      case ALARMTABVALUE:
	*write_method = NULL;
	return (u_char *)&alarm->value;
      case ALARMTABSTARTUPALARM:
	return (u_char *)&alarm->startupAlarm;
      case ALARMTABRISINGTHRESH:
	return (u_char *)&alarm->risingThresh;
      case ALARMTABFALLINGTHRESH:
	return (u_char *)&alarm->fallingThresh;
      case ALARMTABRISINGINDEX:
	return (u_char *)&alarm->risingEventIndex;
      case ALARMTABFALLINGINDEX:
	return (u_char *)&alarm->fallingEventIndex;
      case ALARMTABUNAVAILABLEINDEX:
	return (u_char *)&alarm->fallingEventIndex;
      case ALARMTABSTATUS:
	if (alarm->status == ENTRY_NOTINSERVICE){
	    if (alarm->bitmask !=
		(ALARMTABCOMPLETEMASK & ~ALARMTABVALUEMASK)){
		long_return = ENTRY_NOTREADY;
		return (u_char *)&long_return;
	    }
	}
	return (u_char *)&alarm->status;
      default:
	ERROR_MSG("");
    }
    
    return NULL;
}
