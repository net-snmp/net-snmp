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

/* event.c: implement the event group of the RMON MIB */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
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
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <asn1.h>
#include <snmp_impl.h>
#include <snmp.h>
#include "snmp_vars.h"
#include "m2m.h"
#include "snmp_vars_m2m.h"
#include "alarm.h"
#include "event.h"
#include "snmp_api.h"
#include "party.h"
#include "snmp_client.h"	

static struct eventEntry *eventTab = NULL;
static struct eventNotifyEntry *eventNotifyTab = NULL;
static long eventNextIndex = 1;
static int write_eventtab __P((int, u_char *, u_char, int, u_char *, oid *,int));
static int write_eventnotifytab __P((int, u_char *, u_char, int, u_char *, oid *,int));

#define MIN_INTERVAL	1	/* one second */
#define MAX_RETRANSMISSIONS	20

/* hint for var_eventlogtab() */
static struct eventEntry *eventHint = NULL;
static struct eventNotifyEntry *eventNotifyHint = NULL;

void
time_subtract(result, t1, t2)
    struct timeval *result, *t1, *t2;
{
    result->tv_usec = t1->tv_usec - t2->tv_usec;
    result->tv_sec = t1->tv_sec - t2->tv_sec;
    while (result->tv_usec < 0L) {
	(result->tv_usec) += 1000000L;
	(result->tv_sec)--;
    }
}

/* insert the given row into the event table, ordered by index */
static void
eventInsertRow(event)
    struct eventEntry *event;
{
    struct eventEntry *current;
    struct eventEntry *prev;
    
    for (current = eventTab, prev = NULL; current; current = current->next) {
	if (current->index > event->index) {
	    break;
	}
	prev = current;
    }
    
    /* put the new entry before "current" */
    event->next = current;
    if (prev) {
	prev->next = event;
    }
    else {
	/* this is first on the list */
	eventTab = event;
    }
}

/* insert the given row into the event table, ordered by index */
static void
eventNotifyInsertRow(event)
    struct eventNotifyEntry *event;
{
    struct eventNotifyEntry *current;
    struct eventNotifyEntry *prev;
    
    for (current = eventNotifyTab, prev = NULL; current;
	 current = current->next) {
	if (current->index > event->index) {
	    break;
	}
	prev = current;
    }
    
    /* put the new entry before "current" */
    event->next = current;
    if (prev) {
	prev->next = event;
    }
    else {
	/* this is first on the list */
	eventNotifyTab = event;
    }
}

/* free the shadow space that was allocated to this row */
static void
eventFreeShadow(event)
    struct eventEntry *event;
{
    if (event->shadow == NULL) {
	return;
    }
    
    free((char *)event->shadow);
    event->shadow = NULL;
}

/* free the shadow space that was allocated to this row */
static void
eventNotifyFreeShadow(event)
    struct eventNotifyEntry *event;
{
    if (event->shadow == NULL) {
	return;
    }
    
    free((char *)event->shadow);
    event->shadow = NULL;
}

/* delete the given row from the event table, and free the memory
 ** associated with it.
 */
static void
eventDeleteRow(event)
    struct eventEntry *event;
{
    struct eventEntry *temp;
    struct eventEntry *prev = NULL;
    
    for (temp = eventTab; temp; temp = temp->next) {
	if (temp == event) {
	    /* this is the one to remove */
	    if (prev) {
		prev->next = temp->next;
	    }
	    else {
		/* this is the first on the list */
		eventTab = temp->next;
	    }
	    break;
	}
	prev = temp;
    }
    
    /* KLF debugging */
    if (temp == NULL) {
	printf("eventDeleteRow: didn't find row (%d) in eventTab\n",
	       event->index);
    }
    
    eventFreeShadow(event);
    eventHint = NULL;		/* invalidate the hint */
    free((char *)event);
}

/* delete the given row from the event table, and free the memory
 ** associated with it.
 */
static void
eventNotifyDeleteRow(event)
    struct eventNotifyEntry *event;
{
    struct eventNotifyEntry *temp;
    struct eventNotifyEntry *prev = NULL;
    
    for (temp = eventNotifyTab; temp; temp = temp->next) {
	if (temp == event) {
	    /* this is the one to remove */
	    if (prev) {
		prev->next = temp->next;
	    }
	    else {
		/* this is the first on the list */
		eventNotifyTab = temp->next;
	    }
	    break;
	}
	prev = temp;
    }
    
    /* KLF debugging */
    if (temp == NULL) {
	printf("eventNotifyDeleteRow: didn't find row (%d) in eventNotifyTab\n",
	       event->index);
    }
    
    eventNotifyFreeShadow(event);
    eventNotifyHint = NULL;		/* invalidate the hint */
    free((char *)event);
}

/* create a shadow structure for the given row, and copy the world-visible
 ** data into the shadow structure.  Returns 1 on success, 0 otherwise.
 */
static int
eventShadowRow(event)
    struct eventEntry *event;
{
    int i = 0;
    
    if (event->shadow != NULL) {
	/* it's already been created */
	return 1;
    }
    
    event->shadow = (struct eventEntry *)malloc(sizeof(struct eventEntry));
    while ((event->shadow == NULL) && (i++ < 5)) {
	eventFreeSpace();
	event->shadow = (struct eventEntry *)malloc(sizeof(struct eventEntry));
    }
    if (event->shadow == NULL) {
	/* no more memory */
	return 0;
    }
    
    bcopy((char *)event, (char *)event->shadow, sizeof(struct eventEntry));
    
    return 1;
}

/* create a shadow structure for the given row, and copy the world-visible
 ** data into the shadow structure.  Returns 1 on success, 0 otherwise.
 */
static int
eventNotifyShadowRow(event)
    struct eventNotifyEntry *event;
{
    int i = 0;
    
    if (event->shadow != NULL) {
	/* it's already been created */
	return 1;
    }
    
    event->shadow = (struct eventNotifyEntry *)malloc(sizeof(struct eventNotifyEntry));
    while ((event->shadow == NULL) && (i++ < 5)) {
	eventFreeSpace();
	event->shadow = (struct eventNotifyEntry *)malloc(sizeof(struct eventNotifyEntry));
    }
    if (event->shadow == NULL) {
	/* no more memory */
	return 0;
    }
    
    bcopy((char *)event, (char *)event->shadow, sizeof(struct eventNotifyEntry));
    
    return 1;
}

/* return a pointer to the given row in eventTab */
static struct eventEntry *
eventGetRow(index)
    int index;
{
    struct eventEntry *event;
    
    for (event = eventTab; event; event = event->next) {
	if (event->index == index) {
	    return event;
	}
    }
    
    return NULL;
}

/* create a new row for the event table, with the given index.
 ** Create a shadow for the row.  Put default values into the shadow.
 ** Return a pointer to the new row.  This routine does not check that
 ** the index has not already been used, and does not make the row
 ** visible to a management station that is doing a walk of the table.
 ** It makes sure the index is in the valid range.
 */
static struct eventEntry *
eventNewRow(index)
    int index;
{
    struct eventEntry *event;
    int i = 0;
    
    if ((index < 1) || (index > 65535)) {
	return NULL;
    }
    
    event = (struct eventEntry *)malloc(sizeof(struct eventEntry));
    while ((event == NULL) && (i++ < 5)) {
	eventFreeSpace();
	event = (struct eventEntry *)malloc(sizeof(struct eventEntry));
    }
    if (event == NULL) {
	/* no more room */
	return NULL;
    }
    
    bzero((char *)event, sizeof(struct eventEntry));
    
    event->index = index;
    event->status = ENTRY_DESTROY;
    
    event->bitmask = EVENTTABINDEXMASK;
    
    eventInsertRow(event);
    
    /* this will copy the index, status, and bitmask into the shadow area */
    if (eventShadowRow(event) == 0) {
	/* weren't able to allocate space for the shadow area, so
	 ** remove the entry from the list.
	 */
	eventDeleteRow(event);
	return NULL;
    }
    
    /* add default entries to the shadow copy.  The only variable that
     ** isn't defaulted is owner.
     */
    event->shadow->status = ENTRY_NOTINSERVICE;
    /* KLF should I bother to default these? */
    
    /* note that this assignment implies that lastTimeSent defaults to zero */
    event->shadow->bitmask |= (EVENTTABSTATUSMASK |
			       EVENTTABEVENTSMASK | EVENTTABLASTTIMESENTMASK);
    
    eventNextIndex = random() & 0x0000ffff;
    while (eventGetRow(eventNextIndex) != NULL) {
	eventNextIndex = random() & 0x0000ffff;
    }
    return event;
}

/* create a new row for the event table, with the given index.
 ** Create a shadow for the row.  Put default values into the shadow.
 ** Return a pointer to the new row.  This routine does not check that
 ** the index has not already been used, and does not make the row
 ** visible to a management station that is doing a walk of the table.
 ** It makes sure the index is in the valid range.
 */
static struct eventNotifyEntry *
eventNotifyNewRow(index, context, contextLen)
    int index;
    oid *context;
    int contextLen;
{
    struct eventNotifyEntry *event;
    int i = 0;
    
    if ((index < 1) || (index > 65535)) {
	return NULL;
    }
    
    event = (struct eventNotifyEntry *)malloc(sizeof(struct eventNotifyEntry));
    while ((event == NULL) && (i++ < 5)) {
	eventNotifyFreeSpace();
	event = (struct eventNotifyEntry *)malloc(sizeof(struct eventNotifyEntry));
    }
    if (event == NULL) {
	/* no more room */
	return NULL;
    }
    
    bzero((char *)event, sizeof(struct eventNotifyEntry));
    
    event->index = index;
    event->contextLen = contextLen;
    bcopy(context, event->context, contextLen * sizeof(oid));
    event->status = ENTRY_DESTROY;
    event->interval = 30;
    event->retransmissions = 5;
    event->lifetime = 86400;
    
    eventNotifyInsertRow(event);
    
    /* this will copy the index, status, and bitmask into the shadow area */
    if (eventNotifyShadowRow(event) == 0) {
	/* weren't able to allocate space for the shadow area, so
	 ** remove the entry from the list.
	 */
	eventNotifyDeleteRow(event);
	return NULL;
    }
    
    /* add default entries to the shadow copy.  The only variable that
     ** isn't defaulted is owner.
     */
    event->shadow->status = ENTRY_NOTINSERVICE;
    /* KLF should I bother to default these? */
    
    /* note that this assignment implies that lastTimeSent defaults to zero */
    event->shadow->bitmask |= (EVENTNOTIFYTABSTATUSMASK
			       | EVENTNOTIFYTABINTERVALMASK
			       | EVENTNOTIFYTABLIFETIMEMASK
			       | EVENTNOTIFYTABRETRANSMISSIONSMASK);
    
    return event;
}

/* return a pointer to the given row in eventTab */
static struct eventNotifyEntry *
eventNotifyGetRow(index, context, contextLen)
    int index;
    oid *context;
    int contextLen;
{
    struct eventNotifyEntry *event;
    
    for (event = eventNotifyTab; event; event = event->next) {
	if (event->index == index && event->contextLen == contextLen
	    && !bcmp(event->context, context,
		     contextLen * sizeof(oid))) {
	    return event;
		     }
    }
    
    return NULL;
}

/* copy the data in the given row from the shadow copy into the world-
 ** visible copy, and get rid of the shadow copy.  If no shadow copy
 ** exists, just return.  If we are setting the row to invalid, delete it.
 */
static void
eventCommitRow(event)
    struct eventEntry *event;
{
    struct eventEntry *nextPtr;
    
    if (event->shadow == NULL) {
	return;
    }
    
    /* if this entry is being set to invalid, just delete it */
    if (event->shadow->status == ENTRY_DESTROY) {
	eventDeleteRow(event);
	return;
    }
    
    /* save and restore the pointers.  This is done because eventFreeSpace()
     ** may have been called since the shadow was created.  This could
     ** have changed any of the event pointers.
     */
    nextPtr = event->next;
    bcopy((char *)event->shadow, (char *)event, sizeof(struct eventEntry));
    
    if (event->next != nextPtr) {
	/* KLF debugging */
	printf("eventCommitRow(%d): next pointer was different\n",
	       event->index);
	event->next = nextPtr;
    }
    
    eventFreeShadow(event);
}

/* copy the data in the given row from the shadow copy into the world-
 ** visible copy, and get rid of the shadow copy.  If no shadow copy
 ** exists, just return.  If we are setting the row to invalid, delete it.
 */
static void
eventNotifyCommitRow(event)
    struct eventNotifyEntry *event;
{
    struct eventNotifyEntry *nextPtr;
    
    if (event->shadow == NULL) {
	return;
    }
    
    /* if this entry is being set to invalid, just delete it */
    if (event->shadow->status == ENTRY_DESTROY) {
	eventNotifyDeleteRow(event);
	return;
    }
    
    /* save and restore the pointers.  This is done because eventFreeSpace()
     ** may have been called since the shadow was created.  This could
     ** have changed any of the event pointers.
     */
    nextPtr = event->next;
    bcopy((char *)event->shadow, (char *)event, sizeof(struct eventNotifyEntry));
    
    if (event->next != nextPtr) {
	/* KLF debugging */
	printf("eventNotifyCommitRow(%d): next pointer was different\n",
	       event->index);
	event->next = nextPtr;
    }
    
    eventNotifyFreeShadow(event);
}

/* free some memory that's being used by this module.  Called when a
 ** routine can't malloc some space.  Returns true if successful, and false
 ** if not.
 */
Export int
eventFreeSpace()
{
    int spaceFreed = FALSE;
    
    /* nothing */
    return spaceFreed;
}

/* free some memory that's being used by this module.  Called when a
 ** routine can't malloc some space.  Returns true if successful, and false
 ** if not.
 */
Export int
eventNotifyFreeSpace()
{
    int spaceFreed = FALSE;
    
    /* nothing */
    return spaceFreed;
}


/* add the variables for a objectUnavailableAlarm trap to the
** end of varList.
*/
eventUnavailFillInVars(varList, alarm)
    struct variable_list *varList;
    struct alarmEntry *alarm;
{
    struct variable_list *vp;
    
    vp = (struct variable_list *)malloc(sizeof(struct variable_list));
    varList->next_variable = vp;

    vp->name = (oid *)malloc(alarmVariableOidLen * sizeof(oid));
    bcopy(alarmVariableOid, vp->name, alarmVariableOidLen * sizeof(oid));
    vp->name_length = alarmVariableOidLen;
    vp->type = ASN_OBJECT_ID;
    vp->val_len = alarm->variableLen * sizeof(oid);
    vp->val.objid = (oid *)malloc(vp->val_len);
    bcopy(alarm->variable, vp->val.objid, vp->val_len);
    vp->next_variable = NULL;
}

/* add the variables for an alarm trap to the end of varList */
static void
eventAlarmFillInVars(varList, alarm, trapType)
    struct variable_list *varList;
    struct alarmEntry *alarm;
    int trapType;
{
    struct variable_list *aVar;
    struct variable_list *prevVar;

    aVar = (struct variable_list *)malloc(sizeof(struct variable_list));
    varList->next_variable = aVar;
    
    aVar->name = (oid *)malloc((alarmVariableOidLen + alarm->contextLength + 1) * sizeof(oid));
    bcopy(alarmVariableOid, aVar->name, alarmVariableOidLen * sizeof(oid));
    aVar->name[alarmVariableOidLen] = alarm->contextLength;
    bcopy(alarm->contextID, aVar->name + alarmVariableOidLen + 1,
	  alarm->contextLength * sizeof(oid));
    aVar->name_length = alarmVariableOidLen + alarm->contextLength + 1;
    aVar->type = ASN_OBJECT_ID;
    aVar->val_len = alarm->variableLen * sizeof(oid);
    aVar->val.objid = (oid *)malloc(aVar->val_len);
    bcopy(alarm->variable, aVar->val.objid, aVar->val_len);
    aVar->next_variable = NULL;
    prevVar = aVar;

    aVar = (struct variable_list *)malloc(sizeof(struct variable_list));
    prevVar->next_variable = aVar;
    
    aVar->name = (oid *)malloc((alarmSampleTypeOidLen + alarm->contextLength + 1) * sizeof(oid));
    bcopy(alarmSampleTypeOid, aVar->name, alarmSampleTypeOidLen * sizeof(oid));
    aVar->name[alarmSampleTypeOidLen] = alarm->contextLength;
    bcopy(alarm->contextID, aVar->name + alarmSampleTypeOidLen + 1,
	  alarm->contextLength * sizeof(oid));
    aVar->name_length = alarmSampleTypeOidLen + alarm->contextLength + 1;
    aVar->type = ASN_INTEGER;
    aVar->val_len = sizeof(alarm->sampleType);
    aVar->val.integer = (long *)malloc(sizeof(long));
    bcopy(&alarm->sampleType, aVar->val.integer, sizeof(long));
    aVar->next_variable = NULL;
    prevVar = aVar;

    aVar = (struct variable_list *)malloc(sizeof(struct variable_list));
    prevVar->next_variable = aVar;

    aVar->name = (oid *)malloc((alarmValueOidLen + alarm->contextLength + 1) * sizeof(oid));
    bcopy(alarmValueOid, aVar->name, alarmValueOidLen * sizeof(oid));
    aVar->name[alarmValueOidLen] = alarm->contextLength;
    bcopy(alarm->contextID, aVar->name + alarmValueOidLen + 1,
	  alarm->contextLength * sizeof(oid));
    aVar->name_length = alarmValueOidLen + alarm->contextLength + 1;
    aVar->type = ASN_INTEGER;
    aVar->val_len = sizeof(alarm->value);
    aVar->val.integer = (long *)malloc(sizeof(long));
    bcopy(&alarm->value, aVar->val.integer, sizeof(long));
    aVar->next_variable = NULL;
    prevVar = aVar;

    aVar = (struct variable_list *)malloc(sizeof(struct variable_list));
    prevVar->next_variable = aVar;
    
    if (trapType == TRAP_RISING_ALARM) {
	aVar->name = (oid *)malloc((alarmRisingThreshOidLen + alarm->contextLength + 1) * sizeof(oid));
	bcopy(alarmRisingThreshOid, aVar->name,
	      alarmRisingThreshOidLen * sizeof(oid));
	aVar->name[alarmRisingThreshOidLen] = alarm->contextLength;
	bcopy(alarm->contextID, aVar->name + alarmRisingThreshOidLen + 1,
	  alarm->contextLength * sizeof(oid));
	aVar->name_length = alarmRisingThreshOidLen + alarm->contextLength + 1;
	aVar->type = ASN_INTEGER;
	aVar->val_len = sizeof(alarm->risingThresh);
	aVar->val.integer = (long *)malloc(sizeof(long));
	bcopy(&alarm->risingThresh, aVar->val.integer, sizeof(long));
    }
    else {
	aVar->name = (oid *)malloc((alarmFallingThreshOidLen + alarm->contextLength + 1) * sizeof(oid));
	bcopy(alarmFallingThreshOid, aVar->name,
	      alarmFallingThreshOidLen * sizeof(oid));
	aVar->name[alarmFallingThreshOidLen] = alarm->contextLength;
	bcopy(alarm->contextID, aVar->name + alarmFallingThreshOidLen + 1,
	  alarm->contextLength * sizeof(oid));
	aVar->name_length = alarmFallingThreshOidLen + alarm->contextLength + 1;
	aVar->type = ASN_INTEGER;
	aVar->val_len = sizeof(alarm->fallingThresh);
	aVar->val.integer = (long *)malloc(sizeof(long));
	bcopy(&alarm->fallingThresh, aVar->val.integer, sizeof(long));
    }
    aVar->next_variable = NULL;
}

/* send an SNMPv2 Inform as notification of this event */
static void
eventSendTrap(event, eventType, generic)
    struct eventEntry *event;
    int eventType;
    void *generic;		/* info needed to fill in variables */
{
    struct eventNotifyEntry *np;
    struct variable_list *vp;
    struct snmp_pdu *pdu;
    struct partyEntry *pp;
    u_long uptime;

    for (np = eventNotifyTab; np; np = np->next) {
	if (np->index != event->index
	    || np->status != ENTRY_ACTIVE
	    || !np->ss) /* if session isn't set up, punt */
	    continue;
	pp = party_getEntry(np->dstParty, np->dstPartyLen);
	if (!pp)
	    continue;

	vp = (struct variable_list *)malloc(sizeof(struct variable_list));
	
	/* sysUpTime is the first oid in the inform pdu */
	vp->name = (oid *)malloc(sysUpTimeOidLen * sizeof(oid));
	bcopy(sysUpTimeOid, vp->name, sysUpTimeOidLen * sizeof(oid));
	vp->name_length = sysUpTimeOidLen;
	vp->type = TIMETICKS;
	uptime = get_uptime();
	vp->val_len = sizeof(uptime);
	vp->val.objid = (oid *)malloc(vp->val_len);
	bcopy(&uptime, vp->val.integer, vp->val_len);
	vp->next_variable = NULL;
	
	vp->next_variable
	    = (struct variable_list *)malloc(sizeof(struct variable_list));

	/* event->id is the second oid in the inform pdu */
	vp->next_variable->name = (oid *)malloc((eventIdOidLen + 1) * sizeof(oid));
	bcopy(eventIdOid, vp->next_variable->name, eventIdOidLen * sizeof(oid));
	vp->next_variable->name[eventIdOidLen] = event->index;
	vp->next_variable->name_length = eventIdOidLen + 1;
	vp->next_variable->type = ASN_OBJECT_ID;
	vp->next_variable->val_len = event->idLen * sizeof(oid);
	vp->next_variable->val.objid = (oid *)malloc(vp->next_variable->val_len);
	bcopy(event->id, vp->next_variable->val.objid, vp->next_variable->val_len);
	vp->next_variable->next_variable = NULL;
	
	/* event->id should override the eventType that was passed in */
	if (!bcmp(trapRisingAlarmOid, event->id, trapRisingAlarmOidLen)) {
	    eventType = EVENT_TYPE_RISING;
	}
	else if (!bcmp(trapFallingAlarmOid, event->id,
		       trapFallingAlarmOidLen)) {
	    eventType = EVENT_TYPE_FALLING;
	}
	else if (!bcmp(trapObjUnavailAlarmOid, event->id,
		       trapObjUnavailAlarmOidLen)) {
	    eventType = EVENT_TYPE_UNAVAILABLE;
	}
	
	switch(eventType) {
	  case EVENT_TYPE_STARTUP_RISING:
	  case EVENT_TYPE_RISING:
	    eventAlarmFillInVars(vp, (struct alarmEntry *)generic,
				 TRAP_RISING_ALARM);
	    break;
	  case EVENT_TYPE_STARTUP_FALLING:
	  case EVENT_TYPE_FALLING:
	    eventAlarmFillInVars(vp, (struct alarmEntry *)generic,
				 TRAP_FALLING_ALARM);
	    break;
	  case EVENT_TYPE_UNAVAILABLE:
	    eventUnavailFillInVars(vp, (struct alarmEntry *)generic);
	    break;
	  default:
	    printf("eventSendTrap: unrecognized eventType %d\n", eventType);
	    break;
	}

	pdu = snmp_pdu_create(INFORM_REQ_MSG);
	bcopy(pp->partyTAddress, (char *)&pdu->address.sin_addr.s_addr, 4);
	bcopy(pp->partyTAddress + 4, &pdu->address.sin_port, 2);
	pdu->address.sin_port = 162;
	pdu->address.sin_family = AF_INET;
	pdu->variables = vp;
	(void)snmp_send(np->ss, pdu);
    }
}    

/* perform the action indicated by the event entry corresponding to index
 ** in the event table
 */
Export void
eventGenerate(index, eventType, generic)
    int index;
    int eventType;
    void *generic;		/* info needed for traps */
{
    struct eventEntry *event;
    
    event = eventGetRow(index);
    if (event == NULL) {
	/* event doesn't exist */
	return;
    }
    
    /* set this before calling eventSendTrap(), so it can use the value */
    event->lastTimeSent = get_uptime();
    event->numEvents++;
    
    eventSendTrap(event, eventType, generic);
}

/* count down the lifetime timer, and remove the row when it reaches zero */
Export void
eventTimer(now)
    struct timeval *now;
{
    struct eventNotifyEntry *np;
    struct eventNotifyEntry *next;
    struct timeval elapsed;
    static struct timeval lastCall = {0, 0};

    if (lastCall.tv_sec == 0) {
	/* initialization */
	lastCall.tv_sec = now->tv_sec;
	lastCall.tv_usec = now->tv_usec;
	return;
    }

    time_subtract(&elapsed, now, &lastCall);

    if (elapsed.tv_sec < 0) {
	/* if it's been less than a second, pretend we didn't get called */
	return;
    }

    for (np = eventNotifyTab; np; np = next) {
	next = np->next;
	np->lifetime -= elapsed.tv_sec;
	if (np->lifetime <= 0) {
	    if (np->status != ENTRY_ACTIVE){
		np->lifetime = 0;
	    } else {
		eventNotifyDeleteRow(np);
	    }
	}
    }

    /* set lastCall to now, but skip the usecs that haven't been
    ** subtracted from np->lifetime yet
    */
    elapsed.tv_sec = 0;
    time_subtract(&lastCall, now, &elapsed);
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and event is non-NULL, the instance (row) exists, but not
 * this variable.
 * If statP is NULL and event is NULL, then neither this instance nor the
 * variable exists.
 */
/* return TRUE on success and FALSE on failure */
static int
write_eventtab(action, var_val, var_val_type, var_val_len, statP,
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
    register struct eventEntry *event;
    int size;
    long int_value;
    u_char string_value[MAX_OWNER_STR_LEN];
    oid id_value[MAX_NAME_LEN];
    int buffersize = 1000;
    
    /* .1.3.6.1.6.3.2.1.2.2.1.6.1  */

    if (name_len != 13)
	return SNMP_ERR_NOCREATION;
    index = name[name_len - 1];
    event = eventGetRow(index);
    
    switch (action) {
      case RESERVE1:
	if (event == NULL) {
	    event = eventNewRow(index);
	    if (event == NULL) {
		/* no memory for row */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	else {
	    /* we have a row, but some vars will change.  Remember
	     ** the current numbers.
	     */
	    if (eventShadowRow(event) == 0) {
		/* not enough memory available */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	break;
      case RESERVE2:
	if (event == NULL) {
	    /* this should have been created in the RESERVE1 phase */
	    return SNMP_ERR_GENERR;
	}
	break;
      case COMMIT:
	if (event == NULL) {
	    return SNMP_ERR_GENERR;
	}
	eventCommitRow(event);
	return SNMP_ERR_NOERROR;
      case FREE:
	if (event == NULL) {
	    return SNMP_ERR_GENERR;
	}
	if (event->status == ENTRY_DESTROY) {
	    /* this row did not exist before we began this RESERVE/FREE
	     ** cycle, so delete it now.
	     */
	    eventDeleteRow(event);
	} else {
	    /* the row existed before, so just get rid of the shadow
	     ** copy.
	     */
	    eventFreeShadow(event);
	}
	return SNMP_ERR_NOERROR;
    }
    
    variable = name[name_len - 2];
    
    /* description, type, community, owner, and status
     ** are the only user-writable variables in this table.
     */
    switch (variable) {
      case EVENTTABID:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_OBJECT_ID) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    size = sizeof(id_value);
	    if (asn_parse_objid(var_val, &buffersize, &var_val_type,
				id_value, &size) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
				}
	    event->shadow->idLen = size;
	    bcopy(id_value, event->shadow->id, size * sizeof(oid));
	    event->shadow->bitmask |= EVENTTABIDMASK;
	}
	break;
      case EVENTTABDESCRIPTION:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_OCTET_STR) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    size = sizeof(string_value);
	    if (asn_parse_string(var_val, &buffersize, &var_val_type,
				 string_value, &size) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
				 }
	    event->shadow->descriptionLen = size;
	    bcopy(string_value, event->shadow->description, size);
	    event->shadow->bitmask |= EVENTTABDESCRIPTIONMASK;
	}
	break;
      case EVENTTABSTATUS:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
			      }
	    if (int_value < ENTRY_ACTIVE
		|| int_value > ENTRY_DESTROY
		|| int_value == ENTRY_NOTREADY
		|| int_value == ENTRY_CREATEANDGO) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    
	    if (int_value == ENTRY_CREATEANDWAIT
		|| int_value == ENTRY_CREATEANDGO) {
		if (event->status != ENTRY_DESTROY) {
		    /* this is an entry that already existed; not
		     ** allowed to set it to createRequest
		     */
		    return SNMP_ERR_INCONSISTENTVALUE;
		}
		int_value = ENTRY_NOTINSERVICE;
	    }
	    
	    event->shadow->status = int_value;
	    event->shadow->bitmask |= EVENTTABSTATUSMASK;
	}
	else if (action == RESERVE2) {
	    if ((event->shadow->status == ENTRY_ACTIVE) &&
		(event->shadow->bitmask != EVENTTABCOMPLETEMASK)) {
		return SNMP_ERR_INCONSISTENTVALUE;
		}
	}
	break;
      default:
	return SNMP_ERR_GENERR;
    }
    
    return SNMP_ERR_NOERROR;
}

void
eventNotifyUpdateSession(np)
    struct eventNotifyEntry *np;
{
    struct snmp_session session;
    struct get_req_state *state;
    extern int snmp_input();
    u_long destAddr;

    if (np->status != ENTRY_ACTIVE)
	return;

    ((u_char *)&destAddr)[0] = (u_char)np->context[9];
    ((u_char *)&destAddr)[1] = (u_char)np->context[10];
    ((u_char *)&destAddr)[2] = (u_char)np->context[11];
    ((u_char *)&destAddr)[3] = (u_char)np->context[12];

    np->srcPartyLen
        = np->dstPartyLen = np->contextLen= MAX_NAME_LEN;
    ms_party_init(destAddr, np->srcParty, &(np->srcPartyLen),
                  np->dstParty, &(np->dstPartyLen),
                    np->context, &(np->contextLen));

    if (np->ss)
	snmp_close(np->ss);

    state = (struct get_req_state *)malloc(sizeof(struct get_req_state));
    state->type = EVENT_GET_REQ;
    state->info = (void *)NULL;
    np->magic = state;
    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = SNMP_DEFAULT_PEERNAME;
    session.version = SNMP_VERSION_2p;
    session.srcParty = np->srcParty;
    session.srcPartyLen = np->srcPartyLen;
    session.dstParty = np->dstParty;
    session.dstPartyLen = np->dstPartyLen;
    session.context = np->context;
    session.contextLen = np->contextLen;
    session.retries = np->retransmissions;
    session.timeout = np->interval * 1000000;
    session.callback = snmp_input;
    session.callback_magic = (void *)state;
    np->ss = snmp_open(&session);
    /* no need to check for error, there nothing to do about it anyway */
    if (!np->ss)
	ERROR_MSG("");
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and event is non-NULL, the instance (row) exists, but not
 * this variable.
 * If statP is NULL and event is NULL, then neither this instance nor the
 * variable exists.
 */
/* return TRUE on success and FALSE on failure */
static int
write_eventnotifytab(action, var_val, var_val_type, var_val_len, statP,
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
    register struct eventNotifyEntry *event;
    long int_value;
    int buffersize = 1000;
    oid *context;
    int contextLen;
    
    /* .1.3.6.1.6.3.2.1.2.5.1.4.int.len.context */

    if (name_len < 15)
	return SNMP_ERR_NOCREATION;
    index = name[12];
    contextLen = name[13];
    context = name + 14;
    event = eventNotifyGetRow(index, context, contextLen);
    
    switch (action) {
      case RESERVE1:
	if (event == NULL) {
	    event = eventNotifyNewRow(index, context, contextLen);
	    if (event == NULL) {
		/* no memory for row */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	else {
	    /* we have a row, but some vars will change.  Remember
	     ** the current numbers.
	     */
	    if (eventNotifyShadowRow(event) == 0) {
		/* not enough memory available */
		return SNMP_ERR_RESOURCEUNAVAILABLE;
	    }
	}
	break;
      case RESERVE2:
	if (event == NULL) {
	    /* this should have been created in the RESERVE1 phase */
	    return SNMP_ERR_GENERR;
	}
	break;
      case COMMIT:
	if (event == NULL) {
	    return SNMP_ERR_GENERR;
	}
	eventNotifyCommitRow(event);
	eventNotifyUpdateSession(event);
	return SNMP_ERR_NOERROR;
      case FREE:
	if (event == NULL) {
	    return SNMP_ERR_GENERR;
	}
	if (event->status == ENTRY_DESTROY) {
	    /* this row did not exist before we began this RESERVE/FREE
	     ** cycle, so delete it now.
	     */
	    eventNotifyDeleteRow(event);
	}
	else {
	    /* the row existed before, so just get rid of the shadow
	     ** copy.
	     */
	    eventNotifyFreeShadow(event);
	}
	return SNMP_ERR_NOERROR;
    }
    
    variable = name[11];
    
    /* description, type, community, owner, and status
     ** are the only user-writable variables in this table.
     */
    switch (variable) {
      case EVENTNOTIFYTABINTERVAL:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
			      }
	    if (int_value < MIN_INTERVAL) {
		int_value = MIN_INTERVAL;
	    }
	    event->shadow->interval = int_value;
	    event->shadow->bitmask |= EVENTNOTIFYTABINTERVALMASK;
	}
	break;
      case EVENTNOTIFYTABRETRANSMISSIONS:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
			      }
	    if (int_value > MAX_RETRANSMISSIONS) {
		int_value = MAX_RETRANSMISSIONS;
	    }
	    event->shadow->retransmissions = int_value;
	    event->shadow->bitmask |= EVENTNOTIFYTABRETRANSMISSIONSMASK;
	}
	break;
      case EVENTNOTIFYTABLIFETIME:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
			      }
	    event->shadow->lifetime = int_value;
	    event->shadow->bitmask |= EVENTNOTIFYTABLIFETIMEMASK;
	}
	break;
      case EVENTNOTIFYTABSTATUS:
	if (action == RESERVE1) {
	    if (var_val_type != ASN_INTEGER) {
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (asn_parse_int(var_val, &buffersize, &var_val_type,
			      &int_value, sizeof(int_value)) == NULL) {
		return SNMP_ERR_WRONGLENGTH;
			      }
	    if (int_value < ENTRY_ACTIVE
		|| int_value > ENTRY_DESTROY
		|| int_value == ENTRY_NOTREADY
		|| int_value == ENTRY_CREATEANDGO) {
		return SNMP_ERR_WRONGVALUE;
	    }
	    
	    if (int_value == ENTRY_CREATEANDWAIT
		|| int_value == ENTRY_CREATEANDGO) {
		if (event->status != ENTRY_DESTROY) {
		    /* this is an entry that already existed; not
		     ** allowed to set it to createRequest
		     */
		    return SNMP_ERR_INCONSISTENTVALUE;
		}
		int_value = ENTRY_NOTINSERVICE;
	    }
	    
	    event->shadow->status = int_value;
	    event->shadow->bitmask |= EVENTNOTIFYTABSTATUSMASK;
	}
	else if (action == RESERVE2) {
	    if ((event->shadow->status == ENTRY_ACTIVE) &&
		(event->shadow->bitmask != EVENTNOTIFYTABCOMPLETEMASK)) {
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
var_eventnextindex(vp, name, length, exact, var_len, write_method)
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
      case EVENTNEXTINDEX:
	return (u_char *)&eventNextIndex;
      default:
	ERROR_MSG("");
    }

    return NULL;
}
    
/* respond to requests for variables in the event table */
Export u_char *
var_eventtab(vp, name, length, exact, var_len, write_method)
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
    oid newname[MAX_NAME_LEN];
    int result;
    int mask;
    struct eventEntry *event;
    
    /* .1.3.6.1.6.3.2.1.2.2.1.6.int */
    
    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname, vp->namelen * sizeof(oid));
    *write_method = write_eventtab;
    
    /* find "next" process */
    for (event = eventTab; event; event = event->next) {
	if ((event->bitmask & mask) == 0) {
	    /* this variable isn't available for inspection */
	    continue;
	}
	newname[12] = (oid)event->index;
	result = compare(name, *length, newname, 13);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (event == NULL) {
	return NULL;
    }
    
    bcopy((char *)newname, (char *)name, (int)13 * sizeof(oid));
    *length = 13;
    *var_len = sizeof(long);
    
    switch (vp->magic) {
      case EVENTTABID:
	*var_len = event->idLen * sizeof(oid);
	return (u_char *)event->id;
      case EVENTTABDESCRIPTION:
	*var_len = event->descriptionLen;
	return (u_char *)event->description;
      case EVENTTABEVENTS:
	*write_method = NULL;
	return (u_char *)&event->numEvents;
      case EVENTTABLASTTIMESENT:
	*write_method = NULL;
	return (u_char *)&event->lastTimeSent;
      case EVENTTABSTATUS:
	if (event->status == ENTRY_NOTINSERVICE){
	    if (event->bitmask != EVENTTABCOMPLETEMASK){
		long_return = ENTRY_NOTREADY;
		return (u_char *)&long_return;
	    }
	}
	return (u_char *)&event->status;
      default:
	ERROR_MSG("");
    }
    
    return NULL;
}

/* respond to queries for eventNotifyMinInterval and eventNotifyMaxRetransmissions */
Export u_char *
var_eventnotifyvars(vp, name, length, exact, var_len, write_method)
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

    *write_method = 0;
    result = compare(name, *length, vp->name, (int)vp->namelen);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;

    bcopy((char *)vp->name, (char *)name,
	  (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *var_len = sizeof(long);
    
    switch (vp->magic) {
      case EVENTMININTERVAL:
	long_return = MIN_INTERVAL;
	return (u_char *)&long_return;
      case EVENTMAXRETRANS:
	long_return = MAX_RETRANSMISSIONS;
	return (u_char *)&long_return;
      default:
	ERROR_MSG("");
    }

    return NULL;
}

/* respond to requests for variables in the event table */
Export u_char *
var_eventnotifytab(vp, name, length, exact, var_len, write_method)
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
    oid newname[MAX_NAME_LEN];
    int result;
    int mask;
    struct eventNotifyEntry *event;
    
    
    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname, vp->namelen * sizeof(oid));
    *write_method = write_eventnotifytab;
    
    /* .1.3.6.1.6.3.2.1.2.5.1.4.int.len.context */

    /* find "next" eventNotify entry */
    for (event = eventNotifyTab; event; event = event->next) {
	if ((event->bitmask & mask) == 0) {
	    /* this variable isn't available for inspection */
	    continue;
	}
	newname[12] = (oid)event->index;
	newname[13] = (oid)event->contextLen;
	bcopy(event->context, newname+14, event->contextLen * sizeof(oid));
	result = compare(name, *length, newname, 14 + event->contextLen);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (event == NULL) {
	return NULL;
    }
    
    bcopy((char *)newname, (char *)name,
	  (int)(14 + event->contextLen) * sizeof(oid));
    *length = 14 + event->contextLen;
    *var_len = sizeof(long);
    
    switch (vp->magic) {
      case EVENTNOTIFYTABINTERVAL:
	return (u_char *)&event->interval;
      case EVENTNOTIFYTABRETRANSMISSIONS:
	return (u_char *)&event->retransmissions;
      case EVENTNOTIFYTABLIFETIME:
	return (u_char *)&event->lifetime;
      case EVENTNOTIFYTABSTATUS:
	if (event->status == ENTRY_NOTINSERVICE){
	    if (event->bitmask != EVENTNOTIFYTABCOMPLETEMASK){
		long_return = ENTRY_NOTREADY;
		return (u_char *)&long_return;
	    }
	}
	return (u_char *)&event->status;
      default:
	ERROR_MSG("");
    }
    
    return NULL;
}
