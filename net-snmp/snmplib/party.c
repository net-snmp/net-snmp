#include <config.h>

#include <sys/types.h>
#include <stdio.h>
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
#include "asn1.h"
#include "party.h"



static struct partyEntry *List = NULL, *ScanPtr = NULL;
static struct partyEntry *cache[2];
static int cachePtr;
static int NextIndex = 1;

struct partyEntry *
party_getEntry(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp;

    pp = cache[0];
    if (pp && partyIDLen == pp->partyIdentityLen
#ifdef SVR4
	&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#endif
	return pp;
    }
    pp = cache[1];
    if (pp && partyIDLen == pp->partyIdentityLen
#ifdef SVR4
	&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#endif
	return pp;
    }
    for(pp = List; pp; pp = pp->next){
        if (partyIDLen == pp->partyIdentityLen
#ifdef SVR4
	    && !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#else
	    && !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
#endif
	    cachePtr ^= 1;
	    cache[cachePtr] = pp;
	    return pp;
	}
    }
    return NULL;
}

int
party_scanInit()
{
  ScanPtr = List;
}

struct partyEntry *
party_scanNext()
{
    struct partyEntry *returnval;

    returnval = ScanPtr;
    if (ScanPtr != NULL)
        ScanPtr = ScanPtr->next;
    return returnval;
}

struct partyEntry *
party_createEntry(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp;

    pp = (struct partyEntry *)malloc(sizeof(struct partyEntry));
#ifdef SVR4
    memset((char *)pp, NULL, sizeof(struct partyEntry));
#else
    bzero((char *)pp, sizeof(struct partyEntry));
#endif

#ifdef SVR4
    memmove((char *)pp->partyIdentity, (char *)partyID,
	  partyIDLen * sizeof(oid));
#else
    bcopy((char *)partyID, (char *)pp->partyIdentity,
	  partyIDLen * sizeof(oid));
#endif
    pp->partyIdentityLen = partyIDLen;
    pp->partyIndex = NextIndex++;
    pp->reserved = (struct partyEntry *)malloc(sizeof(struct partyEntry));
#ifdef SVR4
    memset((char *)pp->reserved, NULL, sizeof(struct partyEntry));
#else
    bzero((char *)pp->reserved, sizeof(struct partyEntry));
#endif

    pp->next = List;
    List = pp;
    return pp;
}

void
party_destroyEntry(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp, *lastpp;

    if (List->partyIdentityLen == partyIDLen
#ifdef SVR4
	&& !memcmp((char *)List->partyIdentity, (char *)partyID,
		 partyIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)List->partyIdentity, (char *)partyID,
		 partyIDLen * sizeof(oid))){
#endif
	pp = List;
	List = List->next;
    } else {
	for(pp = List; pp; pp = pp->next){
	    if (pp->partyIdentityLen == partyIDLen
#ifdef SVR4
		&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
			 partyIDLen * sizeof(oid)))
#else
		&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
			 partyIDLen * sizeof(oid)))
#endif
		break;
	    lastpp = pp;
	}
	if (!pp)
	    return;
	lastpp->next = pp->next;
    }
    if (pp->reserved)
	free((char *)pp->reserved);
    free(pp);
    return;
}
