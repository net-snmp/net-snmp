#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
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
	&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	return pp;
    }
    pp = cache[1];
    if (pp && partyIDLen == pp->partyIdentityLen
	&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	return pp;
    }
    for(pp = List; pp; pp = pp->next){
        if (partyIDLen == pp->partyIdentityLen
	    && !memcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	    cachePtr ^= 1;
	    cache[cachePtr] = pp;
	    return pp;
	}
    }
    return NULL;
}

void
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
    memset((char *)pp, 0, sizeof(struct partyEntry));

    memmove((char *)pp->partyIdentity, (char *)partyID,
	  partyIDLen * sizeof(oid));
    pp->partyIdentityLen = partyIDLen;
    pp->partyIndex = NextIndex++;
    pp->reserved = (struct partyEntry *)malloc(sizeof(struct partyEntry));
    memset((char *)pp->reserved, 0, sizeof(struct partyEntry));

    pp->next = List;
    List = pp;
    return pp;
}

void
party_destroyEntry(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp, *lastpp = NULL;

    if (List->partyIdentityLen == partyIDLen
	&& !memcmp((char *)List->partyIdentity, (char *)partyID,
		 partyIDLen * sizeof(oid))){
	pp = List;
	List = List->next;
    } else {
	for(pp = List; pp; pp = pp->next){
	    if (pp->partyIdentityLen == partyIDLen
		&& !memcmp((char *)pp->partyIdentity, (char *)partyID,
			 partyIDLen * sizeof(oid)))
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
