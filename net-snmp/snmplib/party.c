#include <sys/types.h>
#include <sys/time.h>
#include "asn1.h"
#define NULL 0
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
	&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	return pp;
    }
    pp = cache[1];
    if (pp && partyIDLen == pp->partyIdentityLen
	&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	return pp;
    }
    for(pp = List; pp; pp = pp->next){
        if (partyIDLen == pp->partyIdentityLen
	    && !bcmp((char *)pp->partyIdentity, (char *)partyID,
		     partyIDLen * sizeof(oid))){
	    cachePtr ^= 1;
	    cache[cachePtr] = pp;
	    return pp;
	}
    }
    return NULL;
}

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
    bzero((char *)pp, sizeof(struct partyEntry));

    bcopy((char *)partyID, (char *)pp->partyIdentity,
	  partyIDLen * sizeof(oid));
    pp->partyIdentityLen = partyIDLen;
    pp->partyIndex = NextIndex++;
    pp->reserved = (struct partyEntry *)malloc(sizeof(struct partyEntry));
    bzero((char *)pp->reserved, sizeof(struct partyEntry));

    pp->next = List;
    List = pp;
    return pp;
}

party_destroyEntry(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp, *lastpp;

    if (List->partyIdentityLen == partyIDLen
	&& !bcmp((char *)List->partyIdentity, (char *)partyID,
		 partyIDLen * sizeof(oid))){
	pp = List;
	List = List->next;
    } else {
	for(pp = List; pp; pp = pp->next){
	    if (pp->partyIdentityLen == partyIDLen
		&& !bcmp((char *)pp->partyIdentity, (char *)partyID,
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
