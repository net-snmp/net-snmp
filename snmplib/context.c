#include <sys/types.h>
#include <sys/time.h>
#include "asn1.h"
#define NULL 0
#include "context.h"



static struct contextEntry *List = NULL, *ScanPtr = NULL;
static struct contextEntry *cache[2];
static int cachePtr;
static int NextIndex = 1;

struct contextEntry *
context_getEntry(contextID, contextIDLen)
    oid *contextID;
    int contextIDLen;
{
    struct contextEntry *cp;

    /* do I need a cache of two contexts??? */
    cp = cache[0];
    if (cp && contextIDLen == cp->contextIdentityLen
	&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	return cp;
    }
    cp = cache[1];
    if (cp && contextIDLen == cp->contextIdentityLen
	&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	return cp;
    }
    for(cp = List; cp; cp = cp->next){
        if (contextIDLen == cp->contextIdentityLen
	    && !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	    cachePtr ^= 1;
	    cache[cachePtr] = cp;
	    return cp;
	}
    }
    return NULL;
}

context_scanInit()
{
  ScanPtr = List;
}

struct contextEntry *
context_scanNext()
{
    struct contextEntry *returnval;

    returnval = ScanPtr;
    if (ScanPtr != NULL)
        ScanPtr = ScanPtr->next;
    return returnval;
}

struct contextEntry *
context_createEntry(contextID, contextIDLen)
    oid *contextID;
    int contextIDLen;
{
    struct contextEntry *cp;

    cp = (struct contextEntry *)malloc(sizeof(struct contextEntry));
    bzero((char *)cp, sizeof(struct contextEntry));

    bcopy((char *)contextID, (char *)cp->contextIdentity,
	  contextIDLen * sizeof(oid));
    cp->contextIdentityLen = contextIDLen;
    cp->contextIndex = NextIndex++;
    cp->reserved = (struct contextEntry *)malloc(sizeof(struct contextEntry));
    bzero((char *)cp->reserved, sizeof(struct contextEntry));

    cp->next = List;
    List = cp;
    return cp;
}

context_destroyEntry(contextID, contextIDLen)
    oid *contextID;
    int contextIDLen;
{
    struct contextEntry *cp, *lastcp;

    if (List->contextIdentityLen == contextIDLen
	&& !bcmp((char *)List->contextIdentity, (char *)contextID,
		 contextIDLen * sizeof(oid))){
	cp = List;
	List = List->next;
    } else {
	for(cp = List; cp; cp = cp->next){
	    if (cp->contextIdentityLen == contextIDLen
		&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
			 contextIDLen * sizeof(oid)))
		break;
	    lastcp = cp;
	}
	if (!cp)
	    return;
	lastcp->next = cp->next;
    }
    if (cp->reserved)
	free((char *)cp->reserved);
    free(cp);
    return;
}

