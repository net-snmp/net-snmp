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
#ifdef SVR4
	&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#endif
	return cp;
    }
    cp = cache[1];
    if (cp && contextIDLen == cp->contextIdentityLen
#ifdef SVR4
	&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#endif
	return cp;
    }
    for(cp = List; cp; cp = cp->next){
        if (contextIDLen == cp->contextIdentityLen
#ifdef SVR4
	    && !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#else
	    && !bcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
#endif
	    cachePtr ^= 1;
	    cache[cachePtr] = cp;
	    return cp;
	}
    }
    return NULL;
}

int
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
#ifdef SVR4
    memset((char *)cp, NULL, sizeof(struct contextEntry));
#else
    bzero((char *)cp, sizeof(struct contextEntry));
#endif

#ifdef SVR4
    memmove((char *)cp->contextIdentity, (char *)contextID,
	  contextIDLen * sizeof(oid));
#else
    bcopy((char *)contextID, (char *)cp->contextIdentity,
	  contextIDLen * sizeof(oid));
#endif
    cp->contextIdentityLen = contextIDLen;
    cp->contextIndex = NextIndex++;
    cp->reserved = (struct contextEntry *)malloc(sizeof(struct contextEntry));
#ifdef SVR4
    memset((char *)cp->reserved, NULL, sizeof(struct contextEntry));
#else
    bzero((char *)cp->reserved, sizeof(struct contextEntry));
#endif

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
#ifdef SVR4
	&& !memcmp((char *)List->contextIdentity, (char *)contextID,
		 contextIDLen * sizeof(oid))){
#else
	&& !bcmp((char *)List->contextIdentity, (char *)contextID,
		 contextIDLen * sizeof(oid))){
#endif
	cp = List;
	List = List->next;
    } else {
	for(cp = List; cp; cp = cp->next){
	    if (cp->contextIdentityLen == contextIDLen
#ifdef SVR4
		&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
			 contextIDLen * sizeof(oid)))
#else
		&& !bcmp((char *)cp->contextIdentity, (char *)contextID,
			 contextIDLen * sizeof(oid)))
#endif
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

