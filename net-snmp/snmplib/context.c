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
#ifndef NULL
# define NULL 0
#endif
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
	&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	return cp;
    }
    cp = cache[1];
    if (cp && contextIDLen == cp->contextIdentityLen
	&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	return cp;
    }
    for(cp = List; cp; cp = cp->next){
        if (contextIDLen == cp->contextIdentityLen
	    && !memcmp((char *)cp->contextIdentity, (char *)contextID,
		     contextIDLen * sizeof(oid))){
	    cachePtr ^= 1;
	    cache[cachePtr] = cp;
	    return cp;
	}
    }
    return NULL;
}

void
context_scanInit __P((void))
{
  ScanPtr = List;
}

struct contextEntry *
context_scanNext __P((void))
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
    memset((char *)cp, 0, sizeof(struct contextEntry));

    memmove((char *)cp->contextIdentity, (char *)contextID,
	  contextIDLen * sizeof(oid));
    cp->contextIdentityLen = contextIDLen;
    cp->contextIndex = NextIndex++;
    cp->reserved = (struct contextEntry *)malloc(sizeof(struct contextEntry));
    memset((char *)cp->reserved, 0, sizeof(struct contextEntry));

    cp->next = List;
    List = cp;
    return cp;
}

void
context_destroyEntry(contextID, contextIDLen)
    oid *contextID;
    int contextIDLen;
{
    struct contextEntry *cp, *lastcp = NULL;

    if (List->contextIdentityLen == contextIDLen
	&& !memcmp((char *)List->contextIdentity, (char *)contextID,
		 contextIDLen * sizeof(oid))){
	cp = List;
	List = List->next;
    } else {
	for(cp = List; cp; cp = cp->next){
	    if (cp->contextIdentityLen == contextIDLen
		&& !memcmp((char *)cp->contextIdentity, (char *)contextID,
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

