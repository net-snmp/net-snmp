#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#endif
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
#include "acl.h"



static struct aclEntry *List = NULL, *ScanPtr = NULL;

struct aclEntry *
acl_getEntry(target, subject, resources)
    int target, subject, resources;
{
    struct aclEntry *ap;

/* cache here */
    for(ap = List; ap; ap = ap->next){
        if (target == ap->aclTarget && subject == ap->aclSubject
	    && resources == ap->aclResources)
	    return ap;
    }
    return NULL;
}

void
acl_scanInit __P((void))
{
  ScanPtr = List;
}

struct aclEntry *
acl_scanNext __P((void))
{
    struct aclEntry *returnval;

    returnval = ScanPtr;
    if (ScanPtr != NULL)
        ScanPtr = ScanPtr->next;
    return returnval;
}

struct aclEntry *
acl_createEntry(target, subject, resources)
    int target, subject, resources;
{
    struct aclEntry *ap;

    ap = (struct aclEntry *)malloc(sizeof(struct aclEntry));
    memset(ap, 0, sizeof(struct aclEntry));

    ap->aclTarget = target;
    ap->aclSubject = subject;
    ap->aclResources = resources;
    ap->reserved = (struct aclEntry *)malloc(sizeof(struct aclEntry));
    memset(ap->reserved, 0, sizeof(struct aclEntry));

    ap->next = List;
    List = ap;
    return ap;
}

void
acl_destroyEntry(target, subject, resources)
    int target, subject, resources;
{
    struct aclEntry *ap, *lastap = NULL;

    if (List->aclTarget == target && List->aclSubject == subject
	&& List->aclResources == resources){
	ap = List;
	List = List->next;
    } else {
	for(ap = List; ap; ap = ap->next){
	    if (ap->aclTarget == target
		&& ap->aclSubject == subject
		&& ap->aclResources == resources)
		break;
	    lastap = ap;
	}
	if (!ap)
	    return;
	lastap->next = ap->next;
    }
    if (ap->reserved)
	free((char *)ap->reserved);
    free(ap);
    return;
}
