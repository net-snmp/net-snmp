#include <sys/types.h>
#include <sys/time.h>
#include "asn1.h"
#define NULL 0
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

acl_scanInit()
{
  ScanPtr = List;
}

struct aclEntry *
acl_scanNext()
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
    bzero((char *)ap, sizeof(struct aclEntry));

    ap->aclTarget = target;
    ap->aclSubject = subject;
    ap->aclResources = resources;
    ap->reserved = (struct aclEntry *)malloc(sizeof(struct aclEntry));
    bzero((char *)ap->reserved, sizeof(struct aclEntry));

    ap->next = List;
    List = ap;
    return ap;
}

acl_destroyEntry(target, subject, resources)
    int target, subject, resources;
{
    struct aclEntry *ap, *lastap;

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
