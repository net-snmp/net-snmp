#include <sys/types.h>
#include <sys/time.h>
#include "asn1.h"
#define NULL 0
#include "view.h"



static struct viewEntry *List = NULL, *ScanPtr = NULL;


struct viewEntry *
view_getEntry(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    struct viewEntry *vp;

    for(vp = List; vp; vp = vp->next){
        if (viewIndex == vp->viewIndex
	    && viewSubtreeLen == vp->viewSubtreeLen
	    && !bcmp((char *)vp->viewSubtree, (char *)viewSubtree,
		     viewSubtreeLen * sizeof(oid)))
	  return vp;
    }
    return NULL;
}

int
view_scanInit()
{
  ScanPtr = List;
}

struct viewEntry *
view_scanNext()
{
    struct viewEntry *returnval;

    returnval = ScanPtr;
    if (ScanPtr != NULL)
        ScanPtr = ScanPtr->next;
    return returnval;
}

struct viewEntry *
view_createEntry(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    struct viewEntry *vp;

    vp = (struct viewEntry *)malloc(sizeof(struct viewEntry));
    bzero((char *)vp, sizeof(struct viewEntry));

    vp->viewIndex = viewIndex;
    bcopy((char *)viewSubtree, (char *)vp->viewSubtree,
	   viewSubtreeLen * sizeof(oid));
    vp->viewSubtreeLen = viewSubtreeLen;
    vp->reserved = (struct viewEntry *)malloc(sizeof(struct viewEntry));
    bzero((char *)vp->reserved, sizeof(struct viewEntry));

    vp->next = List;
    List = vp;
    return vp;
}

view_destroyEntry(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    struct viewEntry *vp, *lastvp;

    if (List->viewIndex == viewIndex
	&& List->viewSubtreeLen == viewSubtreeLen
	&& !bcmp((char *)List->viewSubtree, (char *)viewSubtree,
		 viewSubtreeLen * sizeof(oid))){
	vp = List;
	List = List->next;
    } else {
	for(vp = List; vp; vp = vp->next){
	    if (vp->viewIndex == viewIndex
		&& vp->viewSubtreeLen  == viewSubtreeLen 
		&& !bcmp((char *)vp->viewSubtree, (char *)viewSubtree,
			 viewSubtreeLen * sizeof(oid)))
		break;
	    lastvp = vp;
	}
	if (!vp)
	    return;
	lastvp->next = vp->next;
    }
    if (vp->reserved)
	free((char *)vp->reserved);
    free(vp);
    return;
}

