#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
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

void
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

void
view_destroyEntry(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    struct viewEntry *vp, *lastvp = NULL;

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

