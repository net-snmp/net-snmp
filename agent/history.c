#include <sys/types.h>
#include "asn1.h"
#define NULL 0
#include "history.h"

static struct historyControlEntry *List = NULL, *ScanPtr = NULL;


struct historyControlEntry *
hc_getEntry(historyControlIndex)
    int historyControlIndex;
{
    struct historyControlEntry *hcp;

    for(hcp = List; hcp; hcp = hcp->next){
        if (hcp->historyControlIndex == historyControlIndex)
	  return hcp;
    }
    return NULL;
}

hc_scanInit()
{
  ScanPtr = List;
}

struct historyControlEntry *
hc_scanNext()
{
    struct historyControlEntry *returnval;

    /* what if entry is deleted during scan */
    returnval = ScanPtr;
    if (ScanPtr != NULL)
        ScanPtr = ScanPtr->next;
    return returnval;
}

struct historyControlEntry *
hc_createEntry(historyControlIndex)
    int historyControlIndex;
{
    struct historyControlEntry *hcp;

    hcp = (struct historyControlEntry *)malloc(sizeof(struct historyControlEntry));
    bzero((char *)hcp, sizeof(struct historyControlEntry));

    hcp->historyControlIndex = historyControlIndex;

    hcp->next = List;
    List = hcp;
    return hcp;
}

hc_destroyEntry(historyControlIndex)
    int historyControlIndex;
{
    struct historyControlEntry *hcp, *lasthcp;

    if (List->historyControlIndex  == historyControlIndex){
	hcp = List;
	List = List->next;
    } else {
	for(hcp = List; hcp; hcp = hcp->next){
	    if (hcp->historyControlIndex == historyControlIndex)
		break;
	    lasthcp = hcp;
	}
	if (!hcp)
	    return;
	lasthcp->next = hcp->next;
    }
    free(hcp);
    return;
}

struct bucketList *
hc_granted(requested)
    int *requested;
{
    struct bucketList *blp;
    int granted;

    if (*requested > 100)
        granted = 100;
    else
        granted = *requested;
    blp = (struct bucketList *)malloc(sizeof(struct bucketList));
    blp->size = granted;
    blp->buckets = (struct bucket *)malloc(granted * sizeof(struct bucket));
    *requested = granted;
    return blp;
}

hc_freeBuckets(blp)
    struct bucketList *blp;
{
    if (!blp){
      printf("Error: Free NULL Bucket pointer\n");
      return;
    }
    if (blp->buckets)
        free(blp->buckets);
    free(blp);
}
