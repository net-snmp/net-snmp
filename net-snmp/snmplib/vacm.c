/*
 * vacm.c
 *
 * SNMPv3 View-based Access Control Model
 */

#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "vacm.h"


static struct vacm_viewEntry *viewList = NULL, *viewScanPtr = NULL;
static struct vacm_accessEntry *accessList = NULL, *accessScanPtr = NULL;
static struct vacm_groupEntry *groupList = NULL, *groupScanPtr = NULL;

struct vacm_viewEntry *
vacm_getViewEntry(viewName, viewSubtree, viewSubtreeLen)
    char *viewName;
    oid *viewSubtree;
    int viewSubtreeLen;
{
    struct vacm_viewEntry *vp;
    char view[32];

    view[0] = strlen(viewName);
    strcpy(view+1, viewName);
    for(vp = viewList; vp; vp = vp->next){
        if (!strcmp(view, vp->viewName)
	    && viewSubtreeLen >= vp->viewSubtreeLen) {
	    int mask = 0x80, maskpos = 0;
	    int oidpos;
	    for (oidpos = 0; oidpos < vp->viewSubtreeLen; oidpos++) {
		if ((vp->viewMask[maskpos] & mask) != 0) {
		    if (viewSubtree[oidpos] != vp->viewSubtree[oidpos])
			return NULL;
		}
		if (mask == 1) {
		    mask = 0x80;
		    maskpos++;
		}
		else mask >>= 1;
	    }
	    return vp;
	}
    }
    return NULL;
}

void
vacm_scanViewInit __P((void))
{
    viewScanPtr = viewList;
}

struct vacm_viewEntry *
vacm_scanViewNext __P((void))
{
    struct vacm_viewEntry *returnval = viewScanPtr;
    if (viewScanPtr) viewScanPtr = viewScanPtr->next;
    return returnval;
}

struct vacm_viewEntry *
vacm_createViewEntry(viewName, viewSubtree, viewSubtreeLen)
    char *viewName;
    oid *viewSubtree;
    int viewSubtreeLen;
{
    struct vacm_viewEntry *vp, *lp, *op = NULL;
    int cmp;

    vp = (struct vacm_viewEntry *)malloc(sizeof(struct vacm_viewEntry));
    memset(vp, 0, sizeof(struct vacm_viewEntry));

    vp->viewName[0] = strlen(viewName);
    strcpy(vp->viewName+1, viewName);
    memcpy(vp->viewSubtree, viewSubtree, viewSubtreeLen * sizeof(oid));
    vp->viewSubtreeLen = viewSubtreeLen;
    vp->reserved = (struct vacm_viewEntry *)malloc(sizeof(struct vacm_viewEntry));
    memset(vp->reserved, 0, sizeof(struct vacm_viewEntry));

    lp = viewList;
    while (lp) {
	cmp = strcmp(lp->viewName, vp->viewName);
	if (cmp > 0) break;
	if (cmp < 0) goto next;
	
next:
	op = lp;
	lp = lp->next;
    }
    vp->next = lp;
    if (op) op->next = vp;
    else viewList = vp;
    return vp;
}

void
vacm_destroyViewEntry(viewName, viewSubtree, viewSubtreeLen)
    char *viewName;
    oid *viewSubtree;
    int viewSubtreeLen;
{
    struct vacm_viewEntry *vp, *lastvp = NULL;

    if (viewList && !strcmp(viewList->viewName, viewName)
	&& viewList->viewSubtreeLen == viewSubtreeLen
	&& !memcmp((char *)viewList->viewSubtree, (char *)viewSubtree,
		 viewSubtreeLen * sizeof(oid))){
	vp = viewList;
	viewList = viewList->next;
    } else {
	for (vp = viewList; vp; vp = vp->next){
	    if (!strcmp(vp->viewName, viewName)
		&& vp->viewSubtreeLen  == viewSubtreeLen 
		&& !memcmp((char *)vp->viewSubtree, (char *)viewSubtree,
			 viewSubtreeLen * sizeof(oid)))
		break;
	    lastvp = vp;
	}
	if (!vp)
	    return;
	lastvp->next = vp->next;
    }
    if (vp->reserved)
	free(vp->reserved);
    free(vp);
    return;
}

void vacm_destroyAllViewEntries __P((void))
{
    struct vacm_viewEntry *vp;
    while ((vp = viewList)) {
	viewList = vp->next;
	if (vp->reserved) free(vp->reserved);
	free(vp);
    }
}

struct vacm_groupEntry *
vacm_getGroupEntry(securityModel, securityName)
    int securityModel;
    char *securityName;
{
    struct vacm_groupEntry *vp;
    char secname[32];

    secname[0] = strlen(securityName);
    strcpy(secname+1, securityName);

    for (vp = groupList; vp; vp = vp->next) {
	if ((securityModel == vp->securityModel || vp->securityModel == SNMP_SEC_MODEL_ANY)
	    && !strcmp(vp->securityName, secname))
	return vp;
    }
    return NULL;
}

void
vacm_scanGroupInit __P((void))
{
    groupScanPtr = groupList;
}

struct vacm_groupEntry *
vacm_scanGroupNext __P((void))
{
    struct vacm_groupEntry *returnval = groupScanPtr;
    if (groupScanPtr) groupScanPtr = groupScanPtr->next;
    return returnval;
}

struct vacm_groupEntry *
vacm_createGroupEntry(securityModel, securityName)
    int securityModel;
    char *securityName;
{
    struct vacm_groupEntry *gp, *lg, *og;
    int cmp;

    gp = (struct vacm_groupEntry *)malloc(sizeof(struct vacm_groupEntry));
    memset(gp, 0, sizeof(struct vacm_groupEntry));

    gp->securityModel = securityModel;
    gp->securityName[0] = strlen(securityName);
    strcpy(gp->securityName+1, securityName);
    gp->reserved = (struct vacm_groupEntry *)malloc(sizeof(struct vacm_groupEntry));
    memset(gp->reserved, 0, sizeof(struct vacm_groupEntry));

    lg = groupList;
    og = NULL;
    while (lg) {
	if (lg->securityModel > securityModel) break;
	if (lg->securityModel == securityModel && 
	    (cmp = strcmp(lg->securityName, gp->securityName)) > 0) break;
	/* if (lg->securityModel == securityModel && cmp == 0) abort(); */
	og = lg; lg = lg->next;
    }
    gp->next = lg;
    if (og == NULL) groupList = gp;
    else og->next = gp;
    return gp;
}

void
vacm_destroyGroupEntry(securityModel, securityName)
    int securityModel;
    char *securityName;
{
    struct vacm_groupEntry *vp, *lastvp = NULL;

    if (groupList && groupList->securityModel == securityModel
	&& !strcmp(groupList->securityName, securityName)) {
	vp = groupList;
	groupList = groupList->next;
    } else {
	for (vp = groupList; vp; vp = vp->next){
	    if (vp->securityModel == securityModel
		&& !strcmp(vp->securityName, securityName))
		break;
	    lastvp = vp;
	}
	if (!vp)
	    return;
	lastvp->next = vp->next;
    }
    if (vp->reserved)
	free(vp->reserved);
    free(vp);
    return;
}

void vacm_destroyAllGroupEntries __P((void))
{
    struct vacm_groupEntry *gp;
    while ((gp = groupList)) {
	groupList = gp->next;
	if (gp->reserved) free(gp->reserved);
	free(gp);
    }
}

struct vacm_accessEntry *
vacm_getAccessEntry(groupName, contextPrefix, securityModel, securityLevel)
    char *groupName, *contextPrefix;
    int securityModel, securityLevel;
{
    struct vacm_accessEntry *vp;
    char group[32];
    char context[32];

    group[0] = strlen(groupName);
    strcpy(group+1, groupName);
    context[0] = strlen(contextPrefix);
    strcpy(context+1, contextPrefix);
    for(vp = accessList; vp; vp = vp->next){
        if ((securityModel == vp->securityModel || vp->securityModel == SNMP_SEC_MODEL_ANY)
	    && securityLevel == vp->securityLevel
	    && !strcmp(vp->groupName, group)
	    && !strcmp(vp->contextPrefix, context))
	  return vp;
    }
    return NULL;
}

void
vacm_scanAccessInit __P((void))
{
    accessScanPtr = accessList;
}

struct vacm_accessEntry *
vacm_scanAccessNext __P((void))
{
    struct vacm_accessEntry *returnval = accessScanPtr;
    if (accessScanPtr) accessScanPtr = accessScanPtr->next;
    return returnval;
}

struct vacm_accessEntry *
vacm_createAccessEntry(groupName, contextPrefix, securityModel, securityLevel)
    char *groupName, *contextPrefix;
    int securityModel, securityLevel;
{
    struct vacm_accessEntry *vp, *lp, *op = NULL;
    int cmp;

    vp = (struct vacm_accessEntry *)malloc(sizeof(struct vacm_accessEntry));
    memset(vp, 0, sizeof(struct vacm_accessEntry));

    vp->securityModel = securityModel;
    vp->securityLevel = securityLevel;
    vp->groupName[0] = strlen(groupName);
    strcpy(vp->groupName+1, groupName);
    vp->contextPrefix[0] = strlen(contextPrefix);
    strcpy(vp->contextPrefix+1, contextPrefix);
    vp->reserved = (struct vacm_accessEntry *)malloc(sizeof(struct vacm_accessEntry));
    memset(vp->reserved, 0, sizeof(struct vacm_accessEntry));

    lp = accessList;
    while (lp) {
	cmp = strcmp(lp->groupName, vp->groupName);
	if (cmp > 0) break;
	if (cmp < 0) goto next;
	cmp = strcmp(lp->contextPrefix, vp->contextPrefix);
	if (cmp > 0) break;
	if (cmp < 0) goto next;
	if (lp->securityModel > securityModel) break;
	if (lp->securityModel < securityModel) goto next;
	if (lp->securityLevel > securityLevel) break;
next:
	op = lp;
	lp = lp->next;
    }
    vp->next = lp;
    if (op == NULL) accessList = vp;
    else op->next = vp;
    return vp;
}

void
vacm_destroyAccessEntry(groupName, contextPrefix, securityModel, securityLevel)
    char *groupName, *contextPrefix;
    int securityModel, securityLevel;
{
    struct vacm_accessEntry *vp, *lastvp = NULL;

    if (accessList && accessList->securityModel == securityModel
	&& accessList->securityModel == securityModel
	&& !strcmp(accessList->groupName, groupName)
	&& !strcmp(accessList->contextPrefix, contextPrefix)) {
	vp = accessList;
	accessList = accessList->next;
    } else {
	for (vp = accessList; vp; vp = vp->next){
	    if (vp->securityModel == securityModel
		&& vp->securityLevel == securityLevel
		&& !strcmp(vp->groupName, groupName)
		&& !strcmp(vp->contextPrefix, contextPrefix))
		break;
	    lastvp = vp;
	}
	if (!vp)
	    return;
	lastvp->next = vp->next;
    }
    if (vp->reserved)
	free(vp->reserved);
    free(vp);
    return;
}

void vacm_destroyAllAccessEntries __P((void))
{
    struct vacm_accessEntry *ap;
    while ((ap = accessList)) {
	accessList = ap->next;
	if (ap->reserved) free(ap->reserved);
	free(ap);
    }
}
