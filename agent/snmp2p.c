/*
 *   snmp2p.c - SNMP v2 (historic) party handling
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#include <config.h>

#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
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

#include "mib_module_config.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "system.h"
#include "snmp.h"

#include "m2m.h"
#include "party.h"
#ifdef USING_V2PARTY_ALARM_MODULE
#include "mibgroup/v2party/alarm.h"
#endif
#if USING_V2PARTY_EVENT_MODULE
#include "mibgroup/v2party/event.h"
#endif
#include "view.h"
#include "context.h"
#include "acl.h"
#include "mib.h"
#include "snmpd.h"

static int agent_party_init __P((in_addr_t, u_short, char *));

/*
 * In: My ip address, View subtree
 * Initializes a noAuth/noPriv party pair, a context, 2 acl entries, and
 * a view subtree. (Are two acl entries really needed?)
 * The view subtree is included by default and has no Mask.
 * Out: returns 0 if OK, 1 if conflict with a pre-installed
 * party/context/acl/view, -1 if an error occurred.
 */
static int
agent_party_init(myaddr, dest_port, view)
    in_addr_t myaddr;
    u_short dest_port;
    char *view;
{
    in_addr_t addr;
    unsigned char *adp;
    u_short port;
    oid partyid1[64];
    int partyidlen1;
    oid partyid2[64];
    int partyidlen2;
    oid contextid[64];
    int contextidlen;
    struct partyEntry *pp1, *pp2, *rp;
    struct contextEntry *cxp, *rxp;
    int viewIndex;
    oid viewSubtree[64];
    int viewSubtreeLen;
    struct viewEntry *vwp;
    struct aclEntry *ap;
    int oneIndex, twoIndex, cxindex;

    
    /*
     * Check for existence of the party, context, acl, and view and
     * exit if any of them exist.  We must create the parties to get the
     * partyIndexes for acl creation, so we delete these parties if we
     * fail anywhere else.
     */
    /* This would be better written as follows:
       We currently check for the existence of each of the
       src/dst/context/acl/view entries before creating anything.
       The problem is that in order to check for the existence of the
       acl entry, we need to create the src/dst/context to get their
       indexes.  So we create them with the proviso that we delete them
       if checks for other src/dst/context/view/acl fail.  [BUG:  we don't
       delete context and view if acl fails or context if view fails].
       Observation:  Because each index for the acl table is taken from
       a newly-created and therefore unique src/dst/context index, there
       is no reason to check for the existence of such an acl entry.
       Therefore, there is no reason to create the party entries until
       *after* we have checked everything.  This greatly simplifies this code.
       In addition, nobody cares what the view index is, so there is no need
       to check for the view's existence (just choose something that isn't
       in use.

       Suggestion:
       check src
       check dst
       check context
       if any used, fail 1
       create src, dst, context
       create acl(src.index, dst.index, context.index) and its brother
       find an unused view index (preferably one)
       create viewEntry(viewIndex, viewSubtree)
       context.viewIndex = viewIndex
     */
    partyidlen1 = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.3.128.2.35.55.1",
		    partyid1, &partyidlen1)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.3.128.2.35.55.1");
	return -1;
    }
    adp = (unsigned char *)&myaddr;
    partyid1[9] =  adp[0];
    partyid1[10] = adp[1];
    partyid1[11] = adp[2];
    partyid1[12] = adp[3];
    partyid1[13] = 1;
    pp1 = party_getEntry(partyid1, partyidlen1);
    if (pp1){
	return 1;
    }
    pp1 = party_createEntry(partyid1, partyidlen1);
    oneIndex = pp1->partyIndex;

    partyidlen2 = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.3.128.2.35.55.1",
		    partyid2, &partyidlen2)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.3.128.2.35.55.1");
	party_destroyEntry(partyid1, partyidlen1);
	return -1;
    }
    partyid2[9] =  adp[0];
    partyid2[10] = adp[1];
    partyid2[11] = adp[2];
    partyid2[12] = adp[3];
    partyid2[13] = 2;
    pp2 = party_getEntry(partyid2, partyidlen2);
    if (pp2){
	party_destroyEntry(partyid1, partyidlen1);
	return 1;
    }
    pp2 = party_createEntry(partyid2, partyidlen2);
    twoIndex = pp2->partyIndex;

    contextidlen = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.4.128.2.35.55.1",
		    contextid, &contextidlen)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.4.128.2.35.55.1");
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return -1;
    }
    contextid[9] =  adp[0];
    contextid[10] = adp[1];
    contextid[11] = adp[2];
    contextid[12] = adp[3];
    contextid[13] = 1;
    cxp = context_getEntry(contextid, contextidlen);
    if (cxp){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    viewIndex = 1;
    viewSubtreeLen = 64;
    if (!read_objid(view, viewSubtree, &viewSubtreeLen)){
	fprintf(stderr, "Bad object identifier: %s\n", view);
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return -1;
    }
    vwp = view_getEntry(viewIndex, viewSubtree, viewSubtreeLen);
    if (vwp){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    ap = acl_getEntry(oneIndex, twoIndex, 1);
    if (ap){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }
    ap = acl_getEntry(twoIndex, oneIndex, 1);
    if (ap){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    rp = pp1->reserved;
    strcpy(pp1->partyName, "noAuthAgent");
    pp1->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
    addr = htonl(myaddr);
    port = htons(dest_port);
    memcpy(pp1->partyTAddress, &addr, sizeof(addr));
    memcpy(pp1->partyTAddress + 4, &port, sizeof(port));
    memcpy(rp->partyTAddress, pp1->partyTAddress, 6);
    pp1->partyTAddressLen = rp->partyTAddressLen = 6;
    pp1->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
    pp1->partyAuthClock = rp->partyAuthClock = 0;
    pp1->tv.tv_sec = pp1->partyAuthClock;
    pp1->partyAuthPublicLen = 0;
    pp1->partyAuthLifetime = rp->partyAuthLifetime = 0;
    pp1->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
    pp1->partyPrivPublicLen = 0;
    pp1->partyMaxMessageSize = rp->partyMaxMessageSize = 1500;
    pp1->partyLocal = 1; /* TRUE */
    pp1->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
    pp1->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
    pp1->partyStorageType = SNMP_STORAGE_VOLATILE;
    pp1->partyStatus = rp->partyStatus = SNMP_ROW_ACTIVE;
#define PARTYCOMPLETE_MASK              65535
    /* all collumns - from party_vars.c XXX */
    pp1->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;

    rp = pp2->reserved;
    strcpy(pp2->partyName, "noAuthMS");
    pp2->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
    memset(pp2->partyTAddress, 0, 6);
    memcpy(rp->partyTAddress, pp2->partyTAddress, 6);
    pp2->partyTAddressLen = rp->partyTAddressLen = 6;
    pp2->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
    pp2->partyAuthClock = rp->partyAuthClock = 0;
    pp2->tv.tv_sec = pp2->partyAuthClock;
    pp2->partyAuthPublicLen = 0;
    pp2->partyAuthLifetime = rp->partyAuthLifetime = 0;
    pp2->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
    pp2->partyPrivPublicLen = 0;
    pp2->partyMaxMessageSize = rp->partyMaxMessageSize = 484; /* ??? */
    pp2->partyLocal = 2; /* FALSE */
    pp2->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
    pp2->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
    pp2->partyStorageType = SNMP_STORAGE_VOLATILE;
    pp2->partyStatus = rp->partyStatus = SNMP_ROW_ACTIVE;
    pp2->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
 
    cxp = context_createEntry(contextid, contextidlen);
    rxp = cxp->reserved;
    strcpy(cxp->contextName, "noAuthContext");
    cxp->contextLocal = 1; /* TRUE */
    cxp->contextViewIndex = 1;
    cxp->contextLocalEntityLen = 0;
    cxp->contextLocalTime = CURRENTTIME;
    cxp->contextProxyContextLen = 0;
    cxp->contextStorageType = SNMP_STORAGE_VOLATILE;
    cxp->contextStatus = rxp->contextStatus = SNMP_ROW_ACTIVE;
#define CONTEXTCOMPLETE_MASK              0x03FF
    /* all collumns - from context_vars.c XXX */
    cxp->contextBitMask = rxp->contextBitMask = CONTEXTCOMPLETE_MASK;
    cxindex = cxp->contextIndex;

    vwp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
    vwp->viewType = VIEWINCLUDED;
    vwp->viewMaskLen = 0;
    vwp->viewStorageType = SNMP_STORAGE_VOLATILE;
    vwp->viewStatus = SNMP_ROW_ACTIVE;
#define VIEWCOMPLETE_MASK              0x3F
    /* all collumns - from view_vars.c XXX */
    vwp->viewBitMask = VIEWCOMPLETE_MASK;
    vwp->reserved->viewBitMask = vwp->viewBitMask;

    viewSubtreeLen = 64;
    if (!read_objid(".2.6.6", viewSubtree, &viewSubtreeLen)){
	fprintf(stderr, "Bad object identifier: .2.6.6\n");
	return -1;
    }
    vwp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
    vwp->viewType = VIEWINCLUDED;
    vwp->viewMaskLen = 0;
    vwp->viewStorageType = SNMP_STORAGE_VOLATILE;
    vwp->viewStatus = SNMP_ROW_ACTIVE;
    vwp->viewBitMask = VIEWCOMPLETE_MASK;
    vwp->reserved->viewBitMask = vwp->viewBitMask;

    ap = acl_createEntry(oneIndex, twoIndex, cxindex);
    ap->aclPriveleges = 132;
    ap->aclStorageType = SNMP_STORAGE_VOLATILE;
    ap->aclStatus = SNMP_ROW_ACTIVE;
#define ACLCOMPLETE_MASK              0x3F
    /* all collumns - from acl_vars.c XXX */
    ap->aclBitMask = ACLCOMPLETE_MASK;
    ap->reserved->aclBitMask = ap->aclBitMask;

    ap = acl_createEntry(twoIndex, oneIndex, cxindex);
    /* To play around with SETs with a minimum of hassle, set this to 43
       and noAuth/noPriv parties will be able to set in this default view.
       Remember to turn it back off when you're done! */
    ap->aclPriveleges = 35;
    ap->aclStorageType = SNMP_STORAGE_VOLATILE;
    ap->aclStatus = SNMP_ROW_ACTIVE;
    ap->aclBitMask = ACLCOMPLETE_MASK;
    ap->reserved->aclBitMask = ap->aclBitMask;

    return 0; /* SUCCESS */
}


void
init_snmp2p( dest_port )
    u_short dest_port;
{
    in_addr_t myaddr;
    char miscfile[300];
    int ret;
    
    sprintf(miscfile,"%s/party.conf",SNMPSHAREPATH);
    if (read_party_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read party database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/context.conf",SNMPSHAREPATH);
    if (read_context_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read context database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/acl.conf",SNMPSHAREPATH);
    if (read_acl_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read acl database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/view.conf",SNMPSHAREPATH);
    if (read_view_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read view database from %s\n",miscfile);
	exit(0);
    }
    
    /* XXX mib-2 subtree only??? */
    myaddr = get_myaddr();
    if ((ret = agent_party_init(myaddr, dest_port, ".1.3.6.1"))){
	if (ret == 1){
	    fprintf(stderr, "Conflict found with initial noAuth/noPriv parties... continuing\n");
	} else if (ret == -1){
	    fprintf(stderr, "Error installing initial noAuth/noPriv parties, exiting\n");
	    exit(1);
	} else {
	    fprintf(stderr, "Unknown error, exiting\n");
	    exit(2);
	}
    }
}

void
open_ports_snmp2p __P((void))
{
    struct partyEntry *pp;
    in_addr_t myaddr;
    u_short dest_port;
    int ret;
    
    party_scanInit();
    myaddr = get_myaddr();
    for(pp = party_scanNext(); pp; pp = party_scanNext()){
#if WORDS_BIGENDIAN
        if ((pp->partyTDomain != DOMAINSNMPUDP)
	    || memcmp(&myaddr, pp->partyTAddress, 4))
          continue;	/* don't listen for non-local parties */
#else
	if ((pp->partyTDomain != DOMAINSNMPUDP)
	    || memcmp(reverse_bytes((char *) &myaddr,sizeof(myaddr)),
                    pp->partyTAddress, 4))
          continue;	/* don't listen for non-local parties */
#endif
	
	dest_port = 0;
#if WORDS_BIGENDIAN
	memcpy(&dest_port, pp->partyTAddress + 4, 2);
#else
	memcpy(&dest_port, reverse_bytes(pp->partyTAddress + 4,2), 2);
#endif
        if (( ret = open_port( dest_port )) > 0 )
            sd_handlers[ret-1] = snmp_read_packet;
        else if ( ret < 0 )
            return;
        /* ret == 0 implies we're already listening on this port */
    }
}    
