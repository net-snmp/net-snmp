#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "asn1.h"
#include "context.h"
#include "system.h"

#define TRUE 1
#define FALSE 0

#define IDENTITY_STATE  1
#define VIEW_STATE	2
#define PROXY_STATE  	3

static error_exit(str, linenumber, filename)
    char *str;
    int linenumber;
    char *filename;
{
    fprintf(stderr, "%s on line %d of %s\n", str, linenumber, filename);
    exit(1);
}

int
read_context_database(filename)
    char *filename;
{
    FILE *fp;
    char buf[256], buf1[256], buf2[256], buf3[256];
    char *cp;
    int blank, nonhex;
    int linenumber = 0, chars = 0, clock_pos;
    int state = IDENTITY_STATE;
    oid contextid[64];
    int contextidlen;
    int view, entityLen, time;
    u_char entity[64];
    int dstParty, srcParty, proxyIdLen;
    oid proxyId[64];
    char name[64];	/* friendly name */
    struct contextEntry *cxp, *rp;
    u_long myaddr;
    int diff;

    fp = fopen(filename, "r");
    if (fp == NULL)
	return -1;
    while (fgets(buf, 256, fp)){
	linenumber++;
	if (strlen(buf) > 250)
	    error_exit("Line longer than 250 bytes", linenumber, filename);
	chars += strlen(buf);
	if (buf[0] == '#')
	    continue;
	blank = TRUE;
	for(cp = buf; *cp; cp++)
	    if (!isspace(*cp)){
		blank = FALSE;
		break;
	    }
	if (blank)
	    continue;
	switch(state){
	  case IDENTITY_STATE:
	    if (sscanf(buf, "%s %s", name, buf1) != 2)
		error_exit("Bad parse", linenumber, filename);
	    contextidlen = 64;
	    if (!read_objid(buf1, contextid, &contextidlen))
		error_exit("Bad object identifier", linenumber, filename);
	    state = VIEW_STATE;
	    break;
	  case VIEW_STATE:
	    if (sscanf(buf, "%s %s %s", buf1, entity, buf3) != 3)
		error_exit("Bad parse", linenumber, filename);
	    for(cp = buf1; *cp; cp++)
		if (!isdigit(*cp))
		    error_exit("Not a view index", linenumber, filename);
	    view = atoi(buf1);
	    if (!strcasecmp(entity, "Null"))
		entityLen = 0;
	    if (!strcasecmp(buf3, "currentTime"))
		time = CURRENTTIME;
	    else if (!strcasecmp(buf3, "restartTime"))
		time = RESTARTTIME;
	    else
		error_exit("Bad local time", linenumber, filename);
	    state = PROXY_STATE;
	    break;
	  case PROXY_STATE:
	    if (sscanf(buf, "%s %s %s", buf1, buf2, buf3) != 3)
		error_exit("Bad parse", linenumber, filename);
	    for(cp = buf1; *cp; cp++)
		if (!isdigit(*cp))
		    error_exit("Bad destination party index", linenumber,
			       filename);
	    dstParty = atoi(buf1);

	    for(cp = buf1; *cp; cp++)
		if (!isdigit(*cp))
		    error_exit("Bad source party index", linenumber, filename);
	    srcParty = atoi(buf2);

	    proxyIdLen = 64;
	    if (!read_objid(buf3, proxyId, &proxyIdLen))
		error_exit("Bad object identifier", linenumber, filename);

	    state = IDENTITY_STATE;

	    cxp = context_getEntry(contextid, contextidlen);
	    if (!cxp)
		cxp = context_createEntry(contextid, contextidlen);
	    rp = cxp->reserved;
	    strcpy(cxp->contextName, name);
	    myaddr = get_myaddr();
	    /* XXX It's bogus to figure out if it is local
	       by testing the ipaddress in the context - fix this XXX */
	    diff  = ((myaddr & 0xFF000000) >> 24) ^ contextid[9];
	    diff |= ((myaddr & 0x00FF0000) >> 16) ^ contextid[10];
	    diff |= ((myaddr & 0x0000FF00) >> 8) ^ contextid[11];
	    diff |= (myaddr & 0x000000FF) ^ contextid[12];
	    if (!diff){
		/* context is local */
		cxp->contextLocal = 1; /* TRUE */
	    } else {
		cxp->contextLocal = 2; /* FALSE */
	    }
	    cxp->contextViewIndex = view;
	    bcopy(entity, cxp->contextLocalEntity, entityLen);
	    cxp->contextLocalEntityLen = entityLen;
	    cxp->contextLocalTime = time;
	    cxp->contextDstPartyIndex = dstParty;
	    cxp->contextSrcPartyIndex = srcParty;
	    bcopy(proxyId, cxp->contextProxyContext, proxyIdLen * sizeof(oid));
	    cxp->contextProxyContextLen = proxyIdLen;
	    cxp->contextStorageType = 2;
	    cxp->contextStatus = rp->contextStatus = CONTEXTACTIVE;
#define CONTEXTCOMPLETE_MASK              0x03FF
	    /* all collumns - from context_vars.c XXX */
	    cxp->contextBitMask = rp->contextBitMask = CONTEXTCOMPLETE_MASK;
	    break;
	  default:
	    error_exit("unknown state", linenumber, filename);
	}
    }
    if (state != IDENTITY_STATE)
	error_exit("Unfinished entry at EOF", linenumber, filename);
    fclose(fp);
    return 0;
}
