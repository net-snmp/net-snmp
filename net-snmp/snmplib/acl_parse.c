#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include "asn1.h"
#include "acl.h"
#include "party.h"
#include "context.h"

#define TRUE 1
#define FALSE 0

static error_exit(str, linenumber, filename)
    char *str;
    int linenumber;
    char *filename;
{
    fprintf(stderr, "%s on line %d of %s\n", str, linenumber, filename);
    exit(1);
}

int
read_acl_database(filename)
    char *filename;
{
    FILE *fp;
    char buf[256], buf1[256], buf2[256], buf3[256], buf4[256];
    char *cp;
    int blank;
    int linenumber = 0;
    oid targetParty[64], subjectParty[64], resources[64];
    int targetPartyLen, subjectPartyLen, resourcesLen;
    int priveleges;
    struct aclEntry *ap;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int subject, target, res;

    fp = fopen(filename, "r");
    if (fp == NULL)
	return -1;
    while (fgets(buf, 256, fp)){
	linenumber++;
	if (strlen(buf) > 250)
	    error_exit("Line longer than 250 bytes", linenumber, filename);
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

	if (sscanf(buf, "%s %s %s %s", buf1, buf2, buf3, buf4) != 4)
	    error_exit("Bad parse", linenumber, filename);
	party_scanInit();
	for(pp = party_scanNext(); pp; pp = party_scanNext()){
	    if (!strcasecmp(pp->partyName, buf1)){
		break;
	    }
	}
	if (!pp){
	    targetPartyLen = 64;
	    if (!read_objid(buf1, targetParty, &targetPartyLen))
		error_exit("Bad target object identifier", linenumber, filename);
	    
	    pp = party_getEntry(targetParty, targetPartyLen);
	    if (!pp)
		error_exit("Unknown target party identifier",
			   linenumber, filename);
	    /* why do I have subject and target mixed up here? */
	}
	subject = pp->partyIndex;

	party_scanInit();
	for(pp = party_scanNext(); pp; pp = party_scanNext()){
	    if (!strcasecmp(pp->partyName, buf2)){
		break;
	    }
	}
	if (!pp){
	    subjectPartyLen = 64;
	    if (!read_objid(buf2, subjectParty, &subjectPartyLen))
		error_exit("Bad subject object identifier", linenumber, filename);
	    
	    
	    pp = party_getEntry(subjectParty, subjectPartyLen);
	    if (!pp)
		error_exit("Unknown subject party identifier",
			   linenumber, filename);
	}
	target = pp->partyIndex;
	
	context_scanInit();
	for(cxp = context_scanNext(); cxp; cxp = context_scanNext()){
	    if (!strcasecmp(cxp->contextName, buf3)){
		break;
	    }
	}
	if (!cxp){
	    resourcesLen = 64;
	    if (!read_objid(buf3, resources, &resourcesLen))
		error_exit("Bad context object identifier", linenumber, filename);
	    
	    cxp = context_getEntry(resources, resourcesLen);
	    if (!cxp)
		error_exit("Unknown context identifier", linenumber, filename);
	}
	res = cxp->contextIndex;

	priveleges = 0;
	for(cp = buf4; *cp; cp++){
	    switch(*cp){
	      case 'g':
	      case 'G':
		priveleges |= ACLPRIVELEGESGET;
		break;
	      case 'n':
	      case 'N':
		priveleges |= ACLPRIVELEGESGETNEXT;
		break;
	      case 'r':
	      case 'R':
		priveleges |= ACLPRIVELEGESGETRESPONSE;
		break;
	      case 's':
	      case 'S':
		priveleges |= ACLPRIVELEGESSET;
		break;
#if 0
	      case 't':
	      case 'T':
		priveleges |= ACLPRIVELEGESTRAP;
		break;
#endif
	      case 'b':
	      case 'B':
		priveleges |= ACLPRIVELEGESBULK;
		break;
	      case 'i':
	      case 'I':
		priveleges |= ACLPRIVELEGESINFORM;
		break;
	      case 'u':	/* find a better letter XXXXXXXXX */
	      case 'U':
		priveleges |= ACLPRIVELEGESTRAP2;
		break;
	      default:
		error_exit("Bad priveleges code", linenumber, filename);
		break;
	    }
	}

	ap = acl_getEntry(target, subject, res);
	if (!ap)
	    ap = acl_createEntry(target, subject, res);
	ap->aclPriveleges = priveleges;
	ap->aclStorageType = 2; /* volatile */
	ap->aclStatus = ACLACTIVE;
#define ACLCOMPLETE_MASK              0x3F
	/* all collumns - from acl_vars.c XXX */
	ap->aclBitMask = ACLCOMPLETE_MASK;
	ap->reserved->aclBitMask = ap->aclBitMask;
    }
    fclose(fp);
    return 0;
}

