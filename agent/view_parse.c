#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
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
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "asn1.h"
#include "mib.h"
#include "view.h"

#define TRUE 1
#define FALSE 0

static void error_exit __P((char *, int, char *));

static void error_exit(str, linenumber, filename)
    char *str;
    int linenumber;
    char *filename;
{
    fprintf(stderr, "%s on line %d of %s\n", str, linenumber, filename);
    exit(1);
}

int
read_view_database(filename)
    char *filename;
{
    FILE *fp;
    char buf[256], buf1[256], buf2[256], buf3[256], buf4[256];
    char *cp;
    int blank, nonhex;
    int linenumber = 0;
    int viewIndex;
    oid viewSubtree[64];
    int viewSubtreeLen;
    int status;
    u_long byte;
    u_char mask[16], *ucp;
    int maskLen;
    struct viewEntry *vwp;

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
	
        for(cp = buf1; *cp; cp++)
            if (!isdigit(*cp))
                error_exit("Bad viewIndex value (should be decimal integer)",
                           linenumber, filename);
	viewIndex = atoi(buf1);

	viewSubtreeLen = 64;
	if (!read_objid(buf2, viewSubtree, &viewSubtreeLen))
	    error_exit("Bad object identifier", linenumber, filename);

	if (!strcasecmp(buf3, "included"))
	    status = VIEWINCLUDED;
	else if (!strcasecmp(buf3, "excluded"))
	    status = VIEWEXCLUDED;
	else
	    error_exit("Bad status field", linenumber, filename);

	if (strlen(buf4) % 2)
	    error_exit("Bad mask (should be an even number of hex digits)",
		       linenumber, filename);
	nonhex = 0;
	for(cp = buf4; *cp; cp++){
	    if (!isxdigit(*cp))
		nonhex = 1;
	}
	if (nonhex){
	    if (strcasecmp(buf4, "Null"))
		error_exit("Bad private key value (should be hex digits or null)",
			   linenumber, filename);
	    maskLen = 0;
	} else {
	    ucp = mask;
	    for(cp = buf4; *cp; cp += 2, ucp++){
		if (sscanf(cp, "%2x", &byte) != 1)
		    error_exit("Bad parse", linenumber, filename);
		*ucp = byte;
	    }
	    maskLen = ucp - mask;
	}
	

	vwp = view_getEntry(viewIndex, viewSubtree, viewSubtreeLen);
	if (!vwp)
	    vwp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
	vwp->viewType = status;
	vwp->viewMaskLen = maskLen;
	vwp->viewStorageType = 2; /* volatile */
	vwp->viewStatus = VIEWACTIVE;
	bcopy(mask, vwp->viewMask, maskLen);
#define VIEWCOMPLETE_MASK              0x3F
	/* all collumns - from view_vars.c XXX */
	vwp->viewBitMask = VIEWCOMPLETE_MASK;
	vwp->reserved->viewBitMask = vwp->viewBitMask;
    }
    fclose(fp);
    return 0;
}

