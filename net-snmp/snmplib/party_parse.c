#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include "asn1.h"
#include "party.h"
#include "system.h"

#define TRUE 1
#define FALSE 0

#define IDENTITY_STATE  1
#define TRANSPORT_STATE	2
#define PROTOCOL_STATE  3
#define LIFETIME_STATE  4
#define CLOCK_STATE	5
#define AUTH_STATE	6
#define PRIV_STATE 	7

static oid noProxy[] = {1, 3, 6, 1, 2, 1, 20, 1, 3, 1};

static error_exit(str, linenumber, filename)
    char *str;
    int linenumber;
    char *filename;
{
    fprintf(stderr, "%s on line %d of %s\n", str, linenumber, filename);
    exit(1);
}

int
read_party_database(filename)
    char *filename;
{
    FILE *fp;
    char buf[256], buf1[256], buf2[256], buf3[256];
    char *cp;
    int blank, nonhex;
    int linenumber = 0, chars = 0, clock_pos;
    int state = IDENTITY_STATE;
    u_long addr;
    u_short port;
    oid partyid[64];
    int partyidlen;
    int priv, auth, proxy;
    int lifetime, maxmessagesize;
    u_long clock;
    u_char privPrivate[32], authPrivate[32], privPublic[64], authPublic[64];
    u_char *ucp;
    u_long byte;
    int privPublicLength, authPublicLength;
    char name[64];	/* friendly name */
    struct partyEntry *pp, *rp;
    u_long myaddr;
    int domain;

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
	    partyidlen = 64;
	    if (!read_objid(buf1, partyid, &partyidlen))
		error_exit("Bad object identifier", linenumber, filename);
	    state = TRANSPORT_STATE;
	    break;
	  case TRANSPORT_STATE:
	    if (sscanf(buf, "%s %s %s", buf1, buf2, buf3) != 3)
		error_exit("Bad parse", linenumber, filename);
	    if (!strcasecmp(buf1, "snmpUdpDomain"))
		domain = DOMAINSNMPUDP;
	    else
		error_exit("Bad protocol type", linenumber, filename);
	    if ((addr = inet_addr(buf2)) == -1)
		error_exit("Bad IP address", linenumber, filename);
	    for(cp = buf3; *cp; cp++)
		if (!isdigit(*cp))
		    error_exit("Not a port number", linenumber, filename);
	    port = atoi(buf3);
	    state = PROTOCOL_STATE;
	    break;
	  case PROTOCOL_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2)
		error_exit("Bad parse", linenumber, filename);
	    /* maybe these should be oids */

	    if (!strcasecmp(buf1, "noAuth"))
		auth = NOAUTH;
	    else if (!strcasecmp(buf1, "snmpv2MD5Auth"))
		auth = SNMPV2MD5AUTHPROT;
	    else
		error_exit("Bad authentication protocol type", linenumber,
			   filename);

	    if (!strcasecmp(buf2, "noPriv"))
		priv = NOPRIV;
	    else if (!strcasecmp(buf2, "desPriv"))
		priv = DESPRIVPROT;
	    else
		error_exit("Bad privacy protocol type", linenumber, filename);
	    state = LIFETIME_STATE;
	    break;
	  case LIFETIME_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2)
		error_exit("Bad parse", linenumber, filename);
	    for(cp = buf1; *cp; cp++)
		if (!isdigit(*cp))
		    error_exit("Bad lifetime value (should be decimal integer)",
			       linenumber, filename);
	    lifetime = atoi(buf1);
	    for(cp = buf2; *cp; cp++)
		if (!isdigit(*cp))
		error_exit("Bad Max Message Size value (should be decimal integer)", linenumber, filename);
	    maxmessagesize = atoi(buf2);
	    state = CLOCK_STATE;
	    break;	    
	  case CLOCK_STATE:
	    if (sscanf(buf, "%s", buf1) != 1)
		error_exit("Bad parse", linenumber, filename);
	    if (strlen(buf1) != 8)
		error_exit("Bad clock value (should be 8 hex digits)",
			   linenumber, filename);
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp))
		    error_exit("Bad clock value (should be 8 hex digits)",
			       linenumber, filename);
	    }
	    if (sscanf(buf1, "%x", &clock) != 1)
		error_exit("Bad clock value", linenumber, filename);
	    clock_pos = chars - strlen(buf);
	    for(cp = buf; *cp && !isxdigit(*cp); cp++)
		clock_pos++;
	    state = AUTH_STATE;
	    break;
	  case AUTH_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2, buf3) != 2)
		error_exit("Bad parse", linenumber, filename);
	    if (strlen(buf1) != 32)
		error_exit("Bad private key (should be 32 hex digits)",
			   linenumber, filename);
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp))
		    error_exit("Bad private key value (should be 32 hex digits)",
			       linenumber, filename);
	    }
	    ucp = authPrivate;
	    for(cp = buf1; *cp; cp += 2, ucp++){
		if (sscanf(cp, "%2x", &byte) != 1)
		    error_exit("Bad parse", linenumber, filename);
		*ucp = byte;
	    }

	    if (strlen(buf2) % 2)
		error_exit("Bad private key value (should be an even number of hex digits)", linenumber, filename);
	    nonhex = 0;
	    for(cp = buf2; *cp; cp++){
		if (!isxdigit(*cp))
		    nonhex = 1;
	    }
	    if (nonhex){
		if (strcasecmp(buf2, "Null"))
		    error_exit("Bad private key value (should be hex digits or null)",
			       linenumber, filename);
		authPublicLength = 0;
	    } else {
		ucp = authPublic;
		for(cp = buf2; *cp; cp += 2, ucp++){
		    if (sscanf(cp, "%2x", &byte) != 1)
			error_exit("Bad parse", linenumber, filename);
		    *ucp = byte;
		}
		authPublicLength = ucp - authPublic;
	    }
	    state = PRIV_STATE;
	    break;
	  case PRIV_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2)
		error_exit("Bad parse", linenumber, filename);
	    if (strlen(buf1) != 32)
		error_exit("Bad private key (should be 32 hex digits)",
			   linenumber, filename);
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp))
		    error_exit("Bad private key value (should be 32 hex digits)",
			       linenumber, filename);
	    }
	    ucp = privPrivate;
	    for(cp = buf1; *cp; cp += 2, ucp++){
		if (sscanf(cp, "%2x", &byte) != 1)
		    error_exit("Bad parse", linenumber, filename);
		*ucp = byte;
	    }

	    if (strlen(buf2) % 2)
		error_exit("Bad private key value (should be an even number of hex digits)", linenumber, filename);
	    nonhex = 0;	
	    for(cp = buf2; *cp; cp++){
		if (!isxdigit(*cp))
		    nonhex = 1;
	    }
	    if (nonhex){
		if (strcasecmp(buf2, "Null"))
		    error_exit("Bad private key value (should be hex digits or null)",
			       linenumber, filename);
		privPublicLength = 0;
	    } else {
		ucp = privPublic;
		for(cp = buf2; *cp; cp += 2, ucp++){
		    if (sscanf(cp, "%2x", &byte) != 1)
			error_exit("Bad parse", linenumber, filename);
		    *ucp = byte;
		}
		privPublicLength = ucp - privPublic;
	    }
	    state = IDENTITY_STATE;

	    pp = party_getEntry(partyid, partyidlen);
	    if (!pp)
		pp = party_createEntry(partyid, partyidlen);
	    rp = pp->reserved;
	    strcpy(pp->partyName, name);
	    pp->partyTDomain = rp->partyTDomain = domain;
	    addr = htonl(addr);
	    port = htons(port);
	    bcopy((char *)&addr, pp->partyTAddress, sizeof(addr));
	    bcopy((char *)&port, pp->partyTAddress + 4, sizeof(port));
	    bcopy(pp->partyTAddress, rp->partyTAddress, 6);
	    pp->partyTAddressLen = rp->partyTAddressLen = 6;
#if 0
/* nuke this??? XXX */
	    if (proxy == NOPROXY){
		bcopy((char *)noProxy, (char *)pp->partyProxyFor,
		      sizeof(noProxy));
		bcopy((char *)noProxy, (char *)rp->partyProxyFor,
		      sizeof(noProxy));
		pp->partyProxyForLen = rp->partyProxyForLen =
		    sizeof(noProxy)/sizeof(oid);
	    } else {
		fprintf(stderr, "Can't handle proxy\n");
		exit(1);
	    }
#endif
	    pp->partyAuthProtocol = rp->partyAuthProtocol = auth;
	    pp->partyAuthClock = rp->partyAuthClock = clock;
	    pp->tv.tv_sec = pp->partyAuthClock;
	    if ((pp->partyAuthPublicLen = authPublicLength) != 0){
		bcopy((char *)authPublic, pp->partyAuthPublic,
		      authPublicLength);
		bcopy((char *)authPublic, rp->partyAuthPublic,
		      authPublicLength);
	    }
	    pp->partyAuthLifetime = rp->partyAuthLifetime = lifetime;
	    pp->partyPrivProtocol = rp->partyPrivProtocol = priv;
	    if ((pp->partyPrivPublicLen = privPublicLength) != 0){
		bcopy((char *)privPublic, pp->partyPrivPublic,
		      privPublicLength);
		bcopy((char *)privPublic, rp->partyPrivPublic,
		      privPublicLength);
	    }
	    myaddr = get_myaddr();
	    if ((rp->partyTDomain == DOMAINSNMPUDP)
		&& !bcmp((char *)&myaddr, rp->partyTAddress, 4)){
		/* party is local */
		/* 1500 should be constant in snmp_impl.h */
		pp->partyMaxMessageSize = rp->partyMaxMessageSize = 1500;
		pp->partyLocal = 1; /* TRUE */
	    } else {
		pp->partyMaxMessageSize =
		    rp->partyMaxMessageSize = maxmessagesize;
		pp->partyLocal = 2; /* FALSE */
	    }
	    bcopy(authPrivate, pp->partyAuthPrivate, 16);
	    bcopy(authPrivate, rp->partyAuthPrivate, 16);
	    pp->partyAuthPrivateLen =
		rp->partyAuthPrivateLen = 16;
	    bcopy(privPrivate, pp->partyPrivPrivate, 16);
	    bcopy(privPrivate, rp->partyPrivPrivate, 16);
	    pp->partyPrivPrivateLen =
		rp->partyPrivPrivateLen = 16;
	    pp->partyStorageType = 2; /* volatile */
	    pp->partyStatus = rp->partyStatus = PARTYACTIVE;
#define PARTYCOMPLETE_MASK              65535
	    /* all collumns - from party_vars.c XXX */
	    pp->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
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

/*
IP 127.0.0.1      2000
1.3.6.1.5.1.4.129.47.1.4.1
noProxy         noAuth       noPriv
30000 484
12345678
00000000000000000000000000000000   00000000000000000000000000000000
00000000000000000000000000000000   00000000000000000000000000000000

  */

int
update_clock(file, pos, clock)
    char *file;
    int pos;
    u_long clock;
{
    int fd;
    char buf[9];

    sprintf(buf, "%08X", clock);
    fd = open(file, O_WRONLY);
    if (lseek(fd, pos, SEEK_SET) != pos){
	fprintf(stderr, "Couldn't update file\n");
	return 0;
    }
    if (write(fd, buf, 8) != 8){
	fprintf(stderr, "Couldn't update file\n");
	return 0;
    }
    if (close(fd) != 0){
	fprintf(stderr, "Couldn't update file\n");
	return 0;
    }
    return 1;
}
