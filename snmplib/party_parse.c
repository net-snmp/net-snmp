#include <config.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_NETINET_IN_H
/* needed for htonl funcs */
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "asn1.h"
#include "mib.h"
#include "party.h"
#include "system.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"

#define TRUE 1
#define FALSE 0

#define IDENTITY_STATE  1
#define TRANSPORT_STATE	2
#define PROTOCOL_STATE  3
#define LIFETIME_STATE  4
#define CLOCK_STATE	5
#define AUTH_STATE	6
#define PRIV_STATE 	7

#if  0
static oid noProxy[] = {1, 3, 6, 1, 2, 1, 20, 1, 3, 1};
#endif

static void error_exit __P((char *, int, char *));
int update_clock __P((char *, int, u_long));

static void error_exit(str, linenumber, filename)
    char *str;
    int linenumber;
    char *filename;
{
  char tmpbuf[1024];
  snmp_errno = SNMPERR_BAD_PARTY;
  sprintf(tmpbuf, "%s on line %d of %s", str, linenumber, filename);
  snmp_set_detail(tmpbuf);
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
    in_addr_t addr;
    u_short port;
    oid partyid[64];
    int partyidlen;
    int priv = 0, auth = 0;
#if 0
    int proxy;
#endif
    int lifetime = 0, maxmessagesize = 0;
    u_long clock;
    u_char privPrivate[32], authPrivate[32], privPublic[64], authPublic[64];
    u_char *ucp;
    u_long byte;
    int privPublicLength, authPublicLength = 0;
    char name[64];	/* friendly name */
    struct partyEntry *pp, *rp;
    u_int myaddr;
    int domain = 0;

    fp = fopen(filename, "r");
    if (fp == NULL)
	return -1;
    while (fgets(buf, 256, fp)){
	linenumber++;
	if (strlen(buf) > 250) {
	    error_exit("Line longer than 250 bytes", linenumber, filename);
	    fclose(fp);
	    return -1;
	}
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
	    if (sscanf(buf, "%s %s", name, buf1) != 2) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    partyidlen = 64;
	    if (!read_objid(buf1, partyid, &partyidlen)) {
		error_exit("Bad object identifier", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    state = TRANSPORT_STATE;
	    break;
	  case TRANSPORT_STATE:
	    if (sscanf(buf, "%s %s %s", buf1, buf2, buf3) != 3) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    if (!strcasecmp(buf1, "snmpUdpDomain"))
		domain = DOMAINSNMPUDP;
	    else {
		error_exit("Bad protocol type", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    if ((int)(addr = inet_addr(buf2)) == -1) {
		error_exit("Bad IP address", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    for(cp = buf3; *cp; cp++)
		if (!isdigit(*cp)) {
		    error_exit("Not a port number", linenumber, filename);
		    fclose(fp);
		    return -1;
		}
	    port = atoi(buf3);
	    state = PROTOCOL_STATE;
	    break;
	  case PROTOCOL_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    /* maybe these should be oids */

	    if (!strcasecmp(buf1, "noAuth"))
		auth = NOAUTH;
	    else if (!strcasecmp(buf1, "snmpv2MD5Auth"))
		auth = SNMPV2MD5AUTHPROT;
	    else {
		error_exit("Bad authentication protocol type", linenumber,
			   filename);
		fclose(fp);
		return -1;
	    }

	    if (!strcasecmp(buf2, "noPriv"))
		priv = NOPRIV;
	    else if (!strcasecmp(buf2, "desPriv"))
		priv = DESPRIVPROT;
	    else {
		error_exit("Bad privacy protocol type", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    state = LIFETIME_STATE;
	    break;
	  case LIFETIME_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    for(cp = buf1; *cp; cp++)
		if (!isdigit(*cp)) {
		    error_exit("Bad lifetime value (should be decimal integer)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
	    lifetime = atoi(buf1);
	    for(cp = buf2; *cp; cp++)
		if (!isdigit(*cp)) {
		error_exit("Bad Max Message Size value (should be decimal integer)", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    maxmessagesize = atoi(buf2);
	    state = CLOCK_STATE;
	    break;	    
	  case CLOCK_STATE:
	    if (sscanf(buf, "%s", buf1) != 1) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    if (strlen(buf1) != 8) {
		error_exit("Bad clock value (should be 8 hex digits)",
			   linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp)) {
		    error_exit("Bad clock value (should be 8 hex digits)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
	    }
	    if (sscanf(buf1, "%lx", &clock) != 1) {
		error_exit("Bad clock value", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    clock_pos = chars - strlen(buf);
	    for(cp = buf; *cp && !isxdigit(*cp); cp++)
		clock_pos++;
	    state = AUTH_STATE;
	    break;
	  case AUTH_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    if (strlen(buf1) != 32) {
		error_exit("Bad private key (should be 32 hex digits)",
			   linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp)) {
		    error_exit("Bad private key value (should be 32 hex digits)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
	    }
	    ucp = authPrivate;
	    for(cp = buf1; *cp; cp += 2, ucp++){
		if (sscanf(cp, "%2lx", &byte) != 1) {
		    error_exit("Bad parse", linenumber, filename);
		    fclose(fp);
		    return -1;
		}
		*ucp = (u_char)byte;
	    }

	    if (strlen(buf2) % 2) {
		error_exit("Bad private key value (should be an even number of hex digits)", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    nonhex = 0;
	    for(cp = buf2; *cp; cp++){
		if (!isxdigit(*cp))
		    nonhex = 1;
	    }
	    if (nonhex){
		if (strcasecmp(buf2, "Null")) {
		    error_exit("Bad private key value (should be hex digits or null)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
		authPublicLength = 0;
	    } else {
		ucp = authPublic;
		for(cp = buf2; *cp; cp += 2, ucp++){
		    if (sscanf(cp, "%2lx", &byte) != 1) {
			error_exit("Bad parse", linenumber, filename);
			fclose(fp);
			return -1;
		    }
		    *ucp = (u_char)byte;
		}
		authPublicLength = ucp - authPublic;
	    }
	    state = PRIV_STATE;
	    break;
	  case PRIV_STATE:
	    if (sscanf(buf, "%s %s", buf1, buf2) != 2) {
		error_exit("Bad parse", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    if (strlen(buf1) != 32) {
		error_exit("Bad private key (should be 32 hex digits)",
			   linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    for(cp = buf1; *cp; cp++){
		if (!isxdigit(*cp)) {
		    error_exit("Bad private key value (should be 32 hex digits)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
	    }
	    ucp = privPrivate;
	    for(cp = buf1; *cp; cp += 2, ucp++){
		if (sscanf(cp, "%2lx", &byte) != 1) {
		    error_exit("Bad parse", linenumber, filename);
		    fclose(fp);
		    return -1;
		}
		*ucp = (u_char)byte;
	    }

	    if (strlen(buf2) % 2) {
		error_exit("Bad private key value (should be an even number of hex digits)", linenumber, filename);
		fclose(fp);
		return -1;
	    }
	    nonhex = 0;	
	    for(cp = buf2; *cp; cp++){
		if (!isxdigit(*cp))
		    nonhex = 1;
	    }
	    if (nonhex){
		if (strcasecmp(buf2, "Null")) {
		    error_exit("Bad private key value (should be hex digits or null)",
			       linenumber, filename);
		    fclose(fp);
		    return -1;
		}
		privPublicLength = 0;
	    } else {
		ucp = privPublic;
		for(cp = buf2; *cp; cp += 2, ucp++){
		    if (sscanf(cp, "%2lx", &byte) != 1) {
			error_exit("Bad parse", linenumber, filename);
			fclose(fp);
			return -1;
		    }
		    *ucp = (u_char)byte;
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
	    memmove(pp->partyTAddress, (char *)&addr, sizeof(addr));
	    memmove(pp->partyTAddress + 4, (char *)&port, sizeof(port));
	    memmove(rp->partyTAddress, pp->partyTAddress, 6);
	    pp->partyTAddressLen = rp->partyTAddressLen = 6;
#if 0
/* nuke this??? XXX */
	    if (proxy == NOPROXY){
		memmove((char *)pp->partyProxyFor, (char *)noProxy,
		      sizeof(noProxy));
		memmove((char *)rp->partyProxyFor, (char *)noProxy,
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
		memmove(pp->partyAuthPublic, (char *)authPublic,
		      authPublicLength);
		memmove(rp->partyAuthPublic, (char *)authPublic,
		      authPublicLength);
	    }
	    pp->partyAuthLifetime = rp->partyAuthLifetime = lifetime;
	    pp->partyPrivProtocol = rp->partyPrivProtocol = priv;
	    if ((pp->partyPrivPublicLen = privPublicLength) != 0){
		memmove(pp->partyPrivPublic, (char *)privPublic,
		      privPublicLength);
		memmove(rp->partyPrivPublic, (char *)privPublic,
		      privPublicLength);
	    }
	    myaddr = get_myaddr();
	    if ((rp->partyTDomain == DOMAINSNMPUDP)
		&& !memcmp((char *)&myaddr, rp->partyTAddress, 4)){
		/* party is local */
		/* 1500 should be constant in snmp_impl.h */
		pp->partyMaxMessageSize = rp->partyMaxMessageSize = 1500;
		pp->partyLocal = 1; /* TRUE */
	    } else {
		pp->partyMaxMessageSize =
		    rp->partyMaxMessageSize = maxmessagesize;
		pp->partyLocal = 2; /* FALSE */
	    }
	    memmove(pp->partyAuthPrivate, authPrivate, 16);
	    memmove(rp->partyAuthPrivate, authPrivate, 16);
	    pp->partyAuthPrivateLen =
		rp->partyAuthPrivateLen = 16;
	    memmove(pp->partyPrivPrivate, privPrivate, 16);
	    memmove(rp->partyPrivPrivate, privPrivate, 16);
	    pp->partyPrivPrivateLen =
		rp->partyPrivPrivateLen = 16;
	    pp->partyStorageType = SNMP_STORAGE_VOLATILE;
	    pp->partyStatus = rp->partyStatus = SNMP_ROW_ACTIVE;
#define PARTYCOMPLETE_MASK              65535
	    /* all collumns - from party_vars.c XXX */
	    pp->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
	    break;
	  default:
	    error_exit("unknown state", linenumber, filename);
	    fclose(fp);
	    return -1;
	}
    }
    if (state != IDENTITY_STATE) {
	error_exit("Unfinished entry at EOF", linenumber, filename);
	fclose(fp);
	return -1;
    }
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

    sprintf(buf, "%08lX", clock);
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
