#include <net-snmp/net-snmp-config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#else
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <net-snmp/config_api.h>
#include <net-snmp/output_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/utilities.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "snmptrapd_handlers.h"
#include "snmptrapd_log.h"
#include "notification_log.h"

char *syslog_format1 = NULL;
char *syslog_format2 = NULL;
char *print_format1  = NULL;
char *print_format2  = NULL;

const char     *trap1_std_str = "%.4y-%.2m-%.2l %.2h:%.2j:%.2k %B [%b] (via %A [%a]): %N\n\t%W Trap (%q) Uptime: %#T\n%v\n";
const char     *trap2_std_str = "%.4y-%.2m-%.2l %.2h:%.2j:%.2k %B [%b]:\n%v\n";



void
snmptrapd_parse_traphandle(const char *token, char *line)
{
    char            buf[STRINGMAX];
    oid             obuf[MAX_OID_LEN];
    int             olen = MAX_OID_LEN;
    char           *cptr;
    netsnmp_trapd_handler *traph;

    cptr = copy_nword(line, buf, sizeof(buf));
    DEBUGMSGTL(("read_config:traphandle", "registering handler for: "));
    if (!strcmp(buf, "default")) {
        DEBUGMSG(("read_config:traphandle", "default"));
        traph = netsnmp_add_default_traphandler( command_handler );
    } else {

        if (!read_objid(buf, obuf, &olen)) {
            char            buf1[STRINGMAX];
            snprintf(buf1,  sizeof(buf1),
                    "Bad trap OID in traphandle directive: %s", buf);
            buf1[ sizeof(buf1)-1 ] = 0;
            config_perror(buf1);
            return;
        }
        DEBUGMSGOID(("read_config:traphandle", obuf, olen));
        traph = netsnmp_add_traphandler( command_handler, obuf, olen );
    }

    DEBUGMSG(("read_config:traphandle", "\n"));

    if (traph) {
        traph->token = strdup(cptr);
    }
}


static void
parse_forward(const char *token, char *line)
{
    char            buf[STRINGMAX];
    oid             obuf[MAX_OID_LEN];
    int             olen = MAX_OID_LEN;
    char           *cptr;
    netsnmp_trapd_handler *traph;

    cptr = copy_nword(line, buf, sizeof(buf));
    DEBUGMSGTL(("read_config:forward", "registering forward for: "));
    if (!strcmp(buf, "default")) {
        DEBUGMSG(("read_config:forward", "default"));
        traph = netsnmp_add_default_traphandler( forward_handler );
    } else {

        if (!read_objid(buf, obuf, &olen)) {
            char            buf1[STRINGMAX];
            snprintf(buf1,  sizeof(buf1),
                    "Bad trap OID in traphandle directive: %s", buf);
            buf1[ sizeof(buf1)-1 ] = 0;
            config_perror(buf1);
            return;
        }
        DEBUGMSGOID(("read_config:forward", obuf, olen));
        traph = netsnmp_add_traphandler( forward_handler, obuf, olen );
    }

    DEBUGMSG(("read_config:forward", "\n"));

    if (traph) {
        traph->token = strdup(cptr);
    }
}


static void
parse_format(const char *token, char *line)
{
    char *cp;

    /*
     * Extract the first token from the value
     * which tells us which style of format this is
     */
    cp = line;
    while (*cp && !isspace(*cp))
        cp++;
    if (!(*cp)) {
        /*
	 * If we haven't got anything left,
	 * then this entry is malformed.
	 * So report this, and give up
	 */
        return;
    }

    *cp = '\0';
    cp++;

    /*
     * OK - now "line" contains the format type,
     *      and cp points to the actual format string.
     * So update the appropriate pointer(s).
     *
     * XXX - the previous values really need to be freed too
     */
    if (!strcmp( line, "print1"))
        print_format1 = strdup(cp);
    else if (!strcmp( line, "print2"))
        print_format2 = strdup(cp);
    else if (!strcmp( line, "print")) {
        print_format1 = strdup(cp);
        print_format2 = strdup(cp);
    } else if (!strcmp( line, "syslog1"))
        syslog_format1 = strdup(cp);
    else if (!strcmp( line, "syslog2"))
        syslog_format2 = strdup(cp);
    else if (!strcmp( line, "syslog")) {
        syslog_format1 = strdup(cp);
        syslog_format2 = strdup(cp);
    }
}


static void
parse_trap1_fmt(const char *token, char *line)
{
    print_format1 = strdup(line);
}


void
free_trap1_fmt(void)
{
    if (print_format1 && print_format1 != trap1_std_str)
        free((char *) print_format1);
    print_format1 = NULL;
}


static void
parse_trap2_fmt(const char *token, char *line)
{
    print_format2 = strdup(line);
}


void
free_trap2_fmt(void)
{
    if (print_format2 && print_format2 != trap2_std_str)
        free((char *) print_format2);
    print_format2 = NULL;
}


void
snmptrapd_register_configs( void )
{
    register_config_handler("snmptrapd", "traphandle",
                            snmptrapd_parse_traphandle, NULL,
                            "oid|\"default\" program [args ...] ");
    register_config_handler("snmptrapd", "format1",
                            parse_trap1_fmt, free_trap1_fmt, "format");
    register_config_handler("snmptrapd", "format2",
                            parse_trap2_fmt, free_trap2_fmt, "format");
    register_config_handler("snmptrapd", "format",
                            parse_format, NULL,
			    "[print{,1,2}|syslog{,1,2}] format");
    register_config_handler("snmptrapd", "forward",
                            parse_forward, NULL, "destination");
}



/*-----------------------------
 *
 * Routines to implement a "registry" of trap handlers
 *
 *-----------------------------*/

netsnmp_trapd_handler *netsnmp_auth_global_traphandlers   = NULL;
netsnmp_trapd_handler *netsnmp_pre_global_traphandlers    = NULL;
netsnmp_trapd_handler *netsnmp_post_global_traphandlers   = NULL;
netsnmp_trapd_handler *netsnmp_default_traphandlers  = NULL;
netsnmp_trapd_handler *netsnmp_specific_traphandlers = NULL;

/*
 * Register a new "global" traphandler,
 * to be applied to *all* incoming traps
 */
netsnmp_trapd_handler *
netsnmp_add_global_traphandler(int list, Netsnmp_Trap_Handler handler) {
    netsnmp_trapd_handler *traph;

    if ( !handler )
        return NULL;

    traph = SNMP_MALLOC_TYPEDEF(netsnmp_trapd_handler);
    if ( !traph )
        return NULL;

    /*
     * Add this new handler to the front of the appropriate global list
     *   (or should it go on the end?)
     */
    traph->handler = handler;
    switch (list) {
    case NETSNMPTRAPD_AUTH_HANDLER:
        traph->nexth   = netsnmp_auth_global_traphandlers;
        netsnmp_auth_global_traphandlers = traph;
        break;
    case NETSNMPTRAPD_PRE_HANDLER:
        traph->nexth   = netsnmp_pre_global_traphandlers;
        netsnmp_pre_global_traphandlers = traph;
        break;
    case NETSNMPTRAPD_POST_HANDLER:
        traph->nexth   = netsnmp_post_global_traphandlers;
        netsnmp_post_global_traphandlers = traph;
        break;
    default:
        free( traph );
        return NULL;
    }
    return traph;
}


/*
 * Register a new "default" traphandler, to be applied to all
 * traps with no specific trap handlers of their own.
 */
netsnmp_trapd_handler *
netsnmp_add_default_traphandler( Netsnmp_Trap_Handler handler) {
    netsnmp_trapd_handler *traph;

    if ( !handler )
        return NULL;

    traph = SNMP_MALLOC_TYPEDEF(netsnmp_trapd_handler);
    if ( !traph )
        return NULL;

    /*
     * Add this new handler to the front of the default list
     *   (or should it go on the end?)
     */
    traph->handler = handler;
    traph->nexth   = netsnmp_default_traphandlers;
    netsnmp_default_traphandlers = traph;
    return traph;
}


/*
 * Register a new trap-specific traphandler
 */
netsnmp_trapd_handler *
netsnmp_add_traphandler(Netsnmp_Trap_Handler handler,
                        oid *trapOid, int trapOidLen ) {
    netsnmp_trapd_handler *traph, *traph2;

    if ( !handler )
        return NULL;

    traph = SNMP_MALLOC_TYPEDEF(netsnmp_trapd_handler);
    if ( !traph )
        return NULL;

    /*
     * Populate this new handler with the trap information
     *   (NB: the OID fields were not used in the default/global lists)
     */
    traph->handler     = handler;
    traph->trapoid_len = trapOidLen;
    memdup((u_char **)&(traph->trapoid), (u_char *)trapOid,
		    sizeof(oid) * trapOidLen);

    /*
     * Now try to find the appropriate place in the trap-specific
     * list for this particular trap OID.  If there's a matching OID
     * already, then find it.  Otherwise find the one that follows.
     * If we run out of entried, the new one should be tacked onto the end.
     */
    for (traph2 = netsnmp_specific_traphandlers;
         traph2; traph2 = traph2->nextt) {
	    		/* XXX - check this! */
        if (snmp_oid_compare(traph2->trapoid, traph2->trapoid_len,
                             trapOid, trapOidLen) <= 0)
	    break;
    }
    if (traph2) {
        /*
         * OK - We've either got an exact match, or we've found the
	 *   entry *after* where the new one should go.
         */
        if (!snmp_oid_compare(traph->trapoid,  traph->trapoid_len,
                              traph2->trapoid, traph2->trapoid_len)) {
            /*
             * Exact match, so find the end of the *handler* list
             *   and tack on this new entry...
             */
            while (traph2->nexth)
                traph2 = traph2->nexth;
            traph2->nexth = traph;
            traph->nextt  = traph2->nextt;   /* Might as well... */
            traph->prevt  = traph2->prevt;
        } else {
            /*
             * .. or the following entry, so insert the new one before it.
             */
            traph->prevt  = traph2->prevt;
            if (traph2->prevt)
	        traph2->prevt->nextt = traph;
            else
	        netsnmp_specific_traphandlers = traph;
            traph2->prevt = traph;
            traph->nextt  = traph2;
        }
    } else {
        /*
         * If we've run out of entries without finding a suitable spot,
	 *   the new one should be tacked onto the end.....
         */
	if (netsnmp_specific_traphandlers) {
            traph2 = netsnmp_specific_traphandlers;
            while (traph2->nextt)
                traph2 = traph2->nextt;
            traph2->nextt = traph;
            traph->prevt  = traph2;
	} else {
            /*
             * .... unless this is the very first entry, of course!
             */
            netsnmp_specific_traphandlers = traph;
        }
    }

    return traph;
}


/*
 * Locate the list of handlers for this particular Trap OID
 * Returns NULL if there are no relevant traps
 */
netsnmp_trapd_handler *
netsnmp_get_traphandler( oid *trapOid, int trapOidLen ) {
    netsnmp_trapd_handler *traph;
    
    if (!trapOid || !trapOidLen)
        return NULL;

    /*
     * Look for a matching OID, and return that list...
     */
    for (traph = netsnmp_specific_traphandlers;
         traph; traph=traph->nextt ) {

        if ( !snmp_oid_compare(traph->trapoid, traph->trapoid_len,
                               trapOid, trapOidLen)) {
            DEBUGMSGTL(( "snmptrapd", "get_traphandler matched (%x)\n", traph));
	    return traph;
	}
    }

    /*
     * .... or failing that, return the "default" list (which may be NULL)
     */
    DEBUGMSGTL(( "snmptrapd", "get_traphandler default (%x)\n",
			    netsnmp_default_traphandlers));
    return netsnmp_default_traphandlers;
}

/*-----------------------------
 *
 * Standard traphandlers for the common requirements
 *
 *-----------------------------*/

#define SYSLOG_V1_STANDARD_FORMAT      "%a: %W Trap (%q) Uptime: %#T%#v\n"
#define SYSLOG_V1_ENTERPRISE_FORMAT    "%a: %W Trap (%q) Uptime: %#T%#v\n" /* XXX - (%q) become (.N) ??? */
#define SYSLOG_V23_NOTIFICATION_FORMAT "%B [%b]: Trap %#v\n"	 	   /* XXX - introduces a leading " ," */

/*
 *  Trap handler for logging via syslog
 */
int   syslog_handler(  netsnmp_pdu           *pdu,
                       netsnmp_transport     *transport,
                       netsnmp_trapd_handler *handler)
{
    u_char         *rbuf = NULL;
    size_t          r_len = 64, o_len = 0;
    int             trunc = 0;
    extern int      SyslogTrap;

    DEBUGMSGTL(( "snmptrapd", "syslog_handler\n"));

    if (SyslogTrap)
        return NETSNMPTRAPD_HANDLER_OK;

    if ((rbuf = (u_char *) calloc(r_len, 1)) == NULL) {
        snmp_log(LOG_ERR, "couldn't display trap -- malloc failed\n");
        return NETSNMPTRAPD_HANDLER_FAIL;	/* Failed but keep going */
    }

    /*
     *  If there's a format string registered for this trap, then use it.
     */
    if (handler && handler->format) {
        DEBUGMSGTL(( "snmptrapd", "format = '%s'\n", handler->format));
        if (*handler->format) {
            trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                     handler->format, pdu, transport);
        } else {
            return NETSNMPTRAPD_HANDLER_OK;    /* A 0-length format string means don't log */
        }

    /*
     *  Otherwise (i.e. a NULL handler format string),
     *      use a standard output format setting
     *      either configurable, or hardwired
     *
     *  XXX - v1 traps use a different hardwired formats for
     *        standard and enterprise specific traps
     *        Do we actually need this?
     */
    } else {
	if ( pdu->command == SNMP_MSG_TRAP ) {
            if (syslog_format1) {
                DEBUGMSGTL(( "snmptrapd", "syslog_format v1 = '%s'\n", syslog_format1));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             syslog_format1, pdu, transport);

	    } else if (pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC) {
                DEBUGMSGTL(( "snmptrapd", "v1 enterprise format\n"));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             SYSLOG_V1_ENTERPRISE_FORMAT,
                                             pdu, transport);
	    } else {
                DEBUGMSGTL(( "snmptrapd", "v1 standard trap format\n"));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             SYSLOG_V1_STANDARD_FORMAT,
                                             pdu, transport);
	    }
	} else {	/* SNMPv2/3 notifications */
            if (syslog_format2) {
                DEBUGMSGTL(( "snmptrapd", "syslog_format v1 = '%s'\n", syslog_format2));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             syslog_format2, pdu, transport);
	    } else {
                DEBUGMSGTL(( "snmptrapd", "v2/3 format\n"));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             SYSLOG_V23_NOTIFICATION_FORMAT,
                                             pdu, transport);
	    }
        }
    }
    snmp_log(LOG_WARNING, "%s%s", rbuf, (trunc?" [TRUNCATED]\n":""));
    free(rbuf);
    return NETSNMPTRAPD_HANDLER_OK;
}


#define PRINT_V23_NOTIFICATION_FORMAT "%.4y-%.2m-%.2l %.2h:%.2j:%.2k %B [%b]:\n%v\n"

/*
 *  Trap handler for logging to a file
 */
int   print_handler(   netsnmp_pdu           *pdu,
                       netsnmp_transport     *transport,
                       netsnmp_trapd_handler *handler)
{
    u_char         *rbuf = NULL;
    size_t          r_len = 64, o_len = 0;
    int             trunc = 0;
    extern int      dropauth;

    DEBUGMSGTL(( "snmptrapd", "print_handler\n"));

    /*
     *  Don't bother logging authentication failures
     *  XXX - can we handle this via suitable handler entries instead?
     */
    if (pdu->trap_type == SNMP_TRAP_AUTHFAIL && dropauth)
        return NETSNMPTRAPD_HANDLER_OK;

    if ((rbuf = (u_char *) calloc(r_len, 1)) == NULL) {
        snmp_log(LOG_ERR, "couldn't display trap -- malloc failed\n");
        return NETSNMPTRAPD_HANDLER_FAIL;	/* Failed but keep going */
    }

    /*
     *  If there's a format string registered for this trap, then use it.
     */
    if (handler && handler->format) {
        DEBUGMSGTL(( "snmptrapd", "format = '%s'\n", handler->format));
        if (*handler->format) {
            trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                     handler->format, pdu, transport);
        } else {
            return NETSNMPTRAPD_HANDLER_OK;    /* A 0-length format string means don't log */
        }

    /*
     *  Otherwise (i.e. a NULL handler format string),
     *      use a standard output format setting
     *      either configurable, or hardwired
     *
     *  XXX - v1 traps use a different routine for hardwired output
     *        Do we actually need this separate v1 routine?
     *        Or would a suitable format string be sufficient?
     */
    } else {
	if ( pdu->command == SNMP_MSG_TRAP ) {
            if (print_format1) {
                DEBUGMSGTL(( "snmptrapd", "print_format v1 = '%s'\n", print_format1));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             print_format1, pdu, transport);
	    } else {
                DEBUGMSGTL(( "snmptrapd", "v1 format\n"));
                trunc = !realloc_format_plain_trap(&rbuf, &r_len, &o_len, 1,
                                                   pdu, transport);
	    }
	} else {
            if (print_format2) {
                DEBUGMSGTL(( "snmptrapd", "print_format v1 = '%s'\n", print_format2));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             print_format2, pdu, transport);
	    } else {
                DEBUGMSGTL(( "snmptrapd", "v2/3 format\n"));
                trunc = !realloc_format_trap(&rbuf, &r_len, &o_len, 1,
                                             PRINT_V23_NOTIFICATION_FORMAT,
                                             pdu, transport);
	    }
        }
    }
    snmp_log(LOG_INFO, "%s%s", rbuf, (trunc?" [TRUNCATED]\n":""));
    return NETSNMPTRAPD_HANDLER_OK;
}


/*
 *  Trap handler for invoking a suitable script
 */
		/* XXX - in snmptrapd.c */
void
do_external(char *cmd, struct hostent *host,
            netsnmp_pdu *pdu, netsnmp_transport *transport);

int   command_handler( netsnmp_pdu           *pdu,
                       netsnmp_transport     *transport,
                       netsnmp_trapd_handler *handler)
{
    struct hostent *host = NULL;

    DEBUGMSGTL(( "snmptrapd", "command_handler\n"));

    DEBUGMSGTL(( "snmptrapd", "token = '%s'\n", handler->token));
    if (handler && handler->token && *handler->token) {

        if (!netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, 
					NETSNMP_DS_APP_NUMERIC_IP)) {
            /*
             * Right, apparently a name lookup is wanted.  This is only
             * reasonable for the UDP and TCP transport domains (we
             * don't want to try to be too clever here).  
             */
            if (transport != NULL
                && (transport->domain == netsnmpUDPDomain
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
                    || transport->domain == netsnmp_snmpTCPDomain
#endif
		)) {
                /*
                 * This is kind of bletcherous -- it breaks the opacity of
                 * transport_data but never mind -- the alternative is a
                 * lot of munging strings from f_fmtaddr.
                 */
                struct sockaddr_in *addr =
                    (struct sockaddr_in *) pdu->transport_data;
                if (addr != NULL && 
		    pdu->transport_data_length == sizeof(struct sockaddr_in)) {
                    host = gethostbyaddr((char *) &(addr->sin_addr),
					     sizeof(struct in_addr), AF_INET);
                }
            }
        }

	/*
	 * XXX - Possibly better to pass the format token as well ??
	 */
        do_external(handler->token, host, pdu, transport);
    }
    return NETSNMPTRAPD_HANDLER_OK;
}


/*
 *  "Notification" handler for implementing NOTIFICATION-MIB
 *  		(presumably)
 */
int   notification_handler(netsnmp_pdu           *pdu,
                           netsnmp_transport     *transport,
                           netsnmp_trapd_handler *handler)
{
    struct hostent *host = NULL;

    DEBUGMSGTL(( "snmptrapd", "notification_handler\n"));

        if (!netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID, 
					NETSNMP_DS_APP_NUMERIC_IP)) {
            /*
             * Right, apparently a name lookup is wanted.  This is only
             * reasonable for the UDP and TCP transport domains (we
             * don't want to try to be too clever here).  
             */
            if (transport != NULL
                && (transport->domain == netsnmpUDPDomain
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
                    || transport->domain == netsnmp_snmpTCPDomain
#endif
		)) {
                /*
                 * This is kind of bletcherous -- it breaks the opacity of
                 * transport_data but never mind -- the alternative is a
                 * lot of munging strings from f_fmtaddr.
                 */
                struct sockaddr_in *addr =
                    (struct sockaddr_in *) pdu->transport_data;
                if (addr != NULL && 
		    pdu->transport_data_length == sizeof(struct sockaddr_in)) {
                    host = gethostbyaddr((char *) &(addr->sin_addr),
					     sizeof(struct in_addr), AF_INET);
                }
            }
        }
    log_notification(host, pdu, transport);
    return NETSNMPTRAPD_HANDLER_OK;
}


/*
 *  Trap handler for doing something with "event" traps
 *      (not entirely clear what this is about ???)
 */
	/* XXX - in snmptrapd.c */
void event_input(netsnmp_variable_list * vp);

int   event_handler( netsnmp_pdu           *pdu,
                     netsnmp_transport     *transport,
                     netsnmp_trapd_handler *handler)
{
    DEBUGMSGTL(( "snmptrapd", "event_handler\n"));
    event_input(pdu->variables);
    return NETSNMPTRAPD_HANDLER_OK;
}


/*
 *  Trap handler for forwarding to another destination
 */
int   forward_handler( netsnmp_pdu           *pdu,
                       netsnmp_transport     *transport,
                       netsnmp_trapd_handler *handler)
{
    netsnmp_session session, *ss;
    netsnmp_pdu *pdu2;

    DEBUGMSGTL(( "snmptrapd", "forward_handler (%s)\n", handler->token));

    snmp_sess_init( &session );
    session.peername = handler->token;
    session.version  = pdu->version;
    ss = snmp_open( &session );

    pdu2 = snmp_clone_pdu(pdu);
    if (pdu2->transport_data) {
        free(pdu2->transport_data);
        pdu2->transport_data        = NULL;
        pdu2->transport_data_length = 0;
    }
    snmp_send( ss, pdu2 );
    snmp_close( ss );
    return NETSNMPTRAPD_HANDLER_OK;
}

