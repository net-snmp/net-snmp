/*
 * tools.h
 */

#ifndef _TOOLS_H
#define _TOOLS_H



/* 
 * General acros and constants.
 */
#define SNMP_MAXBUF		(1024 * 4)
#define SNMP_MAXBUF_MEDIUM	1024
#define SNMP_MAXBUF_SMALL	512

#define SNMP_MAXBUF_MESSAGE	1500

#define SNMP_MAXOID		64

#define SNMP_FILEMODE_CLOSED	0600
#define SNMP_FILEMODE_OPEN	0644

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)
#define ROUNDUP8(x)		( ( (x+7) >> 3 ) * 8 )



#define SNMP_FREE(s)		if (s) { free((void *)s); s=NULL; }
#define SNMP_MALLOC(s)		malloc_zero(s)
					/* XXX Not optimal everywhere. */
#define SNMP_ZERO(s,l)		if (s) memset(s, 0, l);


#define TOUPPER(c)	(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c)
#define TOLOWER(c)	(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c)

#define HEX2VAL(s) \
	((isalpha(s) ? (TOLOWER(s)-'a'+10) : (TOLOWER(s)-'0')) & 0xf)
#define VAL2HEX(s)	( (s) + (((s) >= 10) ? ('a'-10) : '0') )



/* XXX	Got these two somewhere already?
 */
#define SNMP_MAX(a,b) ((a) > (b) ? (a) : (b))
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

/*
 * QUIT the FUNction:
 *	e	Error code variable
 *	l	Label to goto to cleanup and get out of the function.
 *
 * XXX	It would be nice if the label could be constructed by the
 *	preprocessor in context.  Limited to a single error return value.
 *	Temporary hack at best.
 */
#define QUITFUN(e, l)			\
	if ( (e) != SNMPERR_SUCCESS) {	\
		rval = SNMPERR_GENERR;	\
		goto l ;		\
	}

/*
 * DIFFTIMEVAL
 *	Set <diff> to the difference between <now> (current) and <then> (past).
 *
 * ASSUMES that all inputs are (struct timeval)'s.
 * Cf. system.c:calculate_time_diff().
 */
#define DIFFTIMEVAL(now, then, diff) 			\
{							\
	now.tv_sec--;					\
	now.tv_usec += 1000000L;			\
	diff.tv_sec  = now.tv_sec  - then.tv_sec;	\
	diff.tv_usec = now.tv_usec - then.tv_usec;	\
	if (diff.tv_usec > 1000000L){			\
		diff.tv_usec -= 1000000L;		\
		diff.tv_sec++;				\
	}						\
}


/*
 * ISTRANSFORM
 * ASSUMES the minimum length for ttype and toid.
 */
#define USM_LENGTH_OID_TRANSFORM	10

#define ISTRANSFORM(ttype, toid)					\
	!compare(ttype, USM_LENGTH_OID_TRANSFORM,			\
		usm ## toid ## Protocol, USM_LENGTH_OID_TRANSFORM)

#define ENGINETIME_MAX	2147483647	/* ((2^31)-1) */
#define ENGINEBOOT_MAX	2147483647	/* ((2^31)-1) */




/* 
 * Prototypes.
 */
void	free_zero __P((void *buf, u_long size));

char   *malloc_random __P((int *size));
char   *malloc_zero __P((u_long size));
int     memdup __P((u_char **to, u_char *from, u_int size));

u_int	binary_to_hex __P((char *input, u_long len, char **output));
int	hex_to_binary2 __P((char *input, u_long len, char **output));

void	dump_chunk __P((char *title, char *buf, int size));
char   *dump_snmpEngineID __P((u_char *buf, u_int *buflen));

int	snmp_ttyecho(const int fd, const int echo);
char   *snmp_getpassphrase(char *prompt, int visible);


#endif /* _TOOLS_H */

