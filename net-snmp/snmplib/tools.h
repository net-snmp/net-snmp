/*
 * tools.h
 */

#ifndef _TOOLS_H
#define _TOOLS_H




/* 
 * Macros and constants.
 */
#define SNMP_MAXBUF		4096
#define SNMP_FILEMODE		0600

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)


#define SNMP_FREE(s)		if (s) free((void *)s);
#define SNMP_MALLOC(s)		malloc_zero(s)


#define TOUPPER(c)	(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c)
#define TOLOWER(c)	(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c)

#define HEX2VAL(s) \
	((isalpha(s) ? (TOLOWER(s)-'a'+10) : (TOLOWER(s)-'0')) & 0xf)
#define VAL2HEX(s)	( (s) + (((s) >= 10) ? ('a'-10) : '0') )




/* 
 * Prototypes.
 */
void	free_zero __P((void *buf, u_long size));

char   *malloc_random __P((u_long size));
char   *malloc_zero __P((u_long size));

u_int	binary_to_hex __P((char *input, u_long len, char **output));


#endif /* _TOOLS_H */

