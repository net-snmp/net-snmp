/*
 * debug.h
 *
 * This shouldn't need to include *anything.*
 */

#ifndef _DEBUG_H
#define _DEBUG_H




/* ------------------------------------ -o- 
 * Debugging flags.
 *
 * DF	Build a Debug Flag symbol.
 * ISDF	Test whether a given Debug Flag IS defined.
 */
#define DF(l)	(DEBUG_ ## l)
#define ISDF(f) ( (snmp_debug & (DF(ON))) && (snmp_debug & DF(f)) )

#define DEBUG_ON		0x01	/* General ON/OFF switch.	*/
#define DEBUG_EM		0x02	/* Print entry mark messages.	*/
#define DEBUG_KMTDUMP1		0x04	/* Dump keylists from
					 *   sc_internal_kmtlookup().	*/
#define DEBUG_RANDOMZEROS	0x08	/* Use only zero bits for random
					 *   delta portion of KeyChange TC. */
#define DEBUG_CRYPTED_CHUNK	0x10	/* Dump {de,en}crypted scopedPdu's  */

static u_int snmp_debug =	DF(ON) | DF(EM)		/* */
				/* | DF(KMTDUMP1)	*/
				/* | DF(RANDOMZEROS)	*/
				/* | DF(CRYPTED_CHUNK)	*/
	;




/* ------------------------------------ -o-
 * Function entry mark macro.
 *
 * Usage: em(<level>)		-OR-
 *	  emN(<level>, <format_string> [ <variable(s)> ])
 *
 * Where output is given only if level >= _EM_LEVEL, and N = {0..5} is
 * the number of arguments given to a printf-type format string.
 */

#ifndef _EM_H
#define _EM_H

#define _EM_LEVEL	0
#define _EM_FD		stderr

#define em_printClause(em, printfargs)					\
{									\
	if (ISDF(EM) && (_EM_LEVEL <= em)) {				\
		fprintf(_EM_FD, "EM %s(%d).  ", __FUNCTION__, __LINE__);\
		fprintf printfargs ;					\
		fprintf(_EM_FD, "\n");					\
		fflush(_EM_FD);						\
	}								\
};

#define EM(em)			  em_printClause(em, (_EM_FD, " "));
#define EM0(em, fmt)		  em_printClause(em, (_EM_FD, fmt));
#define EM1(em, fmt, arg1)	  em_printClause(em, (_EM_FD, fmt, arg1));
#define EM2(em, fmt, arg1, arg2)  em_printClause(em, (_EM_FD, fmt, arg1, arg2));

#define EM3(em, fmt, arg1, arg2, arg3) \
	em_printClause(em, (_EM_FD, fmt, arg1, arg2, arg3));

#define EM4(em, fmt, arg1, arg2, arg3, arg4) \
	em_printClause(em, (_EM_FD, fmt, arg1, arg2, arg3, arg4));

#define EM5(em, fmt, arg1, arg2, arg3, arg4, arg5) \
	em_printClause(em, (_EM_FD, fmt, arg1, arg2, arg3, arg4, arg5));

#define EM6(em, fmt, arg1, arg2, arg3, arg4, arg5, arg6) \
	em_printClause(em, (_EM_FD, fmt, arg1, arg2, arg3, arg4, arg5, arg6));

#endif /* _EM_H	*/




/* ------------------------------------ -o- 
 * FIX	Another KMT broken API problem...
 * FIX	Get rid of the include's, at least...
 */
#ifdef								HAVE_LIBKMT

#ifdef HAVE_KMT_H
#       include <kmt.h>
#endif
#ifdef HAVE_KMT_ALGS_H
#       include <kmt_algs.h>
#endif

void	kmt_s_dump_keylist(KMT_KEY_LIST *keylist, char *name);

#define	kmt_dump_keylist	kmt_s_dump_keylist

#endif							/* HAVE_LIBKMT */


#endif /* _DEBUG_H */

