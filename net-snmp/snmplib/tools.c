/*
 * tools.c
 */

#include "all_system.h"
#include "all_general_local.h"





/*******************************************************************-o-******
 * free_zero
 *
 * Parameters:
 *	*buf	Pointer at bytes to free.
 *	size	Number of bytes in buf.
 */
void
free_zero(void *buf, u_long size)
{
	if (buf) {
		memset(buf, 0, size);
		free(buf);
	}

}  /* end free_zero() */




/*******************************************************************-o-******
 * malloc_random
 *
 * Parameters:
 *	size	Number of bytes to malloc() and fill with random bytes.
 *      
 * Returns:
 *	<char *>	Pointer to allocaed & set buffer on success.
 *
 * XXX	Degenerates to malloc_zero if HAVE_LIBKMT is not defined.
 */
char *
malloc_random(u_long size)
{
	int	rval = SNMPERR_SUCCESS;
	u_long	actualsize = size;
	char	*buf = (char *) malloc_zero(size);

#ifdef							HAVE_LIBKMT
	if (buf) {
		rval = kmt_random(KMT_RAND_DEFAULT, buf, actualsize);

		if (rval < 0) {
			/* FIX -- Log an error? */
		}
		if (actualsize != rval) {
			/* FIX -- Log an error? */
		}

	} else {
		; /* FIX -- Log a fatal error? */
	}
#endif							/* HAVE_LIBKMT */


	return buf;

}  /* end malloc_random() */




/*******************************************************************-o-******
 * malloc_zero
 *
 * Parameters:
 *	size	Number of bytes to malloc().
 *      
 * Returns:
 *	<char *>	Pointer to allocaed & zeroed buffer on success.
 */
char *
malloc_zero(u_long size)
{
	return (char *) malloc_set(size, 0);

}  /* end malloc_zero() */





/*******************************************************************-o-******
 * binary_to_hex
 *
 * Parameters:
 *	*input		Binary data.
 *	len		Length of binary data.
 *	**output	NULL terminated string equivalent in hex.
 *      
 * Returns:
 *	olen	Length of output string not including NULL terminator.
 *
 * FIX	Is there already one of these in the UCD SNMP codebase?
 *	The old one should be used, or this one should be moved to
 *	snmplib/snmp_api.c.
 */
u_int
binary_to_hex(char *input, u_long len, char **output)
{
	u_int	olen	= (len * 2) + 1;
	char	*s	= (char *) MALLOC(olen),
		*op	= s,
		*ip	= input;

EM(1); /* */

	while (ip-input < len) {
		*op++ = VAL2HEX( (*ip >> 4) & 0xf );
		*op++ = VAL2HEX( *ip & 0xf );
		ip++;
	}
	*op = '\0';
	
	*output = s;
	return olen;

}  /* end binary_to_hex() */

