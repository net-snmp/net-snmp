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
 * Returns pointer to allocaed & set buffer on success, size contains
 * number of random bytes filled.
 *
 * buf is NULL and *size set to KMT error value upon failure.
 *
 * (Degenerates to malloc_zero if HAVE_LIBKMT is not defined.)
 */
char *
malloc_random(int *size)
{
	int	rval	= SNMPERR_SUCCESS;
	char	*buf	= (char *) malloc(*size);

#ifdef							HAVE_LIBKMT
	if (buf) {
		rval = kmt_random(KMT_RAND_DEFAULT, buf, *size);

		if (rval < 0) {
			free_zero(buf, *size);
			buf = NULL;
		} else {
			*size = rval;
		}
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
 * Returns pointer to allocaed & zeroed buffer on success.
 */
char *
malloc_zero(u_long size)
{
	char	*buf = (char *) malloc(size);

	if (buf) {
		memset(buf, 0, size);
	}

	return buf;

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
	char	*s	= (char *) SNMP_MALLOC(olen),
		*op	= s,
		*ip	= input;

/* EM(1); /* */

	while (ip-input < len) {
		*op++ = VAL2HEX( (*ip >> 4) & 0xf );
		*op++ = VAL2HEX( *ip & 0xf );
		ip++;
	}
	*op = '\0';
	
	*output = s;
	return olen;

}  /* end binary_to_hex() */

