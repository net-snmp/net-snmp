/*
 * keytools.c
 */

#include "all_system.h"
#include "all_general_local.h"

#include "keytools.h"




/*******************************************************************-o-******
 * generate_kul
 *
 * Parameters:
 *	 *engineID
 *	 *Ku
 *	  kulen
 *	**Kul
 *	 *kullen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 * FIX	Need to name hash type?
 */
int
generate_kul(	u_char *engineID,       u_int engineIDLen,
		u_char *Ku,		u_int kulen,
		u_char **Kul,		u_int *kullen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

generate_kul_quit:
	return rval;

}  /* end generate_kul() */




/*******************************************************************-o-******
 * generate_Ku
 *
 * Parameters:
 *	 *P
 *	  pplen
 *	**Ku
 *	 *kulen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
generate_Ku(u_char *P, u_int pplen, u_char **Ku, u_int *kulen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

generate_Ku_quit:
	return rval;

}  /* end generate_Ku() */




/*******************************************************************-o-******
 * do_keychange
 *
 * Parameters:
 *	 *userSecurityName
 *	  isOwwn
 *	 *newkey
 *	  newkey_len
 *	**kcstring
 *	 *kcstring_len
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
do_keychange(	u_char *userSecurityName,	int isOwn,
		u_char *newkey,			u_int newkey_len,
		u_char **kcstring,		u_int *kcstring_len)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

do_keychange_quit:
	return rval;

}  /* end do_keychange() */

