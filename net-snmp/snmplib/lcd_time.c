/*
 * lcd_time.c
 */


#include "all_system.h"
#include "all_general_local.h"





/*******************************************************************-o-******
 * get_enginetime
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *	*enginetime
 *	*engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 * FIX	Check case of NULL or "" engineID (sez Ed).
 */
int
get_enginetime(	u_char	*engineID,	
		u_int	 engineID_len,
		u_int	*enginetime,	
		u_int	*engineboot)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

get_enginetime_quit:
	return NULL;

}  /* end get_enginetime() */





/*******************************************************************-o-******
 * get_enginetime_byIP
 *
 * Parameters:
 *	 engineIP
 *	 engineID_len
 *	*enginetime	
 *	*engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 * FIX	Need this at all?
 * FIX	Use sockaddr?
 */
int
get_enginetime_byIP(	struct in_addr	 engineIP,
			u_int		*enginetime,	
			u_int		*engineboot)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

get_enginetime_byIP_quit:
	return NULL;

}  /* end get_enginetime_byIP() */




/*******************************************************************-o-******
 * write_enginetime
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *	 enginetime
 *	 engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
set_enginetime(	u_char	*engineID,
		u_int	 engineID_len,
		u_int  	 enginetime,
		u_int	 engineboot)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

write_enginetime_quit:
	return rval;

}  /* end write_enginetime() */

