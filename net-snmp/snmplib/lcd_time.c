/*
 * lcd_time.c
 *
 * XXX	Should etimelist entries with <0,0> time tuples be timed out?
 * XXX	Need a routine to free the memory?  (Perhaps at shutdown?)
 */

#include "all_system.h"
#include "all_general_local.h"



/*
 * Global static hashlist to contain Enginetime entries.
 *
 * New records are prepended to the appropriate list at the hash index.
 */
static Enginetime etimelist[ETIMELIST_SIZE];




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
 *	SNMPERR_SUCCESS		Success -- when a record for engineID is found.
 *	SNMPERR_GENERR		Otherwise.
 *
 *
 * Lookup engineID and return the recorded values for the
 * <enginetime, engineboot> tuple adjusted to reflect the estimated time
 * at the engine in question.
 *
 * Special case: if engineID is NULL or if engineID_len is 0 then
 * the time tuple is returned immediately as zero.
 *
 * XXX	What if timediff wraps?  >shrug<
 * XXX  Then: you need to increment the boots value.  Now.  Detecting
 *            this is another matter.
 */
int
get_enginetime(	u_char	*engineID,	
		u_int	 engineID_len,
		u_int	*engineboot,
		u_int	*enginetime,
		u_int   authenticated)
{
	int		rval	 = SNMPERR_SUCCESS;
	time_t		timediff = 0;
	Enginetime	e	 = NULL;

EM(-1); /* */


	/*
	 * Sanity check.
	 */
	if ( !enginetime || !engineboot ) {
		QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
	}


	/*
	 * Compute estimated current enginetime tuple at engineID if
	 * a record is cached for it.
	 */
	*enginetime = *engineboot = 0;

	if ( !engineID || (engineID_len<=0) ) {
		QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
	}

	if ( !(e = search_enginetime_list(engineID, engineID_len)) ) {
		QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
	}

#ifdef LCD_TIME_SYNC_OPT
        if (!authenticated || e->authenticatedFlag) {
#endif	
	*enginetime = e->engineTime;
	*engineboot = e->engineBoot;

	timediff = time(NULL) - e->lastReceivedEngineTime;
#ifdef LCD_TIME_SYNC_OPT	
        }
#endif	

	if ( timediff > (ENGINETIME_MAX - *enginetime) ) {
		*enginetime = (timediff - (ENGINETIME_MAX - *enginetime));

		/* FIX -- move this check up... should not change anything
		 * if engineboot is already locked.  ???
		 */
		if (*engineboot < ENGINEBOOT_MAX) {
			*engineboot += 1;
		}

	} else {
		*enginetime += timediff;
	}


get_enginetime_quit:
	return rval;

}  /* end get_enginetime() */




/*******************************************************************-o-******
 * set_enginetime
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *	 enginetime
 *	 engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *	SNMPERR_GENERR		Otherwise.
 *
 *
 * Lookup engineID and store the given <enginetime, engineboot> tuple
 * and then stamp the record with a consistent source of local time.
 * If the engineID record does not exist, create one.
 *
 * Special case: engineID is NULL or engineID_len is 0 defines an engineID
 * that is "always set."
 *
 * XXX	"Current time within the local engine" == time(NULL)...
 */
int
set_enginetime(	u_char	*engineID,
		u_int	 engineID_len,
		u_int	 engineboot,
		u_int  	 enginetime,
		u_int    authenticated)
{
	int		rval = SNMPERR_SUCCESS,
			index;
	Enginetime	e = NULL;

EM(-1); /* */


	/*
	 * Sanity check.
	 */
	if ( !engineID || (engineID_len <= 0) ) {
		return rval;
	}


	/*
	 * Store the given <enginetime, engineboot> tuple in the record
	 * for engineID.  Create a new record if necessary.
	 */
	if ( !(e = search_enginetime_list(engineID, engineID_len)) )
	{
		if ( (index = hash_engineID(engineID, engineID_len)) < 0 )
		{
			QUITFUN(SNMPERR_GENERR, set_enginetime_quit);
		}

		e = (Enginetime) SNMP_MALLOC(sizeof(*e));

		e->next = etimelist[index];
		etimelist[index] = e;

		e->engineID = (u_char *) SNMP_MALLOC(engineID_len);
		memcpy(e->engineID, engineID, engineID_len);

		e->engineID_len = engineID_len;
	}
#ifdef LCD_TIME_SYNC_OPT	
	if (authenticated || !e->authenticatedFlag) {
	  e->authenticatedFlag = authenticated;
#else
	if (authenticated) {
#endif
	  e->engineTime		  = enginetime;
	  e->engineBoot		  = engineboot;
	  e->lastReceivedEngineTime = time(NULL);
        }

	e = NULL;	/* Indicates a successful update. */


set_enginetime_quit:
	SNMP_FREE(e);

	return rval;

}  /* end set_enginetime() */




/*******************************************************************-o-******
 * search_enginetime_list
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *      
 * Returns:
 *	Pointer to a etimelist record with engineID <engineID>  -OR-
 *	NULL if no record exists.
 *
 *
 * Search etimelist for an entry with engineID.
 *
 * ASSUMES that no engineID will have more than one record in the list.
 */
Enginetime
search_enginetime_list(u_char *engineID, u_int engineID_len)
{
	int		rval = SNMPERR_SUCCESS;
	Enginetime	e    = NULL;

EM(-1); /* */

	/*
	 * Sanity check.
	 */
	if ( !engineID || (engineID_len<=0) ) {
		QUITFUN(SNMPERR_GENERR, search_enginetime_list_quit);
	}


	/*
	 * Find the entry for engineID if there be one.
	 */
	rval = hash_engineID(engineID, engineID_len);
	if (rval < 0) {
		QUITFUN(SNMPERR_GENERR, search_enginetime_list_quit);
	}
	e = etimelist[rval];

	for ( /*EMPTY*/; e; e = e->next )
	{
		if ( (engineID_len == e->engineID_len)
			&& !memcmp(e->engineID, engineID, engineID_len) )
		{
			break;
		}
	}
	

search_enginetime_list_quit:
	return e;

}  /* end search_enginetime_list() */





/*******************************************************************-o-******
 * hash_engineID
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *      
 * Returns:
 *	>0			etimelist index for this engineID.
 *	SNMPERR_GENERR		Error.
 *	
 * 
 * Use a cheap hash to build an index into the etimelist.  Method is 
 * to hash the engineID, then split the hash into u_int's and add them up
 * and modulo the size of the list.
 *
 * XXX	Devolves and returns always 0 if HAVE_LIBKMT is not defined.
 *	(Thus the etimelist hash table devolves to a linked list from
 *	index 0.)
 * XXX	Retrofit "internal" MD5 routines?
 */
int
hash_engineID(u_char *engineID, u_int engineID_len)
{
	int		 rval		= SNMPERR_GENERR,
			 buf_len	= SNMP_MAXBUF;
	u_int		 additive	= 0;
	u_int8_t	*bufp,
			 buf[SNMP_MAXBUF];
	void		*context = NULL;

EM(-1); /* */


	/*
	 * Sanity check.
	 */
	if ( !engineID || (engineID_len <= 0) ) {
		QUITFUN(SNMPERR_GENERR, hash_engineID_quit);
	}


	/*
	 * Hash engineID into a list index.
	 */
#ifdef								HAVE_LIBKMT
	SET_HASH_TRANSFORM(kmt_s_md5);

	bufp = (u_int8_t *) buf;
	rval = kmt_hash(KMT_CRYPT_MODE_ALL, &context,
			engineID, engineID_len,
			&bufp, &buf_len);
	QUITFUN(rval, hash_engineID_quit);

	for ( bufp = buf; (bufp-buf) < buf_len; bufp += 4 ) {
		additive += (u_int) *bufp;
	}

#else
	rval = 0;
#endif							/* HAVE_LIBKMT */


hash_engineID_quit:
	SNMP_FREE(context);
	memset(buf, 0, SNMP_MAXBUF);

	return (rval < 0) ? rval : (additive % ETIMELIST_SIZE);

}  /* end hash_engineID() */




/*******************************************************************-o-******
 * dump_etimelist_entry
 *
 * Parameters:
 *	e
 *	count
 */
void
dump_etimelist_entry(Enginetime e, int count)
{
#define pt	DEBUGP("%s", tabs); DEBUGP(
#define p	);

	u_int	 buflen;
	char	 tabs[SNMP_MAXBUF],
		*t = tabs, 
		*s;

EM(-1); /* */


	count += 1;
	while (count--) {
		t += sprintf(t, "  ");
	}


	buflen = e->engineID_len;
	if ( !(s = dump_snmpEngineID(e->engineID, &buflen)) ) {
		binary_to_hex(e->engineID, e->engineID_len, &s);
	}

	pt	"\n"						p
	pt	"%s (len=%d) <%d,%d>\n",
			s, e->engineID_len,
			e->engineTime, e->engineBoot		p
	pt	"%ld (%ld) -- %s",
			e->lastReceivedEngineTime,
			time(NULL) - e->lastReceivedEngineTime,
			ctime(&e->lastReceivedEngineTime)	p

	SNMP_FREE(s);

#undef pt p
	
}  /* end dump_etimelist_entry() */




/*******************************************************************-o-******
 * dump_etimelist
 */
void
dump_etimelist(void)
{
	int		index = -1,
			count = 0;
	Enginetime	e;

EM(-1); /* */


	DEBUGP("\n");

	while (++index < ETIMELIST_SIZE) {
		DEBUGP("[%d]", index);

		count = 0;
		e = etimelist[index];

		while (e) {
			dump_etimelist_entry(e, count++);
			e = e->next;
		}

		if (count > 0) {
			DEBUGP("\n");
		}
	}  /* endwhile */

	DEBUGP("\n");

}  /* end dump_etimelist() */

