/*
 * callback.c: A generic callback mechanism 
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/** @defgroup callback A generic callback mechanism 
 *  @ingroup library
 * 
 *  @{
 */
#include <net-snmp/net-snmp-config.h>
#include <sys/types.h>
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/utilities.h>

#include <net-snmp/library/callback.h>
#include <net-snmp/library/snmp_api.h>

static struct snmp_gen_callback
               *thecallbacks[MAX_CALLBACK_IDS][MAX_CALLBACK_SUBIDS];

/*
 * extermely simplistic locking, just to find problems were the
 * callback list is modified while being traversed. Not intended
 * to do any real protection, or in any way imply that this code
 * has been evaluated for use in a multi-threaded environment.
 */
static int _lock = 0;


/*
 * the chicken. or the egg.  You pick. 
 */
void
init_callbacks(void)
{
    /*
     * probably not needed? Should be full of 0's anyway? 
     */
    /*
     * (poses a problem if you put init_callbacks() inside of
     * init_snmp() and then want the app to register a callback before
     * init_snmp() is called in the first place.  -- Wes 
     */
    /*
     * memset(thecallbacks, 0, sizeof(thecallbacks)); 
     */
    DEBUGMSGTL(("callback", "initialized\n"));
}

/**
 * This function registers a generic callback function.  The major and
 * minor values are used to set the new_callback function into a global 
 * static multi-dimensional array of type struct snmp_gen_callback.  
 * The function makes sure to append this callback function at the end
 * of the link list, snmp_gen_callback->next.
 *
 * @param major is the SNMP callback major type used
 * 		- SNMP_CALLBACK_LIBRARY
 *              - SNMP_CALLBACK_APPLICATION
 *
 * @param minor is the SNMP callback minor type used
 *		- SNMP_CALLBACK_POST_READ_CONFIG
 *		- SNMP_CALLBACK_STORE_DATA	        
 *		- SNMP_CALLBACK_SHUTDOWN		        
 *		- SNMP_CALLBACK_POST_PREMIB_READ_CONFIG	
 *		- SNMP_CALLBACK_LOGGING			
 *		- SNMP_CALLBACK_SESSION_INIT	       
 *
 * @param new_callback is the callback function that is registered.
 *
 * @param arg when not NULL is a void pointer used whenever new_callback 
 *	function is exercised.
 *
 * @return 
 *	Returns SNMPERR_GENERR if major is >= MAX_CALLBACK_IDS or minor is >=
 *	MAX_CALLBACK_SUBIDS or a snmp_gen_callback pointer could not be 
 *	allocated, otherwise SNMPERR_SUCCESS is returned.
 * 	- #define MAX_CALLBACK_IDS    2
 *	- #define MAX_CALLBACK_SUBIDS 16
 *
 * @see snmp_call_callbacks
 * @see snmp_unregister_callback
 */
int
snmp_register_callback(int major, int minor, SNMPCallback * new_callback,
                       void *arg)
{
    return netsnmp_register_callback( major, minor, new_callback, arg, 0);
}

int
netsnmp_register_callback(int major, int minor, SNMPCallback * new_callback,
                          void *arg, int priority)
{
    struct snmp_gen_callback *newscp = NULL, *scp = NULL;
    struct snmp_gen_callback **prevNext = &(thecallbacks[major][minor]);

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }
    if(++_lock > 1) {
        snmp_log(LOG_WARNING,
                 "netsnmp_register_callback called while callbacks _locked\n");
        netsnmp_assert(1==_lock);
    }

    if ((newscp = SNMP_MALLOC_STRUCT(snmp_gen_callback)) == NULL) {
        --_lock;
        return SNMPERR_GENERR;
    } else {
        newscp->priority = priority;
        newscp->sc_client_arg = arg;
        newscp->sc_callback = new_callback;
        newscp->next = NULL;

        for (scp = thecallbacks[major][minor]; scp != NULL;
             scp = scp->next) {
            if (newscp->priority < scp->priority) {
                newscp->next = scp;
                break;
            }
            prevNext = &(scp->next);
        }

        *prevNext = newscp;

        DEBUGMSGTL(("callback", "registered (%d,%d) at %p with priority %d\n",
                    major, minor, newscp, priority));
        --_lock;
        return SNMPERR_SUCCESS;
    }
}

/**
 * This function calls the callback function for each registered callback of
 * type major and minor.
 *
 * @param major is the SNMP callback major type used
 *
 * @param minor is the SNMP callback minor type used
 *
 * @param caller_arg is a void pointer which is sent in as the callback's 
 *	serverarg parameter, if needed.
 *
 * @return Returns SNMPERR_GENERR if major is >= MAX_CALLBACK_IDS or
 * minor is >= MAX_CALLBACK_SUBIDS, otherwise SNMPERR_SUCCESS is returned.
 *
 * @see snmp_register_callback
 * @see snmp_unregister_callback
 */
int
snmp_call_callbacks(int major, int minor, void *caller_arg)
{
    struct snmp_gen_callback *scp;
    unsigned int    count = 0;

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if(++_lock > 1) {
#ifdef NETSNMP_PARANOID_LEVEL_HIGH
        /*
         * Notes:
         * - this gets hit the first time a trap is sent after a new trap
         *   destination has been added (session init cb during send trap cb)
         */
        snmp_log(LOG_WARNING,
                 "snmp_call_callbacks called while callbacks _locked\n");
        netsnmp_assert(1==_lock);
#endif
    }

    DEBUGMSGTL(("callback", "START calling callbacks for maj=%d min=%d\n",
                major, minor));

    /*
     * for each registered callback of type major and minor 
     */
    for (scp = thecallbacks[major][minor]; scp != NULL; scp = scp->next) {

        /*
         * skip unregistered callbacks
         */
        if(NULL == scp->sc_callback)
            continue;

        DEBUGMSGTL(("callback", "calling a callback for maj=%d min=%d\n",
                    major, minor));

        /*
         * call them 
         */
        (*(scp->sc_callback)) (major, minor, caller_arg,
                               scp->sc_client_arg);
        count++;
    }

    DEBUGMSGTL(("callback",
                "END calling callbacks for maj=%d min=%d (%d called)\n",
                major, minor, count));

    --_lock;
    return SNMPERR_SUCCESS;
}

int
snmp_count_callbacks(int major, int minor)
{
    int             count = 0;
    struct snmp_gen_callback *scp;

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    for (scp = thecallbacks[major][minor]; scp != NULL; scp = scp->next) {
        count++;
    }

    return count;
}

int
snmp_callback_available(int major, int minor)
{
    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if (thecallbacks[major][minor] != NULL) {
        return SNMPERR_SUCCESS;
    }

    return SNMPERR_GENERR;
}

/**
 * This function unregisters a specified callback function given a major
 * and minor type.
 *
 * Note: no bound checking on major and minor.
 *
 * @param major is the SNMP callback major type used
 *
 * @param minor is the SNMP callback minor type used
 *
 * @param target is the callback function that will be unregistered.
 *
 * @param arg is a void pointer used for comparison against the registered 
 *	callback's sc_client_arg variable.
 *
 * @param matchargs is an integer used to bypass the comparison of arg and the
 *	callback's sc_client_arg variable only when matchargs is set to 0.
 *
 *
 * @return
 *        Returns the number of callbacks that were unregistered.
 *
 * @see snmp_register_callback
 * @see snmp_call_callbacks
 */

int
snmp_unregister_callback(int major, int minor, SNMPCallback * target,
                         void *arg, int matchargs)
{
    struct snmp_gen_callback *scp = thecallbacks[major][minor];
    struct snmp_gen_callback **prevNext = &(thecallbacks[major][minor]);
    int             count = 0;

    if(++_lock > 1) {
        snmp_log(LOG_WARNING,
                 "snmp_unregister_callback called while callbacks _locked\n");
#ifdef NETSNMP_PARANOID_LEVEL_HIGH
        /*
         * Notes;
         * - this gets hit at shutdown, during cleanup. No easy fix.
         */
        netsnmp_assert(1==_lock);
#endif
    }
    while (scp != NULL) {
        if ((scp->sc_callback == target) &&
            (!matchargs || (scp->sc_client_arg == arg))) {
            DEBUGMSGTL(("callback", "unregistering (%d,%d) at %p\n", major,
                        minor, scp));
            if(_lock == 1) {
                *prevNext = scp->next;
                SNMP_FREE(scp);
                scp = *prevNext;
            }
            else {
                scp->sc_callback = NULL;
                /** set cleanup flag? */
            }
            count++;
        } else {
            prevNext = &(scp->next);
            scp = scp->next;
        }
    }

    --_lock;
    return count;
}

void
clear_callback(void)
{
    unsigned int i = 0, j = 0; 
    struct snmp_gen_callback *scp = NULL, *next = NULL;

    if(++_lock > 1) {
        snmp_log(LOG_WARNING,
                 "clear_callback called while callbacks _locked\n");
        netsnmp_assert(1==_lock);
    }
    DEBUGMSGTL(("callback", "clear callback\n"));
    for (i = 0; i < MAX_CALLBACK_IDS; i++) {
	for (j = 0; j < MAX_CALLBACK_SUBIDS; j++) {
	    scp = thecallbacks[i][j]; 
	    while (scp != NULL) {
		next = scp->next;
		if ((NULL != scp->sc_callback) && (scp->sc_client_arg != NULL))
		    SNMP_FREE(scp->sc_client_arg);
		SNMP_FREE(scp);
		scp = next;
	    }
	    thecallbacks[i][j] = NULL;
	}
    }
    --_lock;
}

struct snmp_gen_callback *
snmp_callback_list(int major, int minor)
{
    return (thecallbacks[major][minor]);
}
/**  @} */
