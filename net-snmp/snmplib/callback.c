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
    struct snmp_gen_callback *newscp = NULL, *scp = NULL;
    struct snmp_gen_callback **prevNext = &(thecallbacks[major][minor]);

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if ((newscp = SNMP_MALLOC_STRUCT(snmp_gen_callback)) == NULL) {
        return SNMPERR_GENERR;
    } else {
        newscp->sc_client_arg = arg;
        newscp->sc_callback = new_callback;
        newscp->next = NULL;

        for (scp = thecallbacks[major][minor]; scp != NULL;
             scp = scp->next) {
            prevNext = &(scp->next);
        }

        *prevNext = newscp;

        DEBUGMSGTL(("callback", "registered (%d,%d) at %p\n", major, minor,
                    newscp));
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

    DEBUGMSGTL(("callback", "START calling callbacks for maj=%d min=%d\n",
                major, minor));

    /*
     * for each registered callback of type major and minor 
     */
    for (scp = thecallbacks[major][minor]; scp != NULL; scp = scp->next) {

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

    while (scp != NULL) {
        if ((scp->sc_callback == target) &&
            (!matchargs || (scp->sc_client_arg == arg))) {
            DEBUGMSGTL(("callback", "unregistering (%d,%d) at %p\n", major,
                        minor, scp));
            *prevNext = scp->next;
            SNMP_FREE(scp);
            scp = *prevNext;
            count++;
        } else {
            prevNext = &(scp->next);
            scp = scp->next;
        }
    }

    return count;
}

struct snmp_gen_callback *
snmp_callback_list(int major, int minor)
{
    return (thecallbacks[major][minor]);
}
/**  @} */
