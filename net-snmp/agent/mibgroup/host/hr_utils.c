/*
 *  Host Resources MIB - utility functions - hr_utils.c
 *
 */


#include <config.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <ctype.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "host_res.h"
#include "hr_utils.h"
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif


u_char *
date_n_time ( time_t *when, size_t  *length)
{
    struct tm	*tm_p;
    static u_char string[11];

		/*
		 * Null time
		 */
    if ( when == NULL || *when == 0 || *when == (time_t)-1 ) {
	string[0] =  0;
	string[1] =  0;
	string[2] =  1;
	string[3] =  1;
	string[4] =  0;
	string[5] =  0;
	string[6] =  0;
	string[7] =  0;
	*length = 8;
	return string;
    }
	

	/*
	 * Basic 'local' time handling
	 */
    tm_p = localtime( when );
    * (short *)string = htons( tm_p->tm_year+1900 );
    string[2] =  tm_p->tm_mon+1;
    string[3] =  tm_p->tm_mday;
    string[4] =  tm_p->tm_hour;
    string[5] =  tm_p->tm_min;
    string[6] =  tm_p->tm_sec;
    string[7] =  0;
    *length = 8;

#ifndef cygwin
	/*
	 * Timezone offset
	 */
#ifndef SYSV
#define timezone tm_p->tm_gmtoff
#endif
    if ( timezone > 0 )
	string[8] = '-';
    else
	string[8] = '+';
    string[9] = abs(timezone)/3600;
    string[10] = (abs(timezone) - string[9]*3600)/60;
    *length = 11;
#endif

#ifdef SYSV
	/*
	 * Daylight saving time
	 */
    if ( tm_p->tm_isdst > 0 ) {
		/* Assume add one hour */
	if ( string[8]=='-' )
	   --string[9];
	else
	   ++string[9];

	if ( string[9]==0 )
	   string[8]='+';
    }
#endif
		
    return string;
}


time_t ctime_to_timet( char* string )
{
    struct tm tm;

    if ( strlen(string) < 24 )
	return 0;

		/* Month */
         if ( !strncmp( string+4, "Jan", 3 ))  tm.tm_mon = 0;
    else if ( !strncmp( string+4, "Feb", 3 ))  tm.tm_mon = 1;
    else if ( !strncmp( string+4, "Mar", 3 ))  tm.tm_mon = 2;
    else if ( !strncmp( string+4, "Apr", 3 ))  tm.tm_mon = 3;
    else if ( !strncmp( string+4, "May", 3 ))  tm.tm_mon = 4;
    else if ( !strncmp( string+4, "Jun", 3 ))  tm.tm_mon = 5;
    else if ( !strncmp( string+4, "Jul", 3 ))  tm.tm_mon = 6;
    else if ( !strncmp( string+4, "Aug", 3 ))  tm.tm_mon = 7;
    else if ( !strncmp( string+4, "Sep", 3 ))  tm.tm_mon = 8;
    else if ( !strncmp( string+4, "Oct", 3 ))  tm.tm_mon = 9;
    else if ( !strncmp( string+4, "Nov", 3 ))  tm.tm_mon = 10;
    else if ( !strncmp( string+4, "Dec", 3 ))  tm.tm_mon = 11;
    else return 0;

	tm.tm_mday = atoi(string+8);
	tm.tm_hour = atoi(string+11);
	tm.tm_min  = atoi(string+14);
	tm.tm_sec  = atoi(string+17);
	tm.tm_year = atoi(string+20) - 1900;

		/* 
		 *  Cope with timezone and DST
		 */

#ifdef SYSV
	if ( daylight )
	    tm.tm_isdst = 1;

	tm.tm_sec -= timezone;
#endif
	
    return( mktime( &tm ));
}
