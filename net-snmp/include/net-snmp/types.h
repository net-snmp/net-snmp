#ifndef NET_SNMP_TYPES_H
#define NET_SNMP_TYPES_H

    /**
     *  Definitions of data structures, used within the library API.
     */

#include <stdio.h>

#ifndef NET_SNMP_CONFIG_H
#error "Please include <net-snmp/net-snmp-config.h> before this file"
#endif

                        /*
                         * For 'timeval' 
                         */
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/types.h>
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>		/* For definition of in_addr_t */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_SUBID               /* temporary - duplicate definition protection */
#ifndef EIGHTBIT_SUBIDS
typedef u_long  oid;
#define MAX_SUBID   0xFFFFFFFF
#else
typedef u_char  oid;
#define MAX_SUBID   0xFF
#endif
#endif

#ifndef HAVE_SOCKLEN_T
typedef u_int socklen_t;
#endif

#ifndef HAVE_IN_ADDR_T
typedef u_int in_addr_t;
#endif

#ifndef HAVE_SSIZE_T
#if defined(__INT_MAX__) && __INT_MAX__ == 2147483647
typedef int ssize_t;
#else
typedef long ssize_t;
#endif
#endif


    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the types and structures relevant to the
     *  Net-SNMP API will be identified, and defined here directly.
     *
     *  But for the time being, this header file is primarily a placeholder,
     *  to allow application writers to adopt the new header file names.
     */


#include <net-snmp/definitions.h>
#include <net-snmp/library/snmp_api.h>
/*
 * #include <net-snmp/library/libsnmp.h> 
 */

    typedef struct netsnmp_index_s {
       int          len;
       oid         *oids;
    } netsnmp_index;


    typedef struct netsnmp_void_array_s {
       size_t  size;
       void * *array;
    } netsnmp_void_array;

    /*
     * references to various types
     */
    typedef struct netsnmp_ref_void {
       void * val;
    } netsnmp_ref_void;

#if 0
    typedef struct netsnmp_ref_u_char {
       u_char * val;
    } netsnmp_ref_U_char;

    typedef struct netsnmp_ref_char {
       char * val;
    } netsnmp_ref_void;

    typedef struct netsnmp_ref_int_s {
       int val;
    } netsnmp_ref_int;

    typedef struct netsnmp_ref_u_int_s {
       u_int val;
    } netsnmp_ref_int;

    typedef struct netsnmp_ref_u_long_s {
       u_long val;
    } netsnmp_ref_u_long;
#endif

    typedef struct netsnmp_ref_size_t_s {
       size_t val;
    } * netsnmp_ref_size_t;

#ifdef __cplusplus
};
#endif

#endif                          /* NET_SNMP_TYPES_H */
