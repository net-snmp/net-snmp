#ifndef SNMP_ASSERT_H
#define SNMP_ASSERT_H

#ifdef NETSNMP_USE_ASSERT
#   include <assert.h>
#else
#   include <net-snmp/library/snmp_logging.h>
#endif


/*
 * MACROs don't need extern "C"
 */

/*
 * always use assert if requested
 */
#ifdef NETSNMP_USE_ASSERT
/*   void netsnmp_assert( int );*/
#   define netsnmp_assert(x)  assert( x )
#else
/*
 *  if asserts weren't requested, just log, unless SNMP_NO_DEBUGGING specified
 */
#   ifndef SNMP_NO_DEBUGGING
#      ifdef  HAVE_CPP_UNDERBAR_FUNCTION_DEFINED
#         define netsnmp_assert(x)  do { \
                 if ( x ) \
                    ; \
                 else \
                    snmp_log(LOG_ERR,"netsnmp_assert %s failed %s:%d %s()\n", \
                             __STRING(x),__FILE__,__LINE__,__FUNCTION__); \
              }while(0)
#      else
#         define netsnmp_assert(x)  do { \
                 if( x )\
                    ; \
                 else \
                    snmp_log(LOG_ERR,"netsnmp_assert %s failed %s:%d\n", \
                             __STRING(x),__FILE__,__LINE__); \
              }while(0)
#      endif
#   else /* NO DEBUGGING */
#      define netsnmp_assert(x) void
#   endif /* NO DEBUGGING */
#endif /* not NETSNMP_USE_ASSERT */


#endif /* SNMP_ASSERT_H */
