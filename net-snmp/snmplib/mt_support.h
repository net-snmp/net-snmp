
/* mt_support.h - multi-thread resource locking support declarations */
/*
 * Author: Markku Laukkanen
 * Created: 6-Sep-1999
 * History:
 *  8-Sep-1999 M. Slifcak method names changed;
 *                        use array of resource locking structures.
 */

#ifndef MT_SUPPORT_H
#define MT_SUPPORT_H

#ifdef __cplusplus
extern "C" {
#endif


/* Lock identifiers for resources */

#define MT_NONE        0
#define MT_SESSION     1
#define MT_REQUESTID   2
#define MT_MESSAGEID   3

#define MT_MAXIMUM     4  /* must be one greater than the last one */


#ifdef _REENTRANT

#if defined(hpux10) || defined(hpux11)
  #include <pthread.h>
  typedef pthread_mutex_t mutex_type;
#elif HAVE_PTHREAD_H
  #include <pthread.h>
  typedef pthread_mutex_t mutex_type;
#elif defined(WIN32)
  #include <windows.h>
  typedef CRITICAL_SECTION  mutex_type;
#else
  error "There is no re-entrant support as defined."
#endif

void snmp_res_init(void);
void snmp_res_lock(int);
void snmp_res_unlock(int);
void snmp_res_destroy_mutex(int);

#else  /* !_REENTRANT */

#define snmp_res_init() 
#define snmp_res_lock(x) 
#define snmp_res_unlock(x) 
#define snmp_res_destroy_mutex(x) 

#endif /* !_REENTRANT */

#ifdef __cplusplus
};
#endif

#endif /* MT_SUPPORT_H */

