
/* mt_support.c - multi-thread resource locking support */
/*
 * Author: Markku Laukkanen
 * Created: 6-Sep-1999
 * History:
 *  8-Sep-1999 M. Slifcak method names changed;
 *                        use array of resource locking structures.
 */

#include <config.h>
#include "mt_support.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _REENTRANT

static
mutex_type s_res[MT_MAXIMUM];  /* locking structures */

static mutex_type * _mt_res(int mt_val)
{
    if (mt_val < 1) return 0;
    if (mt_val >= MT_MAXIMUM) return 0;
    return (&s_res[mt_val]);
}

void snmp_res_init(void)
{    
    int ii = MT_MAXIMUM;
    mutex_type *mutex;

  for (ii = 0; ii < MT_MAXIMUM; ii++)
  {
    mutex = _mt_res(ii);
    if (!mutex) continue;
    
#ifdef hpux10
    pthread_mutex_init(mutex,pthread_mutexattr_default);
#elif HAVE_PTHREAD_H
    pthread_mutex_init(mutex, 0);
#elif defined(solaris2)
    mutex_init(mutex,USYNC_THREAD,NULL);
#elif defined(WIN32)
    InitializeCriticalSection(mutex);
#endif

  }
}

void snmp_res_destroy_mutex(int ii)
{    
    mutex_type *mutex = _mt_res(ii);
    if (!mutex) return;

#if defined(hpux10) || defined(hpux11)
    pthread_mutex_destroy(mutex);
#elif HAVE_PTHREAD_H
    pthread_mutex_destroy(mutex);
#elif defined(solaris2)
    mutex_destroy(mutex);
#elif defined(WIN32)
    DeleteCriticalSection(mutex);
#endif
}
    
void snmp_res_lock(int ii)
{
    mutex_type *mutex = _mt_res(ii);
    if (!mutex) return;

#if defined(hpux10) || defined(hpux11)
    pthread_mutex_lock(mutex);
#elif HAVE_PTHREAD_H
    pthread_mutex_lock(mutex);
#elif defined(solaris2)
    mutex_lock(mutex);
#elif defined(WIN32)
    EnterCriticalSection(mutex);
#endif
}

void snmp_res_unlock(int ii)
{
    mutex_type *mutex = _mt_res(ii);
    if (!mutex) return;

#if defined(hpux10) || defined(hpux11)
    pthread_mutex_unlock(mutex);
#elif HAVE_PTHREAD_H
    pthread_mutex_unlock(mutex);
#elif defined(solaris2)
    mutex_unlock(mutex);
#elif defined(WIN32)
    LeaveCriticalSection(mutex);
#endif
}


#endif /* _REENTRANT */


#ifdef __cplusplus
};
#endif

