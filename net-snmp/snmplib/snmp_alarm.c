/* snmp_alarm.c: generic library based alarm timers for various parts
   of an application */

#include <config.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

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
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_debug.h"
#include "tools.h"
#include "default_store.h"
#include "callback.h"
#include "snmp_alarm.h"

static struct snmp_alarm *thealarms;
static int start_alarms = 0;
static unsigned int regnum = 1;

int
init_alarm_post_config(int majorid, int minorid, void *serverarg,
                     void *clientarg) {
  start_alarms = 1;
  set_an_alarm();
  return SNMPERR_SUCCESS;
}

void
init_snmp_alarm(void) {
  start_alarms = 0;
  snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_POST_READ_CONFIG,
                         init_alarm_post_config, NULL);
}

void
sa_update_entry(struct snmp_alarm *alrm) {
  if (alrm->seconds == 0) {
    DEBUGMSGTL(("snmp_alarm_update_entry","illegal 0 length alarm timer specified\n"));
    return; /* illegal */
  }
  if (alrm->lastcall == 0) {
    /* never been called yet, call seconds from now. */
    alrm->lastcall = time(NULL);
    alrm->nextcall = alrm->lastcall + alrm->seconds;
  } else if (alrm->nextcall == 0) {
    /* We've been called but not reset for the next? call */
    if ((alrm->flags & SA_REPEAT) == SA_REPEAT) {
      alrm->nextcall = alrm->lastcall + alrm->seconds;
    } else {
      /* single time call, remove it */
      snmp_alarm_unregister(alrm->clientreg);
    }
  }
}

void
snmp_alarm_unregister(unsigned int clientreg) {
  struct snmp_alarm *sa_ptr, **prevNext = &thealarms;

  for (sa_ptr = thealarms;
       sa_ptr != NULL && sa_ptr->clientreg != clientreg;
       sa_ptr = sa_ptr->next) {
    prevNext = &(sa_ptr->next);
  }

  if (sa_ptr != NULL) {
    *prevNext = sa_ptr->next;
    DEBUGMSGTL(("snmp_alarm_unregister","alarm %d\n",sa_ptr->clientreg));
    /* Note:  do not free the clientarg, its the clients responsibility */
    free(sa_ptr);
  } else {
    DEBUGMSGTL(("snmp_alarm_unregister","alarm %d doesn't exist\n",clientreg));
  }
}
  

struct snmp_alarm *
sa_find_next(void) {
  struct snmp_alarm *sa_ptr, *sa_ret = NULL;
  for(sa_ptr = thealarms; sa_ptr != NULL; sa_ptr = sa_ptr->next) {
    if (sa_ret == NULL || sa_ptr->nextcall < sa_ret->nextcall)
      sa_ret = sa_ptr;
  }
  return sa_ret;
}

struct snmp_alarm *
sa_find_specific(unsigned int clientreg)
{
  struct snmp_alarm *sa_ptr;
  for (sa_ptr = thealarms; sa_ptr != NULL; sa_ptr = sa_ptr->next) {
    if (sa_ptr->clientreg == clientreg) {
      return sa_ptr;
    }
  }
  return NULL;
}

void
run_alarms(void) {
  int done=0;
  struct snmp_alarm *sa_ptr;
  unsigned int clientreg;

  /* loop through everything we have repeatedly looking for the next
     thing to call until all events are finally in the future again */
  DEBUGMSGTL(("snmp_alarm_run_alarms","looking for alarms to run...\n"));
  while(done == 0) {
    sa_ptr = sa_find_next();
    if (sa_ptr == NULL)
      return;
    if (sa_ptr->nextcall <= time(NULL)) {
      clientreg = sa_ptr->clientreg;
      DEBUGMSGTL(("snmp_alarm_run_alarms","  running alarm %d\n", clientreg));
      (*(sa_ptr->thecallback))(sa_ptr->clientreg, sa_ptr->clientarg);
      DEBUGMSGTL(("snmp_alarm_run_alarms","     ... done\n"));
      if ((sa_ptr = sa_find_specific(clientreg)) != NULL) {
	sa_ptr->lastcall = time(NULL);
	sa_ptr->nextcall = 0;
	sa_update_entry(sa_ptr);
      } else {
	DEBUGMSGTL(("snmp_alarm_run_alarms", "alarm deleted by callback?\n"));
      }
    } else {
      done = 1;
    }
  }
  DEBUGMSGTL(("snmp_alarm_run_alarms","Done.\n"));
}


RETSIGTYPE
alarm_handler(int a) {
  run_alarms();
  set_an_alarm();
}

int
get_next_alarm_delay_time(void) {
  struct snmp_alarm *sa_ptr;
  int nexttime = 0;

  sa_ptr = sa_find_next();
  if (sa_ptr) {
    nexttime = sa_ptr->nextcall - time(NULL);
    if (nexttime <= 0)
      nexttime = 1; /* occurred already, return 1 second */
  }
  return nexttime;
}


void
set_an_alarm(void) {
  int nexttime = get_next_alarm_delay_time();
  
  /* we don't use signals if they asked us nicely not to.  It's
     expected they'll check the next alarm time and do their own
     calling of run_alarms(). */
  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_ALARM_DONT_USE_SIG) && nexttime) {
#ifdef SIGALRM
    alarm(nexttime);
    DEBUGMSGTL(("snmp_alarm_set_an_alarm","setting an alarm for %d seconds from now\n",nexttime));
    signal(SIGALRM, alarm_handler);
#endif /* SIGALRM */
  } else {
    DEBUGMSGTL(("snmp_alarm_set_an_alarm","no alarms found to handle\n"));
  }
}

unsigned int
snmp_alarm_register(unsigned int when, unsigned int flags,
                    SNMPAlarmCallback *thecallback, void *clientarg) {
  struct snmp_alarm **sa_pptr;
  if (thealarms != NULL) {
    for(sa_pptr = &thealarms; (*sa_pptr) != NULL;
        sa_pptr = &((*sa_pptr)->next));
  } else {
    sa_pptr = &thealarms;
  }

  *sa_pptr = SNMP_MALLOC_STRUCT(snmp_alarm);
  if (*sa_pptr == NULL)
    return 0;

  (*sa_pptr)->seconds = when;
  (*sa_pptr)->flags = flags;
  (*sa_pptr)->clientarg = clientarg;
  (*sa_pptr)->thecallback = thecallback;
  (*sa_pptr)->clientreg = regnum++;
  (*sa_pptr)->next = NULL;
  sa_update_entry(*sa_pptr);

  DEBUGMSGTL(("snmp_alarm_register","registered alarm %d, secends=%d, flags=%d\n",
              (*sa_pptr)->clientreg, (*sa_pptr)->seconds, (*sa_pptr)->flags));

  if (start_alarms)
    set_an_alarm();
  return (*sa_pptr)->clientreg;
} 
