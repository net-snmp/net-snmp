#ifndef DELIVERBYNOTIFY_H
#define DELIVERBYNOTIFY_H 1

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

void init_deliverByNotify(void);

void parse_deliver_config(const char *, char *);
void free_deliver_config(void);

SNMPAlarmCallback deliver_execute;


/* implementation details */
typedef struct deliver_by_notify_s {
   int     frequency;
   int     last_run;
   int     next_run;
   oid    *target;
   size_t  target_size;
   int     max_packet_size;
} deliver_by_notify;

int calculate_time_until_next_run(deliver_by_notify *it, time_t *now);

#endif /* deliverByNotify_h */
