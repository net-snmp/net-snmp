#ifndef SNMP_ALARM_H
#define SNMP_ALARM_H

typedef void (SNMPAlarmCallback)(unsigned int clientreg, void *clientarg);

#define SA_REPEAT 0x01

struct snmp_alarm {
   unsigned int seconds;
   unsigned int flags;
   unsigned int clientreg;
   time_t lastcall;
   time_t nextcall;
   void *clientarg;
   SNMPAlarmCallback *thecallback;
   struct snmp_alarm *next;
};

/* the ones you should need */
void snmp_alarm_unregister(unsigned int clientreg);
unsigned int snmp_alarm_register(unsigned int when, unsigned int flags,
                                 SNMPAlarmCallback *thecallback,
                                 void *clientarg);

/* the ones you shouldn't */
void init_snmp_alarm(void);
int init_alarm_post_config(int majorid, int minorid, void *serverarg,
                           void *clientarg);
void sa_update_entry(struct snmp_alarm *alrm);
struct snmp_alarm *sa_find_next(void);
void run_alarms(void);
RETSIGTYPE alarm_handler(int a);
void set_an_alarm(void);


#endif /* SNMP_ALARM_H */
