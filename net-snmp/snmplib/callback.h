/* callback.c: A generic callback mechanism */

#ifndef CALLBACK_H
#define CALLBACK_H

#define MAX_CALLBACK_IDS    1
#define MAX_CALLBACK_SUBIDS 2

/* Callback Major Types */
#define SNMP_CALLBACK_LIBRARY     0
#define SNMP_CALLBACK_APPLICATION 1

/* SNMP_CALLBACK_LIBRARY minor types */
#define SNMP_CALLBACK_POST_READ_CONFIG	0
#define SNMP_CALLBACK_STORE_DATA	1
#define SNMP_CALLBACK_SHUTDOWN		2

typedef int (SNMPCallback)(int majorID, int minorID, void *serverarg,
                           void *clientarg);

struct snmp_gen_callback {
   SNMPCallback         *sc_callback;
   void                 *sc_client_arg;
   struct snmp_gen_callback *next;
};

#endif /* CALLBACK_H */
