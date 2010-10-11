#ifndef SNMPTRAPD_DS_H
#define SNMPTRAPD_DS_H

/* these must not conflict with agent's DS booleans */
#define NETSNMP_DS_APP_NUMERIC_IP       16
#define NETSNMP_DS_APP_NO_AUTHORIZATION 17

/*
 * NB: The NETSNMP_DS_APP_NO_AUTHORIZATION definition is repeated
 *     in the code file agent/mibgroup/mibII/vacm_conf.c
 *     If this definition is changed, it should be updated there too.
 */

#endif /* SNMPTRAPD_DS_H */
