/*
 * snmpv3.h
 */

#ifndef SNMPV3_H
#define SNMPV3_H

#define MAX_ENGINEID_LENGTH 128

int     setup_engineID(u_char **eidp, char *text);
void    engineID_conf(char *word, char *cptr);
void    engineBoots_conf(char *, char *);
void    snmpv3_authtype_conf(char *word, char *cptr);
void    snmpv3_privtype_conf(char *word, char *cptr);
void    init_snmpv3(char *);
void    shutdown_snmpv3(char *type);
int     snmpv3_local_snmpEngineBoots(void);
int     snmpv3_get_engineID(char *buf, int buflen);
u_char *snmpv3_generate_engineID(int *);
int     snmpv3_local_snmpEngineTime(void);
char   *get_default_context(void);
char   *get_default_secName(void);
int     get_default_secLevel(void);
oid    *get_default_authtype(int *);
oid    *get_default_privtype(int *);
char   *get_default_authpass(void);
char   *get_default_privpass(void);
int     snmpv3_set_engineBootsAndTime(int boots, int ttime);

#endif /* SNMPV3_H */
