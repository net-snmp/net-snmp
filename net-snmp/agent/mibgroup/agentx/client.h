#ifndef AGENTX_CLIENT_H
#define AGENTX_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif
/*
 *  Utility functions for Agent Extensibility Protocol (RFC 2257)
 *
 */


int agentx_open_session( struct snmp_session *);
int agentx_close_session( struct snmp_session *, int);
int agentx_register( struct snmp_session *, oid*, size_t, int, int, oid, int);
int agentx_unregister( struct snmp_session *, oid*, size_t, int, int, oid);
struct variable_list *agentx_register_index( struct snmp_session *, struct variable_list*, int);
int agentx_unregister_index( struct snmp_session *, struct variable_list*);
int agentx_add_agentcaps( struct snmp_session *, oid*, size_t, const char*);
int agentx_remove_agentcaps( struct snmp_session *, oid*, size_t);
int agentx_send_ping( struct snmp_session * );

#define AGENTX_CLOSE_OTHER    1
#define AGENTX_CLOSE_PARSE    2
#define AGENTX_CLOSE_PROTOCOL 3
#define AGENTX_CLOSE_TIMEOUT  4
#define AGENTX_CLOSE_SHUTDOWN 5
#define AGENTX_CLOSE_MANAGER  6

#ifdef __cplusplus
}
#endif

#endif /* AGENTX_CLIENT_H */
