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
int agentx_close_session( struct snmp_session *);
int agentx_register( struct snmp_session *, oid*, size_t);
int agentx_unregister( struct snmp_session *, oid*, size_t);
int agentx_add_agentcaps( struct snmp_session *, oid*, size_t, char*);
int agentx_remove_agentcaps( struct snmp_session *, oid*, size_t);


#ifdef __cplusplus
}
#endif

#endif /* AGENTX_CLIENT_H */
