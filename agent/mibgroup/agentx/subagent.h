#ifndef _AGENTX_SUBAGENT_H
#define _AGENTX_SUBAGENT_H

config_belongs_in(agent_module)

config_require(agentx/protocol)
config_require(agentx/client)
config_require(agentx/agentx_config)

#ifndef NETSNMP_TRANSPORT_CALLBACK_DOMAIN
config_error(agentx/subagent depends on the Callback transport)
#endif

     extern int             callback_master_num;

     extern const oid       snmptrap_oid[];
     extern const oid       snmptrapenterprise_oid[];
     extern const oid       sysuptime_oid[];
     extern const size_t    snmptrap_oid_len;
     extern const size_t    snmptrapenterprise_oid_len;
     extern const size_t    sysuptime_oid_len;

     int             subagent_init(void);
     int             handle_agentx_packet(int, netsnmp_session *, int,
                                          netsnmp_pdu *, void *);
     SNMPCallback    agentx_register_callback;
     SNMPCallback    agentx_unregister_callback;
     SNMPAlarmCallback agentx_check_session;

#endif                          /* _AGENTX_SUBAGENT_H */
