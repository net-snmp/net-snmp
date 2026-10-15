/* HEADER Testing netsnmp_agent_session_closed() */

extern netsnmp_agent_session *agent_delegated_list;
extern netsnmp_agent_session *netsnmp_agent_queued_list;
extern int netsnmp_add_queued(netsnmp_agent_session *asp);
extern int netsnmp_wrap_up_request(netsnmp_agent_session *asp, int status);

static const oid sysUpTime_oid[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
netsnmp_session *closed_sess, *open_sess;
netsnmp_pdu *pdu;
netsnmp_agent_session *queued_asp, *delegated_asp, *handled_asp, *other_asp;

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");

closed_sess = calloc(1, sizeof(*closed_sess));
open_sess = calloc(1, sizeof(*open_sess));
pdu = snmp_pdu_create(SNMP_MSG_GET);
OK(closed_sess && open_sess && pdu, "allocation");
snmp_add_null_var(pdu, sysUpTime_oid, OID_LENGTH(sysUpTime_oid));

queued_asp = init_agent_snmp_session(closed_sess, pdu);
delegated_asp = init_agent_snmp_session(closed_sess, pdu);
handled_asp = init_agent_snmp_session(closed_sess, pdu);
other_asp = init_agent_snmp_session(open_sess, pdu);
OK(queued_asp && delegated_asp && handled_asp && other_asp,
   "agent sessions created");

netsnmp_add_queued(queued_asp);
netsnmp_add_queued(other_asp);
delegated_asp->next = agent_delegated_list;
agent_delegated_list = delegated_asp;

OK(handle_snmp_packet(NETSNMP_CALLBACK_OP_DISCONNECT, closed_sess, 0, NULL,
                      NULL) == 1, "disconnect handled");
OK(queued_asp->session == NULL, "queued request forgets the closed session");
OK(delegated_asp->session == NULL,
   "delegated request forgets the closed session");
OK(handled_asp->session == NULL,
   "request being handled forgets the closed session");
OK(other_asp->session == open_sess,
   "request on another session keeps its session");
free(closed_sess);

netsnmp_agent_queued_list = other_asp;
queued_asp->next = NULL;
OK(netsnmp_wrap_up_request(queued_asp, SNMP_ERR_NOERROR) == 1,
   "queued request wrapped up without a session");
OK(netsnmp_wrap_up_request(delegated_asp, SNMP_ERR_NOERROR) == 1,
   "delegated request wrapped up without a session");
OK(agent_delegated_list == NULL, "delegated list empty");
OK(netsnmp_wrap_up_request(handled_asp, SNMP_ERR_NOERROR) == 1,
   "request being handled wrapped up without a session");

OK(netsnmp_agent_session_closed(open_sess) == 1,
   "closing the other session finds its request");
netsnmp_agent_queued_list = NULL;
other_asp->next = NULL;
free_agent_snmp_session(other_asp);
free(open_sess);
snmp_free_pdu(pdu);

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
