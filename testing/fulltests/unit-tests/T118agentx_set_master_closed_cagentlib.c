/* HEADER AgentX subagent SET requests of a master agent that disconnected */

#if !defined(USING_AGENTX_SUBAGENT_MODULE) || \
    !defined(NETSNMP_TRANSPORT_CALLBACK_DOMAIN) || \
    defined(NETSNMP_NO_WRITE_SUPPORT) || \
    defined(NETSNMP_FEATURE_REMOVE_AGENTX_ENABLE_SUBAGENT) || \
    defined(NETSNMP_FEATURE_REMOVE_LONG_INSTANCE)
printf("1..0 # skip AgentX subagent or SET support not enabled\n");
__did_plan = 1;
return 0;
#else
extern int handle_agentx_packet(int operation, netsnmp_session *session,
                                int reqid, netsnmp_pdu *pdu, void *magic);
extern struct agent_netsnmp_set_info *
restore_set_vars(netsnmp_session *sess, netsnmp_pdu *pdu);
extern netsnmp_session *agentx_callback_sess;

/*
 * Pass @cmd of transaction @tid from session @ms to the subagent, as the
 * AgentX session to the master agent does. A TestSet sets the value to @val.
 */
#define FROM_MASTER(ms, cmd, tid, val)                                  \
    do {                                                                \
        netsnmp_pdu *p = snmp_pdu_create(cmd);                          \
        long v = (val);                                                 \
        p->transid = (tid);                                             \
        if ((cmd) == AGENTX_MSG_TESTSET)                                \
            snmp_pdu_add_variable(p, instance_oid,                      \
                                  OID_LENGTH(instance_oid),             \
                                  ASN_INTEGER, &v, sizeof(v));          \
        handle_agentx_packet(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,      \
                             (ms), p->reqid, p, NULL);                  \
        snmp_free_pdu(p);                                               \
    } while (0)
#define MASTER_CLOSED(ms)                                               \
    handle_agentx_packet(NETSNMP_CALLBACK_OP_DISCONNECT, (ms), 0,       \
                         NULL, NULL)
/*
 * Set @freed to whether the subagent has freed the state it saved for
 * transaction @tid. Until then, the state of a set of a closed master
 * session is kept without a session.
 */
#define SET_FREED(tid, freed)                                           \
    do {                                                                \
        netsnmp_pdu *p = snmp_pdu_create(AGENTX_MSG_CLEANUPSET);        \
        p->transid = (tid);                                             \
        (freed) = restore_set_vars(NULL, p) == NULL;                    \
        snmp_free_pdu(p);                                               \
    } while (0)
#define RUN_AGENT()                                                     \
    do {                                                                \
        int i;                                                          \
        for (i = 0; i < 10; i++)                                        \
            agent_check_and_process(0);                                 \
    } while (0)

static oid      instance_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 118, 0 };
static long     value = 1;
netsnmp_session master[5];
int             m, freed;
long            cb_version;

SOCK_STARTUP;

netsnmp_enable_subagent();
netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                       NETSNMP_DS_AGENT_NO_CONNECTION_WARNINGS, 1);
netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_X_SOCKET,
                      "/nonexistent/T118agentx");
init_agent("snmpd");
/* no attempts to reconnect to the master agent */
netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_AGENTX_PING_INTERVAL, 0);
init_snmp("snmpd");

OK(netsnmp_register_long_instance("T118", instance_oid,
                                  OID_LENGTH(instance_oid), &value,
                                  NULL) == MIB_REGISTERED_OK,
   "writable instance registered");

/*
 * The response to each phase is sent to the master session; these are not
 * open sessions, so the library drops what is sent to them.
 */
memset(master, 0, sizeof(master));
for (m = 0; m < 5; m++) {
    master[m].version = AGENTX_VERSION_1;
    master[m].securityModel = SNMP_DEFAULT_SECMODEL;
}

/* The master agent disconnects after TestSet: the set is freed. */
FROM_MASTER(&master[0], AGENTX_MSG_TESTSET, 1, 2);
RUN_AGENT();
MASTER_CLOSED(&master[0]);
RUN_AGENT();
SET_FREED(1, freed);
OK(value == 1 && freed,
   "set waiting for CommitSet is freed when the master closes");

/* The master agent disconnects after CommitSet: the set is undone. */
FROM_MASTER(&master[1], AGENTX_MSG_TESTSET, 2, 3);
RUN_AGENT();
FROM_MASTER(&master[1], AGENTX_MSG_COMMITSET, 2, 0);
RUN_AGENT();
OK(value == 3, "CommitSet changes the value");
MASTER_CLOSED(&master[1]);
RUN_AGENT();
SET_FREED(2, freed);
OK(value == 1 && freed,
   "set waiting for CleanupSet is undone when the master closes");

/* The master agent disconnects while CommitSet is being processed. */
FROM_MASTER(&master[2], AGENTX_MSG_TESTSET, 3, 4);
RUN_AGENT();
FROM_MASTER(&master[2], AGENTX_MSG_COMMITSET, 3, 0);
MASTER_CLOSED(&master[2]);
RUN_AGENT();
SET_FREED(3, freed);
OK(value == 1 && freed,
   "set in CommitSet is undone when the master closes meanwhile");

/* The master agent disconnects while TestSet is being processed. */
FROM_MASTER(&master[3], AGENTX_MSG_TESTSET, 4, 5);
MASTER_CLOSED(&master[3]);
RUN_AGENT();
SET_FREED(4, freed);
OK(value == 1 && freed,
   "set in TestSet is freed when the master closes meanwhile");

/*
 * The master agent disconnects while TestSet is being processed, and the
 * subagent can pass on neither RESERVE2 nor FREE: a session version that does
 * not match the AgentX PDUs makes each send fail. The set is freed once.
 */
FROM_MASTER(&master[4], AGENTX_MSG_TESTSET, 5, 6);
MASTER_CLOSED(&master[4]);
cb_version = agentx_callback_sess->version;
agentx_callback_sess->version = SNMP_VERSION_2c;
RUN_AGENT();
agentx_callback_sess->version = cb_version;
SET_FREED(5, freed);
OK(value == 1 && freed,
   "set whose next phase cannot be passed on is freed once");

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif
