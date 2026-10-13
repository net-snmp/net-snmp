/* HEADER Testing snmp_client APIs, snmp_pdu_add_variable, snmp_synch_input, state_machine */
    int run_t110(void);
    int rc = run_t110();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <net-snmp/library/snmpCallbackDomain.h>
#include <net-snmp/library/snmp_client.h>

static int
t110_step_ok(netsnmp_state_machine_input *input,
             netsnmp_state_machine_step *step)
{
    int *counter = (int *)input->input_context;
    if (counter)
        (*counter)++;
    return SNMPERR_SUCCESS;
}

static int
t110_step_err(netsnmp_state_machine_input *input,
              netsnmp_state_machine_step *step)
{
    int *counter = (int *)input->input_context;
    if (counter)
        (*counter) += 10;
    return SNMPERR_GENERR;
}

static int
t110_step_cleanup(netsnmp_state_machine_input *input,
                  netsnmp_state_machine_step *step)
{
    int *counter = (int *)input->input_context;
    if (counter)
        (*counter) += 100;
    return SNMPERR_SUCCESS;
}

int
run_t110(void)
{
    netsnmp_pdu *pdu;
    oid test_oid[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
    long dummy_val = 42;
    netsnmp_variable_list *vb;

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T110snmp_client");

    /* 1. snmp_pdu_add_variable() with invalid type frees variable and returns NULL */
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    OK(pdu != NULL, "snmp_pdu_create succeeded");
    vb = snmp_pdu_add_variable(pdu, test_oid, OID_LENGTH(test_oid),
                               0xFF /* invalid type */, &dummy_val,
                               sizeof(dummy_val));
    OK(vb == NULL && pdu->variables == NULL,
       "snmp_pdu_add_variable returns NULL and frees var on unknown type");

    vb = snmp_pdu_add_variable(pdu, test_oid, OID_LENGTH(test_oid),
                               ASN_INTEGER, &dummy_val, sizeof(dummy_val));
    OK(vb != NULL && pdu->variables == vb,
       "snmp_pdu_add_variable succeeds for valid ASN_INTEGER");
    snmp_free_pdu(pdu);

    /*
     * 2. snmp_synch_input() with unexpected PDU command (pdu->command != state->waiting)
     * Use callback transport: inject an unsolicited SNMP_MSG_TRAP2 into the
     * client callback queue before calling snmp_synch_response().
     */
#ifdef NETSNMP_TRANSPORT_CALLBACK_DOMAIN
    {
        netsnmp_session *srv_ss, *cli_ss, *to_cli_ss;
        netsnmp_pdu *req_pdu, *unexp_pdu, *resp_pdu = NULL;
        int rc;

        srv_ss = netsnmp_callback_open(0, NULL, NULL, NULL);
        OK(srv_ss != NULL, "server callback session created");
        cli_ss = netsnmp_callback_open(srv_ss ? srv_ss->local_port : 1,
                                       NULL, NULL, NULL);
        OK(cli_ss != NULL, "client callback session created");
        if (cli_ss) {
            cli_ss->version = SNMP_VERSION_2c;
            free(cli_ss->community);
            cli_ss->community = (u_char *)strdup("public");
            cli_ss->community_len = 6;
            cli_ss->retries = 0;
            cli_ss->timeout = 50000;
        }

        to_cli_ss = netsnmp_callback_open(cli_ss ? cli_ss->local_port : 2,
                                          NULL, NULL, NULL);
        if (to_cli_ss && cli_ss) {
            to_cli_ss->version = SNMP_VERSION_2c;
            free(to_cli_ss->community);
            to_cli_ss->community = (u_char *)strdup("public");
            to_cli_ss->community_len = 6;

            req_pdu = snmp_pdu_create(SNMP_MSG_GET);
            snmp_add_null_var(req_pdu, test_oid, OID_LENGTH(test_oid));

            unexp_pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
            unexp_pdu->version = SNMP_VERSION_2c;
            unexp_pdu->reqid = req_pdu->reqid;
            snmp_send(to_cli_ss, unexp_pdu);

            rc = snmp_synch_response(cli_ss, req_pdu, &resp_pdu);
            OK(rc == STAT_SUCCESS || rc == STAT_ERROR,
               "snmp_synch_response processed queued unexpected PDU");
            if (resp_pdu)
                snmp_free_pdu(resp_pdu);
        }
        if (to_cli_ss)
            snmp_close(to_cli_ss);
        if (cli_ss)
            snmp_close(cli_ss);
        if (srv_ss)
            snmp_close(srv_ss);
    }
#endif

    /* 3. netsnmp_state_machine_run() positive and error/cleanup paths */
    {
        int ctx = 0;
        netsnmp_state_machine_step cleanup_step = {
            "cleanup_step", 0, t110_step_cleanup, 0, NULL, NULL, 0, NULL
        };
        netsnmp_state_machine_step step2 = {
            "step2_err", 0, t110_step_err, 0, NULL, NULL, 0, NULL
        };
        netsnmp_state_machine_step step1 = {
            "step1_ok", 0, t110_step_ok, 0, &step2, NULL, 0, NULL
        };
        netsnmp_state_machine_input sm_input = {
            "test_machine", 0, &step1, &cleanup_step, NULL, &ctx
        };
        int rc;

#ifndef NETSNMP_USE_ASSERT
        OK(netsnmp_state_machine_run(NULL) == SNMPERR_GENERR,
           "netsnmp_state_machine_run rejects NULL input");
#endif
        rc = netsnmp_state_machine_run(&sm_input);
        OK(rc == SNMPERR_GENERR && ctx == 111,
           "netsnmp_state_machine_run executes steps and runs cleanup step on error");
    }

    snmp_shutdown("T110snmp_client");
