/* HEADER Verify session template is not mutated by snmp_open (issue 1055) */

/*
 * Regression test for https://github.com/net-snmp/net-snmp/issues/1055
 *
 * Before commit 6a16c2df, f_setup_session() was called on the caller's
 * template session in snmp_sess_add_ex(), writing the OS-assigned
 * ephemeral port into in_session->local_port. A second snmp_open() on
 * the same template then tried to bind that port (now in use by the
 * first session), failing with EADDRINUSE.
 *
 * Bisected to ed917bfdb0 ("Copy the listening port number into
 * snmp_session.local_port").
 *
 * This test opens two sessions on the same template struct and verifies:
 * 1. The template's local_port remains zero after each open.
 * 2. Both sessions open successfully (the second would fail pre-fix).
 */

{
    netsnmp_session  session, *ss1, *ss2;

    SOCK_STARTUP;
    init_snmp("T021sessionreuse");

    snmp_sess_init(&session);
    session.peername = strdup("udp:127.0.0.1:65535");
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *) strdup("public");
    session.community_len = strlen("public");
    session.retries = 0;
    session.timeout = 100000;   /* 0.1s -- no agent needed, we only test open */

    OKF(session.local_port == 0,
        ("local_port is 0 before first open"));

    ss1 = snmp_open(&session);
    if (ss1) {
        OKF(session.local_port == 0,
            ("template local_port still 0 after first snmp_open (got %d)",
             session.local_port));

        ss2 = snmp_open(&session);
        OKF(ss2 != NULL,
            ("second snmp_open on same template succeeds (pre-fix: EADDRINUSE)"));

        if (ss2) {
            OKF(session.local_port == 0,
                ("template local_port still 0 after second snmp_open (got %d)",
                 session.local_port));
            snmp_close(ss2);
        }
        snmp_close(ss1);
    } else {
        OKF(1, ("skipped -- could not open UDP socket"));
    }

    free(session.peername);
    free(session.community);
    snmp_shutdown("T021sessionreuse");
    SOCK_CLEANUP;
}
