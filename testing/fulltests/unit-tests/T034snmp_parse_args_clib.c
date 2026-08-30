/* HEADER Verify snmp_parse_args -t and -r argument parsing (issue 1120) */

/*
 * Regression test for https://github.com/net-snmp/net-snmp/issues/1120
 *
 * Test parsing of timeout (-t) and retry (-r) options in snmp_parse_args().
 */

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_parse_args.h>

    int test_main(void);
    return test_main();
}

static void dummy_proc(int argc, char *const *argv, int opt)
{
}

int test_main(void)
{
    netsnmp_session session;
    int res;

    SOCK_STARTUP;
    init_snmp("T034snmp_parse_args");

    /* Valid timeout tests */
    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "1", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-t 1 parsed successfully"));
        OKF(session.timeout == 1000000L, ("-t 1 sets timeout to 1000000 us (got %ld)", session.timeout));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "0.5", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-t 0.5 parsed successfully"));
        OKF(session.timeout == 500000L, ("-t 0.5 sets timeout to 500000 us (got %ld)", session.timeout));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "2.5", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-t 2.5 parsed successfully"));
        OKF(session.timeout == 2500000L, ("-t 2.5 sets timeout to 2500000 us (got %ld)", session.timeout));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "0.000001", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-t 0.000001 parsed successfully"));
        OKF(session.timeout == 1L, ("-t 0.000001 sets timeout to 1 us (got %ld)", session.timeout));
        netsnmp_cleanup_session(&session);
    }

    /* Invalid timeout tests */
    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "3333333333333333333333333333333333333u", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t huge overflow with 'u' suffix is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "3333333333333333333333333333333333333", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t huge overflow is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "1e300", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t 1e300 is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "0", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t 0 is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "-1", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t -1 is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "abc", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t abc is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char t[] = "-t", val[] = "10abc", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, t, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-t 10abc is rejected"));
        netsnmp_cleanup_session(&session);
    }

    /* Valid retry tests */
    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "0", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-r 0 parsed successfully"));
        OKF(session.retries == 0, ("-r 0 sets retries to 0 (got %d)", session.retries));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "5", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res > 0, ("-r 5 parsed successfully"));
        OKF(session.retries == 5, ("-r 5 sets retries to 5 (got %d)", session.retries));
        netsnmp_cleanup_session(&session);
    }

    /* Invalid retry tests */
    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "-1", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-r -1 is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "abc", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-r abc is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "5abc", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-r 5abc is rejected"));
        netsnmp_cleanup_session(&session);
    }

    {
        char prog[] = "testprog", v[] = "-v", v2c[] = "2c", c[] = "-c", comm[] = "public";
        char r[] = "-r", val[] = "3333333333333333333333333333333333333", host[] = "localhost";
        char *argv[] = { prog, v, v2c, c, comm, r, val, host, NULL };
        res = netsnmp_parse_args(8, argv, &session, NULL, dummy_proc, NETSNMP_PARSE_ARGS_NOZERO);
        OKF(res == NETSNMP_PARSE_ARGS_ERROR_USAGE, ("-r huge overflow is rejected"));
        netsnmp_cleanup_session(&session);
    }

    snmp_shutdown("T034snmp_parse_args");
    SOCK_CLEANUP;
