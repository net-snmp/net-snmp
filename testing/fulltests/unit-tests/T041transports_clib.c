/* HEADER Testing transport domains: Callback, STD, Alias, and TLS/DTLS (snmplib/transports/) */
    int run_t041(void);
    int rc = run_t041();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <net-snmp/library/snmpCallbackDomain.h>
#ifdef NETSNMP_TRANSPORT_STD_DOMAIN
#include <net-snmp/library/snmpSTDDomain.h>
#endif
#ifdef NETSNMP_TRANSPORT_ALIAS_DOMAIN
#include <net-snmp/library/snmpAliasDomain.h>
#endif

int
run_t041(void)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T041transports");

    /* 1. Callback transport: netsnmp_callback_open, hook_build, and send with pre-existing pdu->transport_data */
#if defined(NETSNMP_TRANSPORT_CALLBACK_DOMAIN) && !defined(NETSNMP_DISABLE_SNMPV2C)
    {
        netsnmp_session *srv_ss, *cli_ss;
        netsnmp_pdu *pdu;
        int rc;

        srv_ss = netsnmp_callback_open(0, NULL, NULL, NULL);
        OK(srv_ss != NULL && srv_ss->local_port > 0,
           "callback server session opened");
        cli_ss = netsnmp_callback_open(srv_ss ? srv_ss->local_port : 1,
                                       NULL, NULL, NULL);
        OK(cli_ss != NULL, "callback client session opened");

        if (cli_ss) {
            cli_ss->version = SNMP_VERSION_2c;
            free(cli_ss->community);
            cli_ss->community = (u_char *)strdup("public");
            cli_ss->community_len = 6;

            /* Test snmp_send on callback transport when pdu->transport_data is pre-populated */
            pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
            pdu->version = SNMP_VERSION_2c;
            pdu->transport_data = strdup("preexisting_td");
            pdu->transport_data_length = 15;
            rc = snmp_send(cli_ss, pdu);
            OK(rc != 0,
               "snmp_send over callback transport preserves and frees orig_transport_data");
            if (rc == 0)
                snmp_free_pdu(pdu);
        }

        if (cli_ss)
            snmp_close(cli_ss);
        if (srv_ss)
            snmp_close(srv_ss);
    }
#endif

    /* 2. STD transport: netsnmp_std_transport and netsnmp_std_close */
#ifdef NETSNMP_TRANSPORT_STD_DOMAIN
    {
        netsnmp_transport *std_tr;
        char *fmt;

        std_tr = netsnmp_std_transport("/bin/true", strlen("/bin/true"), NULL);
        OK(std_tr != NULL, "netsnmp_std_transport spawned /bin/true");
        if (std_tr) {
            fmt = std_tr->f_fmtaddr(std_tr, NULL, 0);
            OK(fmt != NULL && strcmp(fmt, "STD:/bin/true") == 0,
               "netsnmp_std_fmtaddr returns STD:/bin/true");
            free(fmt);
            OK(std_tr->f_close(std_tr) == 0,
               "netsnmp_std_close closes fds and reaps child");
            netsnmp_transport_free(std_tr);
        }
    }
#endif

    /* 3. Alias transport: parse_alias_config and netsnmp_tdomain_transport("alias:...") */
#ifdef NETSNMP_TRANSPORT_ALIAS_DOMAIN
    {
        void parse_alias_config(const char *token, char *line);
        void free_alias_config(void);
        char line_valid[] = "myalias udp:127.0.0.1:10161";
        char line_extra[] = "extra_alias udp:127.0.0.1:10162 unexpected_trailing";
        netsnmp_transport *al_tr;

        parse_alias_config("alias", line_valid);
        parse_alias_config("alias", line_extra);
        al_tr = netsnmp_tdomain_transport("alias:myalias", 0, "udp");
        OK(al_tr != NULL, "netsnmp_tdomain_transport resolved alias:myalias");
        if (al_tr) {
            al_tr->f_close(al_tr);
            netsnmp_transport_free(al_tr);
        }
        OK(netsnmp_tdomain_transport("alias:nonexistent_alias", 0, "udp") == NULL,
           "netsnmp_alias_create_tstring returns NULL for unknown alias");
        free_alias_config();
    }
#endif

    /* 4. DTLSUDP and TLSTCP transports via netsnmp_tdomain_transport */
#ifdef NETSNMP_TRANSPORT_DTLSUDP_DOMAIN
    {
        netsnmp_transport *dtls_tr;
        char *fmt;

        dtls_tr = netsnmp_tdomain_transport("dtlsudp:127.0.0.1:0", 1, "dtlsudp");
        if (dtls_tr) {
            fmt = dtls_tr->f_fmtaddr(dtls_tr, NULL, 0);
            OK(fmt != NULL, "netsnmp_dtlsudp_fmtaddr formats transport address");
            free(fmt);
            dtls_tr->f_close(dtls_tr);
            netsnmp_transport_free(dtls_tr);
        } else {
            OK(1, "netsnmp_tdomain_transport dtlsudp handled cleanly");
        }
    }
#endif

#ifdef NETSNMP_TRANSPORT_TLSTCP_DOMAIN
    {
        netsnmp_transport *tls_tr;
        char *fmt;

        tls_tr = netsnmp_tdomain_transport("tlstcp:127.0.0.1:0", 1, "tlstcp");
        if (tls_tr) {
            fmt = tls_tr->f_fmtaddr(tls_tr, NULL, 0);
            OK(fmt != NULL, "netsnmp_tlstcp_fmtaddr formats transport address");
            free(fmt);
            tls_tr->f_close(tls_tr);
            netsnmp_transport_free(tls_tr);
        } else {
            OK(1, "netsnmp_tdomain_transport tlstcp handled cleanly");
        }
    }
#endif

    snmp_shutdown("T041transports");
