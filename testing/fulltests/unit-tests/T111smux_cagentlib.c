/* HEADER Testing SMUX protocol parsing and peer cleanup */

#if !defined(USING_SMUX_MODULE) || defined(WIN32) || !defined(AF_UNIX)
printf("1..0 # skip SMUX not enabled\n");
__did_plan = 1;
return 0;
#else
#include "smux/smux.h"

extern void smux_parse_peer_auth(const char *token, char *cptr);
extern void smux_free_peer_auth(void);
extern int var_smux_write(int action, u_char *var_val, u_char var_val_type,
                          size_t var_val_len, oid *name, size_t name_len);
extern u_char *var_smux_get(oid *root, size_t root_len, oid *name,
                            size_t *length, int exact, size_t *var_len,
                            u_char *var_type);

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");

{
    char auth_cfg[] = ".1.3.6.1.4.1.99999.111 secret";
    int  sv[2];
    int  rc;

    smux_parse_peer_auth("smuxpeer", auth_cfg);

    /*
     * 1. smux_open_process() tests with malformed/truncated ASN.1 inputs
     */
    {
        /* 1a. Truncated version integer in SMUX_OPEN */
        u_char trunc_ver[] = { SMUX_OPEN, 0x02, ASN_INTEGER, 0x05 };

        rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        OK(rc == 0, "socketpair for truncated version SMUX_OPEN");
        if (rc == 0) {
            (void) write(sv[1], trunc_ver, sizeof(trunc_ver));
            OK(smux_process(sv[0]) == -1,
               "smux_open_process rejects truncated version integer");
            /* smux_process closes sv[0] on auth failure */
            close(sv[1]);
        }
    }

    {
        /* 1b. Truncated OID in SMUX_OPEN */
        u_char trunc_oid[] = {
            SMUX_OPEN, 0x05,
            ASN_INTEGER, 0x01, 0x00,
            ASN_OBJECT_ID, 0x10
        };

        rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        OK(rc == 0, "socketpair for truncated OID SMUX_OPEN");
        if (rc == 0) {
            (void) write(sv[1], trunc_oid, sizeof(trunc_oid));
            OK(smux_process(sv[0]) == -1,
               "smux_open_process rejects truncated OID");
            close(sv[1]);
        }
    }

    {
        /* 1c. Oversized descr string (> SMUXMAXSTRLEN = 1024 bytes) in SMUX_OPEN */
        u_char big_descr[1400];
        u_char *p = big_descr;
        size_t rem = sizeof(big_descr);
        long ver = 0;
        oid peer_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111 };
        char long_descr[1100];

        memset(long_descr, 'D', sizeof(long_descr));
        /* Build inner payload after 4-byte SMUX_OPEN header */
        p = big_descr + 4;
        rem = sizeof(big_descr) - 4;
        p = asn_build_int(p, &rem, ASN_INTEGER, &ver, sizeof(ver));
        p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                            OID_LENGTH(peer_oid));
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) long_descr,
                             sizeof(long_descr));
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) "secret", 6);
        {
            size_t payload_len = (size_t) (p - (big_descr + 4));
            big_descr[0] = SMUX_OPEN;
            big_descr[1] = 0x82;
            big_descr[2] = (u_char) ((payload_len >> 8) & 0xff);
            big_descr[3] = (u_char) (payload_len & 0xff);

            rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            OK(rc == 0, "socketpair for oversized descr SMUX_OPEN");
            if (rc == 0) {
                (void) write(sv[1], big_descr, payload_len + 4);
                OK(smux_process(sv[0]) == -1,
                   "smux_open_process rejects descr > sizeof(descr) - 1 without overflow");
                close(sv[1]);
            }
        }
    }

    {
        /* 1d. Truncated passwd in SMUX_OPEN */
        u_char trunc_pw[] = {
            SMUX_OPEN, 16,
            ASN_INTEGER, 1, 0,
            ASN_OBJECT_ID, 4, 0x2b, 0x06, 0x01, 0x04,
            ASN_OCTET_STR, 2, 'o', 'k',
            ASN_OCTET_STR, 10, 'x'
        };

        rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        OK(rc == 0, "socketpair for truncated passwd SMUX_OPEN");
        if (rc == 0) {
            (void) write(sv[1], trunc_pw, sizeof(trunc_pw));
            OK(smux_process(sv[0]) == -1,
               "smux_open_process rejects truncated passwd");
            close(sv[1]);
        }
    }

    /*
     * 2. Authenticate a valid peer and exercise smux_rreq_process(),
     *    var_smux_write(), smux_trap_process(), and smux_peer_cleanup()
     */
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    OK(rc == 0, "socketpair for authenticated SMUX peer session");
    if (rc == 0) {
        u_char pkt[256];
        u_char *p;
        size_t rem;
        long ver = 0;
        oid peer_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111 };
        oid subtree_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111, 1 };
        u_char rrsp_buf[16];
        ssize_t nread;

        /* 2a. Send valid SMUX_OPEN */
        p = pkt + 2;
        rem = sizeof(pkt) - 2;
        p = asn_build_int(p, &rem, ASN_INTEGER, &ver, sizeof(ver));
        p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                            OID_LENGTH(peer_oid));
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) "testpeer", 8);
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) "secret", 6);
        pkt[0] = SMUX_OPEN;
        pkt[1] = (u_char) (p - (pkt + 2));

        (void) write(sv[1], pkt, (size_t) (p - pkt));
        OK(smux_process(sv[0]) == 0, "valid SMUX_OPEN authenticated peer");

        /* 2b. Malformed SMUX_RREQ: truncated subtree OID */
        {
            u_char bad_rreq_oid[] = {
                SMUX_RREQ, 3,
                ASN_OBJECT_ID, 10, 0x2b
            };
            (void) write(sv[1], bad_rreq_oid, sizeof(bad_rreq_oid));
            OK(smux_process(sv[0]) == 0,
               "smux_rreq_process handles truncated subtree OID without crashing");
            nread = read(sv[1], rrsp_buf, sizeof(rrsp_buf));
            OK(nread >= 3 && rrsp_buf[0] == SMUX_RRSP && rrsp_buf[2] == 0xff,
               "smux_rreq_process sends RRSP(-1) on truncated OID");
        }

        /* 2c. Malformed SMUX_RREQ: priority < -1 (e.g. -2) */
        {
            long bad_prio = -2;
            long op = SMUX_REGOP_REGISTER_RW;

            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, subtree_oid,
                                OID_LENGTH(subtree_oid));
            p = asn_build_int(p, &rem, ASN_INTEGER, &bad_prio, sizeof(bad_prio));
            p = asn_build_int(p, &rem, ASN_INTEGER, &op, sizeof(op));
            pkt[0] = SMUX_RREQ;
            pkt[1] = (u_char) (p - (pkt + 2));

            (void) write(sv[1], pkt, (size_t) (p - pkt));
            OK(smux_process(sv[0]) == 0,
               "smux_rreq_process handles out-of-range priority (-2)");
            nread = read(sv[1], rrsp_buf, sizeof(rrsp_buf));
            OK(nread >= 3 && rrsp_buf[0] == SMUX_RRSP && rrsp_buf[2] == 0xff,
               "smux_rreq_process sends RRSP(-1) on priority < -1");
        }

        /* 2d. Malformed SMUX_RREQ: invalid operation (99) */
        {
            long prio = 0;
            long bad_op = 99;

            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, subtree_oid,
                                OID_LENGTH(subtree_oid));
            p = asn_build_int(p, &rem, ASN_INTEGER, &prio, sizeof(prio));
            p = asn_build_int(p, &rem, ASN_INTEGER, &bad_op, sizeof(bad_op));
            pkt[0] = SMUX_RREQ;
            pkt[1] = (u_char) (p - (pkt + 2));

            (void) write(sv[1], pkt, (size_t) (p - pkt));
            OK(smux_process(sv[0]) == 0,
               "smux_rreq_process handles invalid operation (99)");
            nread = read(sv[1], rrsp_buf, sizeof(rrsp_buf));
            OK(nread >= 3 && rrsp_buf[0] == SMUX_RRSP && rrsp_buf[2] == 0xff,
               "smux_rreq_process sends RRSP(-1) on invalid operation");
        }

        /* 2e. Valid SMUX_RREQ: register subtree_oid RW at priority 0 */
        {
            long prio = 0;
            long op = SMUX_REGOP_REGISTER_RW;

            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, subtree_oid,
                                OID_LENGTH(subtree_oid));
            p = asn_build_int(p, &rem, ASN_INTEGER, &prio, sizeof(prio));
            p = asn_build_int(p, &rem, ASN_INTEGER, &op, sizeof(op));
            pkt[0] = SMUX_RREQ;
            pkt[1] = (u_char) (p - (pkt + 2));

            (void) write(sv[1], pkt, (size_t) (p - pkt));
            OK(smux_process(sv[0]) == 0,
               "smux_rreq_process registered valid subtree");
            nread = read(sv[1], rrsp_buf, sizeof(rrsp_buf));
            OK(nread >= 3 && rrsp_buf[0] == SMUX_RRSP && rrsp_buf[2] == 0x00,
               "smux_rreq_process sends RRSP(0) on valid registration");
        }

        /*
         * 3. var_smux_write() tests with ActiveRegs populated:
         *    Verify RESERVE1 with var_val == NULL / var_val_len == 0 or a
         *    1-byte buffer and invalid var_val_type does not read var_val[1].
         */
        {
            u_char *one_byte = malloc(1);

            OK(var_smux_write(RESERVE1, NULL, ASN_NULL, 0,
                              subtree_oid, OID_LENGTH(subtree_oid)) ==
               SNMP_ERR_GENERR,
               "var_smux_write(RESERVE1) with NULL var_val returns SNMP_ERR_GENERR without OOB read");

            if (one_byte) {
                one_byte[0] = 0x00;
                OK(var_smux_write(RESERVE1, one_byte, 0xff, 1,
                                  subtree_oid, OID_LENGTH(subtree_oid)) ==
                   SNMP_ERR_GENERR,
                   "var_smux_write(RESERVE1) with 1-byte buffer and invalid type does not read var_val[1]");
                free(one_byte);
            }
        }

        /*
         * 4. smux_trap_process() tests:
         *    4a. Truncated trap header
         *    4b. Trap varbind with ASN_IPADDRESS of length != 4 (length 2)
         *    4c. Trap varbind with inner ASN_OCTET_STR length exceeding varbind container
         */
        {
            u_char trunc_trap[] = {
                SMUX_TRAP, 2,
                ASN_OBJECT_ID, 10
            };
            (void) write(sv[1], trunc_trap, sizeof(trunc_trap));
            OK(smux_process(sv[0]) == 0,
               "smux_trap_process rejects truncated trap header cleanly");
        }

        {
            /* Trap with ASN_IPADDRESS varbind of length 2 (!= 4) */
            long generic = 6, specific = 1;
            u_long ticks = 100;
            u_char ip4[4] = { 127, 0, 0, 1 };
            u_char bad_ip_vb[] = {
                ASN_SEQUENCE | ASN_CONSTRUCTOR, 10,
                ASN_SEQUENCE | ASN_CONSTRUCTOR, 8,
                ASN_OBJECT_ID, 2, 0x2b, 0x06,
                ASN_IPADDRESS, 2, 127, 1
            };

            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                                OID_LENGTH(peer_oid));
            p = asn_build_string(p, &rem, ASN_IPADDRESS, ip4, sizeof(ip4));
            p = asn_build_int(p, &rem, ASN_INTEGER, &generic, sizeof(generic));
            p = asn_build_int(p, &rem, ASN_INTEGER, &specific, sizeof(specific));
            p = asn_build_unsigned_int(p, &rem, ASN_TIMETICKS, &ticks,
                                       sizeof(ticks));
            memcpy(p, bad_ip_vb, sizeof(bad_ip_vb));
            p += sizeof(bad_ip_vb);
            pkt[0] = SMUX_TRAP;
            pkt[1] = (u_char) (p - (pkt + 2));

            (void) write(sv[1], pkt, (size_t) (p - pkt));
            OK(smux_process(sv[0]) == 0,
               "smux_trap_process rejects ASN_IPADDRESS varbind with length != 4");
        }

        {
            /* Trap with varbind whose inner value claims length > container */
            long generic = 6, specific = 1;
            u_long ticks = 100;
            u_char ip4[4] = { 127, 0, 0, 1 };
            u_char bad_len_vb[] = {
                ASN_SEQUENCE | ASN_CONSTRUCTOR, 9,
                ASN_SEQUENCE | ASN_CONSTRUCTOR, 7,
                ASN_OBJECT_ID, 2, 0x2b, 0x06,
                ASN_OCTET_STR, 50, 'A'
            };

            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                                OID_LENGTH(peer_oid));
            p = asn_build_string(p, &rem, ASN_IPADDRESS, ip4, sizeof(ip4));
            p = asn_build_int(p, &rem, ASN_INTEGER, &generic, sizeof(generic));
            p = asn_build_int(p, &rem, ASN_INTEGER, &specific, sizeof(specific));
            p = asn_build_unsigned_int(p, &rem, ASN_TIMETICKS, &ticks,
                                       sizeof(ticks));
            memcpy(p, bad_len_vb, sizeof(bad_len_vb));
            p += sizeof(bad_len_vb);
            pkt[0] = SMUX_TRAP;
            pkt[1] = (u_char) (p - (pkt + 2));

            (void) write(sv[1], pkt, (size_t) (p - pkt));
            OK(smux_process(sv[0]) == 0,
               "smux_trap_process rejects varbind with inner length exceeding container");
        }

        /*
         * 5. With the peer gone, var_smux_write() and var_smux_get() fail
         *    but leave the registration in place: they run inside
         *    smux_handler(), which uses that registration.
         */
        {
            oid instance[MAX_OID_LEN];
            size_t instance_len = OID_LENGTH(subtree_oid) + 1;
            size_t var_len = 0;
            u_char var_type = 0;
            long value = 1;
            netsnmp_subtree *tp;

            memcpy(instance, subtree_oid, sizeof(subtree_oid));
            instance[OID_LENGTH(subtree_oid)] = 0;

            shutdown(sv[1], SHUT_WR);

            OK(var_smux_write(RESERVE1, (u_char *) &value, ASN_INTEGER,
                              sizeof(value), instance,
                              OID_LENGTH(subtree_oid) + 1) == SNMP_ERR_GENERR,
               "var_smux_write(RESERVE1) returns SNMP_ERR_GENERR when the peer has closed");
            tp = netsnmp_subtree_find(instance, OID_LENGTH(subtree_oid) + 1,
                                      NULL, "");
            OK(tp && tp->reginfo && tp->reginfo->handlerName &&
               strcmp(tp->reginfo->handlerName, "smux") == 0,
               "var_smux_write keeps the peer's registration");

            OK(var_smux_get(subtree_oid, OID_LENGTH(subtree_oid), instance,
                            &instance_len, 1, &var_len, &var_type) == NULL,
               "var_smux_get returns NULL when the peer has closed");
            tp = netsnmp_subtree_find(instance, OID_LENGTH(subtree_oid) + 1,
                                      NULL, "");
            OK(tp && tp->reginfo && tp->reginfo->handlerName &&
               strcmp(tp->reginfo->handlerName, "smux") == 0,
               "var_smux_get keeps the peer's registration");
        }

        /*
         * 6. smux_process(sv[0]) on the closed peer triggers
         *    smux_peer_cleanup(sv[0]), verifying ActiveRegs and MIB
         *    registration are cleaned up without leaks.
         */
        OK(smux_process(sv[0]) == -1,
           "smux_process on closed peer triggers smux_peer_cleanup and returns -1");
        {
            oid instance[MAX_OID_LEN];
            netsnmp_subtree *tp;

            memcpy(instance, subtree_oid, sizeof(subtree_oid));
            instance[OID_LENGTH(subtree_oid)] = 0;
            tp = netsnmp_subtree_find(instance, OID_LENGTH(subtree_oid) + 1,
                                      NULL, "");
            OK(!tp || !tp->reginfo || !tp->reginfo->handlerName ||
               strcmp(tp->reginfo->handlerName, "smux") != 0,
               "smux_peer_cleanup removes the peer's registration");
        }
        close(sv[1]);
        close(sv[0]);
    }

    /*
     * 7. A peer that closes after a configuration reload (which forgets
     *    the authenticated peers) still has its registration removed.
     */
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    OK(rc == 0, "socketpair for SMUX peer across a reload");
    if (rc == 0) {
        char reload_cfg[] = ".1.3.6.1.4.1.99999.111 secret";
        u_char pkt[256];
        u_char *p;
        size_t rem;
        long ver = 0, prio = 0, op = SMUX_REGOP_REGISTER_RW;
        oid peer_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111 };
        oid subtree_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111, 2 };
        oid instance[] = { 1, 3, 6, 1, 4, 1, 99999, 111, 2, 0 };
        u_char rrsp_buf[16];
        netsnmp_subtree *tp;

        p = pkt + 2;
        rem = sizeof(pkt) - 2;
        p = asn_build_int(p, &rem, ASN_INTEGER, &ver, sizeof(ver));
        p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                            OID_LENGTH(peer_oid));
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) "testpeer", 8);
        p = asn_build_string(p, &rem, ASN_OCTET_STR, (u_char *) "secret", 6);
        pkt[0] = SMUX_OPEN;
        pkt[1] = (u_char) (p - (pkt + 2));
        (void) write(sv[1], pkt, (size_t) (p - pkt));
        OK(smux_process(sv[0]) == 0, "second SMUX peer authenticated");

        p = pkt + 2;
        rem = sizeof(pkt) - 2;
        p = asn_build_objid(p, &rem, ASN_OBJECT_ID, subtree_oid,
                            OID_LENGTH(subtree_oid));
        p = asn_build_int(p, &rem, ASN_INTEGER, &prio, sizeof(prio));
        p = asn_build_int(p, &rem, ASN_INTEGER, &op, sizeof(op));
        pkt[0] = SMUX_RREQ;
        pkt[1] = (u_char) (p - (pkt + 2));
        (void) write(sv[1], pkt, (size_t) (p - pkt));
        OK(smux_process(sv[0]) == 0 &&
           read(sv[1], rrsp_buf, sizeof(rrsp_buf)) >= 3 &&
           rrsp_buf[0] == SMUX_RRSP && rrsp_buf[2] == 0x00,
           "second SMUX peer registered its subtree");

        smux_free_peer_auth();
        smux_parse_peer_auth("smuxpeer", reload_cfg);

        close(sv[1]);
        OK(smux_process(sv[0]) == -1,
           "smux_process on a peer closed after a reload returns -1");
        tp = netsnmp_subtree_find(instance, OID_LENGTH(instance), NULL, "");
        OK(!tp || !tp->reginfo || !tp->reginfo->handlerName ||
           strcmp(tp->reginfo->handlerName, "smux") != 0,
           "smux_process removes the registration of a peer closed after a reload");
    }

    /*
     * 8. Peers that close after a configuration reload do not use up the
     *    SMUXMAXPEERS peers that smux_accept() admits.
     */
    {
        u_char pkt[256];
        u_char *p;
        size_t rem;
        long ver = 0;
        oid peer_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 111 };
        int i, cycled = 0;

        for (i = 0; i < SMUXMAXPEERS; i++) {
            char reload_cfg[] = ".1.3.6.1.4.1.99999.111 secret";

            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
                break;
            p = pkt + 2;
            rem = sizeof(pkt) - 2;
            p = asn_build_int(p, &rem, ASN_INTEGER, &ver, sizeof(ver));
            p = asn_build_objid(p, &rem, ASN_OBJECT_ID, peer_oid,
                                OID_LENGTH(peer_oid));
            p = asn_build_string(p, &rem, ASN_OCTET_STR,
                                 (u_char *) "testpeer", 8);
            p = asn_build_string(p, &rem, ASN_OCTET_STR,
                                 (u_char *) "secret", 6);
            pkt[0] = SMUX_OPEN;
            pkt[1] = (u_char) (p - (pkt + 2));
            (void) write(sv[1], pkt, (size_t) (p - pkt));
            rc = smux_process(sv[0]);

            smux_free_peer_auth();
            smux_parse_peer_auth("smuxpeer", reload_cfg);

            close(sv[1]);
            if (rc == 0 && smux_process(sv[0]) == -1)
                cycled++;
        }
        OK(cycled == SMUXMAXPEERS,
           "peers authenticated, then closed after a reload");

#ifdef NETSNMP_TRANSPORT_TCP_DOMAIN
        {
            netsnmp_transport *listener, *client = NULL;
            struct sockaddr_in sin;
            socklen_t sinlen = sizeof(sin);
            char addr[64];
            NETSNMP_SOCKET fd = NETSNMP_INVALID_SOCKET;

            memset(&sin, 0, sizeof(sin));
            listener = netsnmp_tdomain_transport("tcp:127.0.0.1:0", 1, "tcp");
            if (listener &&
                getsockname(listener->sock, (struct sockaddr *) &sin,
                            &sinlen) == 0) {
                snprintf(addr, sizeof(addr), "tcp:127.0.0.1:%d",
                         ntohs(sin.sin_port));
                client = netsnmp_tdomain_transport(addr, 0, "tcp");
            }
            if (client)
                fd = smux_accept(listener->sock);
            OK(NETSNMP_IS_VALID_SOCKET(fd),
               "smux_accept admits a peer after peers closed after reloads");
            if (NETSNMP_IS_VALID_SOCKET(fd))
                close(fd);
            if (client) {
                client->f_close(client);
                netsnmp_transport_free(client);
            }
            if (listener) {
                listener->f_close(listener);
                netsnmp_transport_free(listener);
            }
        }
#endif
    }

    smux_free_peer_auth();
}

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif
