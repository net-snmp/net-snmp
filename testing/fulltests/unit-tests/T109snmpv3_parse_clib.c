/* HEADER Testing snmpv3_parse and USM security parameter bounds checking (issue 1065) */

{
    netsnmp_session session;
    netsnmp_pdu *pdu;
    size_t bytes_remaining;
    int rc;

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T109snmpv3_parse");

    /*
     * Test 1: pov1 from issue 1065 (oss-fuzz truncated SNMPv3 packet).
     * Packet ends right after the secParams header where claimed length (17)
     * exceeds actual remaining buffer bytes (0 payload bytes).
     * Pre-fix: integer underflow in calculating 'remaining' caused heap buffer over-read.
     */
    {
        static const u_char pov1[] = {
            0x30, 0x15, 0x02, 0x01, 0x22, 0x30, 0x00, 0x02, 0x02, 0x30, 0x60,
            0x02, 0x02, 0x09, 0x93, 0x04, 0x01, 0x25, 0x02, 0x01, 0x03, 0x04,
            0x11
        };
        u_char *pov1_buf = netsnmp_memdup(pov1, sizeof(pov1));
        bytes_remaining = sizeof(pov1);
        memset(&session, 0, sizeof(session));
        snmp_sess_init(&session);
        pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
        rc = snmpv3_parse(pdu, pov1_buf, &bytes_remaining, NULL, &session);
        OKF(rc != SNMPERR_SUCCESS,
            ("snmpv3_parse rejects truncated USM packet (issue 1065 pov1): rc=%d", rc));
        snmp_free_pdu(pdu);
        free(pov1_buf);
        netsnmp_cleanup_session(&session);
    }

    /*
     * Test 2: Crafted packet from issue 1065 PoC with lying secParams/secName lengths.
     * secParams claims 200 bytes and USM sequence claims 190 bytes on a 60-byte packet.
     * Pre-fix: integer underflow allowed out-of-bounds read and returned
     * SNMPERR_USM_UNKNOWNSECURITYNAME with leaked memory in securityName.
     * Post-fix: rejected with ASN/USM parse error.
     */
    {
        static const u_char exploit_pkt[] = {
            0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0e, 0x02, 0x01, 0x01,
            0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01,
            0x03, 0x04, 0x81, 0xc8, 0x30, 0x81, 0xbe, 0x04, 0x11, 0x80,
            0x00, 0x1f, 0x88, 0x80, 0xcb, 0x70, 0xbe, 0x39, 0xab, 0xd6,
            0x9d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x00, 0x04, 0x20, 0x4c, 0x45, 0x41, 0x4b, 0x30, 0x00
        };
        u_char *exploit_buf = netsnmp_memdup(exploit_pkt, sizeof(exploit_pkt));
        bytes_remaining = sizeof(exploit_pkt);
        memset(&session, 0, sizeof(session));
        snmp_sess_init(&session);
        pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
        rc = snmpv3_parse(pdu, exploit_buf, &bytes_remaining, NULL, &session);
        OKF(rc != SNMPERR_SUCCESS,
            ("snmpv3_parse rejects crafted USM packet with lying lengths: rc=%d", rc));
        OKF(rc == SNMPERR_ASN_PARSE_ERR || rc == SNMPERR_USM_PARSEERROR,
            ("error is ASN/USM parse error: rc=%d", rc));
        snmp_free_pdu(pdu);
        free(exploit_buf);
        netsnmp_cleanup_session(&session);
    }

    /*
     * Test 3: Truncated security parameters in a validly framed message.
     * USM engineID claims length 0x20 (32 bytes) but only 7 bytes follow.
     */
    {
        static const u_char trunc_pkt[] = {
            0x30, 0x20, 0x02, 0x01, 0x03, 0x30, 0x0e, 0x02, 0x01, 0x01,
            0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01,
            0x03, 0x04, 0x0b, 0x30, 0x09, 0x04, 0x20, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07
        };
        u_char *trunc_buf = netsnmp_memdup(trunc_pkt, sizeof(trunc_pkt));
        bytes_remaining = sizeof(trunc_pkt);
        memset(&session, 0, sizeof(session));
        snmp_sess_init(&session);
        pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
        rc = snmpv3_parse(pdu, trunc_buf, &bytes_remaining, NULL, &session);
        OKF(rc != SNMPERR_SUCCESS,
            ("snmpv3_parse rejects packet with truncated USM engineID: rc=%d", rc));
        snmp_free_pdu(pdu);
        free(trunc_buf);
        netsnmp_cleanup_session(&session);
    }

    /*
     * Test 4: Valid discovery packet parses successfully.
     */
    {
        static const u_char discovery_pkt[] = {
            0x30, 0x46, 0x02, 0x01, 0x03, 0x30, 0x0e, 0x02, 0x01, 0x01,
            0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01,
            0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30,
            0x1f, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x19, 0x02, 0x01, 0x01,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00
        };
        u_char *disc_buf = netsnmp_memdup(discovery_pkt, sizeof(discovery_pkt));
        bytes_remaining = sizeof(discovery_pkt);
        memset(&session, 0, sizeof(session));
        snmp_sess_init(&session);
        pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
        rc = snmpv3_parse(pdu, disc_buf, &bytes_remaining, NULL, &session);
        OKF(rc == SNMPERR_SUCCESS,
            ("snmpv3_parse succeeds for valid discovery packet: rc=%d", rc));
        snmp_free_pdu(pdu);
        free(disc_buf);
        netsnmp_cleanup_session(&session);
    }

    snmp_shutdown("T109snmpv3_parse");
}
