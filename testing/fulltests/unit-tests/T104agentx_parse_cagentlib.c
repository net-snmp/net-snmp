/* HEADER oss-fuzz bug 14502 */
/*
 * Verify whether agentx_parse() does not access any memory outside its
 * bounds for a particular invalid AgentX input. See also
 * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=14502.
 */

#ifndef USING_AGENTX_PROTOCOL_MODULE
printf("1..0 # skip AgentX not enabled\n");
__did_plan = 1;
return 0;
#else
netsnmp_session session;
netsnmp_pdu pdu;
int rc;
static u_char data[] = {
    0x20, 0x08, 0x20, 0x20, 0x20, 0x20, 0xff, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x14, 0x00, 0x00, 0x00, 0x44, 0x00, 0x20, 0x20,
    0x00, 0x20, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x20, 0x20, 0x20, 0x20, 0x20, 0xff, 0x20,
};
static const size_t data_length = sizeof(data);

memset(&session, 0, sizeof(session));
session.version = AGENTX_VERSION_1;

memset(&pdu, 0, sizeof(pdu));

rc = agentx_parse(&session, &pdu, data, data_length);

fprintf(stderr, "rc = %d\n", rc);
fflush(stderr);

OKF(rc != 0, ("Parsing of AgentX data failed"));

{
    /*
     * Verify that agentx_parse() rejects an AgentX OPEN PDU whose expanded
     * OID length (n_subid + 5 * (prefix != 0)) exceeds MAX_OID_LEN (128).
     */
    u_char oversized_oid_pkt[20 + 4 + 4 + 125 * 4];
    netsnmp_pdu pdu2;

    memset(oversized_oid_pkt, 0, sizeof(oversized_oid_pkt));
    oversized_oid_pkt[0] = 1; /* version 1 */
    oversized_oid_pkt[1] = AGENTX_MSG_OPEN;
    oversized_oid_pkt[2] = AGENTX_FLAGS_NETWORK_BYTE_ORDER;
    /* payload length = 4 (timeout) + 4 (OID hdr) + 500 (125 subids) = 508 (0x01fc) */
    oversized_oid_pkt[18] = 0x01;
    oversized_oid_pkt[19] = 0xfc;
    /* OID header at offset 24: n_subid = 125, prefix = 4 -> 125 + 5 = 130 > MAX_OID_LEN */
    oversized_oid_pkt[24] = 125;
    oversized_oid_pkt[25] = 4;

    memset(&pdu2, 0, sizeof(pdu2));
    OK(agentx_parse(&session, &pdu2, oversized_oid_pkt,
                    sizeof(oversized_oid_pkt)) != SNMP_ERR_NOERROR,
       "agentx_parse() rejects expanded OID exceeding MAX_OID_LEN");
}

{
    /*
     * Verify that agentx_check_packet() rejects an AgentX header whose
     * 32-bit payload length would overflow a signed int when 20 is added.
     */
    u_char overflow_hdr[20] = {
        1, AGENTX_MSG_OPEN, AGENTX_FLAGS_NETWORK_BYTE_ORDER, 0,
        0, 0, 0, 1,
        0, 0, 0, 1,
        0, 0, 0, 1,
        0xff, 0xff, 0xff, 0xf0
    };
    OK(agentx_check_packet(overflow_hdr, sizeof(overflow_hdr)) == -1,
       "agentx_check_packet() rejects payload_len > INT_MAX - 20");
}

netsnmp_cleanup_session(&session);
#endif
