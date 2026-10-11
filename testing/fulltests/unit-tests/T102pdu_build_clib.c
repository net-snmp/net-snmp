/* HEADER PDU building */

netsnmp_pdu *pdu;
u_char *packet;
size_t packet_len, offset = 0;
netsnmp_session session, *ss;
int rc;

SOCK_STARTUP;

init_snmp("testing");
snmp_sess_init(&session);
#if !defined(NETSNMP_DISABLE_SNMPV2C)
session.version = SNMP_VERSION_2c;
#elif !defined(NETSNMP_DISABLE_SNMPV1)
session.version = SNMP_VERSION_1;
#else
#error This test does not (yet?) support SNMPv3
#endif
session.peername = strdup("udp:127.0.0.1"); /* we won't actually connect */
session.community = (u_char *) strdup("bogus");
session.community_len = strlen((char *) session.community);
ss = snmp_open(&session);

OKF((ss != NULL), ("Creating a session failed"));
if (ss == NULL)
    snmp_perror("ack");

packet_len = 4096;
packet = malloc(packet_len);

pdu = snmp_pdu_create(SNMP_MSG_GET);
pdu->version = session.version;

OKF((pdu != NULL), ("Creating a GET PDU failed"));

rc = snmp_build(&packet, &packet_len, &offset, ss, pdu);
snmp_free_pdu(pdu);

#ifndef NETSNMP_NOTIFY_ONLY
OKF((rc == SNMPERR_SUCCESS),
    ("Building a GET PDU/packet should have worked: %d", rc));
#else /* NETSNMP_NOTIFY_ONLY */
OKF((rc != SNMPERR_SUCCESS),
    ("Building a GET PDU/packet should have failed: %d", rc));
#endif /* NETSNMP_NOTIFY_ONLY */

offset = 0;
pdu = snmp_pdu_create(SNMP_MSG_GET);
pdu->version = session.version;
pdu->command = 163; /* a SET message */
rc = snmp_build(&packet, &packet_len, &offset, ss, pdu);
snmp_free_pdu(pdu);

#ifndef NETSNMP_NO_WRITE_SUPPORT
OKF((rc == SNMPERR_SUCCESS),
    ("Building a SET PDU/packet should have succeeded: %d", rc));
#else /* NETSNMP_NO_WRITE_SUPPORT */
OKF((rc != SNMPERR_SUCCESS),
    ("Building a SET PDU/packet should have failed: %d", rc));
#endif /* NETSNMP_NO_WRITE_SUPPORT */



offset = 0;
pdu = snmp_pdu_create(SNMP_MSG_GET);
pdu->version = session.version;
pdu->command = SNMP_MSG_INFORM;
rc = snmp_build(&packet, &packet_len, &offset, ss, pdu);
snmp_free_pdu(pdu);

OKF((rc == SNMPERR_SUCCESS),
    ("Building an INFORM PDU/packet should have succeed: %d", rc));

{
    oid test_oid[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_CHECK_RANGE, 1);
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    rc = snmp_add_var(pdu, test_oid, OID_LENGTH(test_oid), 'b', "0,4096");
    OKF(rc == 0 && pdu->variables != NULL && pdu->variables->val_len == 513,
        ("snmp_add_var bitstring with bit 4096 succeeded (rc=%d)", rc));
    snmp_free_pdu(pdu);
}

#ifdef NETSNMP_USE_REVERSE_ASNENCODING
{
    u_char tiny_buf[2];
    u_char *tiny_pkt = tiny_buf;
    size_t tiny_len = 1, tiny_offset = 0;

    rc = asn_realloc_rbuild_sequence(&tiny_pkt, &tiny_len, &tiny_offset, 0,
                                     (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                     0);
    OKF(rc == 0, ("asn_realloc_rbuild_sequence fails when buffer is too small"));

    tiny_len = 0;
    tiny_offset = 0;
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    rc = snmp_pdu_realloc_rbuild(NULL, &tiny_len, &tiny_offset, pdu);
    OKF(rc == 0, ("snmp_pdu_realloc_rbuild fails when sequence header fails"));
    snmp_free_pdu(pdu);
}
#endif

free(packet);
netsnmp_cleanup_session(&session);
snmp_shutdown("testing");

SOCK_CLEANUP;
