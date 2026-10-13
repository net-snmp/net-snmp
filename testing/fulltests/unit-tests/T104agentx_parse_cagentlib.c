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
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/agent_module_config.h>

extern int allocate_idx_list(netsnmp_session *session, netsnmp_pdu *pdu);
extern int release_idx_list(netsnmp_session *session, netsnmp_pdu *pdu);
extern int remove_index(netsnmp_variable_list *varbind, netsnmp_session *ss);
extern int handle_agentx_packet(int operation, netsnmp_session *session,
                                int reqid, netsnmp_pdu *pdu, void *magic);

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

#if defined(USING_AGENTX_MASTER_ADMIN_MODULE) && !defined(NETSNMP_FEATURE_REMOVE_REMOVE_INDEX)
{
    /*
     * Test allocate_idx_list() and release_idx_list() (agentx/master_admin.c):
     * 1) Allocate and release an ASN_OCTET_STR index varbind larger than
     *    vp->buf (64 bytes) so heap-allocated val.string is exercised and
     *    freed without leaking res or vp->val.string.
     * 2) Partial-failure rollback in allocate_idx_list() when the 2nd varbind
     *    requests an already-allocated index.
     * 3) Partial-failure rollback in release_idx_list() when the 2nd varbind
     *    requests an unallocated index.
     */
    netsnmp_session  master_sess, *sub_sess;
    netsnmp_pdu     *idx_pdu;
    oid              str_idx_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 104, 1 };
    oid              int_idx_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 104, 2 };
    char             long_str[65];
    long             idx_val1 = 10, idx_val2 = 20, idx_unalloc = 999;

    memset(&master_sess, 0, sizeof(master_sess));
    sub_sess = SNMP_MALLOC_TYPEDEF(netsnmp_session);
    OK(sub_sess != NULL, "allocated AgentX subsession");
    sub_sess->sessid = 1;
    sub_sess->flags = SNMP_FLAGS_SUBSESSION;
    sub_sess->subsession = &master_sess;
    master_sess.subsession = sub_sess;

    memset(long_str, 'x', 64);
    long_str[64] = '\0';

    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    idx_pdu->sessid = 1;
    idx_pdu->flags = 0;
    snmp_pdu_add_variable(idx_pdu, str_idx_oid, OID_LENGTH(str_idx_oid),
                          ASN_OCTET_STR, long_str, 64);

    rc = allocate_idx_list(&master_sess, idx_pdu);
    OKF(rc == AGENTX_ERR_NOERROR,
        ("allocate_idx_list for 64-byte ASN_OCTET_STR succeeded (%d == %d)",
         rc, AGENTX_ERR_NOERROR));

    rc = release_idx_list(&master_sess, idx_pdu);
    OKF(rc == AGENTX_ERR_NOERROR,
        ("release_idx_list for 64-byte ASN_OCTET_STR succeeded (%d == %d)",
         rc, AGENTX_ERR_NOERROR));

    /* Re-allocate and remove_index to free the registry entry completely */
    rc = allocate_idx_list(&master_sess, idx_pdu);
    OK(rc == AGENTX_ERR_NOERROR, "re-allocated 64-byte ASN_OCTET_STR index");
    remove_index(idx_pdu->variables, sub_sess);
    snmp_free_pdu(idx_pdu);

    /*
     * Partial-failure rollback in allocate_idx_list():
     * First allocate idx_val1 (10), then attempt to allocate [idx_val2 (20), idx_val1 (10)].
     */
    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    idx_pdu->sessid = 1;
    idx_pdu->flags = 0;
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val1, sizeof(idx_val1));
    rc = allocate_idx_list(&master_sess, idx_pdu);
    OK(rc == AGENTX_ERR_NOERROR, "allocated initial integer index 10");
    snmp_free_pdu(idx_pdu);

    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    idx_pdu->sessid = 1;
    idx_pdu->flags = 0;
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val2, sizeof(idx_val2));
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val1, sizeof(idx_val1));
    rc = allocate_idx_list(&master_sess, idx_pdu);
    OKF(rc == AGENTX_ERR_INDEX_NONE_AVAILABLE,
        ("allocate_idx_list fails when 2nd varbind is already allocated (%d)",
         rc));
    snmp_free_pdu(idx_pdu);

    /* Verify idx_val2 (20) was rolled back by remove_index(vp2, sp) and can now be allocated */
    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    idx_pdu->sessid = 1;
    idx_pdu->flags = 0;
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val2, sizeof(idx_val2));
    rc = allocate_idx_list(&master_sess, idx_pdu);
    OK(rc == AGENTX_ERR_NOERROR,
       "idx_val2 (20) was rolled back on failure and can be allocated");
    snmp_free_pdu(idx_pdu);

    /*
     * Partial-failure rollback in release_idx_list():
     * Attempt to release [idx_val1 (10), idx_unalloc (999)].
     * Releasing 999 fails, so 10 must be reinstated on sub_sess without leaking rv.
     */
    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_DEALLOCATE);
    idx_pdu->sessid = 1;
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val1, sizeof(idx_val1));
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_unalloc, sizeof(idx_unalloc));
    rc = release_idx_list(&master_sess, idx_pdu);
    OKF(rc == AGENTX_ERR_INDEX_NOT_ALLOCATED,
        ("release_idx_list fails when 2nd varbind is not allocated (%d)", rc));
    snmp_free_pdu(idx_pdu);

    /* Verify idx_val1 (10) is still owned by sub_sess and both 10 and 20 can be released */
    idx_pdu = snmp_pdu_create(AGENTX_MSG_INDEX_DEALLOCATE);
    idx_pdu->sessid = 1;
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val1, sizeof(idx_val1));
    snmp_pdu_add_variable(idx_pdu, int_idx_oid, OID_LENGTH(int_idx_oid),
                          ASN_INTEGER, &idx_val2, sizeof(idx_val2));
    rc = release_idx_list(&master_sess, idx_pdu);
    OK(rc == AGENTX_ERR_NOERROR,
       "reinstated idx_val1 (10) and idx_val2 (20) released cleanly");

    /* Re-allocate and remove_index both so index registry is completely empty */
    idx_pdu->command = AGENTX_MSG_INDEX_ALLOCATE;
    idx_pdu->flags = 0;
    rc = allocate_idx_list(&master_sess, idx_pdu);
    OK(rc == AGENTX_ERR_NOERROR, "re-allocated 10 and 20 for cleanup");
    remove_index(idx_pdu->variables, sub_sess);
    remove_index(idx_pdu->variables->next_variable, sub_sess);
    snmp_free_pdu(idx_pdu);
    SNMP_FREE(sub_sess);
}
#endif

#ifdef USING_AGENTX_SUBAGENT_MODULE
{
    /*
     * Exercise handle_agentx_packet() (agentx/subagent.c) when
     * agentx_callback_sess == NULL (snmp_async_send fails) on
     * AGENTX_MSG_GETNEXT and AGENTX_MSG_CLEANUPSET to verify smagic and
     * smagic->ovars are freed without leaks.
     */
    netsnmp_session sub_sess;
    netsnmp_pdu    *gn_pdu;
    oid             test_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 104, 3, 0 };

    memset(&sub_sess, 0, sizeof(sub_sess));
    sub_sess.version = AGENTX_VERSION_1;
    sub_sess.securityModel = SNMP_DEFAULT_SECMODEL;

    gn_pdu = snmp_pdu_create(AGENTX_MSG_GETNEXT);
    snmp_add_null_var(gn_pdu, test_oid, OID_LENGTH(test_oid));
    rc = handle_agentx_packet(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
                              &sub_sess, 1, gn_pdu, NULL);
    OK(rc == 1,
       "handle_agentx_packet(AGENTX_MSG_GETNEXT) with NULL callback session frees smagic and ovars");
    snmp_free_pdu(gn_pdu);

#ifndef NETSNMP_NO_WRITE_SUPPORT
    {
        netsnmp_pdu *cln_pdu = snmp_pdu_create(AGENTX_MSG_CLEANUPSET);
        cln_pdu->transid = 999;
        rc = handle_agentx_packet(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
                                  &sub_sess, 2, cln_pdu, NULL);
        OK(rc == 1,
           "handle_agentx_packet(AGENTX_MSG_CLEANUPSET) with unknown transid cleans up without leaks");
        snmp_free_pdu(cln_pdu);
    }
#endif
}
#endif

netsnmp_cleanup_session(&session);
#endif
