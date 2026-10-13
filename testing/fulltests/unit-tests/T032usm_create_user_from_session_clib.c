/* HEADER Testing usm_create_user_from_session credential updates */

#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>
#include <net-snmp/net-snmp-includes.h>

{
    netsnmp_session session;
    struct usmUser *user;
    u_char engineID[] = { 0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04 };
    size_t engineIDLen = sizeof(engineID);
    u_char authKey1[16] = "1234567890123456";
    u_char privKey1[16] = "abcdefghijklmnop";
    u_char authKey2[20] = "12345678901234567890";
    u_char privKey2[16] = "ponmlkjihgfedcba";
    u_char authKu3[20] = "0123456789abcdefghij";
    u_char privKu3[20] = "jihgfedcba9876543210";
    u_char authKey4[20] = "authkey4authkey4auth";
    int    ret;

    init_snmp("T032usm");

    /* 1. Create a user initially */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("testuser320");
    session.securityNameLen = strlen("testuser320");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
#ifndef NETSNMP_DISABLE_MD5
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACMD5AuthProtocol, OID_LENGTH(usmHMACMD5AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACMD5AuthProtocol);
#else
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
#endif
#ifndef NETSNMP_DISABLE_DES
    session.securityPrivProto = snmp_duplicate_objid(
        usmDESPrivProtocol, OID_LENGTH(usmDESPrivProtocol));
    session.securityPrivProtoLen = OID_LENGTH(usmDESPrivProtocol);
#else
    session.securityPrivProto = snmp_duplicate_objid(
        usmAESPrivProtocol, OID_LENGTH(usmAESPrivProtocol));
    session.securityPrivProtoLen = OID_LENGTH(usmAESPrivProtocol);
#endif
    session.securityAuthLocalKey = netsnmp_memdup(authKey1, sizeof(authKey1));
    session.securityAuthLocalKeyLen = sizeof(authKey1);
    session.securityPrivLocalKey = netsnmp_memdup(privKey1, sizeof(privKey1));
    session.securityPrivLocalKeyLen = sizeof(privKey1);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS, ("initial user creation succeeded"));

    user = usm_get_user(engineID, engineIDLen, "testuser320");
    OKF(user != NULL, ("user exists in USM list"));
    if (user) {
#ifndef NETSNMP_DISABLE_MD5
        OKF(user->authProtocolLen == OID_LENGTH(usmHMACMD5AuthProtocol) &&
            snmp_oid_compare(user->authProtocol, user->authProtocolLen,
                             usmHMACMD5AuthProtocol,
                             OID_LENGTH(usmHMACMD5AuthProtocol)) == 0,
            ("initial authProtocol is MD5"));
#endif
#ifndef NETSNMP_DISABLE_DES
        OKF(user->privProtocolLen == OID_LENGTH(usmDESPrivProtocol) &&
            snmp_oid_compare(user->privProtocol, user->privProtocolLen,
                             usmDESPrivProtocol,
                             OID_LENGTH(usmDESPrivProtocol)) == 0,
            ("initial privProtocol is DES"));
#endif
        OKF(user->authKeyLen == sizeof(authKey1) &&
            memcmp(user->authKey, authKey1, sizeof(authKey1)) == 0,
            ("initial authKey matches"));
        OKF(user->privKeyLen == sizeof(privKey1) &&
            memcmp(user->privKey, privKey1, sizeof(privKey1)) == 0,
            ("initial privKey matches"));
    }
    netsnmp_cleanup_session(&session);

    /* 2. Update existing user's credentials via another session */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("testuser320");
    session.securityNameLen = strlen("testuser320");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
    session.securityPrivProto = snmp_duplicate_objid(
        usmAESPrivProtocol, OID_LENGTH(usmAESPrivProtocol));
    session.securityPrivProtoLen = OID_LENGTH(usmAESPrivProtocol);
    session.securityAuthLocalKey = netsnmp_memdup(authKey2, sizeof(authKey2));
    session.securityAuthLocalKeyLen = sizeof(authKey2);
    session.securityPrivLocalKey = netsnmp_memdup(privKey2, sizeof(privKey2));
    session.securityPrivLocalKeyLen = sizeof(privKey2);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS, ("user update succeeded"));

    user = usm_get_user(engineID, engineIDLen, "testuser320");
    OKF(user != NULL, ("user still exists in USM list"));
    if (user) {
        OKF(user->authProtocolLen == OID_LENGTH(usmHMACSHA1AuthProtocol) &&
            snmp_oid_compare(user->authProtocol, user->authProtocolLen,
                             usmHMACSHA1AuthProtocol,
                             OID_LENGTH(usmHMACSHA1AuthProtocol)) == 0,
            ("updated authProtocol is SHA1"));
        OKF(user->privProtocolLen == OID_LENGTH(usmAESPrivProtocol) &&
            snmp_oid_compare(user->privProtocol, user->privProtocolLen,
                             usmAESPrivProtocol,
                             OID_LENGTH(usmAESPrivProtocol)) == 0,
            ("updated privProtocol is AES"));
        OKF(user->authKeyLen == sizeof(authKey2) &&
            memcmp(user->authKey, authKey2, sizeof(authKey2)) == 0,
            ("updated authKey matches"));
        OKF(user->privKeyLen == sizeof(privKey2) &&
            memcmp(user->privKey, privKey2, sizeof(privKey2)) == 0,
            ("updated privKey matches"));
    }
    netsnmp_cleanup_session(&session);

    /* 3. Update existing user using unlocalized Ku keys */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("testuser320");
    session.securityNameLen = strlen("testuser320");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
    session.securityPrivProto = snmp_duplicate_objid(
        usmAESPrivProtocol, OID_LENGTH(usmAESPrivProtocol));
    session.securityPrivProtoLen = OID_LENGTH(usmAESPrivProtocol);
    memcpy(session.securityAuthKey, authKu3, sizeof(authKu3));
    session.securityAuthKeyLen = sizeof(authKu3);
    memcpy(session.securityPrivKey, privKu3, sizeof(privKu3));
    session.securityPrivKeyLen = sizeof(privKu3);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS,
        ("user update with unlocalized keys succeeded"));

    user = usm_get_user(engineID, engineIDLen, "testuser320");
    OKF(user != NULL, ("user still exists after unlocalized update"));
    if (user) {
        OKF(user->authKey != NULL && user->authKeyLen > 0,
            ("updated authKey generated"));
        OKF(user->privKey != NULL && user->privKeyLen > 0,
            ("updated privKey generated"));
        /* Ensure it no longer equals authKey2/privKey2 */
        if (user->authKey) {
            OKF(memcmp(user->authKey, authKey2, sizeof(authKey2)) != 0,
                ("authKey changed from authKey2"));
        }
        if (user->privKey) {
            OKF(memcmp(user->privKey, privKey2, sizeof(privKey2)) != 0,
                ("privKey changed from privKey2"));
        }
    }
    netsnmp_cleanup_session(&session);

    /* 4. Update only authKey without privKey */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("testuser320");
    session.securityNameLen = strlen("testuser320");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
    session.securityAuthLocalKey = netsnmp_memdup(authKey4, sizeof(authKey4));
    session.securityAuthLocalKeyLen = sizeof(authKey4);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS, ("user update with only authKey succeeded"));

    user = usm_get_user(engineID, engineIDLen, "testuser320");
    OKF(user != NULL, ("user still exists after authKey only update"));
    if (user) {
        OKF(user->authKeyLen == sizeof(authKey4) &&
            memcmp(user->authKey, authKey4, sizeof(authKey4)) == 0,
            ("authKey updated to authKey4"));
        OKF(user->privKey != NULL && user->privKeyLen > 0,
            ("privKey remains intact"));
    }
    netsnmp_cleanup_session(&session);

    /* 5. Create authNoPriv user */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("testuser_nopriv");
    session.securityNameLen = strlen("testuser_nopriv");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
    session.securityAuthLocalKey = netsnmp_memdup(authKey1, sizeof(authKey1));
    session.securityAuthLocalKeyLen = sizeof(authKey1);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS, ("authNoPriv user creation succeeded"));

    user = usm_get_user(engineID, engineIDLen, "testuser_nopriv");
    OKF(user != NULL, ("authNoPriv user exists in USM list"));
    if (user) {
        OKF(user->privKey == NULL, ("authNoPriv user has no privKey"));
        usm_remove_user(user);
        usm_free_user(user);
    }
    netsnmp_cleanup_session(&session);

    /* 6. Session-specific user (SNMP_FLAGS_SESSION_USER) */
    snmp_sess_init(&session);
    session.flags |= SNMP_FLAGS_SESSION_USER;
    session.version = SNMP_VERSION_3;
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityName = strdup("sessuser320");
    session.securityNameLen = strlen("sessuser320");
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityAuthProto = snmp_duplicate_objid(
        usmHMACSHA1AuthProtocol, OID_LENGTH(usmHMACSHA1AuthProtocol));
    session.securityAuthProtoLen = OID_LENGTH(usmHMACSHA1AuthProtocol);
    session.securityAuthLocalKey = netsnmp_memdup(authKey1, sizeof(authKey1));
    session.securityAuthLocalKeyLen = sizeof(authKey1);

    ret = usm_create_user_from_session(&session);
    OKF(ret == SNMPERR_SUCCESS, ("session user creation succeeded"));
    OKF(session.sessUser != NULL, ("session->sessUser is non-NULL"));
    if (session.sessUser) {
        OKF(session.sessUser->authKeyLen == sizeof(authKey1) &&
            memcmp(session.sessUser->authKey, authKey1,
                   sizeof(authKey1)) == 0, ("session user authKey matches"));
    }
    OKF(usm_get_user(engineID, engineIDLen, "sessuser320") == NULL,
        ("session user is not in global USM list"));
    netsnmp_cleanup_session(&session);

    /* Clean up global user */
    user = usm_get_user(engineID, engineIDLen, "testuser320");
    if (user) {
        usm_remove_user(user);
        usm_free_user(user);
    }
    {
        u_char short_key[12] = { 0 };
        u_char msg[8] = "testmsg";
        u_char mac[64];
        size_t mac_len = sizeof(mac);

        OK(sc_generate_keyed_hash(usmHMACSHA1AuthProtocol,
                                  OID_LENGTH(usmHMACSHA1AuthProtocol),
                                  short_key, sizeof(short_key),
                                  msg, sizeof(msg),
                                  mac, &mac_len) != SNMPERR_SUCCESS,
           "sc_generate_keyed_hash rejects key shorter than full hash length");
    }

    {
        u_char dummy_ku[64] = { 0 };
        u_char dummy_kul[64] = { 0 };
        size_t kul_len = sizeof(dummy_kul);
        u_char huge_engine[SNMP_MAXBUF + 16];
        u_char huge_key[SNMP_MAXBUF_SMALL];
        u_char kcout[2 * SNMP_MAXBUF_SMALL];
        size_t kcout_len = sizeof(kcout);

        memset(huge_engine, 0xaa, sizeof(huge_engine));
        memset(huge_key, 0xbb, sizeof(huge_key));
        OK(generate_kul(usmHMACSHA1AuthProtocol,
                        OID_LENGTH(usmHMACSHA1AuthProtocol),
                        huge_engine, sizeof(huge_engine),
                        dummy_ku, sizeof(dummy_ku),
                        dummy_kul, &kul_len) == SNMPERR_GENERR,
           "generate_kul rejects oversized engineID_len");
        OK(encode_keychange(usmHMACSHA1AuthProtocol,
                            OID_LENGTH(usmHMACSHA1AuthProtocol),
                            huge_key, sizeof(huge_key),
                            huge_key, sizeof(huge_key),
                            kcout, &kcout_len) == SNMPERR_GENERR,
           "encode_keychange rejects oversized key length");
    }

#ifdef NETSNMP_USMAUTH_HMAC192SHA256
    {
        struct snmp_secmod_def *sptr = find_sec_mod(USM_SEC_MODEL_NUMBER);
        struct snmp_secmod_outgoing_params parms;
        struct usmUser *sha256_user = usm_create_user();
        u_char sha256_key[32];
        u_char msg_buf[512];
        u_char *whole_msg = msg_buf;
        size_t whole_msg_len = sizeof(msg_buf);
        size_t sec_params_len = sizeof(msg_buf) - 10;
        u_char scoped_pdu[] = { ASN_SEQUENCE | ASN_CONSTRUCTOR, 2, 4, 0 };

        memset(sha256_key, 0x5a, sizeof(sha256_key));
        memset(msg_buf, 0, sizeof(msg_buf));
        msg_buf[0] = ASN_SEQUENCE | ASN_CONSTRUCTOR;
        msg_buf[1] = 0x82;
        if (sha256_user) {
            sha256_user->engineID = netsnmp_memdup(engineID, engineIDLen);
            sha256_user->engineIDLen = engineIDLen;
            sha256_user->name = strdup("sha256user");
            sha256_user->secName = strdup("sha256user");
            SNMP_FREE(sha256_user->authProtocol);
            sha256_user->authProtocol = snmp_duplicate_objid(
                usmHMAC192SHA256AuthProtocol,
                OID_LENGTH(usmHMAC192SHA256AuthProtocol));
            sha256_user->authProtocolLen =
                OID_LENGTH(usmHMAC192SHA256AuthProtocol);
            sha256_user->authKey = netsnmp_memdup(sha256_key, sizeof(sha256_key));
            sha256_user->authKeyLen = sizeof(sha256_key);
        }
        snmp_sess_init(&session);
        session.sessUser = sha256_user;
        memset(&parms, 0, sizeof(parms));
        parms.msgProcModel = SNMP_VERSION_3;
        parms.globalData = msg_buf;
        parms.globalDataLen = 10;
        parms.maxMsgSize = sizeof(msg_buf);
        parms.secModel = SNMP_SEC_MODEL_USM;
        parms.secEngineID = engineID;
        parms.secEngineIDLen = engineIDLen;
        parms.secName = "sha256user";
        parms.secNameLen = 10;
        parms.secLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
        parms.scopedPdu = scoped_pdu;
        parms.scopedPduLen = sizeof(scoped_pdu);
        parms.session = &session;
        parms.secParams = msg_buf + 10;
        parms.secParamsLen = &sec_params_len;
        parms.wholeMsg = &whole_msg;
        parms.wholeMsgLen = &whole_msg_len;
        OK(sptr != NULL && sptr->encode_forward != NULL,
           "USM encode_forward callback registered");
        if (sptr && sptr->encode_forward) {
            ret = sptr->encode_forward(&parms);
            OKF(ret == SNMPERR_SUCCESS,
                ("usm_generate_out_msg with HMAC-SHA256 succeeded (ret=%d)", ret));
        }
        usm_free_user(sha256_user);
    }
#endif

    {
        u_char eid1[4] = { 0x80, 0x00, 0x00, 0x01 };
        u_char eid2[4] = { 0x80, 0x00, 0x00, 0x02 };
        u_int boots = 0, etime = 0, cand;
        int h1 = hash_engineID(eid1, sizeof(eid1));

        for (cand = 2; cand < 256; cand++) {
            eid2[3] = (u_char)cand;
            if (hash_engineID(eid2, sizeof(eid2)) == h1)
                break;
        }
        OK(hash_engineID(eid2, sizeof(eid2)) == h1,
           "found two engineIDs hashing to same etimelist bucket");
        OK(set_enginetime(eid1, sizeof(eid1), 5, 100, TRUE) == SNMPERR_SUCCESS,
           "set_enginetime eid1 succeeded");
        OK(set_enginetime(eid2, sizeof(eid2), 7, 200, TRUE) == SNMPERR_SUCCESS,
           "set_enginetime eid2 succeeded");
        free_enginetime(eid1, sizeof(eid1));
        OK(get_enginetime(eid1, sizeof(eid1), &boots, &etime, TRUE) !=
           SNMPERR_SUCCESS,
           "free_enginetime removed eid1");
        OK(get_enginetime(eid2, sizeof(eid2), &boots, &etime, TRUE) ==
           SNMPERR_SUCCESS && boots == 7,
           "free_enginetime preserved colliding eid2 in same bucket");
        free_enginetime(eid2, sizeof(eid2));
    }

    /*
     * 7. Test usm_set_user_password() error path (frees existing authKey and sets authKeyLen=0),
     * usm_parse_security_parameters() with 64-bit engineBoots/engineTime,
     * and sc_encrypt() debug logging with ptlen < ctlen.
     */
    {
        void usm_set_user_password(struct usmUser *user, const char *token,
                                   char *line);
        struct usmUser *pw_user = usm_create_user();

        if (pw_user) {
            pw_user->authKey = (u_char *)strdup("0123456789abcdef");
            pw_user->authKeyLen = 16;
            usm_set_user_password(pw_user, "userSetAuthPass", NULL);
            OK(pw_user->authKey == NULL && pw_user->authKeyLen == 0,
               "usm_set_user_password frees authKey and resets authKeyLen on error");
            usm_free_user(pw_user);
        }
    }

    {
        /* Incoming USM packet with 5-byte BER integer for msgAuthoritativeEngineBoots (> ENGINEBOOT_MAX) */
        static const u_char big_boots_pkt[] = {
            0x30, 0x32,
            0x02, 0x01, 0x03,
            0x30, 0x0e, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xe3,
                        0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
            0x04, 0x14, 0x30, 0x12,
                        0x04, 0x04, 0x80, 0x00, 0x00, 0x01,
                        0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00, /* 2147483648 */
                        0x02, 0x01, 0x01,
                        0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x30, 0x07, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x01, 0x00
        };
        u_char *pkt_copy = netsnmp_memdup(big_boots_pkt, sizeof(big_boots_pkt));
        size_t rem = sizeof(big_boots_pkt);
        netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);

        snmp_sess_init(&session);
        ret = snmpv3_parse(pdu, pkt_copy, &rem, NULL, &session);
        OK(ret != SNMPERR_SUCCESS,
           "usm_parse_security_parameters rejects engineBoots > ENGINEBOOT_MAX");
        snmp_free_pdu(pdu);
        free(pkt_copy);
        netsnmp_cleanup_session(&session);
    }

    {
        /* Test sc_encrypt with scapi debug token enabled and ptlen < ctlen */
        u_char key[16] = "0123456789abcdef";
        u_char iv[16] = "fedcba9876543210";
        u_char pt[5] = "hello";
        u_char ct[64];
        size_t ct_len = sizeof(ct);

        memset(ct, 0, sizeof(ct));
        snmp_set_do_debugging(1);
        debug_register_tokens("scapi");
        ret = sc_encrypt(usmAESPrivProtocol, OID_LENGTH(usmAESPrivProtocol),
                         key, sizeof(key), iv, sizeof(iv),
                         pt, sizeof(pt), ct, &ct_len);
        snmp_set_do_debugging(0);
        OK(ret == SNMPERR_SUCCESS,
           "sc_encrypt with scapi debugging logs safely when ptlen < ctlen");
    }

    snmp_shutdown("T032usm");
}
