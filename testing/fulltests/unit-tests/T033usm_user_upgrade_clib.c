/* HEADER Verify upgrading USM user from noAuth to authPriv via snmp_add (issue 1125) */

/*
 * Regression test for https://github.com/net-snmp/net-snmp/issues/1125
 *
 * Calling snmp_add() for SNMPv3 sessions with the same engineID+securityName
 * but upgrading from noAuth (authProtocol = usmNoAuthProtocol) to authPriv
 * (e.g. SHA/AES) previously caused usm_create_user_from_session() to fail
 * credential generation (since usmNoAuthProtocol is not a hash algorithm)
 * and erroneously free the existing in-list user node without unlinking it,
 * corrupting the global USM userList and causing a SIGSEGV on subsequent calls.
 *
 * This test verifies that:
 * 1. A noAuth SNMPv3 session can be added with snmp_add().
 * 2. An authPriv SNMPv3 session with the same engineID and securityName
 *    successfully updates the existing user in the global USM list.
 * 3. Subsequent session additions succeed without crashes or memory corruption.
 * 4. The user credentials in the USM list are properly updated.
 */

#include <net-snmp/library/keytools.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>
#include <net-snmp/net-snmp-includes.h>

{
    netsnmp_session     session, *ss;
    netsnmp_transport  *t;
    struct usmUser     *user;
    const oid          *auth_oid, *priv_oid;
    size_t              auth_len = 0, priv_len = 0;
    static const u_char engineID[] = { 0x80, 0x00, 0x05, 0x23, 0x05, 0x00,
                                       0x11, 0x22, 0x33, 0x44, 0x55 };
    const size_t        engineIDLen = sizeof(engineID);
    const char         *secName = "cmcadmin";

    SOCK_STARTUP;
    init_snmp("T033usm_user_upgrade");

    /* =====================================================================
     * Step 1: Create a noAuth user (authProtocol = usmNoAuthProtocol)
     * ===================================================================== */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.peername = strdup("udp:127.0.0.1:162");
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityName = strdup(secName);
    session.securityNameLen = strlen(secName);
    session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
    session.flags |= SNMP_FLAGS_DONT_PROBE;

    auth_oid = sc_get_auth_oid(NETSNMP_USMAUTH_NOAUTH, &auth_len);
    session.securityAuthProto = snmp_duplicate_objid(auth_oid, auth_len);
    session.securityAuthProtoLen = auth_len;

    t = netsnmp_transport_open_client("udp", session.peername);
    OKF(t != NULL, ("step 1: open UDP transport for noAuth session"));

    if (t) {
        ss = snmp_add(&session, t, NULL, NULL);
        OKF(ss != NULL, ("step 1: snmp_add noAuth session succeeded"));
        if (ss)
            snmp_close(ss);
    }
    netsnmp_cleanup_session(&session);

    /* Verify noAuth user exists in global USM list */
    user = usm_get_user(engineID, engineIDLen, secName);
    OKF(user != NULL, ("step 1: user exists in global USM list"));
    if (user) {
        OKF(user->authProtocolLen == auth_len &&
                snmp_oid_compare(user->authProtocol, user->authProtocolLen,
                                 auth_oid, auth_len) == 0,
            ("step 1: user authProtocol is usmNoAuthProtocol"));
        OKF(user->authKey == NULL, ("step 1: user has no authKey"));
        OKF(user->privKey == NULL, ("step 1: user has no privKey"));
    }

    /* =====================================================================
     * Step 2: Upgrade user to authPriv (SHA1 / AES) with same engineID+name
     * ===================================================================== */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.peername = strdup("udp:127.0.0.1:162");
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityName = strdup(secName);
    session.securityNameLen = strlen(secName);
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
    session.flags |= SNMP_FLAGS_DONT_PROBE;

    auth_oid = sc_get_auth_oid(NETSNMP_USMAUTH_HMACSHA1, &auth_len);
    session.securityAuthProto = snmp_duplicate_objid(auth_oid, auth_len);
    session.securityAuthProtoLen = auth_len;
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                (const u_char *)"password", strlen("password"),
                session.securityAuthKey, &session.securityAuthKeyLen);

    priv_oid = sc_get_priv_oid(USM_CREATE_USER_PRIV_AES, &priv_len);
    session.securityPrivProto = snmp_duplicate_objid(priv_oid, priv_len);
    session.securityPrivProtoLen = priv_len;
    session.securityPrivKeyLen = USM_PRIV_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                (const u_char *)"password", strlen("password"),
                session.securityPrivKey, &session.securityPrivKeyLen);

    t = netsnmp_transport_open_client("udp", session.peername);
    OKF(t != NULL,
        ("step 2: open UDP transport for authPriv upgrade session"));

    if (t) {
        ss = snmp_add(&session, t, NULL, NULL);
        OKF(ss != NULL, ("step 2: snmp_add authPriv upgrade session succeeded "
                         "(pre-fix: FAIL)"));
        if (ss)
            snmp_close(ss);
    }
    netsnmp_cleanup_session(&session);

    /* Verify user credentials were upgraded */
    user = usm_get_user(engineID, engineIDLen, secName);
    OKF(user != NULL, ("step 2: user still exists in global USM list"));
    if (user) {
        OKF(user->authProtocolLen == auth_len &&
                snmp_oid_compare(user->authProtocol, user->authProtocolLen,
                                 auth_oid, auth_len) == 0,
            ("step 2: user authProtocol upgraded to HMAC-SHA1"));
        OKF(user->privProtocolLen == priv_len &&
                snmp_oid_compare(user->privProtocol, user->privProtocolLen,
                                 priv_oid, priv_len) == 0,
            ("step 2: user privProtocol upgraded to AES"));
        OKF(user->authKey != NULL && user->authKeyLen > 0,
            ("step 2: user has valid authKey"));
        OKF(user->privKey != NULL && user->privKeyLen > 0,
            ("step 2: user has valid privKey"));
    }

    /* =====================================================================
     * Step 3: Next authPriv session with same user (pre-fix crashed with SIGSEGV)
     * ===================================================================== */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.peername = strdup("udp:127.0.0.1:162");
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityName = strdup(secName);
    session.securityNameLen = strlen(secName);
    session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
    session.flags |= SNMP_FLAGS_DONT_PROBE;

    session.securityAuthProto = snmp_duplicate_objid(auth_oid, auth_len);
    session.securityAuthProtoLen = auth_len;
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                (const u_char *)"password", strlen("password"),
                session.securityAuthKey, &session.securityAuthKeyLen);

    session.securityPrivProto = snmp_duplicate_objid(priv_oid, priv_len);
    session.securityPrivProtoLen = priv_len;
    session.securityPrivKeyLen = USM_PRIV_KU_LEN;
    generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                (const u_char *)"password", strlen("password"),
                session.securityPrivKey, &session.securityPrivKeyLen);

    t = netsnmp_transport_open_client("udp", session.peername);
    OKF(t != NULL,
        ("step 3: open UDP transport for subsequent authPriv session"));

    if (t) {
        ss = snmp_add(&session, t, NULL, NULL);
        OKF(ss != NULL,
            ("step 3: snmp_add subsequent session succeeded without SIGSEGV"));
        if (ss)
            snmp_close(ss);
    }
    netsnmp_cleanup_session(&session);

    /* =====================================================================
     * Step 4: Adding another user with a different name also succeeds
     * (verifies userList integrity)
     * ===================================================================== */
    snmp_sess_init(&session);
    session.version = SNMP_VERSION_3;
    session.peername = strdup("udp:127.0.0.1:162");
    session.securityModel = SNMP_SEC_MODEL_USM;
    session.securityEngineID = netsnmp_memdup(engineID, engineIDLen);
    session.securityEngineIDLen = engineIDLen;
    session.securityName = strdup("seconduser");
    session.securityNameLen = strlen("seconduser");
    session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
    session.flags |= SNMP_FLAGS_DONT_PROBE;

    auth_oid = sc_get_auth_oid(NETSNMP_USMAUTH_NOAUTH, &auth_len);
    session.securityAuthProto = snmp_duplicate_objid(auth_oid, auth_len);
    session.securityAuthProtoLen = auth_len;

    t = netsnmp_transport_open_client("udp", session.peername);
    OKF(t != NULL, ("step 4: open UDP transport for second user"));
    if (t) {
        ss = snmp_add(&session, t, NULL, NULL);
        OKF(ss != NULL, ("step 4: snmp_add second user succeeded"));
        if (ss)
            snmp_close(ss);
    }
    netsnmp_cleanup_session(&session);

    /* Clean up USM users */
    user = usm_get_user(engineID, engineIDLen, secName);
    if (user) {
        usm_remove_user(user);
        usm_free_user(user);
    }
    user = usm_get_user(engineID, engineIDLen, "seconduser");
    if (user) {
        usm_remove_user(user);
        usm_free_user(user);
    }

    snmp_shutdown("T033usm_user_upgrade");
    SOCK_CLEANUP;
}
