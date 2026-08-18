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
    snmp_shutdown("T032usm");
}
