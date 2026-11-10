/* HEADER USM privacy salts are seeded and change between messages */

/*
 * The USM salts are seeded with random data the first time that they are
 * used. This test builds two SNMPv3 authPriv messages for each privacy
 * protocol and reads msgPrivacyParameters from the encoded packets. It
 * verifies that:
 * 1. The random part of the first salt is not all zeros. Unseeded salts
 *    start at zero.
 * 2. The salts of the two messages are different.
 */

#include <net-snmp/library/keytools.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/transform_oids.h>

{
    static const u_char engineID[] = { 0x80, 0x00, 0x1f, 0x88, 0x80,
                                       0x01, 0x02, 0x03, 0x04 };
    static const u_char zeros[8];
    static const struct {
        int         type;
        const char *name;
        size_t      random_offset;  /* start of the random part of the salt */
    } privs[] = {
#ifdef HAVE_AES
        { USM_CREATE_USER_PRIV_AES, "AES", 0 },
#endif
#ifndef NETSNMP_DISABLE_DES
        /* The DES salt is snmpEngineBoots followed by the random part. */
        { USM_CREATE_USER_PRIV_DES, "DES", 4 },
#endif
        { 0, NULL, 0 }
    };
    const oid      *auth_oid, *priv_oid;
    size_t          auth_len = 0, priv_len = 0;
    int             i, n;

    SOCK_STARTUP;
    init_snmp("T122usm_salt_seed");

    /* The packet is located at the end of the buffer with reverse encoding. */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_REVERSE_ENCODE, 1);

    for (i = 0; privs[i].name; i++) {
        netsnmp_session session, *ss;
        u_char          salt[2][8];
        size_t          salt_len[2] = { 0, 0 };

        snmp_sess_init(&session);
        session.version = SNMP_VERSION_3;
        session.peername = strdup("udp:127.0.0.1:162"); /* not used */
        session.securityModel = SNMP_SEC_MODEL_USM;
        session.securityEngineID = netsnmp_memdup(engineID, sizeof(engineID));
        session.securityEngineIDLen = sizeof(engineID);
        session.securityName = strdup(privs[i].name);
        session.securityNameLen = strlen(privs[i].name);
        session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
        session.flags |= SNMP_FLAGS_DONT_PROBE;

        auth_oid = sc_get_auth_oid(NETSNMP_USMAUTH_HMACSHA1, &auth_len);
        session.securityAuthProto = snmp_duplicate_objid(auth_oid, auth_len);
        session.securityAuthProtoLen = auth_len;
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
        generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                    (const u_char *)"authpassword", strlen("authpassword"),
                    session.securityAuthKey, &session.securityAuthKeyLen);

        priv_oid = sc_get_priv_oid(privs[i].type, &priv_len);
        session.securityPrivProto = snmp_duplicate_objid(priv_oid, priv_len);
        session.securityPrivProtoLen = priv_len;
        session.securityPrivKeyLen = USM_PRIV_KU_LEN;
        generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                    (const u_char *)"privpassword", strlen("privpassword"),
                    session.securityPrivKey, &session.securityPrivKeyLen);

        ss = snmp_open(&session);
        OKF(ss != NULL, ("%s: open authPriv session", privs[i].name));
        netsnmp_cleanup_session(&session);
        if (!ss)
            continue;

        for (n = 0; n < 2; n++) {
            netsnmp_pdu    *pdu = snmp_pdu_create(SNMP_MSG_GET);
            size_t          pkt_len = 4096, offset = 0, len, str_len;
            u_char         *pkt = malloc(pkt_len), *data = NULL;
            u_char          type, str[256], secparams[256];
            long            l;
            int             rc;

            pdu->version = SNMP_VERSION_3;
            rc = snmp_build(&pkt, &pkt_len, &offset, ss, pdu);
            snmp_free_pdu(pdu);
            if (rc == 0)
                data = pkt + pkt_len - offset;

            /* SNMPv3Message: msgVersion and msgGlobalData. */
            len = offset;
#define PARSE(expr) if (data) data = (expr)
#define PARSE_STR(d, buf) \
            (str_len = sizeof(buf), asn_parse_string(d, &len, &type, buf, &str_len))
            PARSE(asn_parse_sequence(data, &len, &type,
                                     ASN_SEQUENCE | ASN_CONSTRUCTOR, "msg"));
            PARSE(asn_parse_int(data, &len, &type, &l, sizeof(l)));
            /*
             * Skip msgGlobalData. asn_parse_sequence() sets len to the
             * length of the sequence contents.
             */
            if (data) {
                u_char         *start = data;
                size_t          rest = len;

                data = asn_parse_sequence(data, &len, &type,
                                          ASN_SEQUENCE | ASN_CONSTRUCTOR,
                                          "global");
                if (data) {
                    data += len;
                    len = rest - (data - start);
                }
            }
            PARSE(PARSE_STR(data, secparams));

            /* UsmSecurityParameters: msgPrivacyParameters is the last field. */
            if (data) {
                data = secparams;
                len = str_len;
            }
            PARSE(asn_parse_sequence(data, &len, &type,
                                     ASN_SEQUENCE | ASN_CONSTRUCTOR, "usm"));
            PARSE(PARSE_STR(data, str));    /* msgAuthoritativeEngineID */
            PARSE(asn_parse_int(data, &len, &type, &l, sizeof(l)));
            PARSE(asn_parse_int(data, &len, &type, &l, sizeof(l)));
            PARSE(PARSE_STR(data, str));    /* msgUserName */
            PARSE(PARSE_STR(data, str));    /* msgAuthenticationParameters */
            PARSE(PARSE_STR(data, salt[n]));
            if (data)
                salt_len[n] = str_len;
#undef PARSE_STR
#undef PARSE

            OKF(rc == 0 && data != NULL,
                ("%s: build and parse message %d%s%s", privs[i].name, n + 1,
                 data ? "" : ": ",
                 data ? "" : snmp_api_errstring(ss->s_snmp_errno)));
            free(pkt);
        }

        if (salt_len[0] == 8 && salt_len[1] == 8) {
            size_t off = privs[i].random_offset;

            OKF(memcmp(salt[0] + off, zeros, 8 - off) != 0,
                ("%s: first salt is seeded (not all zeros)", privs[i].name));
            OKF(memcmp(salt[0], salt[1], 8) != 0,
                ("%s: salts of two messages are different", privs[i].name));
        } else {
            OKF(0, ("%s: salt lengths are %d and %d, expected 8",
                    privs[i].name, (int)salt_len[0], (int)salt_len[1]));
        }

        snmp_close(ss);
    }

    snmp_shutdown("T122usm_salt_seed");
    SOCK_CLEANUP;
}
