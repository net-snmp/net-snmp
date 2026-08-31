/* HEADER Testing USM OID parsing (usm_parse_oid, usm_parse_user) (issue 1039) */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <snmpv3/usmUser.h>

{
    unsigned char *engineID = NULL, *name = NULL;
    size_t engineIDLen = 0, nameLen = 0;
    struct usmUser *uptr = NULL;
    int res;

    /*
     * 1. Issue 1039: 0x80000000 (2147483648) or 0xFFFFFFFF in *oidIndex
     * with short oidLen. Must be rejected without buffer over-read or crash.
     */
    oid f1039_oid[] = { 2147483648UL, 0 };
    res = usm_parse_oid(f1039_oid, sizeof(f1039_oid) / sizeof(f1039_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with 0x80000000 in engineID length rejected");
    OK(engineID == NULL && name == NULL, "usm_parse_oid outputs remain NULL on error");

    oid fmax_oid[] = { 0xFFFFFFFFUL, 0xFFFFFFFFUL };
    res = usm_parse_oid(fmax_oid, sizeof(fmax_oid) / sizeof(fmax_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with 0xFFFFFFFF in engineID length rejected");

    /* Single element OID */
    oid single_oid[] = { 2147483648UL };
    res = usm_parse_oid(single_oid, sizeof(single_oid) / sizeof(single_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with single element OID rejected");

    /* Large engineID length exceeding oidLen */
    oid large_eid_oid[] = { 5, 1, 2, 3 };
    res = usm_parse_oid(large_eid_oid, sizeof(large_eid_oid) / sizeof(large_eid_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with engineID length > oidLen - 2 rejected");

    /* Large name length exceeding oidLen - engineIDL - 2 */
    oid large_name_oid[] = { 2, 1, 2, 10, 'a', 'b' };
    res = usm_parse_oid(large_name_oid, sizeof(large_name_oid) / sizeof(large_name_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with name length mismatch rejected");

    /* 0x80000000 in name length */
    oid large_name_signed_oid[] = { 2, 1, 2, 2147483648UL, 'a', 'b' };
    res = usm_parse_oid(large_name_signed_oid,
                        sizeof(large_name_signed_oid) / sizeof(large_name_signed_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with 0x80000000 in name length rejected");

    /* NULL / 0 length checks */
    res = usm_parse_oid(NULL, 10, &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with NULL oidIndex rejected");

    res = usm_parse_oid(f1039_oid, 0, &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with oidLen=0 rejected");

    res = usm_parse_oid(f1039_oid, 1, &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with oidLen=1 rejected");

    /* Character > 255 in engineID */
    oid oob_char_eid[] = { 2, 300, 2, 1, 'a' };
    res = usm_parse_oid(oob_char_eid, sizeof(oob_char_eid) / sizeof(oob_char_eid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with engineID sub-id > 255 rejected");

    /* Character > 255 in name */
    oid oob_char_name[] = { 2, 1, 2, 2, 'a', 300 };
    res = usm_parse_oid(oob_char_name, sizeof(oob_char_name) / sizeof(oob_char_name[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res != 0, "usm_parse_oid with name sub-id > 255 rejected");

    /* Valid USM OID index parsing */
    oid valid_usm_oid[] = { 5, 0x80, 0x00, 0x00, 0x01, 0x02, 5, 'u', 's', 'e', 'r', '1' };
    engineID = NULL;
    name = NULL;
    res = usm_parse_oid(valid_usm_oid, sizeof(valid_usm_oid) / sizeof(valid_usm_oid[0]),
                        &engineID, &engineIDLen, &name, &nameLen);
    OK(res == 0, "usm_parse_oid with valid OID succeeded");
    OK(engineID != NULL && engineIDLen == 5 &&
       engineID[0] == 0x80 && engineID[1] == 0x00 && engineID[2] == 0x00 &&
       engineID[3] == 0x01 && engineID[4] == 0x02,
       "usm_parse_oid parsed engineID correctly");
    OK(name != NULL && nameLen == 5 && strcmp((char *)name, "user1") == 0,
       "usm_parse_oid parsed name correctly");
    free(engineID);
    free(name);

    /* 2. Test usm_parse_user with short name_len (< USM_MIB_LENGTH) */
    oid short_user_oid[] = { 1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1 }; /* len = 11 < 12 */
    uptr = usm_parse_user(short_user_oid, sizeof(short_user_oid) / sizeof(short_user_oid[0]));
    OK(uptr == NULL, "usm_parse_user with name_len < USM_MIB_LENGTH returns NULL");

    /* usm_parse_user with crafted malformed index */
    oid malformed_user_oid[] = { 1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 13, 2147483648UL };
    uptr = usm_parse_user(malformed_user_oid,
                          sizeof(malformed_user_oid) / sizeof(malformed_user_oid[0]));
    OK(uptr == NULL, "usm_parse_user with crafted 0x80000000 OID index returns NULL");
}
