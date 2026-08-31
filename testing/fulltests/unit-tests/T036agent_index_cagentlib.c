/* HEADER Testing agent_index allocation bounds checking and rollover */

#include <net-snmp/agent/agent_index.h>

extern netsnmp_session *main_session;

{
    oid name[] = { 1, 3, 6, 1, 4, 1, 8072, 9999, 1 };
    oid overflow_oid[] = { 2, 255, 255, 255, 255, 255 }; /* 6 elements = 48 bytes > 40 bytes buf */
    oid rollover_oid[] = { 2, 255, 255 }; /* 3 elements */
    oid standard_oid[] = { 1, 255, 255 }; /* 3 elements */
    oid single_oid[] = { 255 }; /* 1 element */
    oid inc_oid[] = { 1, 2 };
    netsnmp_variable_list *res;
    char max_buf_str[40];
    char *sres;
    int ires;

    init_agent("test");
    init_snmp("test");

    /*
     * 1. Test issue #1046: OID index allocation heap buffer overflow.
     * When the previous index is 6 elements (48 bytes > 40 bytes) with all elements maxed out,
     * allocating ANY_INDEX must not overflow the buffer and should return NULL gracefully.
     */
    name[8] = 1;
    res = register_oid_index(name, OID_LENGTH(name), overflow_oid,
                             OID_LENGTH(overflow_oid));
    OK(res != NULL, "Register initial 6-element OID index");
    if (res)
        snmp_free_varbind(res);

    res = register_oid_index(name, OID_LENGTH(name), ANY_OID_INDEX, 0);
    OK(res == NULL, "Allocating ANY_INDEX when extending 6-element OID exceeds capacity returns NULL");
    if (res)
        snmp_free_varbind(res);

    /*
     * 2. Test OID index rollover when extending fits within buf.
     * Initial index: {2, 255, 255} (3 elements, 24 bytes).
     * Next ANY_INDEX should roll over and extend to {1, 1, 1, 1} (4 elements, 32 bytes).
     */
    name[8] = 2;
    res = register_oid_index(name, OID_LENGTH(name), rollover_oid,
                             OID_LENGTH(rollover_oid));
    OK(res != NULL, "Register initial {2, 255, 255} OID index");
    if (res)
        snmp_free_varbind(res);

    res = register_oid_index(name, OID_LENGTH(name), ANY_OID_INDEX, 0);
    OK(res != NULL, "Allocating ANY_INDEX from {2, 255, 255} succeeds");
    if (res) {
        OK(res->val_len == 4 * sizeof(oid), "Length is 4 OID elements");
        OK(res->val.objid[0] == 1 && res->val.objid[1] == 1 &&
           res->val.objid[2] == 1 && res->val.objid[3] == 1,
           "Extended value is {1, 1, 1, 1}");
        snmp_free_varbind(res);
    }

    /*
     * 3. Test OID index rollover without extending.
     * Initial index: {1, 255, 255} (3 elements).
     * Next ANY_INDEX should roll over subids to {2, 1, 1} (3 elements).
     */
    name[8] = 3;
    res = register_oid_index(name, OID_LENGTH(name), standard_oid,
                             OID_LENGTH(standard_oid));
    OK(res != NULL, "Register initial {1, 255, 255} OID index");
    if (res)
        snmp_free_varbind(res);

    res = register_oid_index(name, OID_LENGTH(name), ANY_OID_INDEX, 0);
    OK(res != NULL, "Allocating ANY_INDEX from {1, 255, 255} succeeds");
    if (res) {
        OK(res->val_len == 3 * sizeof(oid), "Length is 3 OID elements");
        OK(res->val.objid[0] == 2 && res->val.objid[1] == 1 &&
           res->val.objid[2] == 1, "Value rolled over to {2, 1, 1}");
        snmp_free_varbind(res);
    }

    /*
     * 4. Test single-element OID index rollover: {255} -> {1, 1}.
     */
    name[8] = 4;
    res = register_oid_index(name, OID_LENGTH(name), single_oid,
                             OID_LENGTH(single_oid));
    OK(res != NULL, "Register initial {255} OID index");
    if (res)
        snmp_free_varbind(res);

    res = register_oid_index(name, OID_LENGTH(name), ANY_OID_INDEX, 0);
    OK(res != NULL, "Allocating ANY_INDEX from {255} succeeds");
    if (res) {
        OK(res->val_len == 2 * sizeof(oid), "Length is 2 OID elements");
        OK(res->val.objid[0] == 1 && res->val.objid[1] == 1,
           "Extended value is {1, 1}");
        snmp_free_varbind(res);
    }

    /*
     * 5. Test standard OID increment without rollover: {1, 2} -> {1, 3}.
     */
    name[8] = 5;
    res = register_oid_index(name, OID_LENGTH(name), inc_oid,
                             OID_LENGTH(inc_oid));
    OK(res != NULL, "Register initial {1, 2} OID index");
    if (res)
        snmp_free_varbind(res);

    res = register_oid_index(name, OID_LENGTH(name), ANY_OID_INDEX, 0);
    OK(res != NULL, "Allocating ANY_INDEX from {1, 2} succeeds");
    if (res) {
        OK(res->val_len == 2 * sizeof(oid), "Length is 2 OID elements");
        OK(res->val.objid[0] == 1 && res->val.objid[1] == 3,
           "Incremented value is {1, 3}");
        snmp_free_varbind(res);
    }

    /*
     * 6. Test string index rollover:
     * "aaaz" -> "aaba"
     * "zzzz" -> "aaaaa"
     */
    name[8] = 6;
    sres = register_string_index(name, OID_LENGTH(name), "aaaz");
    OK(sres != NULL, "Register initial 'aaaz' string index");
    free(sres);

    sres = register_string_index(name, OID_LENGTH(name), ANY_STRING_INDEX);
    OK(sres != NULL, "Allocating ANY_STRING_INDEX from 'aaaz' succeeds");
    if (sres) {
        OK(strcmp(sres, "aaba") == 0, "Rolled over to 'aaba'");
        free(sres);
    }

    name[8] = 7;
    sres = register_string_index(name, OID_LENGTH(name), "zzzz");
    OK(sres != NULL, "Register 'zzzz' string index");
    free(sres);

    sres = register_string_index(name, OID_LENGTH(name), ANY_STRING_INDEX);
    OK(sres != NULL, "Allocating ANY_STRING_INDEX from 'zzzz' succeeds");
    if (sres) {
        OK(strcmp(sres, "aaaaa") == 0, "Rolled over and extended to 'aaaaa'");
        free(sres);
    }

    /*
     * 7. Test string index capacity limit:
     * When string fills buf (39 'z' chars), extending must return NULL without buffer overflow.
     */
    name[8] = 8;
    memset(max_buf_str, 'z', sizeof(max_buf_str) - 1);
    max_buf_str[sizeof(max_buf_str) - 1] = '\0';
    sres = register_string_index(name, OID_LENGTH(name), max_buf_str);
    OK(sres != NULL, "Register max-capacity string index");
    free(sres);

    sres = register_string_index(name, OID_LENGTH(name), ANY_STRING_INDEX);
    OK(sres == NULL, "Allocating ANY_STRING_INDEX when max capacity is reached returns NULL");
    if (sres)
        free(sres);

    /*
     * 8. Test integer index allocation:
     * 5 -> 6
     */
    name[8] = 9;
    ires = register_int_index(name, OID_LENGTH(name), 5);
    OK(ires == 5, "Register integer index 5");

    ires = register_int_index(name, OID_LENGTH(name), ANY_INTEGER_INDEX);
    OK(ires == 6, "Allocating ANY_INTEGER_INDEX from 5 produces 6");

    unregister_index_by_session(main_session);

    snmp_shutdown("test");
    shutdown_agent();
}
