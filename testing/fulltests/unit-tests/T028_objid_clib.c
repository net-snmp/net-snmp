/* HEADER ASN OBJECT ID parsing and encoding */

static const struct testdata_s {
    int      valid;
    oid      objid[5];
    uint16_t objid_length;
    u_char   encoded[14];
    uint16_t encoded_length;
} testdata[] = {
    { 1, {},                0, { 6, 1, 0 },       3 },
    { 1, { 0 },             1, { 6, 1, 0 },       3 },
    { 1, { 1 },             1, { 6, 1, 40 },      3 },
    { 1, { 0, 0 },          2, { 6, 1, 0 },       3 },
    { 1, { 0, 39 },         2, { 6, 1, 39 },      3 },
    { 0, { 0, 40 },         2                       },
    { 0, { 1, 40 },         2                       },
    { 1, { 1, 3 },          2, { 6, 1, 0x2b },    3 },
    { 1, { 1, 3, 4 },       3, { 6, 2, 0x2b, 4 }, 4 },
    { 1, { 1, 3, 4444444 }, 3, { 6, 5, 0x2b, 0x82, 0x8f, 0xa2, 0x1c }, 7 },
    { 1, { 0, 0, 4294967295, 0, 4294967295 }, 5,
      { 6, 12, 0, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0, 0x8f, 0xff, 0xff, 0xff, 0x7f },
      14 },
#if !defined(__CYGWIN__) && !defined(EIGHTBIT_SUBIDS) && \
    defined(SIZEOF_UNSIGNED_LONG) && SIZEOF_UNSIGNED_LONG > 4
    { 1, { 1, 3, 1ull << 32 }, 3, { 6, 2, 0x2b, 0 }, 4 },
#endif
    { 1, { 2, 99, 1 },       3, { 6, 3, 0x81, 0x33, 1 }, 5 },
    { 1, { 2, (1ull << 32) - 2 * 40 - 1 }, 2,
      { 6, 5, 0x8f, 0xff, 0xff, 0xff, 0x7f }, 7 },
    { 0, { 2, (1ull << 32) - 2 * 40 }, 2 },
    { 0, { 3, 0, 1 },       3 },
};

int i, j;

for (i = 0; i < sizeof(testdata) / sizeof(testdata[0]); i++) {
    const struct testdata_s *t = &testdata[i];
    {
        uint8_t data[16];
        size_t datalength = sizeof(data);
        uint8_t *res = asn_build_objid(data, &datalength, ASN_OBJECT_ID,
                                       t->objid, t->objid_length);
        OKF(!!res == t->valid, ("[%d] asn_build_objid() %s; OID %s", i,
                                res ? "succeeded" : "failed",
                                t->valid ? "valid" : "not valid"));
        if (res != NULL) {
            uint16_t encoded_length = sizeof(data) - datalength;
            OKF(t->encoded_length == encoded_length,
                ("[%d] encoded length %d <> %d", i, t->encoded_length,
                 encoded_length));
            if (t->encoded_length == encoded_length) {
                int cmp_res = memcmp(data, t->encoded, t->encoded_length);
                OKF(cmp_res == 0, ("[%d] asn_build_objid() memcmp()", i));
                if (cmp_res != 0) {
                    for (j = 0; j < encoded_length; j++)
                        printf("%02x ", data[j]);
                    printf("\n");
                }
            }
        }
    }
    {
        uint8_t *pkt = NULL;
        size_t pkt_len = 0, offset = 0;
        int res = asn_realloc_rbuild_objid(&pkt, &pkt_len, &offset, TRUE,
                                           ASN_OBJECT_ID, t->objid,
                                           t->objid_length);
        OKF(!!res == t->valid, ("[%d] asn_realloc_rbuild_objid() %s; OID %s",
                                i, res ? "succeeded" : "failed",
                                t->valid ? "valid" : "not valid"));
        if (res != 0) {
            OKF(t->encoded_length == offset,
                ("[%d] encoded length %d <> %" NETSNMP_PRIz "d", i,
                 t->encoded_length, offset));
            if (t->encoded_length == offset) {
                const uint8_t *const start = pkt + pkt_len - offset;
                int cmp_res = memcmp(start, t->encoded, t->encoded_length);
                OKF(cmp_res == 0, ("[%d] asn_rbuild_objid() memcmp()", i));
                if (cmp_res != 0) {
                    for (j = 0; j < offset; j++)
                        printf("%02x ", start[j]);
                    printf("\n");
                }
            }
        }
        free(pkt);
    }
    if (t->encoded_length) {
        size_t datalength = t->encoded_length;
        u_char type;
        oid objid[8];
        size_t objid_len = sizeof(objid) / sizeof(objid[0]);
        uint8_t *end =
            asn_parse_objid(NETSNMP_REMOVE_CONST(uint8_t *, t->encoded),
                            &datalength, &type, objid, &objid_len);
        OKF(end != NULL, ("[%d] asn_parse_objid()", i));
        if (end != NULL) {
            uint32_t exp_len;
            OKF(datalength == 0, ("[%d] datalength %zu", i, datalength));
            OKF(type == ASN_OBJECT_ID, ("[%d] type %u", i, type));

            exp_len = t->objid_length >= 2 ? t->objid_length : 2;
            OKF(exp_len == objid_len, ("[%d] objid len %d <> %zd", i, exp_len,
                                       objid_len));
            if (exp_len == objid_len) {
                int cmp_res = 0;
                for (j = 0; j < objid_len; j++)
                    if ((uint32_t)t->objid[j] != objid[j])
                        cmp_res |= 1;
                OKF(cmp_res == 0, ("[%d] asn_parse_objid() memcmp()", i));
                if (cmp_res != 0) {
                    for (j = 0; j < objid_len; j++)
                        printf("%" NETSNMP_PRIo "d ", objid[j]);
                    printf("\n");
                }
            }
        }
    }
    
}

{
    oid out_oid[MAX_OID_LEN];
    size_t out_len = MAX_OID_LEN;

    OK(snmp_parse_oid(".1.3.6.1.\"unclosed", out_oid, &out_len) == NULL,
       "snmp_parse_oid rejects unclosed quote");

#ifndef NETSNMP_DISABLE_MIB_LOADING
    {
        unsigned char *new_val = (unsigned char *)1;
        int new_val_len = -1;
        char mibdir[PATH_MAX];

        OK(parse_octet_hint("1z", "abc", &new_val, &new_val_len) != NULL &&
           new_val == NULL && new_val_len == 0,
           "parse_octet_hint rejects invalid format 1z");
        OK(parse_octet_hint("0a", "abc", &new_val, &new_val_len) != NULL &&
           new_val == NULL && new_val_len == 0,
           "parse_octet_hint rejects zero-length 0a");
        OK(parse_octet_hint("10x", "1234", &new_val, &new_val_len) != NULL &&
           new_val == NULL && new_val_len == 0,
           "parse_octet_hint rejects oversized integer length 10x");
        OK(parse_octet_hint("1x:1x", "aa-bb", &new_val, &new_val_len) != NULL &&
           new_val == NULL && new_val_len == 0,
           "parse_octet_hint frees result on mismatched separator");

        snprintf(mibdir, sizeof(mibdir), "%s/%s", ABS_SRCDIR, "mibs");
        netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS,
                              mibdir);
        netsnmp_init_mib();
        out_len = MAX_OID_LEN;
        OK(read_objid(".1.3.6.1.99999.\"hi\"", out_oid, &out_len) == 1 &&
           out_len == 8 && out_oid[5] == 2 && out_oid[6] == 'h' &&
           out_oid[7] == 'i',
           "read_objid encodes double-quoted string length and bytes");
        out_len = MAX_OID_LEN;
        OK(read_objid(".1.3.6.1.99999.'hi'", out_oid, &out_len) == 1 &&
           out_len == 7 && out_oid[5] == 'h' && out_oid[6] == 'i',
           "read_objid encodes single-quoted fixed string bytes");
        out_len = MAX_OID_LEN;
        OK(read_objid("SNMP-VIEW-BASED-ACM-MIB::vacmSecurityToGroupStatus.3.120.65",
                      out_oid, &out_len) == 0,
           "read_objid rejects index length exceeding MAX_OID_LEN in _add_strings_to_oid");
        out_len = MAX_OID_LEN;
        OK(read_objid("SNMP-VIEW-BASED-ACM-MIB::vacmSecurityToGroupStatus.3.1.300",
                      out_oid, &out_len) == 0,
           "read_objid rejects string index subid > 255 in _add_strings_to_oid");
        unload_all_mibs();
        shutdown_mib();
        netsnmp_ds_shutdown();
    }
#endif

    /* Test parse_one_oid_index and build_oid_noalloc bounds */
    {
        oid idx_oids[MAX_OID_LEN + 4];
        oid *oid_ptr;
        size_t oid_rem;
        netsnmp_variable_list var;
        oid prefix[MAX_OID_LEN - 4];
        char long_str[16] = "0123456789abcde";

        memset(&var, 0, sizeof(var));
        memset(idx_oids, 0, sizeof(idx_oids));
        idx_oids[0] = MAX_OID_LEN + 1;
        oid_ptr = idx_oids;
        oid_rem = MAX_OID_LEN + 2;
        var.type = ASN_OCTET_STR;
        OK(parse_one_oid_index(&oid_ptr, &oid_rem, &var, 0) == SNMPERR_GENERR,
           "parse_one_oid_index rejects ASN_OCTET_STR with uitmp > MAX_OID_LEN");
        snmp_reset_var_buffers(&var);

        idx_oids[0] = MAX_OID_LEN + 1;
        oid_ptr = idx_oids;
        oid_rem = MAX_OID_LEN + 2;
        var.type = ASN_OBJECT_ID;
        OK(parse_one_oid_index(&oid_ptr, &oid_rem, &var, 0) == SNMPERR_GENERR,
           "parse_one_oid_index rejects ASN_OBJECT_ID with uitmp > MAX_OID_LEN");
        snmp_reset_var_buffers(&var);

        memset(prefix, 1, sizeof(prefix));
        memset(&var, 0, sizeof(var));
        snmp_set_var_objid(&var, prefix, 2);
        snmp_set_var_typed_value(&var, ASN_OCTET_STR, long_str,
                                 sizeof(long_str) - 1);
        out_len = MAX_OID_LEN;
        OK(build_oid_noalloc(out_oid, MAX_OID_LEN, &out_len,
                             prefix, OID_LENGTH(prefix), &var) == SNMPERR_GENERR,
           "build_oid_noalloc rejects index overflowing MAX_OID_LEN");
        snmp_reset_var_buffers(&var);
    }
}
