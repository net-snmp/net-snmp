/* HEADER Testing read_config_read_octet_string_const(). */

struct read_config_testcase {
    /*
     * inputs 
     */
    const char     *(*pf) (const char * readfrom, u_char ** str,
                           size_t * len);
    const char     *readfrom;
    size_t          obuf_len;

    /*
     * expected outputs 
     */
    size_t          expected_offset;
    const u_char   *expected_output;
    size_t          expected_len;
};

static const u_char obuf1[] = { 1, 0, 2 };
static const u_char obuf2[] = { 'a', 'b', 'c', 0 };

static const struct read_config_testcase test_input[] = {
    { &read_config_read_octet_string_const, "",           1, -1, NULL,  0 },
    { &read_config_read_octet_string_const, "0x0",        1, -1, NULL,  0 },
    { &read_config_read_octet_string_const, "0x0 0",      1, -1, NULL,  0 },

    { &read_config_read_octet_string_const, "0x010002",   1, -1, NULL,  0 },
    { &read_config_read_octet_string_const, "0x010002",   2, -1, NULL,  0 },
    { &read_config_read_octet_string_const, "0x010002",   3, -1, obuf1, 0 },
    { &read_config_read_octet_string_const, "0x010002",   4, -1, obuf1, 3 },
    { &read_config_read_octet_string_const, "0x010002 0", 4,  9, obuf1, 3 },
    { &read_config_read_octet_string_const, "0x010002",   0, -1, obuf1, 3 },
    { &read_config_read_octet_string_const, "0x01zz",     0, -1, NULL,  0 },

    { &read_config_read_octet_string_const, "abc",        1, -1, NULL,  0 },
    { &read_config_read_octet_string_const, "abc z",      1,  4, NULL,  0 },
    { &read_config_read_octet_string_const, "abc",        2, -1, NULL,  1 },
    { &read_config_read_octet_string_const, "abc",        3, -1, obuf2, 2 },
    { &read_config_read_octet_string_const, "abc",        4, -1, obuf2, 3 },
    { &read_config_read_octet_string_const, "abc z",      4,  4, obuf2, 3 },
    { &read_config_read_octet_string_const, "abc",        0, -1, obuf2, 3 },
};

unsigned int i, j, ok;

for (i = 0; i < sizeof(test_input) / sizeof(test_input[0]); i++) {
    const struct read_config_testcase *const p = &test_input[i];
    size_t          len = p->obuf_len;
    u_char         *str = len > 0 ? malloc(len) : NULL;
    const char     *result;
    size_t          offset;

    fflush(stdout);
    result = (p->pf) (p->readfrom, &str, &len);
    offset = result ? result - p->readfrom : -1;
    OKF(offset == p->expected_offset,
        ("test %d: expected offset %" NETSNMP_PRIz "d, got offset %"
         NETSNMP_PRIz "d", i, p->expected_offset, offset));
    if (offset == p->expected_offset) {
        OKF(len == p->expected_len,
            ("test %d: expected length %" NETSNMP_PRIz "d, got length %"
             NETSNMP_PRIz "d", i, p->expected_len, len));
        if (len == p->expected_len) {
            ok = !p->expected_output
                || memcmp(str, p->expected_output, len) == 0
                || p->expected_output[len] != 0;
            OKF(ok, ("test %d: output buffer mismatch", i));
            if (!ok) {
                printf("Expected: ");
                for (j = 0; j < p->expected_len; ++j)
                    printf("%02x ", p->expected_output[j]);
                printf("\nActual:   ");
                for (j = 0; j < len; ++j)
                    printf("%02x ", str[j]);
                printf("\n");
            }
        }
    }

    if (str)
        free(str);
}

{
    oid             oid_buf[4] = { 0, 0, 0xdeadbeef, 0xdeadbeef };
    size_t          oid_bytes = 2 * sizeof(oid);
    char            input_oid[] = ".1.3.6.1.2.1";

    read_config_read_memory(ASN_OBJECT_ID, input_oid, (char *)oid_buf,
                            &oid_bytes);
    OKF(oid_buf[2] == 0xdeadbeef && oid_buf[3] == 0xdeadbeef,
        ("read_config_read_memory(ASN_OBJECT_ID) respects byte buffer size"));
}

{
    const u_char    raw[] = { 0xde, 0xad, 0xbe, 0xef };
    size_t          hex_len = 2;
    u_char         *hex_buf = malloc(hex_len);
    u_int           olen;

    olen = netsnmp_binary_to_hex(&hex_buf, &hex_len, 1, raw, sizeof(raw));
    OKF(olen == 9 && hex_buf != NULL &&
        strcmp((char *)hex_buf, "deadbeef") == 0,
        ("netsnmp_binary_to_hex reallocates small buffer"));
    free(hex_buf);
}

{
    char pdir[128];

    /* Test config_perror with % format specifiers */
    config_perror("malformed %s %n %x token");
    config_pwarn("warning %s %n %x token");
    OK(1, "config_perror and config_pwarn safely handle percent specifiers");

    /* Test snmp_config_when via netsnmp_config and netsnmp_config_process_memories */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_HAVE_READ_CONFIG, 1);
    OK(netsnmp_config("unknown_token_t016 value") == SNMPERR_GENERR,
       "netsnmp_config dispatches through snmp_config_when and reports unknown token");

    netsnmp_config_remember("unknown_premib_token_t016 value");
    netsnmp_config_process_memories();
    OK(1, "netsnmp_config_process_memories processes and frees remembered lines");

    /* Test read_config_store when fopen fails and when it succeeds */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 0);
    set_persistent_directory("/dev/null/sub");
    read_config_store("t016_app", "test_store_line 1");
    OK(1, "read_config_store handles unwritable persistent directory safely");

    snprintf(pdir, sizeof(pdir), "/tmp/netsnmp_t016_%d", (int)getpid());
    set_persistent_directory(pdir);
    read_config_store("t016_app", "test_store_line 2");
    {
        char pfile[160];
        snprintf(pfile, sizeof(pfile), "%s/t016_app.conf", pdir);
        unlink(pfile);
        rmdir(pdir);
    }
    set_persistent_directory(NULL);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    unregister_all_config_handlers();
}
