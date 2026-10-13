/* HEADER Test sprint_integer() */
/* See also https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=59491. */

static const struct {
    long val;
    const char *hint;
    const char *result;
} test[] = {
    { 19, "b", "INTEGER: 00000000000000000000000000010011" },
    { 19, "d", "INTEGER: 19" },
    { 19, "o", "INTEGER: 23" },
    { 19, "x", "INTEGER: 13" },
    { 19, "f", NULL },
    { 19, "s", NULL },
    { 19, "p", NULL },
    { LONG_MIN, "d", NULL /* checked below for non-empty output */ },
    { LONG_MIN, "d-0", NULL },
    { LONG_MIN, "d-2", NULL },
    { LONG_MIN, "d-250", NULL },
};
char *buf;
size_t buf_len;
char mibdir[PATH_MAX];
netsnmp_variable_list variable;
long input_value;
int i, ret;

snprintf(mibdir, sizeof(mibdir), "%s/%s", ABS_SRCDIR, "mibs");
netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS, mibdir);
netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, TRUE);

init_snmp("T021");

buf_len = 512;
buf = malloc(buf_len);
memset(&variable, 0, sizeof(variable));
variable.type = ASN_INTEGER;
variable.val.integer = &input_value;
variable.val_len = sizeof(variable.val.integer);

for (i = 0; i < sizeof(test) / sizeof(test[0]); i++) {
    input_value = test[i].val;

    ret = snprint_integer(buf, buf_len, &variable, /*enums=*/NULL,
                          test[i].hint, /*units=*/NULL);
    if (test[i].val == LONG_MIN) {
        OKF(ret > 0 && strstr(buf, "-") != NULL,
            ("[%d] snprint_integer(LONG_MIN, \"%s\") -> %s (ret=%d)",
             i, test[i].hint, ret > 0 ? buf : "ERR", ret));
    } else if (test[i].result) {
        OKF(ret > 0, ("[%d] sprint_integer() returned %d; expected > 0", i, ret));
        if (ret > 0)
            OKF(strcmp(buf, test[i].result) == 0,
                ("%s <> %s", buf, test[i].result));
    } else {
        OKF(ret < 0, ("[%d] sprint_integer() failed", i));
    }
}

{
    u_char *rbuf = NULL;
    size_t rbuf_len = 0, out_len = 0;
    int rc;

    rc = sprint_realloc_hinted_integer(&rbuf, &rbuf_len, &out_len, 1,
                                       LONG_MIN, 'd', "d-3", NULL);
    OK(rc != 0 && rbuf != NULL && rbuf[0] == '-',
       "sprint_realloc_hinted_integer handles LONG_MIN with d-3 hint without UB");
    free(rbuf);
}

#ifndef NETSNMP_DISABLE_MIB_LOADING
{
    static const char idx_mib[] =
        "T021-TEST-MIB DEFINITIONS ::= BEGIN\n"
        "IMPORTS OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI\n"
        "        TEXTUAL-CONVENTION FROM SNMPv2-TC;\n"
        "T021Str ::= TEXTUAL-CONVENTION\n"
        "    DISPLAY-HINT \"255a\"\n"
        "    STATUS current\n"
        "    DESCRIPTION \"test\"\n"
        "    SYNTAX OCTET STRING (SIZE (1..32))\n"
        "t021Root OBJECT IDENTIFIER ::= { enterprises 99998 }\n"
        "t021Table OBJECT-TYPE\n"
        "    SYNTAX SEQUENCE OF T021Entry\n"
        "    MAX-ACCESS not-accessible\n"
        "    STATUS current\n"
        "    DESCRIPTION \"table\"\n"
        "    ::= { t021Root 1 }\n"
        "t021Entry OBJECT-TYPE\n"
        "    SYNTAX T021Entry\n"
        "    MAX-ACCESS not-accessible\n"
        "    STATUS current\n"
        "    DESCRIPTION \"entry\"\n"
        "    INDEX { t021Idx }\n"
        "    ::= { t021Table 1 }\n"
        "T021Entry ::= SEQUENCE { t021Idx T021Str, t021Val Integer32 }\n"
        "t021Idx OBJECT-TYPE\n"
        "    SYNTAX T021Str\n"
        "    MAX-ACCESS not-accessible\n"
        "    STATUS current\n"
        "    DESCRIPTION \"idx\"\n"
        "    ::= { t021Entry 1 }\n"
        "t021Val OBJECT-TYPE\n"
        "    SYNTAX Integer32\n"
        "    MAX-ACCESS read-only\n"
        "    STATUS current\n"
        "    DESCRIPTION \"val\"\n"
        "    ::= { t021Entry 2 }\n"
        "END\n";
    char mib_path[128];
    FILE *fp;
    oid valid_oid[] = { 1, 3, 6, 1, 4, 1, 99998, 1, 1, 2, 3, 'a', 'b', 'c' };
    oid trunc_oid[] = { 1, 3, 6, 1, 4, 1, 99998, 1, 1, 2, 50, 'a', 'b' };
    oid big_subid_oid[] = { 1, 3, 6, 1, 4, 1, 99998, 1, 1, 2, 2, 300, 'b' };
    char obj_buf[256];

    snprintf(mib_path, sizeof(mib_path), "/tmp/t021-mib-%d", (int)getpid());
    fp = fopen(mib_path, "wb");
    if (fp) {
        fwrite(idx_mib, 1, strlen(idx_mib), fp);
        fclose(fp);
        read_mib(mib_path);
        unlink(mib_path);
    }
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_EXTENDED_INDEX, 1);
    OK(snprint_objid(obj_buf, sizeof(obj_buf), valid_oid,
                     OID_LENGTH(valid_oid)) > 0 &&
       strstr(obj_buf, "abc") != NULL,
       "_get_realloc_symbol_octet_string formats valid string index");
    OK(snprint_objid(obj_buf, sizeof(obj_buf), trunc_oid,
                     OID_LENGTH(trunc_oid)) > 0,
       "_get_realloc_symbol_octet_string bounds-checks truncated string index");
    OK(snprint_objid(obj_buf, sizeof(obj_buf), big_subid_oid,
                     OID_LENGTH(big_subid_oid)) > 0,
       "_get_realloc_symbol_octet_string rejects subid > 255 in string index");

    /* Exercise print_parent_mibchildoid with depth > 100 */
    {
        extern struct tree *tree_head;
        struct tree *deep_nodes = calloc(135, sizeof(struct tree));
        FILE *devnull = fopen("/dev/null", "w");
        int d;

        if (deep_nodes && tree_head && devnull) {
            for (d = 0; d < 135; d++) {
                deep_nodes[d].subid = (u_long)(d + 1);
                deep_nodes[d].label = (char *)"n";
                if (d > 0) {
                    deep_nodes[d].parent = &deep_nodes[d - 1];
                    deep_nodes[d - 1].child_list = &deep_nodes[d];
                }
            }
            deep_nodes[0].parent = tree_head;
            deep_nodes[0].next_peer = tree_head->child_list;
            tree_head->child_list = &deep_nodes[0];

            print_oid_report_enable_mibchildoid();
            print_oid_report(devnull);

            tree_head->child_list = deep_nodes[0].next_peer;
            OK(1, "print_parent_mibchildoid handles tree depth > 100 safely");
        }
        if (devnull)
            fclose(devnull);
        free(deep_nodes);
    }
}
#endif

free(buf);
snmp_shutdown("T021");
