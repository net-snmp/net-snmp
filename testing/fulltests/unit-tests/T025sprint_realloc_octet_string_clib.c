/* HEADER Test sprint_realloc_octet_string() display hint handling */

static const unsigned char data_single[] = {42};
static const unsigned char data_two[] = {10, 20};
static const unsigned char data_three[] = {0x0A, 0x14, 0x1E};
static const unsigned char data_hex_colon[] = {0xAA, 0xBB, 0xCC};
static const unsigned char data_decimal_dot[] = {192, 168, 1, 1};
static const unsigned char data_ascii[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
static const unsigned char data_dateandtime[] = {0x07, 0xE8, 0x01, 0x0F};
static const unsigned char data_octal[] = {8, 16, 32};
static const unsigned char data_ab[] = {0x41, 0x42};
static const unsigned char data_ipv6_addr[] = {
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x50
};
static const unsigned char data_repeat[] = {3, 0xAA, 0xBB, 0xCC};
static const unsigned char data_repeat_zero[] = {0, 42};
static const unsigned char data_repeat_exhaust[] = {5, 10, 20};

static const struct {
    const char *name;
    const char *hint;
    const unsigned char *data;
    size_t data_len;
} malformed_tests[] = {
    {"zero-width hex only", "0x", data_three, 3},
    {"zero-width decimal only", "0d", data_three, 3},
    {"zero-width octal only", "0o", data_three, 3},
    {"zero-width ascii only", "0a", data_three, 3},
    {"empty data", "1d.1d.1d.1d", data_three, 0},
    {"invalid format character", "1z", data_three, 3}
};

static const struct {
    const char *name;
    const char *hint;
    const unsigned char *data;
    size_t data_len;
    const char *expected;
} tests[] = {
    {
        "hex with colon separator",
        "1x:",
        data_hex_colon,
        3,
        "aa:bb:cc"
    },
    {
        "decimal with dot separator",
        "1d.",
        data_decimal_dot,
        4,
        "192.168.1.1"
    },
    {
        "ascii string",
        "255a",
        data_ascii,
        5,
        "Hello"
    },
    {
        "multi-byte decimal (DateAndTime style)",
        "2d-1d-1d",
        data_dateandtime,
        4,
        "2024-1-15"
    },
    {
        "octal format",
        "1o:",
        data_octal,
        3,
        "10:20:40"
    },
    {
        "zero-width prefix bracket",
        "0a[1d",
        data_single,
        1,
        "[42"
    },
    {
        "zero-width literal between specs",
        "1d0a/1d",
        data_two,
        2,
        "10/20"
    },
    {
        "multiple consecutive zero-width",
        "0a<0a<1d",
        data_single,
        1,
        "<<42"
    },
    {
        "zero-width mid-hint with separator",
        "1d-0a.1d",
        data_two,
        2,
        "10-.20"
    },
    {
        "zero-width bracket suffix",
        "1a0a]1a",
        data_ab,
        2,
        "A]B"
    },
    {
        "RFC 3419 IPv6 transport address",
        "0a[2x:2x:2x:2x:2x:2x:2x:2x]0a:2d",
        data_ipv6_addr,
        18,
        "[2001:db8:0:0:0:0:0:1]:80"
    },
    {
        "repeat indicator basic",
        "*1x:",
        data_repeat,
        4,
        "aa:bb:cc"
    },
    {
        "data shorter than hint spec",
        "1d.1d.1d.1d",
        data_two,
        2,
        "10.20"
    },
    {
        "repeat indicator zero count",
        "*1d./1d",
        data_repeat_zero,
        2,
        "/42"
    },
    {
        "repeat indicator exhausted mid-data",
        "*1d.",
        data_repeat_exhaust,
        3,
        "10.20"
    },
    {
        "trailing separator suppressed (single byte)",
        "1d.",
        data_single,
        1,
        "42"
    },
    {
        "trailing separator suppressed (multi byte)",
        "1d.",
        data_two,
        2,
        "10.20"
    },
    {
        "trailing terminator suppressed",
        "*1x:;",
        data_repeat,
        4,
        "aa:bb:cc"
    },
    {
        "zero-width at end ignored when data exhausted",
        "1d0a]",
        data_single,
        1,
        "42"
    },
    {
        "zero-width suffix mid-data",
        "1d0a]1d",
        data_two,
        2,
        "10]20"
    },
    {
        "zero-width last spec drops remaining data",
        "1d0a]",
        data_two,
        2,
        "10"
    }
};

char *buf;
size_t buf_len;
netsnmp_variable_list variable;
int i, ret;

netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, TRUE);

init_snmp("T025");

buf_len = 256;
buf = malloc(buf_len);
memset(&variable, 0, sizeof(variable));
variable.type = ASN_OCTET_STR;

for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
    memset(buf, 0, buf_len);
    variable.val.string = (unsigned char *)tests[i].data;
    variable.val_len = tests[i].data_len;

    ret = snprint_octet_string(buf, buf_len, &variable, NULL,
                               tests[i].hint, NULL);

    OKF(ret > 0,
        ("[%d] %s: snprint_octet_string() returned %d, expected > 0",
         i, tests[i].name, ret));

    if (ret > 0) {
        OKF(strcmp(buf, tests[i].expected) == 0,
            ("[%d] %s: got \"%s\", expected \"%s\"",
             i, tests[i].name, buf, tests[i].expected));
    }
}

/* Edge cases: verify they complete without hanging or crashing. */
for (i = 0; i < (int)(sizeof(malformed_tests) / sizeof(malformed_tests[0])); i++) {
    memset(buf, 0, buf_len);
    variable.val.string = (unsigned char *)malformed_tests[i].data;
    variable.val_len = malformed_tests[i].data_len;

    ret = snprint_octet_string(buf, buf_len, &variable, NULL,
                               malformed_tests[i].hint, NULL);

    OKF(ret >= 0,
        ("[malformed %d] %s: returned %d, expected >= 0 (completed without hang)",
         i, malformed_tests[i].name, ret));
}

free(buf);
snmp_shutdown("T025");
