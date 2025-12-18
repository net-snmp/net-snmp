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
    { 1, { 1, 3, 1ull << 32 }, 3, { 6, 2, 0x2b, 0 }, 4 },
    { 1, { 2, (1ull << 32) - 2 * 40 - 1 }, 2,
      { 6, 5, 0x8f, 0xff, 0xff, 0xff, 0x7f }, 7 },
};

int i, j;

for (i = 0; i < sizeof(testdata) / sizeof(testdata[0]); i++) {
    const struct testdata_s *t = &testdata[i];
    {
        uint8_t data[16];
        size_t datalength = sizeof(data);
        uint8_t *res = asn_build_objid(data, &datalength, ASN_OBJECT_ID,
                                       t->objid, t->objid_length);
        OKF(!!res == t->valid, ("[%d] asn_build_objid()", i));
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
        OKF(!!res == t->valid, ("[%d] asn_realloc_rbuild_objid()", i));
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
