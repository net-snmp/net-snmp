/* HEADER Testing agent helpers (instance, stash_cache, override, iquery) */

#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/mib_module_config.h>
#include <net-snmp/agent/agent_module_config.h>
#include <net-snmp/agent/stash_cache.h>

extern netsnmp_stash_cache_info *netsnmp_get_new_stash_cache(void);
extern Netsnmp_Node_Handler override_handler;
extern netsnmp_session *netsnmp_iquery_session(char *secName, int version,
                                               int secModel, int secLevel,
                                               u_char *engineID,
                                               size_t engIDLen);

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");

/*
 * 1. netsnmp_instance_num_file_handler() tests (agent/helpers/instance.c)
 */
#if !defined(NETSNMP_NO_WRITE_SUPPORT) && !defined(NETSNMP_FEATURE_REMOVE_INSTANCE)
{
    char                          tmp_path[] = "/tmp/netsnmp_num_file_XXXXXX";
    int                           fd;
    FILE                         *fp;
    char                          buf[64];
    oid                           num_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 44, 1, 0 };
    netsnmp_subtree              *st;
    netsnmp_handler_registration *reginfo = NULL;
    netsnmp_mib_handler          *nf_h = NULL;
    netsnmp_agent_request_info    reqinfo;
    netsnmp_request_info          request;
    netsnmp_variable_list         vb;
    long                          val;
    int                           rc;

    fd = mkstemp(tmp_path);
    OK(fd >= 0, "mkstemp created temporary file for instance_num_file_handler");
    if (fd >= 0) {
        ssize_t wr = write(fd, "100000\n", 7);
        OK(wr == 7, "wrote initial 100000\\n to temporary file");
        close(fd);
    }

    rc = netsnmp_register_num_file_instance("test_num_file", num_oid,
                                            OID_LENGTH(num_oid), tmp_path,
                                            ASN_INTEGER, HANDLER_CAN_RWRITE,
                                            NULL, NULL);
    OK(rc == MIB_REGISTERED_OK, "netsnmp_register_num_file_instance succeeded");

    st = netsnmp_subtree_find(num_oid, OID_LENGTH(num_oid), NULL, "");
    if (st && st->reginfo) {
        reginfo = st->reginfo;
        nf_h = netsnmp_find_handler_by_name(reginfo, "test_num_file");
    }
    OK(nf_h != NULL, "located test_num_file handler in registered subtree");

    /*
     * 1a. RESERVE1 with val_len != sizeof(long) fails with SNMP_ERR_WRONGLENGTH
     */
    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    memset(&vb, 0, sizeof(vb));
    val = 42;
    reqinfo.mode = MODE_SET_RESERVE1;
    vb.name = num_oid;
    vb.name_length = OID_LENGTH(num_oid);
    vb.type = ASN_INTEGER;
    vb.val.integer = &val;
    vb.val_len = 2; /* wrong length */
    request.requestvb = &vb;

    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OKF(request.status == SNMP_ERR_WRONGLENGTH,
        ("RESERVE1 with val_len != sizeof(long) rejected with SNMP_ERR_WRONGLENGTH (%d == %d)",
         request.status, SNMP_ERR_WRONGLENGTH));
    netsnmp_free_request_data_sets(&request);

    /*
     * 1b. SET sequence RESERVE1 -> RESERVE2 -> ACTION -> COMMIT writing 42
     *     Verify file is truncated to "42" (not "420000\n").
     */
    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    val = 42;
    vb.val_len = sizeof(val);
    request.requestvb = &vb;

    reqinfo.mode = MODE_SET_RESERVE1;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 42 RESERVE1 succeeded");

    reqinfo.mode = MODE_SET_RESERVE2;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 42 RESERVE2 succeeded");

    reqinfo.mode = MODE_SET_ACTION;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 42 ACTION succeeded");

    reqinfo.mode = MODE_SET_COMMIT;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 42 COMMIT succeeded");
    netsnmp_free_request_data_sets(&request);

    memset(buf, 0, sizeof(buf));
    fp = fopen(tmp_path, "r");
    OK(fp != NULL, "opened temporary file after COMMIT");
    if (fp) {
        size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[nread] = '\0';
        fclose(fp);
    }
    OKF(strcmp(buf, "42") == 0,
        ("file truncated to \"42\" after COMMIT (got \"%s\")", buf));

    /*
     * 1c. SET sequence RESERVE1 -> RESERVE2 -> ACTION -> UNDO writing 999999
     *     Verify file is rewound and truncated back to "42".
     */
    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    val = 999999;
    vb.val_len = sizeof(val);
    request.requestvb = &vb;

    reqinfo.mode = MODE_SET_RESERVE1;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 999999 RESERVE1 succeeded");

    reqinfo.mode = MODE_SET_RESERVE2;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 999999 RESERVE2 succeeded");

    reqinfo.mode = MODE_SET_ACTION;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 999999 ACTION succeeded");

    reqinfo.mode = MODE_SET_UNDO;
    netsnmp_instance_num_file_handler(nf_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "SET 999999 UNDO succeeded");
    netsnmp_free_request_data_sets(&request);

    memset(buf, 0, sizeof(buf));
    fp = fopen(tmp_path, "r");
    OK(fp != NULL, "opened temporary file after UNDO");
    if (fp) {
        size_t nread = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[nread] = '\0';
        fclose(fp);
    }
    OKF(strcmp(buf, "42") == 0,
        ("file restored and truncated to \"42\" after UNDO (got \"%s\")", buf));

    unregister_mib(num_oid, OID_LENGTH(num_oid));
    unlink(tmp_path);
}
#endif

/*
 * 2. netsnmp_stash_cache_helper() tests (agent/helpers/stash_cache.c)
 */
#ifndef NETSNMP_FEATURE_REMOVE_STASH_CACHE
{
    oid                           root_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 44, 2 };
    oid                           oid1[] = { 1, 3, 6, 1, 4, 1, 99999, 44, 2, 1 };
    oid                           oid2[] = { 1, 3, 6, 1, 4, 1, 99999, 44, 2, 2 };
    long                          val1 = 111, val2 = 222;
    netsnmp_variable_list        *var1 = NULL, *var2 = NULL;
    netsnmp_variable_list         req_vb1, req_vb2;
    netsnmp_request_info          req1, req2;
    netsnmp_agent_request_info    reqinfo;
    netsnmp_handler_registration *reginfo;
    netsnmp_mib_handler          *sc_h;
    netsnmp_cache                *cache;
    netsnmp_stash_cache_info     *cinfo;
    int                           rc;

    reginfo = netsnmp_create_handler_registration("test_stash_cache", NULL,
                                                  root_oid,
                                                  OID_LENGTH(root_oid),
                                                  HANDLER_CAN_RONLY);
    sc_h = netsnmp_create_handler("stash_cache", netsnmp_stash_cache_helper);
    cache = netsnmp_cache_create(30, NULL, NULL, root_oid,
                                 OID_LENGTH(root_oid));
    OK(reginfo != NULL && sc_h != NULL && cache != NULL,
       "created stash_cache registration, handler, and cache");

    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&req1, 0, sizeof(req1));
    memset(&req2, 0, sizeof(req2));
    memset(&req_vb1, 0, sizeof(req_vb1));
    memset(&req_vb2, 0, sizeof(req_vb2));

    reqinfo.mode = MODE_GET;
    netsnmp_cache_reqinfo_insert(cache, &reqinfo, reginfo->handlerName);

    /* 2a. Verify NULL cinfo (cache->magic == NULL) returns SNMP_ERR_GENERR cleanly */
    cache->magic = NULL;
    rc = netsnmp_stash_cache_helper(sc_h, reginfo, &reqinfo, &req1);
    OKF(rc == SNMP_ERR_GENERR,
        ("stash_cache_helper with NULL cinfo returns SNMP_ERR_GENERR (%d)", rc));

    /* 2b. Multi-varbind MODE_GET returns each varbind's own cached value */
    cinfo = netsnmp_get_new_stash_cache();
    OK(cinfo != NULL, "netsnmp_get_new_stash_cache succeeded");
    cache->magic = cinfo;

    snmp_varlist_add_variable(&var1, oid1, OID_LENGTH(oid1), ASN_INTEGER,
                              &val1, sizeof(val1));
    snmp_varlist_add_variable(&var2, oid2, OID_LENGTH(oid2), ASN_INTEGER,
                              &val2, sizeof(val2));
    netsnmp_oid_stash_add_data(&cinfo->cache, oid1, OID_LENGTH(oid1), var1);
    netsnmp_oid_stash_add_data(&cinfo->cache, oid2, OID_LENGTH(oid2), var2);

    snmp_set_var_objid(&req_vb1, oid1, OID_LENGTH(oid1));
    req_vb1.type = ASN_NULL;
    snmp_set_var_objid(&req_vb2, oid2, OID_LENGTH(oid2));
    req_vb2.type = ASN_NULL;

    req1.requestvb = &req_vb1;
    req1.next = &req2;
    req2.requestvb = &req_vb2;
    req2.next = NULL;

    rc = netsnmp_stash_cache_helper(sc_h, reginfo, &reqinfo, &req1);
    OK(rc == SNMP_ERR_NOERROR, "multi-varbind stash_cache MODE_GET succeeded");
    OK(req_vb1.type == ASN_INTEGER && req_vb1.val.integer != NULL &&
       *req_vb1.val.integer == 111,
       "first varbind in MODE_GET received its cached value (111)");
    OK(req_vb2.type == ASN_INTEGER && req_vb2.val.integer != NULL &&
       *req_vb2.val.integer == 222,
       "second varbind in MODE_GET received its cached value (222)");

    snmp_free_var_internals(&req_vb1);
    snmp_free_var_internals(&req_vb2);
    netsnmp_free_agent_data_sets(&reqinfo);
    netsnmp_oid_stash_free(&cinfo->cache,
                           (NetSNMPStashFreeNode *) snmp_free_var);
    SNMP_FREE(cinfo);
    cache->magic = NULL;
    netsnmp_cache_remove(cache);
    netsnmp_cache_free(cache);
    netsnmp_handler_free(sc_h);
    netsnmp_handler_registration_free(reginfo);
}
#endif

/*
 * 3. override_handler() tests (agent/mibgroup/utilities/override.c)
 */
#if defined(USING_UTILITIES_OVERRIDE_MODULE) && !defined(NETSNMP_NO_WRITE_SUPPORT)
{
    struct test_override_data {
        int    type;
        void  *value;
        size_t value_len;
        void  *set_space;
        size_t set_len;
    } *od;
    oid                           ov_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 44, 3, 0 };
    netsnmp_handler_registration *reginfo;
    netsnmp_mib_handler          *ov_h;
    netsnmp_agent_request_info    reqinfo;
    netsnmp_request_info          request;
    netsnmp_variable_list         vb;
    long                          bad_int = 77;

    od = SNMP_MALLOC_TYPEDEF(struct test_override_data);
    OK(od != NULL, "allocated override_data structure");
    od->type = ASN_OCTET_STR;
    od->value = strdup("initial");
    od->value_len = strlen("initial");

    reginfo = netsnmp_create_handler_registration("test_override", NULL,
                                                  ov_oid, OID_LENGTH(ov_oid),
                                                  HANDLER_CAN_RWRITE);
    ov_h = netsnmp_create_handler("override", override_handler);
    ov_h->myvoid = od;

    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    memset(&vb, 0, sizeof(vb));
    vb.name = ov_oid;
    vb.name_length = OID_LENGTH(ov_oid);
    vb.type = ASN_OCTET_STR;
    vb.val.string = (u_char *) "updated";
    vb.val_len = strlen("updated");
    request.requestvb = &vb;

    reqinfo.mode = MODE_SET_RESERVE1;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR, "override RESERVE1 succeeded");

    reqinfo.mode = MODE_SET_RESERVE2;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_NOERROR && od->set_space != NULL,
       "override RESERVE2 allocated set_space");

    reqinfo.mode = MODE_SET_ACTION;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(od->value_len == 7 && memcmp(od->value, "updated", 7) == 0,
       "override ACTION swapped in updated value");

    reqinfo.mode = MODE_SET_UNDO;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(od->value_len == 7 && memcmp(od->value, "initial", 7) == 0 &&
       od->set_space == NULL && od->set_len == 0,
       "override UNDO restored value and cleared set_space pointer");

    reqinfo.mode = MODE_SET_FREE;
    override_handler(ov_h, reginfo, &reqinfo, &request);

    /* Second failed SET (wrong type in RESERVE1 -> FREE) must not free od->value */
    memset(&request, 0, sizeof(request));
    vb.type = ASN_INTEGER;
    vb.val.integer = &bad_int;
    vb.val_len = sizeof(bad_int);
    request.requestvb = &vb;

    reqinfo.mode = MODE_SET_RESERVE1;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(request.status == SNMP_ERR_WRONGTYPE,
       "override RESERVE1 with wrong type sets SNMP_ERR_WRONGTYPE");

    reqinfo.mode = MODE_SET_FREE;
    request.processed = 0;
    override_handler(ov_h, reginfo, &reqinfo, &request);
    OK(od->value != NULL && od->value_len == 7 &&
       memcmp(od->value, "initial", 7) == 0,
       "override value remains intact after subsequent failed SET FREE");

    SNMP_FREE(od->value);
    SNMP_FREE(od->set_space);
    SNMP_FREE(od);
    netsnmp_handler_free(ov_h);
    netsnmp_handler_registration_free(reginfo);
}
#endif

/*
 * 4. netsnmp_iquery_session() NULL secName test (agent/mibgroup/utilities/iquery.c)
 */
#if defined(USING_UTILITIES_IQUERY_MODULE) && !defined(NETSNMP_FEATURE_REMOVE_IQUERY)
{
    netsnmp_session *ss;

    ss = netsnmp_iquery_session(NULL, SNMP_VERSION_3, SNMP_SEC_MODEL_USM,
                                SNMP_SEC_LEVEL_NOAUTH, NULL, 0);
    OK(ss == NULL, "netsnmp_iquery_session(NULL, ...) returns NULL without crashing");
}
#endif

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
