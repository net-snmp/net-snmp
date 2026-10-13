/* HEADER Testing table_dataset */
#include <net-snmp/net-snmp-features.h>

/*
 * Note: the primary purpose of this unit test is to verify whether all memory
 * that is allocated for storing a table dataset is freed properly. Feel free
 * to extend this unit test such that it tests more of the table dataset code.
 */

enum { COL3 = 2, COL4 = 3, COL5 = 4, };

static const oid Oid[] = { 1, 3, 6, 1, 3, 277 };
netsnmp_table_data_set* tds;
netsnmp_handler_registration* th;
netsnmp_table_row* row;
int32_t ival;
int32_t i, j;

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");

tds = netsnmp_create_table_data_set("table_dataset unit-test");
OK(tds, "table data set creation");

netsnmp_table_dataset_add_index(tds, ASN_INTEGER);
netsnmp_table_dataset_add_index(tds, ASN_INTEGER);
netsnmp_table_set_add_default_row(tds, COL3, ASN_INTEGER,   FALSE, NULL, 0);
netsnmp_table_set_add_default_row(tds, COL4, ASN_COUNTER,   FALSE, NULL, 0);
netsnmp_table_set_add_default_row(tds, COL5, ASN_OCTET_STR, FALSE, NULL, 0);

th = netsnmp_create_handler_registration("unit-test handler", NULL, Oid,
                                         OID_LENGTH(Oid), HANDLER_CAN_RWRITE);
OK(th, "table handler registration");

OK(netsnmp_register_table_data_set(th, tds, NULL) == SNMPERR_SUCCESS,
   "table data set registration");

for (i = 1; i <= 2; i++) {
    for (j = 1; j <= 2; j++) {
        row = netsnmp_create_table_data_row();
        netsnmp_table_row_add_index(row, ASN_INTEGER, &i, sizeof(i));
        netsnmp_table_row_add_index(row, ASN_INTEGER, &j, sizeof(j));
        netsnmp_table_dataset_add_row(tds, row);

        ival = 10 * i + j;
        OK(netsnmp_set_row_column(row, COL3, ASN_INTEGER, &ival, sizeof(ival))
           == SNMPERR_SUCCESS, "set INTEGER column");
        OK(netsnmp_set_row_column(row, COL5, ASN_OCTET_STR, "test",
                                  sizeof("test") - 1)
           == SNMPERR_SUCCESS, "set OCTET_STR column");
    }
}

#ifndef NETSNMP_NO_WRITE_SUPPORT
{
    /*
     * Verify that netsnmp_table_data_set_helper_handler() rejects an invalid
     * ASN.1 type on a RowStatus column with SNMP_ERR_WRONGTYPE rather than
     * dereferencing val.integer as an integer pointer.
     */
    netsnmp_agent_request_info reqinfo;
    netsnmp_request_info       request;
    netsnmp_table_request_info tbl_req;
    netsnmp_variable_list      vb;
    oid                        req_oid[] = { 1, 3, 6, 1, 3, 277, 1, COL3, 99, 99 };

    tds->rowstatus_column = COL3;
    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    memset(&tbl_req, 0, sizeof(tbl_req));
    memset(&vb, 0, sizeof(vb));

    reqinfo.mode = MODE_SET_RESERVE1;
    vb.name = req_oid;
    vb.name_length = OID_LENGTH(req_oid);
    vb.type = ASN_OCTET_STR;
    vb.val.string = (u_char *) "bad";
    vb.val_len = 3;
    request.requestvb = &vb;
    tbl_req.colnum = COL3;
    netsnmp_request_add_list_data(
        &request, netsnmp_create_data_list(TABLE_HANDLER_NAME, &tbl_req, NULL));

    netsnmp_mib_handler *tds_h = netsnmp_get_table_data_set_handler(tds);
    netsnmp_table_data_set_helper_handler(tds_h, th, &reqinfo, &request);
    netsnmp_handler_free(tds_h);
    OKF(request.status == SNMP_ERR_WRONGTYPE,
        ("RowStatus SET with ASN_OCTET_STR status (%d == %d)",
         request.status, SNMP_ERR_WRONGTYPE));
    netsnmp_free_request_data_sets(&request);
    netsnmp_free_agent_data_sets(&reqinfo);
}

{
    /*
     * Verify multi-varbind SET handling in netsnmp_table_data_set_helper_handler():
     * 1) suffix and suffix_len are computed per request->requestvb rather than
     *    requests->requestvb, and errors on request2 set request2.status rather
     *    than only request.status.
     * 2) a short OID (< rootoid_len + 2) on request2 is rejected with
     *    SNMP_ERR_NOCREATION on request2.
     */
    netsnmp_agent_request_info reqinfo;
    netsnmp_request_info       request, request2;
    netsnmp_table_request_info tbl_req1, tbl_req2;
    netsnmp_variable_list      vb1, vb2;
    oid                        oid1[] = { 1, 3, 6, 1, 3, 277, 1, COL5, 1, 1 };
    oid                        oid2[] = { 1, 3, 6, 1, 3, 277, 1, COL5, 1, 2 };
    oid                        short_oid[] = { 1, 3, 6, 1, 3, 277, 1 };
    oid                        suffix1[] = { 1, 1 };
    oid                        suffix2[] = { 1, 2 };
    netsnmp_table_row         *row1, *row2;
    netsnmp_oid_stash_node   **stashp;
    long                       bad_int = 123;
    netsnmp_mib_handler       *tds_h;

    row1 = netsnmp_table_data_get_from_oid(tds->table, suffix1,
                                           OID_LENGTH(suffix1));
    row2 = netsnmp_table_data_get_from_oid(tds->table, suffix2,
                                           OID_LENGTH(suffix2));
    OK(row1 != NULL && row2 != NULL, "existing rows (1,1) and (1,2) found");
    netsnmp_mark_row_column_writable(row1, COL5, 1);
    netsnmp_mark_row_column_writable(row2, COL5, 1);

    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    memset(&request2, 0, sizeof(request2));
    memset(&tbl_req1, 0, sizeof(tbl_req1));
    memset(&tbl_req2, 0, sizeof(tbl_req2));
    memset(&vb1, 0, sizeof(vb1));
    memset(&vb2, 0, sizeof(vb2));

    reqinfo.mode = MODE_SET_RESERVE1;
    request.next = &request2;

    vb1.name = oid1;
    vb1.name_length = OID_LENGTH(oid1);
    vb1.type = ASN_OCTET_STR;
    vb1.val.string = (u_char *) "ok";
    vb1.val_len = 2;
    request.requestvb = &vb1;
    tbl_req1.colnum = COL5;
    netsnmp_request_add_list_data(
        &request, netsnmp_create_data_list(TABLE_HANDLER_NAME, &tbl_req1, NULL));
    netsnmp_request_add_list_data(
        &request, netsnmp_create_data_list(TABLE_DATA_NAME, row1, NULL));

    vb2.name = oid2;
    vb2.name_length = OID_LENGTH(oid2);
    vb2.type = ASN_INTEGER;
    vb2.val.integer = &bad_int;
    vb2.val_len = sizeof(bad_int);
    request2.requestvb = &vb2;
    tbl_req2.colnum = COL5;
    netsnmp_request_add_list_data(
        &request2, netsnmp_create_data_list(TABLE_HANDLER_NAME, &tbl_req2, NULL));
    netsnmp_request_add_list_data(
        &request2, netsnmp_create_data_list(TABLE_DATA_NAME, row2, NULL));

    tds_h = netsnmp_get_table_data_set_handler(tds);
    netsnmp_table_data_set_helper_handler(tds_h, th, &reqinfo, &request);
    OKF(request.status == SNMP_ERR_NOERROR,
        ("first varbind status unchanged (%d == %d)",
         request.status, SNMP_ERR_NOERROR));
    OKF(request2.status == SNMP_ERR_WRONGTYPE,
        ("second varbind status set to SNMP_ERR_WRONGTYPE (%d == %d)",
         request2.status, SNMP_ERR_WRONGTYPE));

    stashp = netsnmp_table_dataset_get_or_create_stash(&reqinfo, tds, &tbl_req1);
    OK(stashp != NULL &&
       netsnmp_oid_stash_get_data(*stashp, suffix1, OID_LENGTH(suffix1)) != NULL &&
       netsnmp_oid_stash_get_data(*stashp, suffix2, OID_LENGTH(suffix2)) != NULL &&
       netsnmp_oid_stash_get_data(*stashp, suffix1, OID_LENGTH(suffix1)) !=
       netsnmp_oid_stash_get_data(*stashp, suffix2, OID_LENGTH(suffix2)),
       "per-varbind suffix stashes distinct row entries for request1 and request2");

    reqinfo.mode = MODE_SET_FREE;
    request.processed = 0;
    request2.processed = 0;
    netsnmp_table_data_set_helper_handler(tds_h, th, &reqinfo, &request);
    netsnmp_free_request_data_sets(&request);
    netsnmp_free_request_data_sets(&request2);
    netsnmp_free_agent_data_sets(&reqinfo);

    /* Test short OID on request2 in a multi-varbind SET */
    memset(&reqinfo, 0, sizeof(reqinfo));
    memset(&request, 0, sizeof(request));
    memset(&request2, 0, sizeof(request2));
    reqinfo.mode = MODE_SET_RESERVE1;
    request.next = &request2;
    request.requestvb = &vb1;
    netsnmp_request_add_list_data(
        &request, netsnmp_create_data_list(TABLE_HANDLER_NAME, &tbl_req1, NULL));
    netsnmp_request_add_list_data(
        &request, netsnmp_create_data_list(TABLE_DATA_NAME, row1, NULL));

    vb2.name = short_oid;
    vb2.name_length = OID_LENGTH(short_oid);
    vb2.type = ASN_OCTET_STR;
    vb2.val.string = (u_char *) "ok";
    vb2.val_len = 2;
    request2.requestvb = &vb2;
    netsnmp_request_add_list_data(
        &request2, netsnmp_create_data_list(TABLE_HANDLER_NAME, &tbl_req2, NULL));

    netsnmp_table_data_set_helper_handler(tds_h, th, &reqinfo, &request);
    OKF(request.status == SNMP_ERR_NOERROR &&
        request2.status == SNMP_ERR_NOCREATION,
        ("short OID on second varbind rejected with SNMP_ERR_NOCREATION (%d, %d)",
         request.status, request2.status));
    reqinfo.mode = MODE_SET_FREE;
    request.processed = 0;
    request2.processed = 0;
    netsnmp_table_data_set_helper_handler(tds_h, th, &reqinfo, &request);
    netsnmp_handler_free(tds_h);
    netsnmp_free_request_data_sets(&request);
    netsnmp_free_request_data_sets(&request2);
    netsnmp_free_agent_data_sets(&reqinfo);
}
#endif /* !NETSNMP_NO_WRITE_SUPPORT */

#ifndef NETSNMP_FEATURE_REMOVE_TABLE_DATA_CLONE_ROW
{
    /*
     * Exercise netsnmp_table_data_clone_row() on a row with multiple index
     * varbinds and verify the cloned row and its indexes are properly
     * duplicated and freed via netsnmp_table_data_delete_row().
     */
    int32_t            idx1 = 2, idx2 = 1;
    netsnmp_table_row *orig_row, *cloned_row;

    orig_row = netsnmp_create_table_data_row();
    OK(orig_row != NULL, "created multi-index row (2,1) to clone");
    netsnmp_table_row_add_index(orig_row, ASN_INTEGER, &idx1, sizeof(idx1));
    netsnmp_table_row_add_index(orig_row, ASN_INTEGER, &idx2, sizeof(idx2));
    netsnmp_table_data_generate_index_oid(orig_row);

    cloned_row = netsnmp_table_data_clone_row(orig_row);
    OK(cloned_row != NULL && cloned_row != orig_row,
       "netsnmp_table_data_clone_row returns distinct row");
    OK(cloned_row->indexes != NULL &&
       cloned_row->indexes != orig_row->indexes &&
       cloned_row->indexes->next_variable != NULL &&
       cloned_row->indexes->next_variable != orig_row->indexes->next_variable &&
       *cloned_row->indexes->val.integer == 2 &&
       *cloned_row->indexes->next_variable->val.integer == 1,
       "cloned row duplicates full multi-varbind index chain");
    OK(cloned_row->index_oid != NULL &&
       cloned_row->index_oid != orig_row->index_oid &&
       cloned_row->index_oid_len == orig_row->index_oid_len &&
       snmp_oid_compare(cloned_row->index_oid, cloned_row->index_oid_len,
                        orig_row->index_oid, orig_row->index_oid_len) == 0,
       "cloned row duplicates index_oid");
    netsnmp_table_data_delete_row(cloned_row);
    netsnmp_table_data_delete_row(orig_row);
    OK(netsnmp_table_data_clone_row(NULL) == NULL,
       "netsnmp_table_data_clone_row(NULL) returns NULL");
}
#endif /* !NETSNMP_FEATURE_REMOVE_TABLE_DATA_CLONE_ROW */

netsnmp_delete_table_data_set(tds);

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;

OK(TRUE, "done");
