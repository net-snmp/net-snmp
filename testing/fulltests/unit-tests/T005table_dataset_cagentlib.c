/* HEADER Testing table_dataset */

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

netsnmp_delete_table_data_set(tds);

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;

OK(TRUE, "done");
