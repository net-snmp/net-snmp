/* HEADER Testing netsnmp_oid_stash APIs (oid_stash.c) */
    int run_t042(void);
    int rc = run_t042();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <net-snmp/net-snmp-features.h>
#include <net-snmp/library/oid_stash.h>

#ifndef NETSNMP_FEATURE_REMOVE_OID_STASH_ALL
static int
t042_stash_dump_cb(char *line, size_t len,
                   void *node_data, netsnmp_oid_stash_node *node)
{
    snprintf(line, len, "%s", (const char *)node_data);
    return SNMP_ERR_NOERROR;
}
#endif

int
run_t042(void)
{
#ifndef NETSNMP_FEATURE_REMOVE_OID_STASH_ALL
    void oid_stash_dump(netsnmp_oid_stash_node *root, char *prefix);
    netsnmp_oid_stash_node *root = NULL;
    netsnmp_oid_stash_node *next_node;
    /* Choose OIDs that both spread across depth and collide in the same hash bucket */
    oid oid1[] = { 1, 3, 6, 1, 4, 1, 10 };
    oid oid2[] = { 1, 3, 6, 1, 4, 1, 10 + OID_STASH_CHILDREN_SIZE };
    oid oid3[] = { 1, 3, 6, 1, 4, 1, 10 + 2 * OID_STASH_CHILDREN_SIZE };
    oid oid4[] = { 1, 3, 6, 1, 4, 1, 10, 1 };
    oid oid_prefix[] = { 1, 3, 6, 1, 4, 1 };
    int rc;

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T042oid_stash");

    rc = netsnmp_oid_stash_add_data(&root, oid1, OID_LENGTH(oid1),
                                    strdup("val1"));
    OK(rc == SNMPERR_SUCCESS && root != NULL,
       "netsnmp_oid_stash_add_data inserts oid1");

    rc = netsnmp_oid_stash_add_data(&root, oid2, OID_LENGTH(oid2),
                                    strdup("val2"));
    OK(rc == SNMPERR_SUCCESS,
       "netsnmp_oid_stash_add_data inserts colliding sibling oid2");

    rc = netsnmp_oid_stash_add_data(&root, oid3, OID_LENGTH(oid3),
                                    strdup("val3"));
    OK(rc == SNMPERR_SUCCESS,
       "netsnmp_oid_stash_add_data inserts second colliding sibling oid3");

    rc = netsnmp_oid_stash_add_data(&root, oid4, OID_LENGTH(oid4),
                                    strdup("val4"));
    OK(rc == SNMPERR_SUCCESS,
       "netsnmp_oid_stash_add_data inserts child oid4");

    /* Duplicate insertion returns SNMPERR_GENERR */
    rc = netsnmp_oid_stash_add_data(&root, oid1, OID_LENGTH(oid1), "dup");
    OK(rc == SNMPERR_GENERR,
       "netsnmp_oid_stash_add_data rejects duplicate OID");

    OK(strcmp((const char *)netsnmp_oid_stash_get_data(root, oid1,
                                                       OID_LENGTH(oid1)),
              "val1") == 0 &&
       strcmp((const char *)netsnmp_oid_stash_get_data(root, oid2,
                                                       OID_LENGTH(oid2)),
              "val2") == 0 &&
       strcmp((const char *)netsnmp_oid_stash_get_data(root, oid3,
                                                       OID_LENGTH(oid3)),
              "val3") == 0 &&
       strcmp((const char *)netsnmp_oid_stash_get_data(root, oid4,
                                                       OID_LENGTH(oid4)),
              "val4") == 0,
       "netsnmp_oid_stash_get_data retrieves all stored values");

    next_node = netsnmp_oid_stash_getnext_node(root, oid_prefix,
                                               OID_LENGTH(oid_prefix));
    OK(next_node != NULL && next_node->thedata != NULL &&
       strcmp((const char *)next_node->thedata, "val1") == 0,
       "netsnmp_oid_stash_getnext_node finds first descendant");

    next_node = netsnmp_oid_stash_getnext_node(root, oid1, OID_LENGTH(oid1));
    OK(next_node != NULL && next_node->thedata != NULL &&
       strcmp((const char *)next_node->thedata, "val4") == 0,
       "netsnmp_oid_stash_getnext_node traverses child before siblings");

    next_node = netsnmp_oid_stash_getnext_node(root, oid4, OID_LENGTH(oid4));
    OK(next_node != NULL && next_node->thedata != NULL &&
       strcmp((const char *)next_node->thedata, "val2") == 0,
       "netsnmp_oid_stash_getnext_node traverses colliding sibling");

    /* Exercise netsnmp_oid_stash_store and oid_stash_dump */
    {
        oid store_prefix[MAX_OID_LEN];
#ifndef NETSNMP_FEATURE_REMOVE_OID_STASH_DUMP
        char prefix_str[] = "t042";
#endif
        netsnmp_oid_stash_store(root, "T042", t042_stash_dump_cb,
                                store_prefix, 0);
#ifndef NETSNMP_FEATURE_REMOVE_OID_STASH_DUMP
        oid_stash_dump(root, prefix_str);
#endif
        OK(1, "netsnmp_oid_stash_store and oid_stash_dump complete without error");
    }

    netsnmp_oid_stash_free(&root, free);
    OK(root == NULL, "netsnmp_oid_stash_free frees all nodes and sets root to NULL");

    snmp_shutdown("T042oid_stash");
#else
    OK(1, "skipped: oid_stash disabled");
#endif
