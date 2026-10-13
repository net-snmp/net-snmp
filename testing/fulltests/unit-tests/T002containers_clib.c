/* HEADER Testing the container API */
    int run_t002(void);
    int rc = run_t002();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <net-snmp/library/container_iterator.h>
#include <net-snmp/library/container_list_ssll.h>
#include <net-snmp/library/data_list.h>

static int
t002_iter_first(void *iterator_ctx, netsnmp_ref_void *loop_ctx,
                netsnmp_ref_void *key)
{
    int *val = (int *)iterator_ctx;
    if (val)
        *val = 1;
    loop_ctx->val = iterator_ctx;
    key->val = iterator_ctx;
    return SNMP_ERR_NOERROR;
}

static int
t002_iter_next(void *iterator_ctx, netsnmp_ref_void *loop_ctx,
               netsnmp_ref_void *key)
{
    loop_ctx->val = NULL;
    key->val = NULL;
    return SNMP_ENDOFMIBVIEW;
}

static int
t002_save_cb(char *buf, size_t len, void *datum)
{
    snprintf(buf, len, "%s", (const char *)datum);
    return SNMP_ERR_NOERROR;
}

static void *
t002_read_cb(char *buf, size_t len)
{
    return strdup(buf);
}

static void
t002_free_cb(void *datum)
{
    free(datum);
}

static netsnmp_data_list *t002_dlist = NULL;

int
run_t002(void)
{
netsnmp_container *container;
void *p;

netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
init_snmp("container-test");
container = netsnmp_container_find("fifo");
container->compare = netsnmp_str_compare;

CONTAINER_INSERT(container, "foo");
CONTAINER_INSERT(container, "bar");
CONTAINER_INSERT(container, "baz");

OK(CONTAINER_FIND(container, "bar") != NULL,
   "should be able to find the stored 'bar' string");

OK(CONTAINER_FIND(container, "foobar") == NULL,
   "shouldn't be able to find the (not) stored 'foobar' string");

OK(CONTAINER_SIZE(container) == 3,
   "container has the proper size for the elements we've added");

CONTAINER_REMOVE(container, "bar");

OK(CONTAINER_FIND(container, "bar") == NULL,
   "should no longer be able to find the (removed) 'bar' string");

OK(CONTAINER_SIZE(container) == 2,
   "container has the proper size for the elements after a removal");

{
    int rc;

    container->flags |= CONTAINER_KEY_ALLOW_DUPLICATES;
    CONTAINER_CHECK_OPTION(container, CONTAINER_KEY_ALLOW_DUPLICATES, rc);
    OK(rc != 0, "CONTAINER_CHECK_OPTION reports set option");
}

while ((p = CONTAINER_FIRST(container)))
  CONTAINER_REMOVE(container, p);
CONTAINER_FREE(container);

#ifndef NETSNMP_FEATURE_REMOVE_CONTAINER_ITERATOR
/* Test container_iterator with free_user_ctx == NULL */
{
    int user_ctx = 0;
    netsnmp_container *cit;

    cit = netsnmp_container_iterator_get(&user_ctx, netsnmp_str_compare,
                                         t002_iter_first, t002_iter_next,
                                         NULL, NULL, NULL, NULL,
                                         NULL /* free_user_ctx == NULL */, 1);
    OK(cit != NULL, "netsnmp_container_iterator_get succeeded");
    if (cit) {
        OK(CONTAINER_FIRST(cit) == &user_ctx,
           "CONTAINER_FIRST on iterator returns user_ctx");
        OK(CONTAINER_FREE(cit) == 0,
           "CONTAINER_FREE on iterator with NULL free_user_ctx succeeds");
    }
}
#endif

#ifndef NETSNMP_FEATURE_REMOVE_CONTAINER_LINKED_LIST
/* Test singly-linked list (ssll) sorted and unsorted operations */
{
    netsnmp_container *ssll = netsnmp_container_find("sorted_singly_linked_list");

    OK(ssll != NULL, "netsnmp_container_find sorted_singly_linked_list succeeded");
    if (ssll) {
        ssll->compare = netsnmp_str_compare;
        CONTAINER_INSERT(ssll, "charlie");
        CONTAINER_INSERT(ssll, "alpha");
        CONTAINER_INSERT(ssll, "bravo");
        OK(CONTAINER_SIZE(ssll) == 3 &&
           strcmp((const char *)CONTAINER_FIRST(ssll), "alpha") == 0,
           "sorted ssll orders elements correctly");
        OK(CONTAINER_FIND(ssll, "bravo") != NULL &&
           CONTAINER_NEXT(ssll, "alpha") != NULL,
           "sorted ssll find and next work");
        CONTAINER_REMOVE(ssll, "bravo");
        CONTAINER_REMOVE(ssll, "alpha");
        CONTAINER_REMOVE(ssll, "charlie");
        CONTAINER_FREE(ssll);
    }
}
#endif

/* Test data_list registration, save, read, and shutdown */
#ifndef NETSNMP_FEATURE_REMOVE_DATA_LIST
{
    char read_line[] = "\"mytag2\" myvalue2";

    netsnmp_add_list_data(&t002_dlist,
                          netsnmp_create_data_list("mytag",
                                                   strdup("myvalue"),
                                                   t002_free_cb));
    netsnmp_register_save_list(&t002_dlist, "container-test", "list1",
                               t002_save_cb, t002_read_cb, t002_free_cb);
    OK(netsnmp_save_all_data_callback(0, 0, NULL, NULL) == SNMP_ERR_NOERROR,
       "netsnmp_save_all_data_callback handles NULL clientarg");
    netsnmp_read_data_callback("list1", read_line);
    OK(netsnmp_get_list_data(t002_dlist, "mytag2") != NULL,
       "netsnmp_read_data_callback populates data_list");
    netsnmp_free_all_list_data(t002_dlist);
    t002_dlist = NULL;
}
#endif

OK(snmp_call_callbacks(-1, 0, NULL) == SNMPERR_GENERR &&
   snmp_count_callbacks(0, -1) == SNMPERR_GENERR &&
   snmp_callback_available(-1, -1) == SNMPERR_GENERR &&
   snmp_unregister_callback(-1, 0, NULL, NULL, 0) == SNMPERR_GENERR &&
#ifndef NETSNMP_FEATURE_REMOVE_CALLBACK_LIST
   snmp_callback_list(-1, 0) == NULL &&
#endif
   netsnmp_callback_clear_client_arg(NULL, -1, 0) == SNMPERR_GENERR,
   "callback functions reject negative major and minor indices");

#ifndef NETSNMP_FEATURE_REMOVE_USM_SCAPI
{
    size_t rand_sz = 16;
    u_char *rand_buf = malloc_random(&rand_sz);

    OK(rand_buf != NULL && rand_sz == 16,
       "malloc_random preserves requested byte count on success");
    free(rand_buf);
}
#endif

snmp_shutdown("container-test");
