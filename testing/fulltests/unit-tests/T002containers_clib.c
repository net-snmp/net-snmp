/* HEADER Testing the container API */

netsnmp_container *container;
void *p;

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

OK(snmp_call_callbacks(-1, 0, NULL) == SNMPERR_GENERR &&
   snmp_count_callbacks(0, -1) == SNMPERR_GENERR &&
   snmp_callback_available(-1, -1) == SNMPERR_GENERR &&
   snmp_unregister_callback(-1, 0, NULL, NULL, 0) == SNMPERR_GENERR &&
   snmp_callback_list(-1, 0) == NULL &&
   netsnmp_callback_clear_client_arg(NULL, -1, 0) == SNMPERR_GENERR,
   "callback functions reject negative major and minor indices");

snmp_shutdown("container-test");
