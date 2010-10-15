/* HEADER Testing SNMP handler registration */

static oid Oid[] = { 1, 3, 6, 1, 3, 327 }; /* experimental.327 */
netsnmp_handler_registration *handler, *handler2;
netsnmp_mib_handler *dh;

init_snmp("snmp");

handler = netsnmp_create_handler_registration("experimental.327", NULL,
	Oid, OID_LENGTH(Oid), HANDLER_CAN_RWRITE);
OK(handler != NULL, "Handler creation.");
handler->handler->myvoid = calloc(1, sizeof(netsnmp_cache));
handler->handler->data_clone = (void *(*)(void *))netsnmp_cache_clone;
handler->handler->data_free = (void(*)(void *))netsnmp_cache_free;

OK(netsnmp_register_instance(handler) == MIB_REGISTERED_OK,
   "MIB registration.");

handler2 = netsnmp_create_handler_registration("experimental.327", NULL,
        Oid, OID_LENGTH(Oid), HANDLER_CAN_RWRITE);
OK(handler2 != NULL, "Second registration");

OK(netsnmp_register_instance(handler2) == MIB_DUPLICATE_REGISTRATION,
   "Duplicate MIB registration.");

dh = netsnmp_handler_dup(handler->handler);
OK(dh, "Handler duplication.");

OK(netsnmp_unregister_handler(handler) == SNMPERR_SUCCESS,
   "Handler unregistration.");

netsnmp_handler_free(dh);
OK(TRUE, "Freeing duplicate handler");

snmp_shutdown("snmp");
