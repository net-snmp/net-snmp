/* HEADER Testing SNMP handler registration */

static oid Oid[] = { 1, 3, 6, 1, 3, 327 }; /* experimental.327 */
netsnmp_handler_registration *handler;
netsnmp_mib_handler *dh = NULL;

init_snmp("snmp");

handler = netsnmp_create_handler_registration("experimental.327", NULL,
	Oid, OID_LENGTH(Oid), HANDLER_CAN_RWRITE);
OK(handler != NULL, "Handler creation.");
handler->handler->myvoid = malloc(329);
handler->handler->data_free = free;

OK(netsnmp_register_instance(handler) == MIB_REGISTERED_OK,
   "MIB registration.");

#if 0
dh = netsnmp_handler_dup(handler->handler);
OK(dh, "Handler duplication.");
#endif

OK(netsnmp_unregister_handler(handler) == SNMPERR_SUCCESS,
   "Handler unregistration.");

netsnmp_handler_free(dh);
OK(TRUE, "Freeing duplicate handler");

snmp_shutdown("snmp");
