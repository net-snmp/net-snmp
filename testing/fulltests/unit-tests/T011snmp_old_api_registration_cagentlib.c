/* HEADER Testing SNMP handler registration via the old API */

static oid Oid[] = { 1, 3, 6, 1, 3, 327 }; /* experimental.327 */
static oid OversizedOid[UCD_REGISTRY_OID_MAX_LEN + 1];
struct variable var_array[] = {
    { 0, 0/*type*/, 0/*acl*/, NULL/*findVar*/, 7, { 1, 3, 6, 1, 3, 327, 1 } },
    { 0, 0/*type*/, 0/*acl*/, NULL/*findVar*/, 7, { 1, 3, 6, 1, 3, 327, 2 } },
    { 0, 0/*type*/, 0/*acl*/, NULL/*findVar*/, 7, { 1, 3, 6, 1, 3, 327, 3 } },
};
netsnmp_session *sess;
int res;

init_snmp("snmp");

sess = calloc(1, sizeof(*sess));
snmp_sess_init(sess);

res = 
netsnmp_register_old_api("exp.327.a",
                         var_array,
                         sizeof(var_array[0]),
                         sizeof(var_array)/sizeof(var_array[0]),
                         Oid,
                         sizeof(Oid)/sizeof(Oid[0]),
                         2, /* priority */
                         0, /* range_subid */
                         0, /* range_ubound */
                         sess,
                         "context", 5/*timeout*/, 0/*flags - ignored*/);
OK(res == SNMPERR_SUCCESS, "Handler registration (1).");

/* Verify that duplicate registration does not cause any havoc. */
res = 
netsnmp_register_old_api("exp.327.b",
                         var_array,
                         sizeof(var_array[0]),
                         sizeof(var_array)/sizeof(var_array[0]),
                         Oid,
                         sizeof(Oid)/sizeof(Oid[0]),
                         2, /* priority */
                         0, /* range_subid */
                         0, /* range_ubound */
                         sess,
                         "context", 5/*timeout*/, 0/*flags - ignored*/);
OK(res == MIB_DUPLICATE_REGISTRATION, "Handler registration (2).");

memset(OversizedOid, 1, sizeof(OversizedOid));
res = netsnmp_register_old_api("oversized",
                               var_array,
                               sizeof(var_array[0]),
                               sizeof(var_array)/sizeof(var_array[0]),
                               OversizedOid,
                               OID_LENGTH(OversizedOid),
                               2, 0, 0, sess, "context", 5, 0);
OK(res == MIB_REGISTRATION_FAILED,
   "An OID larger than the registry representation is rejected.");

snmp_shutdown("snmp");
free(sess);
