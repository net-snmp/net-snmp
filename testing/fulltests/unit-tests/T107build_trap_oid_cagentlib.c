/* HEADER Testing netsnmp_build_trap_oid() enterprise_length bounds check
 *
 * Expected SUCCESSes for all tests:    2
 */

netsnmp_pdu *pdu;
oid t_oid[MAX_OID_LEN + 2];
size_t t_oid_len;
int rc;

/* enterprise_length > MAX_OID_LEN must be rejected */
pdu = snmp_pdu_create(SNMP_MSG_TRAP);
pdu->trap_type = SNMP_TRAP_ENTERPRISESPECIFIC;
pdu->enterprise_length = MAX_OID_LEN + 1;
pdu->enterprise = calloc(pdu->enterprise_length, sizeof(oid));
t_oid_len = sizeof(t_oid) / sizeof(t_oid[0]);
rc = netsnmp_build_trap_oid(pdu, t_oid, &t_oid_len);
OKF(rc == SNMPERR_LONG_OID,
    ("enterprise_length %zu > MAX_OID_LEN should return SNMPERR_LONG_OID, got %d",
     pdu->enterprise_length, rc));
snmp_free_pdu(pdu);

/* enterprise_length == MAX_OID_LEN with sufficient buffer must succeed */
pdu = snmp_pdu_create(SNMP_MSG_TRAP);
pdu->trap_type = SNMP_TRAP_ENTERPRISESPECIFIC;
pdu->enterprise_length = MAX_OID_LEN;
pdu->enterprise = calloc(pdu->enterprise_length, sizeof(oid));
t_oid_len = MAX_OID_LEN + 2;
rc = netsnmp_build_trap_oid(pdu, t_oid, &t_oid_len);
OKF(rc == SNMPERR_SUCCESS,
    ("enterprise_length %zu == MAX_OID_LEN should return SNMPERR_SUCCESS, got %d",
     pdu->enterprise_length, rc));
snmp_free_pdu(pdu);
