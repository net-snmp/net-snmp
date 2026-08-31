/* HEADER Testing convert_v2pdu_to_v1() bounds checks and conversions */

static const oid sysuptime_name[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
static const oid snmptrap_name[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static const oid snmptrapenterprise_name[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0 };
static const oid agentaddr_name[] = { 1, 3, 6, 1, 6, 3, 18, 1, 3, 0 };

static const oid cold_start_val[] = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 1 };
static const oid link_down_val[] = { 1, 3, 6, 1, 6, 3, 1, 1, 5, 3 };
static const oid trap_prefix_val[] = { 1, 3, 6, 1, 6, 3, 1, 1, 5 };
static const oid enterprise_trap_val[] = { 1, 3, 6, 1, 4, 1, 8072, 2, 1, 0, 1 };
static const oid enterprise_trap_no_zero[] = { 1, 3, 6, 1, 4, 1, 8072, 2, 1, 1 };
static const oid short_oid_1[] = { 1 };
static const oid short_oid_2_zero[] = { 0, 0 };
static const oid short_oid_2_nonzero[] = { 1, 2 };
static const oid custom_enterprise[] = { 1, 3, 6, 1, 4, 1, 8072 };

netsnmp_pdu *v2pdu;
netsnmp_pdu *v1pdu;
netsnmp_variable_list *trap_vars;
u_long uptime_val = 12345;
u_char ip_addr[4] = { 10, 0, 0, 1 };
u_char bad_ip_addr[2] = { 10, 0 };
struct counter64 c64_val = { 0, 100 };

/* Test 1: Standard coldStart trap */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)cold_start_val, sizeof(cold_start_val));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "coldStart conversion succeeded");
if (v1pdu) {
    OK(v1pdu->trap_type == SNMP_TRAP_COLDSTART, "trap_type is COLDSTART");
    OK(v1pdu->specific_type == 0, "specific_type is 0");
    OK(v1pdu->time == uptime_val, "time matches uptime");
    OK(v1pdu->enterprise != NULL && v1pdu->enterprise_length == OID_LENGTH(trap_prefix_val),
       "default enterprise set to trap_prefix");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 2: Standard trap with explicit snmpTrapEnterprise.0 */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)link_down_val, sizeof(link_down_val));
snmp_pdu_add_variable(v2pdu, snmptrapenterprise_name, OID_LENGTH(snmptrapenterprise_name),
                      ASN_OBJECT_ID, (u_char *)custom_enterprise, sizeof(custom_enterprise));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "linkDown conversion succeeded");
if (v1pdu) {
    OK(v1pdu->trap_type == SNMP_TRAP_LINKDOWN, "trap_type is LINKDOWN");
    OK(v1pdu->enterprise_length == OID_LENGTH(custom_enterprise) &&
       snmp_oid_compare(v1pdu->enterprise, v1pdu->enterprise_length,
                        custom_enterprise, OID_LENGTH(custom_enterprise)) == 0,
       "enterprise matches snmpTrapEnterprise");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 3: Enterprise-specific trap (with .0) */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)enterprise_trap_val, sizeof(enterprise_trap_val));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "enterprise-specific trap conversion succeeded");
if (v1pdu) {
    OK(v1pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC, "trap_type is ENTERPRISESPECIFIC");
    OK(v1pdu->specific_type == 1, "specific_type is 1");
    OK(v1pdu->enterprise_length == 9, "enterprise length is 9");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 4: Enterprise-specific trap (without .0) */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)enterprise_trap_no_zero, sizeof(enterprise_trap_no_zero));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "enterprise-specific trap without 0 conversion succeeded");
if (v1pdu) {
    OK(v1pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC, "trap_type is ENTERPRISESPECIFIC");
    OK(v1pdu->specific_type == 1, "specific_type is 1");
    OK(v1pdu->enterprise_length == 9, "enterprise length is 9");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 5: PoC from issue 1103: snmpTrapOID.0 equals trap_prefix (length 9) */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)trap_prefix_val, sizeof(trap_prefix_val));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "PoC trap_prefix conversion succeeded without overflow");
if (v1pdu) {
    OK(v1pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC, "trap_type is ENTERPRISESPECIFIC");
    OK(v1pdu->specific_type == 5, "specific_type is 5");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 6: Short OID length 1 rejected */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)short_oid_1, sizeof(short_oid_1));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu == NULL, "short OID length 1 correctly rejected");
snmp_free_pdu(v2pdu);

/* Test 7: Short OID 0.0 rejected */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)short_oid_2_zero, sizeof(short_oid_2_zero));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu == NULL, "short OID 0.0 correctly rejected");
snmp_free_pdu(v2pdu);

/* Test 8: Short OID 1.2 accepted */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)short_oid_2_nonzero, sizeof(short_oid_2_nonzero));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "short OID 1.2 conversion succeeded");
if (v1pdu) {
    OK(v1pdu->specific_type == 2, "specific_type is 2");
    OK(v1pdu->enterprise_length == 1, "enterprise length is 1");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 9: Valid agent address */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)cold_start_val, sizeof(cold_start_val));
snmp_pdu_add_variable(v2pdu, agentaddr_name, OID_LENGTH(agentaddr_name),
                      ASN_IPADDRESS, ip_addr, sizeof(ip_addr));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "trap with valid agent address succeeded");
if (v1pdu) {
    OK(memcmp(v1pdu->agent_addr, ip_addr, 4) == 0, "agent_addr set correctly");
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 10: Invalid short agent address */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)cold_start_val, sizeof(cold_start_val));
snmp_pdu_add_variable(v2pdu, agentaddr_name, OID_LENGTH(agentaddr_name),
                      ASN_IPADDRESS, bad_ip_addr, sizeof(bad_ip_addr));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu != NULL, "trap with short agent address handled safely");
if (v1pdu) {
    snmp_free_pdu(v1pdu);
}
snmp_free_pdu(v2pdu);

/* Test 11: Counter64 rejected */
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_pdu_add_variable(v2pdu, snmptrap_name, OID_LENGTH(snmptrap_name),
                      ASN_OBJECT_ID, (u_char *)cold_start_val, sizeof(cold_start_val));
snmp_pdu_add_variable(v2pdu, sysuptime_name, OID_LENGTH(sysuptime_name),
                      ASN_COUNTER64, (u_char *)&c64_val, sizeof(c64_val));
v1pdu = convert_v2pdu_to_v1(v2pdu);
OK(v1pdu == NULL, "Counter64 trap correctly rejected");
snmp_free_pdu(v2pdu);

/* Test 12: NULL and empty PDU checks */
OK(convert_v2pdu_to_v1(NULL) == NULL, "NULL PDU rejected");
v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
OK(convert_v2pdu_to_v1(v2pdu) == NULL, "Empty PDU rejected");
snmp_free_pdu(v2pdu);

/* Test 13: End-to-end path via send_enterprise_trap_vars (issue 1103 trigger) */
trap_vars = NULL;
snmp_varlist_add_variable(&trap_vars, snmptrap_name, OID_LENGTH(snmptrap_name),
                          ASN_OBJECT_ID, (u_char *)trap_prefix_val, sizeof(trap_prefix_val));
send_enterprise_trap_vars(-1, 0, custom_enterprise, OID_LENGTH(custom_enterprise), trap_vars);
snmp_free_varbind(trap_vars);
OK(TRUE, "send_enterprise_trap_vars with issue 1103 input completed without crash");

/* Test 14: End-to-end path via send_enterprise_trap_vars with short OID */
trap_vars = NULL;
snmp_varlist_add_variable(&trap_vars, snmptrap_name, OID_LENGTH(snmptrap_name),
                          ASN_OBJECT_ID, (u_char *)short_oid_1, sizeof(short_oid_1));
send_enterprise_trap_vars(-1, 0, custom_enterprise, OID_LENGTH(custom_enterprise), trap_vars);
snmp_free_varbind(trap_vars);
OK(TRUE, "send_enterprise_trap_vars with short OID completed without crash");

/* Test 15: End-to-end path via send_enterprise_trap_vars with sysUptime + trap_prefix */
trap_vars = NULL;
snmp_varlist_add_variable(&trap_vars, sysuptime_name, OID_LENGTH(sysuptime_name),
                          ASN_TIMETICKS, (u_char *)&uptime_val, sizeof(uptime_val));
snmp_varlist_add_variable(&trap_vars, snmptrap_name, OID_LENGTH(snmptrap_name),
                          ASN_OBJECT_ID, (u_char *)trap_prefix_val, sizeof(trap_prefix_val));
send_enterprise_trap_vars(-1, 0, custom_enterprise, OID_LENGTH(custom_enterprise), trap_vars);
snmp_free_varbind(trap_vars);
OK(TRUE, "send_enterprise_trap_vars with sysUptime and trap_prefix completed without crash");
