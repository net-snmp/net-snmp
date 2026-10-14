/* HEADER netsnmp_check_vb_indexes_max_size() */
netsnmp_variable_list *indexes = NULL;
char name[33];
oid number = 1;

memset(name, 'a', sizeof(name));

/* Two string indexes and an integer index, all within 32 bytes. */
snmp_varlist_add_variable(&indexes, NULL, 0, ASN_OCTET_STR,
                          (u_char *)name, 32);
snmp_varlist_add_variable(&indexes, NULL, 0, ASN_PRIV_IMPLIED_OCTET_STR,
                          (u_char *)name, 0);
snmp_varlist_add_variable(&indexes, NULL, 0, ASN_UNSIGNED,
                          (u_char *)&number, sizeof(number));
OKF(netsnmp_check_vb_indexes_max_size(indexes, 32) == SNMP_ERR_NOERROR,
    ("string indexes of 32 and 0 bytes fit a 32 byte limit"));

/* The integer index is not a string: its length does not count. */
OKF(netsnmp_check_vb_indexes_max_size(indexes->next_variable->next_variable,
                                      0) == SNMP_ERR_NOERROR,
    ("an integer index is not checked against the string limit"));

/* First string index one byte too long. */
snmp_set_var_value(indexes, name, 33);
OKF(netsnmp_check_vb_indexes_max_size(indexes, 32) == SNMP_ERR_NOCREATION,
    ("a 33 byte first index is rejected with noCreation"));

/* Second (implied) string index too long. */
snmp_set_var_value(indexes, name, 1);
snmp_set_var_value(indexes->next_variable, name, 33);
OKF(netsnmp_check_vb_indexes_max_size(indexes, 32) == SNMP_ERR_NOCREATION,
    ("a 33 byte implied index is rejected with noCreation"));

OKF(netsnmp_check_vb_indexes_max_size(NULL, 32) == SNMP_ERR_NOERROR,
    ("a table without indexes passes"));

snmp_free_varbind(indexes);
