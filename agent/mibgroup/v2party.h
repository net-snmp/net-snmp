/* module to include the modules relavent to the party mib(s) */
config_require(v2party/acl_vars)
config_require(v2party/party_vars)
config_require(v2party/view_vars)
config_require(v2party/context_vars)
config_require(v2party/alarm)
config_require(v2party/event)
config_add_mib(SNMPv2-PARTY-MIB SNMPv2-M2M-MIB)

void init_v2party __P((void));
