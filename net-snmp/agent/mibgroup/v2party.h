/* module to include the modules relavent to the party mib(s) */
config_require(acl_vars)
config_require(party_vars)
config_require(view_vars)
config_require(context_vars)
config_require(alarm)
config_require(event)
config_add_mib(SNMPv2-PARTY-MIB SNMPv2-M2M-MIB)
