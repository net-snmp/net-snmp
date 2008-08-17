#ifndef SCTP_TABLES_H
#define SCTP_TABLES_H
config_require(sctp-mib/sctpTables_common)
config_require(sctp-mib/sctpAssocRemAddrTable)
config_require(sctp-mib/sctpAssocLocalAddrTable)
config_require(sctp-mib/sctpLookupLocalPortTable)
config_require(sctp-mib/sctpLookupRemPortTable)
config_require(sctp-mib/sctpLookupRemHostNameTable)
config_require(sctp-mib/sctpLookupRemPrimIPAddrTable)
config_require(sctp-mib/sctpLookupRemIPAddrTable)
/*
 * this one must be last to ensure proper initialization ordering 
 */
config_require(sctp-mib/sctpAssocTable)
#if defined( linux )
config_require(sctp-mib/sctpTables_linux)
#else
/*
* couldn't determine the correct file!
* require a bogus file to generate an error.
*/
config_require(sctp-mib/tables-unknown-arch)
#endif
#endif                          /* SCTP_TABLES_H */
