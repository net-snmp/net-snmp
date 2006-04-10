/*
 * module to include the ifTable implementation modules  
 */
/*
 */
#if defined( linux ) || defined( openbsd3 )
config_require(if-mib/ifTable)
#else
config_require(mibII/interfaces)
#endif
