/*
 * udp_endpoint data access header
 *
 * $Id$
 */
/**---------------------------------------------------------------------*/
/*
 * configure required files
 *
 * Notes:
 *
 * 1) prefer functionality over platform, where possible. If a method
 *    is available for multiple platforms, test that first. That way
 *    when a new platform is ported, it won't need a new test here.
 *
 * 2) don't do detail requirements here. If, for example,
 *    HPUX11 had different reuirements than other HPUX, that should
 *    be handled in the *_hpux.h header file.
 */
config_require(udp-mib/data_access/udp_endpoint_common)
#if defined( linux )
config_require(udp-mib/data_access/udp_endpoint_linux)
config_require(util_funcs/get_pid_from_inode)
#elif defined( solaris2 )
config_require(udp-mib/data_access/udp_endpoint_solaris2)
#else
#   define NETSNMP_UDP_ENDPOINT_COMMON_ONLY
#endif
