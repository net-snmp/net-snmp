/*
 * route data access header
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
config_require(ip-forward-mib/data_access/route_common)
#if defined( linux )
config_require(ip-forward-mib/data_access/route_linux);
#elif defined ( solaris )
config_require(ip-forward-mib/data_access/route_solaris);
#elif defined ( hpux )
config_require(ip-forward-mib/data_access/route_hpux);
#elif defined ( bsd )
config_require(ip-forward-mib/data_access/route_bsd);
#else
/*
 * couldn't determine the correct file!
 * require a bogus file to generate an error.
 */
configure_require(ip-forward-mib/data_access/route_unknown-arch);
#endif

/** need interface for ifIndex */
config_require(if-mib/data_access/interface);

