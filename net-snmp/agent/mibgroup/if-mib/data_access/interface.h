/*
 * interface data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_INTERFACE_CONFIG_H
#define NETSNMP_ACCESS_INTERFACE_CONFIG_H

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
config_require(if-mib/data_access/interface_common)
#if defined( linux )
config_require(if-mib/data_access/interface_linux);
config_require(if-mib/data_access/interface_ioctl);
#elif defined ( solaris )
config_require(if-mib/data_access/interface_solaris);
#elif defined ( hpux )
config_require(if-mib/data_access/interface_hpux);
#elif defined ( bsd )
config_require(if-mib/data_access/interface_bsd);
#else
/*
 * couldn't determine the correct file!
 * require a bogus file to generate an error.
 */
configure_require(if-mib/data_access/interface-unknown-arch);
#endif

void netsnmp_access_interface_arch_init(void);

int netsnmp_arch_set_admin_status(netsnmp_interface_entry * entry,
                                  int ifAdminStatus_val);



#endif /* NETSNMP_ACCESS_INTERFACE_CONFIG_H */
