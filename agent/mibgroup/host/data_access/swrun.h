/*
 * swrun data access header
 *
 * $Id: swrun.h 15346 2006-09-26 23:34:50Z rstory $
 */
/*
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#ifndef NETSNMP_ACCESS_SWRUN_CONFIG_H
#define NETSNMP_ACCESS_SWRUN_CONFIG_H

/*
 * all platforms use this generic code
 */
config_require(host/data_access/swrun)

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

#ifdef NETSNMP_INCLUDE_HRSWRUN_REWRITES

config_exclude(host/hr_swrun)

#   if defined( darwin )

    config_require(host/data_access/swrun_darwin)

#   else

    config_error(This platform does not yet support hrSWRunTable rewrites)

#   endif
#else
#   define NETSNMP_ACCESS_SWRUN_NOARCH 1
#endif

#endif /* NETSNMP_ACCESS_SWRUN_CONFIG_H */
