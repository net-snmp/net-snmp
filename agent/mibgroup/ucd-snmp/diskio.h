#ifndef _MIBGROUP_DISKIO_H
#define _MIBGROUP_DISKIO_H

config_require(util_funcs/header_simple_table);
config_add_mib(UCD-DISKIO-MIB);
#if defined(aix4)
config_require(ucd-snmp/diskio_aix);
#elif defined(bsdi3)
config_require(ucd-snmp/diskio_bsdi);
#elif defined(darwin)
config_require(ucd-snmp/diskio_darwin);
#elif defined(freebsd3)
config_require(ucd-snmp/diskio_freebsd);
#elif defined(linux)
config_require(ucd-snmp/diskio_linux);
#elif defined(openbsd4)
config_require(ucd-snmp/diskio_openbsd);
#elif defined(netbsd1)
config_require(ucd-snmp/diskio_netbsd);
#elif defined(solaris2)
config_require(ucd-snmp/diskio_solaris);
#endif

void            init_diskio(void);
int             diskio_cache_valid(time_t now);
void            diskio_set_cache_time(time_t now);
void            devla_getstats(unsigned int regno, void *dummy);
FindVarMethod   var_diskio;

/*
 * Magic number definitions.  These numbers are the last oid index
 * numbers to the table that you are going to define.  For example,
 * lets say (since we are) creating a mib table at the location
 * .1.3.6.1.4.1.2021.254.  The following magic numbers would be the
 * next numbers on that oid for the var_example function to use, ie:
 * .1.3.6.1.4.1.2021.254.1 (and .2 and .3 ...) 
 */

#define	DISKIO_INDEX		1
#define DISKIO_DEVICE		2
#define DISKIO_NREAD		3
#define DISKIO_NWRITTEN		4
#define DISKIO_READS		5
#define DISKIO_WRITES		6
#define DISKIO_LA1		9
#define DISKIO_LA5              10
#define DISKIO_LA15             11
#define DISKIO_NREADX           12
#define DISKIO_NWRITTENX        13
#define DISKIO_BUSYTIME		14

/* sampling interval, in seconds */
#define DISKIO_SAMPLE_INTERVAL 5

#endif                          /* _MIBGROUP_DISKIO_H */
