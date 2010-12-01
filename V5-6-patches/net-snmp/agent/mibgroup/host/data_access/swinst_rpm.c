/*
 * swinst_rpm.c:
 *     hrSWInstalledTable data access:
 */
#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_RPM_RPMLIB_H
#include <rpm/rpmlib.h>
#endif
#ifdef HAVE_RPM_RPMLIB_H
#include <rpm/header.h>
#endif
#ifdef HAVE_RPMGETPATH		/* HAVE_RPM_RPMMACRO_H */
#include <rpm/rpmmacro.h>
#endif
#ifdef HAVE_RPM_RPMDB_H
#include <rpm/rpmdb.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/data_access/swinst.h>

   /*
    * Location of RPM package directory.
    * Used for:
    *    - reporting hrSWInstalledLast* objects
    *    - detecting when the cached contents are out of date.
    */
char pkg_directory[SNMP_MAXPATH];

/* ---------------------------------------------------------------------
 */
void
netsnmp_swinst_arch_init(void)
{
    char        *rpmdbpath = NULL;
    const char  *dbpath;
    struct stat  stat_buf;

#ifdef HAVE_RPMGETPATH
    rpmReadConfigFiles( NULL, NULL );
    rpmdbpath = rpmGetPath( "%{_dbpath}", NULL );
    dbpath = rpmdbpath;
#else
#ifdef RPMVAR_DBPATH
    rpmReadConfigFiles( NULL, NULL, NULL, 0 );
    rpmdbpath = rpmGetVar( RPMVAR_DBPATH );
    dbpath = rpmdbpath;
#else
    dbpath = "/var/lib/rpm";   /* Most likely */
#endif
#endif

    snprintf( pkg_directory, SNMP_MAXPATH, "%s/Packages", dbpath );
    if (-1 == stat( pkg_directory, &stat_buf ))
        snprintf( pkg_directory, SNMP_MAXPATH, "%s/packages.rpm", dbpath );
    SNMP_FREE(rpmdbpath);
    dbpath = NULL;
    if (-1 == stat( pkg_directory, &stat_buf )) {
        snmp_log(LOG_ERR, "Can't find directory of RPM packages");
        pkg_directory[0] = '\0';
    }
}

void
netsnmp_swinst_arch_shutdown(void)
{
     /* Nothing to do */
     return;
}

/* ---------------------------------------------------------------------
 */
int
netsnmp_swinst_arch_load( netsnmp_container *container, u_int flags)
{
    rpmdb                 db;

#if defined(RPMDBI_PACKAGES)
    rpmdbMatchIterator    mi;
#else
    int                   offset;
#endif
    Header                h;
    char                 *n, *v, *r, *g;
    int32_t              *t;
    time_t                install_time;
    size_t                date_len;
    int                   rc, i = 1;
    netsnmp_swinst_entry *entry;

    if (rpmdbOpen("", &db, O_RDONLY, 0644))
	NETSNMP_LOGONCE((LOG_ERR, "rpmdbOpen() failed\n"));

#if defined(RPMDBI_PACKAGES)
    mi = rpmdbInitIterator( db, RPMDBI_PACKAGES, NULL, 0);
    while (NULL != (h = rpmdbNextIterator( mi )))
#else
    for (offset  = rpmdbFirstRecNum( db );
         offset != 0;
         offset  = rpmdbNextRecNum(  db, offset ))
#endif
    {

        entry = netsnmp_swinst_entry_create( i++ );
        if (NULL == entry)
            continue;   /* error already logged by function */
        rc = CONTAINER_INSERT(container, entry);

#if defined(RPMDBI_PACKAGES)
        h = headerLink( h );
#else
        h = rpmdbGetRecord( db, offset );
#endif
        headerGetEntry( h, RPMTAG_NAME,        NULL, (void**)&n, NULL);
        headerGetEntry( h, RPMTAG_VERSION,     NULL, (void**)&v, NULL);
        headerGetEntry( h, RPMTAG_RELEASE,     NULL, (void**)&r, NULL);
        headerGetEntry( h, RPMTAG_GROUP,       NULL, (void**)&g, NULL);
        headerGetEntry( h, RPMTAG_INSTALLTIME, NULL, (void**)&t, NULL);

        entry->swName_len = snprintf( entry->swName, sizeof(entry->swName),
                                      "%s-%s-%s", n, v, r);
        if (entry->swName_len > sizeof(entry->swName))
            entry->swName_len = sizeof(entry->swName);
        entry->swType = (NULL != strstr( g, "System Environment"))
                        ? 2      /* operatingSystem */
                        : 4;     /*  application    */

        install_time = *t;
        entry->swDate_len = snprintf( entry->swDate, sizeof(entry->swDate),
                                      "%s", date_n_time( &install_time, &date_len ));

        headerFree( h );
    }
#if defined(RPMDBI_PACKAGES)
    rpmdbFreeIterator( mi );
#endif
    rpmdbClose( db );

    DEBUGMSGTL(("swinst:load:arch", "loaded %d entries\n",
                (int)CONTAINER_SIZE(container)));

    return 0;
}
