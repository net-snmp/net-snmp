#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <stdio.h>
#include <ctype.h>
#if HAVE_STDLIB_H
#   include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#   include <unistd.h>
#endif
#if HAVE_STRING_H
#   include <string.h>
#else
#  include <strings.h>
#endif

#include <sys/types.h>

#if HAVE_SYS_PARAM_H
#   include <sys/param.h>
#endif
#ifdef HAVE_SYS_STAT_H
#   include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#   include <fcntl.h>
#endif

#include <errno.h>

#if HAVE_DMALLOC_H
#  include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/file_utils.h>


/*------------------------------------------------------------------
 *
 * Prototypes
 *
 */




/*------------------------------------------------------------------
 *
 * Core Functions
 *
 */

/**
 * allocate a netsnmp_file structure
 *
 * This routine should be used instead of allocating on the stack,
 * for future compatability.
 */
netsnmp_file *
netsnmp_file_create(void)
{
    netsnmp_file *filei = SNMP_MALLOC_TYPEDEF(netsnmp_file);

    /*
     * 0 is a valid file descriptor, so init to -1
     */
    if (NULL != filei)
        filei->fd = -1;

    return filei;
}

/**
 * fill core members in a netsnmp_file structure
 *
 * @param filei      structure to fill; if NULL, a new one will be allocated
 */
netsnmp_file *
netsnmp_file_fill(netsnmp_file * filei, const char* name,
                  int fs_flags, mode_t mode, u_int ns_flags)
{
    if (NULL == filei) {
        filei = netsnmp_file_create();
        if (NULL == filei)
            return NULL;
    }

    if (NULL != name)
        filei->name = strdup(name);

    filei->fs_flags = fs_flags;
    filei->ns_flags = ns_flags;

    return filei;
}

/**
 * release a netsnmp_file structure
 */
int
netsnmp_file_release(netsnmp_file * filei)
{
    int rc;

    if (NULL == filei)
        return -1;

    if ((filei->fd > 0) && NS_FI_AUTOCLOSE(filei->ns_flags))
        rc = close(filei->fd);

    if (NULL != filei->name)
        free(filei->name); /* no point in SNMP_FREE */

    if (NULL != filei->extras)
        netsnmp_free_all_list_data(filei->extras);

    return rc;
}

/**
 * open a file structure
 */
int
netsnmp_file_open(netsnmp_file * filei)
{
    if ((NULL == filei) || (NULL == filei->name))
        return -1;

    if (-1 != filei->fd) {
        // error handling
        return filei->fd;
    }

    if (0 == filei->mode)
        filei->fd = open(filei->name, filei->fs_flags);
    else
        filei->fd = open(filei->name, filei->fs_flags, filei->mode);

    if (filei->fd < 0) {
        snmp_log(LOG_ERR, "error opening %s (%d)\n", filei->name, errno);
    }

    return filei->fd;
}


/**
 * close a file structure
 */
int
netsnmp_file_close(netsnmp_file * filei)
{
    int rc;

    if ((NULL == filei) || (NULL != filei->name))
        return -1;

    if (-1 == filei->fd) {
        return 0;
    }

    rc = close(filei->fd);
    if (rc < 0) {
        snmp_log(LOG_ERR, "error closing %s (%d)\n", filei->name, errno);
    }
    else
        filei->fd = -1;

    return rc;
}

