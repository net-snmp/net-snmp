/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
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
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include <errno.h>

#if HAVE_DMALLOC_H
#  include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/container_binary_array.h>
#include <net-snmp/library/dir_utils.h>

netsnmp_container *
netsnmp_directory_container_read(netsnmp_container *user_container,
                                 const char *dirname, u_int flags)
{
    DIR               *dir;
    netsnmp_container *container = user_container, *tmp_c;
    struct dirent     *file;
    char               path[PATH_MAX];
    u_char             dirname_len;
    int                rc;
#if !(defined(HAVE_STRUCT_DIRENT_D_TYPE) && defined(DT_DIR)) && defined(S_ISDIR)
    struct stat        statbuf;
#endif

    DEBUGMSGTL(("directory:container", "reading %s\n", dirname));

    /*
     * create the container, if needed
     */
    if (NULL == container) {
        container = netsnmp_container_find("directory_container:cstring");
        if (NULL == container)
            return NULL;
        container->container_name = strdup("directory container");
        netsnmp_binary_array_options_set(container, 1, CONTAINER_KEY_UNSORTED);
    }

    dir = opendir(dirname);
    if (NULL == dir) {
        DEBUGMSGTL(("directory:container", "  not a dir\n"));
        return NULL;
    }

    /** copy dirname into path */
    dirname_len = strlen(dirname);
    strncpy(path, dirname, sizeof(path));
    if ((dirname_len + 2) > sizeof(path)) {
        /** not enough room for files */
        closedir(dir);
        return NULL;
    }
    path[dirname_len] = '/';
    path[++dirname_len] = 0;

    /** iterate over dir */
    while ((file = readdir(dir))) {

        if ((file->d_name == NULL) || (file->d_name[0] == 0))
            continue;

        /** skip '.' and '..' */
        if ((file->d_name[0] == '.') &&
            ((file->d_name[1] == 0) ||
             ((file->d_name[1] == '.') && ((file->d_name[2] == 0)))))
            continue;

        strncpy(&path[dirname_len], file->d_name, sizeof(path) - dirname_len);
        DEBUGMSGTL(("9:directory:container", "  found %s\n", path));
#if defined(HAVE_STRUCT_DIRENT_D_TYPE) && defined(DT_DIR)
        if ((file->d_type == DT_DIR) && (flags & NETSNMP_DIR_RECURSE)) {
#elif defined(S_ISDIR)
        if ((flags & NETSNMP_DIR_RECURSE) && (stat(file->d_name, &statbuf) != 0) && (S_ISDIR(statbuf.st_mode))) {
#else
        if (flags & NETSNMP_DIR_RECURSE) {
#endif
            /** xxx add the dir as well? not for now.. maybe another flag? */
            tmp_c = netsnmp_directory_container_read(container, path, flags);
        }
        else {
            char *dup = strdup(path);
            if (NULL == dup) {
               snmp_log(LOG_ERR, "strdup failed\n");
               break;
            }
            rc = CONTAINER_INSERT(container, dup);
            if (-1 == rc ) {
                DEBUGMSGTL(("directory:container", "  err adding %s\n", path));
                free(dup);
            }
        }
    }

    closedir(dir);

    DEBUGMSGTL(("directory:container", "  container now has %d items\n",
                (int)CONTAINER_SIZE(container)));
    
    return container;
}

void
netsnmp_directory_container_free(netsnmp_container *container)
{
    CONTAINER_CLEAR(container, netsnmp_container_simple_free, NULL);
    CONTAINER_FREE(container);
}
