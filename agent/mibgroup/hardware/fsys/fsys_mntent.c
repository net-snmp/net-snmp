#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/fsys.h>

#include <stdio.h>
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif

int
_fsys_remote( char *device, int type )
{
    if (( type == NETSNMP_FS_TYPE_NFS) ||
        ( type == NETSNMP_FS_TYPE_AFS))
        return 1;
    else
        return 0;
}

int
_fsys_type( char *typename )
{
    DEBUGMSGTL(("fsys:type", "Classifying %s\n", typename));

    if ( !typename || *typename=='\0' )
       return NETSNMP_FS_TYPE_UNKNOWN;

#include "mnttypes.h"

    else if ( !strcmp(typename, MNTTYPE_FFS) )
       return NETSNMP_FS_TYPE_BERKELEY;
    else if ( !strcmp(typename, MNTTYPE_UFS) )
       return _NETSNMP_FS_TYPE_UFS;   /* either N_FS_TYPE_BERKELEY or N_FS_TYPE_SYSV */
    else if ( !strcmp(typename, MNTTYPE_SYSV) )
       return NETSNMP_FS_TYPE_SYSV;
    else if ( !strcmp(typename, MNTTYPE_PC) ||
              !strcmp(typename, MNTTYPE_MSDOS) )
       return NETSNMP_FS_TYPE_FAT;
    else if ( !strcmp(typename, MNTTYPE_HFS) )
       return NETSNMP_FS_TYPE_HFS;
    else if ( !strcmp(typename, MNTTYPE_MFS) )
       return NETSNMP_FS_TYPE_MFS;
    else if ( !strcmp(typename, MNTTYPE_NTFS) )
       return NETSNMP_FS_TYPE_NTFS;
    else if ( !strcmp(typename, MNTTYPE_ISO9660) ||
              !strcmp(typename, MNTTYPE_CD9660) )
       return NETSNMP_FS_TYPE_ISO9660;
    else if ( !strcmp(typename, MNTTYPE_CDFS) )
       return _NETSNMP_FS_TYPE_CDFS;   /* either N_FS_TYPE_ISO9660 or N_FS_TYPE_ROCKRIDGE */
    else if ( !strcmp(typename, MNTTYPE_HSFS) )
       return NETSNMP_FS_TYPE_ROCKRIDGE;
    else if ( !strcmp(typename, MNTTYPE_NFS)  ||
              !strcmp(typename, MNTTYPE_NFS3) ||
              !strcmp(typename, MNTTYPE_SMBFS) /* ?? */ )
       return NETSNMP_FS_TYPE_NFS;
    else if ( !strcmp(typename, MNTTYPE_NCPFS) )
       return NETSNMP_FS_TYPE_NETWARE;
    else if ( !strcmp(typename, MNTTYPE_AFS) )
       return NETSNMP_FS_TYPE_AFS;
    else if ( !strcmp(typename, MNTTYPE_EXT2) ||
              !strcmp(typename, MNTTYPE_EXT3) ||
              !strcmp(typename, MNTTYPE_EXT2FS) ||
              !strcmp(typename, MNTTYPE_EXT3FS) )
       return NETSNMP_FS_TYPE_EXT2;
    else if ( !strcmp(typename, MNTTYPE_FAT32) ||
              !strcmp(typename, MNTTYPE_VFAT) )
       return NETSNMP_FS_TYPE_FAT32;

    /*
     *  The following code maps these filesystems into
     *    distinct types - all of which are then skipped.
     *  An alternative approach would be to map them all
     *    into the single type N_FS_TYPE_IGNORE
     */
    else if ( !strcmp(typename, MNTTYPE_IGNORE) )
       return NETSNMP_FS_TYPE_IGNORE;
    else if ( !strcmp(typename, MNTTYPE_PROC) )
       return NETSNMP_FS_TYPE_PROC;
    else if ( !strcmp(typename, MNTTYPE_DEVPTS) )
       return NETSNMP_FS_TYPE_DEVPTS;
    else if ( !strcmp(typename, MNTTYPE_SYSFS) )
       return NETSNMP_FS_TYPE_SYSFS;
    else if ( !strcmp(typename, MNTTYPE_TMPFS) )
       return NETSNMP_FS_TYPE_TMPFS;
    else if ( !strcmp(typename, MNTTYPE_USBFS) )
       return NETSNMP_FS_TYPE_USBFS;

    else
       return NETSNMP_FS_TYPE_OTHER;
}

void
netsnmp_fsys_arch_init( void )
{
    return;
}

void
netsnmp_fsys_arch_load( void )
{
    FILE              *fp=NULL;
    struct mntent     *m;
    struct statfs      stat_buf;
    netsnmp_fsys_info *entry;
    char               tmpbuf[1024];

    /*
     * Retrieve information about the currently mounted filesystems...
     */
    fp = fopen( ETC_MNTTAB, "r" );   /* OR setmntent()?? */
    if ( !fp ) {
        snprintf( tmpbuf, sizeof(tmpbuf), "Cannot open %s\n", ETC_MNTTAB );
        snmp_log_perror( tmpbuf );
        return;
    }

    /*
     * ... and insert this into the filesystem container.
     */
    while ((m = getmntent(fp)) != NULL ) {
        entry = netsnmp_fsys_by_path( m->mnt_dir, NETSNMP_FS_FIND_CREATE );
        if (!entry) {
            continue;
        }

        strncpy( entry->path,   m->mnt_dir,    sizeof( entry->path   ));
        strncpy( entry->device, m->mnt_fsname, sizeof( entry->device ));
        entry->type   = _fsys_type(  m->mnt_type );
        if (!(entry->type & _NETSNMP_FS_TYPE_SKIP_BIT))
            entry->flags |= NETSNMP_FS_FLAG_ACTIVE;

        if ( _fsys_remote( entry->device, entry->type ))
            entry->flags |= NETSNMP_FS_FLAG_REMOTE;
#if HAVE_HASMNTOPT
        if (hasmntopt( m, "ro" ))
            entry->flags |= NETSNMP_FS_FLAG_RONLY;
#endif
        /*
         *  The root device is presumably bootable.
         *  Other partitions probably aren't!
         *
         *  XXX - what about /boot ??
         */
        if ((entry->path[0] == '/') &&
            (entry->path[1] == '\0'))
            entry->flags |= NETSNMP_FS_FLAG_BOOTABLE;


        /*
         *  Optionally skip retrieving statistics for remote mounts
         */
        if ( (entry->flags & NETSNMP_FS_FLAG_REMOTE) &&
            netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                   NETSNMP_DS_AGENT_SKIPNFSINHOSTRESOURCES))
            continue;

        if ( statfs( entry->path, &stat_buf ) < 0 ) {
            snprintf( tmpbuf, sizeof(tmpbuf), "Cannot statfs %s\n", entry->path );
            snmp_log_perror( tmpbuf );
            continue;
        }
        entry->units =  stat_buf.f_bsize;
        entry->size  =  stat_buf.f_blocks;
        entry->used  = (stat_buf.f_blocks - stat_buf.f_bfree);
        entry->avail =  stat_buf.f_bavail;
        entry->inums_total = stat_buf.f_files;
        entry->inums_avail = stat_buf.f_ffree;
    }
    fclose( fp );
}

