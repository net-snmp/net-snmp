#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/fsys.h>
#include "hw_fsys.h"
#include "hardware/fsys/hw_fsys_private.h"

#include <stdio.h>
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#ifdef HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif

#ifdef solaris2
#define _NETSNMP_GETMNTENT_TWO_ARGS 1
#else
#undef  _NETSNMP_GETMNTENT_TWO_ARGS 
#endif

    /*
     * Handle naming differences between getmntent() APIs
     */
#ifdef _NETSNMP_GETMNTENT_TWO_ARGS
    /* Two-argument form (Solaris) */
#define NSFS_MNTENT   struct mnttab
#define NSFS_PATH     mnt_mountp
#define NSFS_DEV      mnt_special
#define NSFS_TYPE     mnt_fstype

#define NSFS_STATFS   statvfs
#define NSFS_SIZE     f_frsize

#else
    /* One-argument form (everything else?) */
#define NSFS_MNTENT   struct mntent
#define NSFS_PATH     mnt_dir
#define NSFS_DEV      mnt_fsname
#define NSFS_TYPE     mnt_type

#define NSFS_STATFS   statfs
#define NSFS_SIZE     f_bsize

#endif

static void     parse_mount_config(const char *, char *);
static void     free_mount_config(void);

/*
 * File systems to monitor and that are not covered by any hrFSTypes
 * enumeration.
 */
static const char *other_fs[] = {
    "acfs",
    "btrfs",
    "cvfs",
    "f2fs",
    "fuse.glusterfs",
    "gfs",
    "gfs2",
    "glusterfs",
    "jfs",
    "jffs2",
    "lofs",
    "mvfs",
    "nsspool",
    "nssvol",
    "nvmfs",
    "ocfs2",
    "reiserfs",
    "simfs",
    "tmpfs",
    "vxfs",
    "xfs",
    "zfs",
    NULL,
};

static int
_fsys_remote( char *device, int type )
{
    if (( type == NETSNMP_FS_TYPE_NFS) ||
        ( type == NETSNMP_FS_TYPE_AFS))
        return 1;
    else
        return 0;
}

static int
_fsys_type( char *typename )
{
    const char **fs;

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
              !strcmp(typename, MNTTYPE_NFS4) ||
              !strcmp(typename, MNTTYPE_CIFS) ||  /* i.e. SMB - ?? */
              !strcmp(typename, MNTTYPE_SMBFS) || /* ?? */
              /* mvfs (IBM ClearCase) is nfs-like in nature */
              !strcmp(typename, MNTTYPE_MVFS))
       return NETSNMP_FS_TYPE_NFS;
    else if ( !strcmp(typename, MNTTYPE_NCPFS) )
       return NETSNMP_FS_TYPE_NETWARE;
    else if ( !strcmp(typename, MNTTYPE_AFS) )
       return NETSNMP_FS_TYPE_AFS;
    else if ( !strcmp(typename, MNTTYPE_EXT2) ||
              !strcmp(typename, MNTTYPE_EXT3) ||
              !strcmp(typename, MNTTYPE_EXT4) ||
              !strcmp(typename, MNTTYPE_EXT2FS) ||
              !strcmp(typename, MNTTYPE_EXT3FS) ||
              !strcmp(typename, MNTTYPE_EXT4FS) )
       return NETSNMP_FS_TYPE_EXT2;
    else if ( !strcmp(typename, MNTTYPE_FAT32) ||
              !strcmp(typename, MNTTYPE_VFAT) )
       return NETSNMP_FS_TYPE_FAT32;

    for (fs = other_fs; *fs; fs++)
        if (strcmp(typename, *fs) == 0)
            return NETSNMP_FS_TYPE_OTHER;

    /* Detection of AUTOFS.
     * This file system will be ignored by default
     */ 
    if (!strcmp(typename, MNTTYPE_AUTOFS))
        return NETSNMP_FS_TYPE_AUTOFS;


    /*    
     *  All other types are silently skipped
     */
    return NETSNMP_FS_TYPE_IGNORE;
}

void
netsnmp_fsys_arch_init( void )
{
    snmpd_register_config_handler("ignoremount", parse_mount_config,
                                  free_mount_config, "name");
}

#define ITEM_STRING	1
#define ITEM_SET	2
#define ITEM_STAR	3
#define ITEM_ANY	4

typedef unsigned char details_set[32];

typedef struct _conf_mount_item {
    int             item_type;  /* ITEM_STRING, ITEM_SET, ITEM_STAR, ITEM_ANY */
    void           *item_details;       /* content depends upon item_type */
    struct _conf_mount_item *item_next;
} conf_mount_item;

typedef struct _conf_mount_list {
    conf_mount_item *list_item;
    struct _conf_mount_list *list_next;
} conf_mount_list;
static conf_mount_list *conf_list = NULL;

static int      match_mount_config(const char *);
static int      match_mount_config_item(const char *, conf_mount_item *);

static void
parse_mount_config(const char *token, char *cptr)
{
    conf_mount_list *d_new = NULL;
    conf_mount_item *di_curr = NULL;
    details_set    *d_set = NULL;
    char           *name = NULL, *p = NULL, *d_str = NULL, c;
    unsigned int    i, neg, c1, c2;
    char           *st = NULL;

    name = strtok_r(cptr, " \t", &st);
    if (!name) {
        config_perror("Missing NAME parameter");
        return;
    }
    d_new = (conf_mount_list *) malloc(sizeof(conf_mount_list));
    if (!d_new) {
        config_perror("Out of memory");
        return;
    }
    di_curr = (conf_mount_item *) malloc(sizeof(conf_mount_item));
    if (!di_curr) {
        SNMP_FREE(d_new);
        config_perror("Out of memory");
        return;
    }
    d_new->list_item = di_curr;
    /* XXX: on error/return conditions we need to free the entire new
       list, not just the last node like this is doing! */
    for (;;) {
        if (*name == '?') {
            di_curr->item_type = ITEM_ANY;
            di_curr->item_details = (void *) 0;
            name++;
        } else if (*name == '*') {
            di_curr->item_type = ITEM_STAR;
            di_curr->item_details = (void *) 0;
            name++;
        } else if (*name == '[') {
            d_set = (details_set *) calloc(sizeof(details_set), 1);
            if (!d_set) {
                config_perror("Out of memory");
                SNMP_FREE(d_new);
                SNMP_FREE(di_curr);
                SNMP_FREE(d_set);
                SNMP_FREE(d_str);
                return;
            }
            name++;
            if (*name == '^' || *name == '!') {
                neg = 1;
                name++;
            } else {
                neg = 0;
            }
            while (*name && *name != ']') {
                c1 = ((unsigned int) *name++) & 0xff;
                if (*name == '-' && *(name + 1) != ']') {
                    name++;
                    c2 = ((unsigned int) *name++) & 0xff;
                } else {
                    c2 = c1;
                }
                for (i = c1; i <= c2; i++)
                    (*d_set)[i / 8] |= (unsigned char) (1 << (i % 8));
            }
            if (*name != ']') {
                config_perror
                    ("Syntax error in NAME: invalid set specified");
                SNMP_FREE(d_new);
                SNMP_FREE(di_curr);
                SNMP_FREE(d_set);
                SNMP_FREE(d_str);
                return;
            }
            if (neg) {
                for (i = 0; i < sizeof(details_set); i++)
                    (*d_set)[i] = (*d_set)[i] ^ (unsigned char) 0xff;
            }
            di_curr->item_type = ITEM_SET;
            di_curr->item_details = (void *) d_set;
            name++;
        } else {
            for (p = name;
                 *p != '\0' && *p != '?' && *p != '*' && *p != '['; p++);
            c = *p;
            *p = '\0';
            d_str = (char *) malloc(strlen(name) + 1);
            if (!d_str) {
                SNMP_FREE(d_new);
                SNMP_FREE(d_str);
                SNMP_FREE(di_curr);
                SNMP_FREE(d_set);
                config_perror("Out of memory");
                return;
            }
            strcpy(d_str, name);
            *p = c;
            di_curr->item_type = ITEM_STRING;
            di_curr->item_details = (void *) d_str;
            name = p;
        }
        if (!*name) {
            di_curr->item_next = (conf_mount_item *) 0;
            break;
        }
        di_curr->item_next =
            (conf_mount_item *) malloc(sizeof(conf_mount_item));
        if (!di_curr->item_next) {
            SNMP_FREE(di_curr->item_next);
            SNMP_FREE(d_new);
            SNMP_FREE(di_curr);
            SNMP_FREE(d_set);
            SNMP_FREE(d_str);
            config_perror("Out of memory");
            return;
        }
        di_curr = di_curr->item_next;
    }
    d_new->list_next = conf_list;
    conf_list = d_new;
}

static void
free_mount_config(void)
{
    conf_mount_list *d_ptr = conf_list, *d_next;
    conf_mount_item *di_ptr, *di_next;

    while (d_ptr) {
        d_next = d_ptr->list_next;
        di_ptr = d_ptr->list_item;
        while (di_ptr) {
            di_next = di_ptr->item_next;
            if (di_ptr->item_details)
                free(di_ptr->item_details);
            free((void *) di_ptr);
            di_ptr = di_next;
        }
        free((void *) d_ptr);
        d_ptr = d_next;
    }
    conf_list = (conf_mount_list *) 0;
}

static int
match_mount_config_item(const char *name, conf_mount_item * di_ptr)
{
    int             result = 0;
    size_t          len;
    details_set    *d_set;
    unsigned int    c;

    if (di_ptr) {
        switch (di_ptr->item_type) {
        case ITEM_STRING:
            len = strlen((const char *) di_ptr->item_details);
            if (!strncmp(name, (const char *) di_ptr->item_details, len))
                result = match_mount_config_item(name + len,
                                                di_ptr->item_next);
            break;
        case ITEM_SET:
            if (*name) {
                d_set = (details_set *) di_ptr->item_details;
                c = ((unsigned int) *name) & 0xff;
                if ((*d_set)[c / 8] & (unsigned char) (1 << (c % 8)))
                    result = match_mount_config_item(name + 1,
                                                    di_ptr->item_next);
            }
            break;
        case ITEM_STAR:
            if (di_ptr->item_next) {
                for (; !result && *name; name++)
                    result = match_mount_config_item(name,
                                                    di_ptr->item_next);
            } else {
                result = 1;
            }
            break;
        case ITEM_ANY:
            if (*name)
                result = match_mount_config_item(name + 1,
                                                di_ptr->item_next);
            break;
        }
    } else {
        if (*name == '\0')
            result = 1;
    }

    return result;
}

static int
match_mount_config(const char *name)
{
    conf_mount_list *d_ptr = conf_list;

    while (d_ptr) {
        if (match_mount_config_item(name, d_ptr->list_item))
            return 1;           /* match found in ignorelist */
        d_ptr = d_ptr->list_next;
    }

    /*
     * no match in ignorelist 
     */
    return 0;
}

void
netsnmp_fsys_arch_load( void )
{
    FILE              *fp=NULL;
#ifdef _NETSNMP_GETMNTENT_TWO_ARGS
    struct mnttab      mtmp;
    struct mnttab     *m = &mtmp;
#else
    struct mntent     *m;
#endif
    struct NSFS_STATFS stat_buf;
    netsnmp_fsys_info *entry;
    char              *tmpbuf = NULL;

    /*
     * Retrieve information about the currently mounted filesystems...
     */
    fp = fopen( ETC_MNTTAB, "r" );   /* OR setmntent()?? */
    if ( !fp ) {
        if (asprintf(&tmpbuf, "Cannot open %s", ETC_MNTTAB) >= 0)
            snmp_log_perror(tmpbuf);
        free(tmpbuf);
        return;
    }

    /*
     * ... and insert this into the filesystem container.
     */
    while 
#ifdef _NETSNMP_GETMNTENT_TWO_ARGS
          ((getmntent(fp, m)) == 0 )
#else
          ((m = getmntent(fp)) != NULL )
#endif
    {
        entry = netsnmp_fsys_by_path( m->NSFS_PATH, NETSNMP_FS_FIND_CREATE );
        if (!entry) {
            continue;
        }

        strlcpy(entry->path, m->NSFS_PATH, sizeof(entry->path));
        strlcpy(entry->device, m->NSFS_DEV, sizeof(entry->device));
        entry->type = _fsys_type(m->NSFS_TYPE);
        if (!(entry->type & _NETSNMP_FS_TYPE_SKIP_BIT))
            entry->flags |= NETSNMP_FS_FLAG_ACTIVE;

        if ( _fsys_remote( entry->device, entry->type ))
            entry->flags |= NETSNMP_FS_FLAG_REMOTE;
#ifdef HAVE_HASMNTOPT
        if (hasmntopt( m, NETSNMP_REMOVE_CONST(char *, "ro") ))
            entry->flags |= NETSNMP_FS_FLAG_RONLY;
        else
            entry->flags &= ~NETSNMP_FS_FLAG_RONLY;
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
         *  XXX - identify removeable disks
         */

        /*
         *  Optionally skip retrieving statistics for remote mounts or ignored mounts
         */
	if (match_mount_config(entry->path)) 
	    continue;

        if ( (entry->flags & NETSNMP_FS_FLAG_REMOTE) &&
            netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                   NETSNMP_DS_AGENT_SKIPNFSINHOSTRESOURCES))
            continue;

        /* Skip AUTOFS entries */
        if (entry->type == NETSNMP_FS_TYPE_AUTOFS)
            continue;

#ifdef irix6
        if ( NSFS_STATFS( entry->path, &stat_buf, sizeof(struct statfs), 0) < 0 )
#else
        if ( NSFS_STATFS( entry->path, &stat_buf ) < 0 )
#endif
        {
            static char logged = 0;

            if (!logged &&
                asprintf(&tmpbuf, "Cannot statfs %s", entry->path) >= 0) {
                snmp_log_perror(tmpbuf);
                free(tmpbuf);
                logged = 1;
            }
            memset(&stat_buf, 0, sizeof(stat_buf));
        }
        entry->units =  stat_buf.NSFS_SIZE;
        entry->size  =  stat_buf.f_blocks;
        entry->used  = (stat_buf.f_blocks - stat_buf.f_bfree);
        entry->avail =  stat_buf.f_bavail;
        entry->inums_total = stat_buf.f_files;
        entry->inums_avail = stat_buf.f_ffree;
        netsnmp_fsys_calculate32(entry);
    }
    fclose( fp );
}
