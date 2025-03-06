/*
 *  Host Resources MIB - disk device group implementation - hr_disk.c
 *
 */
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
#include "host_res.h"
#include "hr_disk.h"
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <net-snmp/agent/agent_read_config.h>
#include <net-snmp/library/read_config.h>

        /*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static const char *describe_disk(int);

int             header_hrdisk(struct variable *, oid *, size_t *, int,
                              size_t *, WriteMethod **);

int             HRD_type_index;
static int      HRD_index;
char            HRD_savedModel[HRD_SAVED_MODEL_SIZE];
long            HRD_savedCapacity = 1044;
static time_t   HRD_history[HRDEV_TYPE_MASK + 1];

static void     parse_disk_config(const char *, char *);
static void     free_disk_config(void);

        /*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

#define	HRDISK_ACCESS		1
#define	HRDISK_MEDIA		2
#define	HRDISK_REMOVEABLE	3
#define	HRDISK_CAPACITY		4

struct variable4 hrdisk_variables[] = {
    {HRDISK_ACCESS, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_hrdisk, 2, {1, 1}},
    {HRDISK_MEDIA, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_hrdisk, 2, {1, 2}},
    {HRDISK_REMOVEABLE, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_hrdisk, 2, {1, 3}},
    {HRDISK_CAPACITY, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_hrdisk, 2, {1, 4}}
};
oid             hrdisk_variables_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 6 };


void
init_hr_disk(void)
{
    int             i;

    init_device[HRDEV_DISK] = Init_HR_Disk;
    next_device[HRDEV_DISK] = Get_Next_HR_Disk;
    save_device[HRDEV_DISK] = Save_HR_Disk_General;
    dev_idx_inc[HRDEV_DISK] = 1;

    init_hr_disk_entries();

    device_descr[HRDEV_DISK] = describe_disk;
    HRD_savedModel[0] = '\0';
    HRD_savedCapacity = 0;

    for (i = 0; i < HRDEV_TYPE_MASK; ++i)
        HRD_history[i] = -1;

    REGISTER_MIB("host/hr_disk", hrdisk_variables, variable4,
                 hrdisk_variables_oid);

    snmpd_register_config_handler("ignoredisk", parse_disk_config,
                                  free_disk_config, "name");
}

#define ITEM_STRING	1
#define ITEM_SET	2
#define ITEM_STAR	3
#define ITEM_ANY	4

typedef unsigned char details_set[32];

typedef struct _conf_disk_item {
    int             item_type;  /* ITEM_STRING, ITEM_SET, ITEM_STAR, ITEM_ANY */
    void           *item_details;       /* content depends upon item_type */
    struct _conf_disk_item *item_next;
} conf_disk_item;

typedef struct _conf_disk_list {
    conf_disk_item *list_item;
    struct _conf_disk_list *list_next;
} conf_disk_list;
static conf_disk_list *conf_list = NULL;

static int      match_disk_config(const char *);
static int      match_disk_config_item(const char *, conf_disk_item *);

static void
parse_disk_config(const char *token, char *cptr)
{
    conf_disk_list *d_new = NULL;
    conf_disk_item *di_curr = NULL;
    details_set    *d_set = NULL;
    char           *name = NULL, *p = NULL, *d_str = NULL, c;
    unsigned int    i, neg, c1, c2;
    char           *st = NULL;

    name = strtok_r(cptr, " \t", &st);
    if (!name) {
        config_perror("Missing NAME parameter");
        return;
    }
    d_new = (conf_disk_list *) malloc(sizeof(conf_disk_list));
    if (!d_new) {
        config_perror("Out of memory");
        return;
    }
    di_curr = (conf_disk_item *) malloc(sizeof(conf_disk_item));
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
            d_set = calloc(1, sizeof(details_set));
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
            d_str = strdup(name);
            if (!d_str) {
                SNMP_FREE(d_new);
                SNMP_FREE(d_str);
                SNMP_FREE(di_curr);
                SNMP_FREE(d_set);
                config_perror("Out of memory");
                return;
            }
            *p = c;
            di_curr->item_type = ITEM_STRING;
            di_curr->item_details = (void *) d_str;
            name = p;
        }
        if (!*name) {
            di_curr->item_next = (conf_disk_item *) 0;
            break;
        }
        di_curr->item_next =
            (conf_disk_item *) malloc(sizeof(conf_disk_item));
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
free_disk_config(void)
{
    conf_disk_list *d_ptr = conf_list, *d_next;
    conf_disk_item *di_ptr, *di_next;

    while (d_ptr) {
        d_next = d_ptr->list_next;
        di_ptr = d_ptr->list_item;
        while (di_ptr) {
            di_next = di_ptr->item_next;
            if (di_ptr->item_details)
                free(di_ptr->item_details);
            free(di_ptr);
            di_ptr = di_next;
        }
        free(d_ptr);
        d_ptr = d_next;
    }
    conf_list = (conf_disk_list *) 0;
}

static int
match_disk_config_item(const char *name, conf_disk_item * di_ptr)
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
                result = match_disk_config_item(name + len,
                                                di_ptr->item_next);
            break;
        case ITEM_SET:
            if (*name) {
                d_set = (details_set *) di_ptr->item_details;
                c = ((unsigned int) *name) & 0xff;
                if ((*d_set)[c / 8] & (unsigned char) (1 << (c % 8)))
                    result = match_disk_config_item(name + 1,
                                                    di_ptr->item_next);
            }
            break;
        case ITEM_STAR:
            if (di_ptr->item_next) {
                for (; !result && *name; name++)
                    result = match_disk_config_item(name,
                                                    di_ptr->item_next);
            } else {
                result = 1;
            }
            break;
        case ITEM_ANY:
            if (*name)
                result = match_disk_config_item(name + 1,
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
match_disk_config(const char *name)
{
    conf_disk_list *d_ptr = conf_list;

    while (d_ptr) {
        if (match_disk_config_item(name, d_ptr->list_item))
            return 1;           /* match found in ignorelist */
        d_ptr = d_ptr->list_next;
    }

    /*
     * no match in ignorelist 
     */
    return 0;
}

/*
 * header_hrdisk(...
 * Arguments:
 * vp     IN      - pointer to variable entry that points here
 * name    IN/OUT  - IN/name requested, OUT/name found
 * length  IN/OUT  - length of IN/OUT oid's 
 * exact   IN      - TRUE if an exact match was requested
 * var_len OUT     - length of variable or 0 if function returned
 * write_method
 */

int
header_hrdisk(struct variable *vp,
              oid * name,
              size_t * length,
              int exact, size_t * var_len, WriteMethod ** write_method)
{
#define HRDISK_ENTRY_NAME_LENGTH	11
    oid             newname[MAX_OID_LEN];
    int             disk_idx, LowIndex = -1;
    int             result;

    DEBUGMSGTL(("host/hr_disk", "var_hrdisk: "));
    DEBUGMSGOID(("host/hr_disk", name, *length));
    DEBUGMSG(("host/hr_disk", " %d\n", exact));

    memcpy((char *) newname, (char *) vp->name,
           (int) vp->namelen * sizeof(oid));
    /*
     * Find "next" disk entry 
     */

    Init_HR_Disk();
    for (;;) {
        disk_idx = Get_Next_HR_Disk();
        DEBUGMSGTL(("host/hr_disk", "... index %d\n", disk_idx));
        if (disk_idx == -1)
            break;
        newname[HRDISK_ENTRY_NAME_LENGTH] = disk_idx;
        result =
            snmp_oid_compare(name, *length, newname,
                             (int) vp->namelen + 1);
        if (exact && (result == 0)) {
            LowIndex = disk_idx;
            Save_HR_Disk_Specific();
            break;
        }
        if ((!exact && (result < 0)) &&
            (LowIndex == -1 || disk_idx < LowIndex)) {
            LowIndex = disk_idx;
            Save_HR_Disk_Specific();
            break;
        }
    }

    if (LowIndex == -1) {
        DEBUGMSGTL(("host/hr_disk", "... index out of range\n"));
        return (MATCH_FAILED);
    }

    newname[HRDISK_ENTRY_NAME_LENGTH] = LowIndex;
    memcpy((char *) name, (char *) newname,
           ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = (WriteMethod*)0;
    *var_len = sizeof(long);    /* default to 'long' results */

    DEBUGMSGTL(("host/hr_disk", "... get disk stats "));
    DEBUGMSGOID(("host/hr_disk", name, *length));
    DEBUGMSG(("host/hr_disk", "\n"));

    return LowIndex;
}


        /*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char         *
var_hrdisk(struct variable * vp,
           oid * name,
           size_t * length,
           int exact, size_t * var_len, WriteMethod ** write_method)
{
    int             disk_idx;

    disk_idx =
        header_hrdisk(vp, name, length, exact, var_len, write_method);
    if (disk_idx == MATCH_FAILED)
        return NULL;


    switch (vp->magic) {
    case HRDISK_ACCESS:
        long_return = Is_It_Writeable();
        return (u_char *) & long_return;
    case HRDISK_MEDIA:
        long_return = What_Type_Disk();
        return (u_char *) & long_return;
    case HRDISK_REMOVEABLE:
        long_return = Is_It_Removeable();
        return (u_char *) & long_return;
    case HRDISK_CAPACITY:
        long_return = HRD_savedCapacity;
        return (u_char *) & long_return;
    default:
        DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrdisk\n",
                    vp->magic));
    }
    return NULL;
}


        /*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

#define MAX_NUMBER_DISK_TYPES	16      /* probably should be a variable */
#define MAX_DISKS_PER_TYPE	15      /* SCSI disks - not a hard limit */
#define	HRDISK_TYPE_SHIFT	4       /* log2 (MAX_DISKS_PER_TYPE+1) */

typedef struct {
    const char     *disk_devpart_string;        /* printf() format disk part. name */
    short           disk_controller;    /* controller id or -1 if NA */
    short           disk_device_first;  /* first device id */
    short           disk_device_last;   /* last device id */
    const char     *disk_devfull_string;        /* printf() format full disk name */
    short           disk_partition_first;       /* first partition id */
    short           disk_partition_last;        /* last partition id */
} HRD_disk_t;

static HRD_disk_t disk_devices[MAX_NUMBER_DISK_TYPES];
static int      HR_number_disk_types = 0;

void
Add_HR_Disk_entry(const char *devpart_string,
                  int first_ctl,
                  int last_ctl,
                  int first_dev,
                  int last_dev,
                  const char *devfull_string,
                  int first_partn, int last_partn)
{
    int lodev, hidev, nbr_created = 0;

    while (first_ctl <= last_ctl) {
      for (lodev = first_dev;
           lodev <= last_dev && MAX_NUMBER_DISK_TYPES > HR_number_disk_types;
           lodev += (1+MAX_DISKS_PER_TYPE), HR_number_disk_types++)
      {
        nbr_created++;
        /*
         * Split long runs of disks into separate "types"
         */
        hidev = lodev + MAX_DISKS_PER_TYPE;
        if (last_dev < hidev)
            hidev = last_dev;
        disk_devices[HR_number_disk_types].disk_devpart_string =
            devpart_string;
        disk_devices[HR_number_disk_types].disk_controller = first_ctl;
        disk_devices[HR_number_disk_types].disk_device_first = lodev;
        disk_devices[HR_number_disk_types].disk_device_last = hidev;
        disk_devices[HR_number_disk_types].disk_devfull_string =
            devfull_string;
        disk_devices[HR_number_disk_types].disk_partition_first =
            first_partn;
        disk_devices[HR_number_disk_types].disk_partition_last =
            last_partn;
#ifdef DEBUG_TEST
        DEBUGMSGTL(("host/hr_disk",
                    "Add_HR %02d '%s' first=%d last=%d\n",
                    HR_number_disk_types, devpart_string, lodev, hidev));
#endif
      }
      first_ctl++;
    }

    if (nbr_created == 0 || MAX_NUMBER_DISK_TYPES < HR_number_disk_types) {
        HR_number_disk_types = MAX_NUMBER_DISK_TYPES;
        DEBUGMSGTL(("host/hr_disk",
                    "WARNING! Add_HR_Disk_entry '%s' incomplete, %d created\n",
                    devpart_string, nbr_created));
    }
#ifdef DEBUG_TEST
    else
        DEBUGMSGTL(("host/hr_disk",
                    "Add_HR_Disk_entry '%s' completed, %d created\n",
                    devpart_string, nbr_created));
#endif
}

void
Init_HR_Disk(void)
{
    HRD_type_index = 0;
    HRD_index = -1;
    DEBUGMSGTL(("host/hr_disk", "Init_Disk\n"));
}

int
Get_Next_HR_Disk(void)
{
    char            string[PATH_MAX+1];
    int             fd, result;
    int             iindex;
    int             max_disks;
    time_t          now;

    HRD_index++;
    time(&now);
    DEBUGMSGTL(("host/hr_disk", "Next_Disk type %d of %d\n",
                HRD_type_index, HR_number_disk_types));
    while (HRD_type_index < HR_number_disk_types) {
        max_disks = disk_devices[HRD_type_index].disk_device_last -
            disk_devices[HRD_type_index].disk_device_first + 1;
        DEBUGMSGTL(("host/hr_disk", "Next_Disk max %d of type %d\n",
                    max_disks, HRD_type_index));

        while (HRD_index < max_disks) {
            iindex = (HRD_type_index << HRDISK_TYPE_SHIFT) + HRD_index;

            /*
             * Check to see whether this device
             *   has been probed for 'recently'
             *   and skip if so.
             * This has a *major* impact on run
             *   times (by a factor of 10!)
             */
            if ((HRD_history[iindex] > 0) &&
                ((now - HRD_history[iindex]) < 60)) {
                HRD_index++;
                continue;
            }

            /*
             * Construct the full device name in "string" 
             */
            if (disk_devices[HRD_type_index].disk_controller != -1) {
                snprintf(string, sizeof(string)-1,
                        disk_devices[HRD_type_index].disk_devfull_string,
                        disk_devices[HRD_type_index].disk_controller,
                        disk_devices[HRD_type_index].disk_device_first +
                        HRD_index);
	    } else if (disk_devices[HRD_type_index].disk_device_first == disk_devices[HRD_type_index].disk_device_last) {
		/* exact device name */
		snprintf(string, sizeof(string)-1, "%s", disk_devices[HRD_type_index].disk_devfull_string);
            } else {
                snprintf(string, sizeof(string)-1,
                        disk_devices[HRD_type_index].disk_devfull_string,
                        disk_devices[HRD_type_index].disk_device_first +
                        HRD_index);
            }
            string[ sizeof(string)-1 ] = 0;

            DEBUGMSGTL(("host/hr_disk", "Get_Next_HR_Disk: %s (%d/%d)\n",
                        string, HRD_type_index, HRD_index));

            if (HRD_history[iindex] == -1) {
                /*
                 * check whether this device is in the "ignoredisk" list in
                 * the config file. if yes this device will be marked as
                 * invalid for the future, i.e. it won't ever be checked
                 * again.
                 */
                if (match_disk_config(string)) {
                    /*
                     * device name matches entry in ignoredisk list 
                     */
                    DEBUGMSGTL(("host/hr_disk",
                                "Get_Next_HR_Disk: %s ignored\n", string));
                    HRD_history[iindex] = (time_t)LONG_MAX;
                    HRD_index++;
                    continue;
                }
            }

            /*
             * use O_NDELAY to avoid CDROM spin-up and media detection
             * * (too slow) --okir 
             */
            /*
             * at least with HP-UX 11.0 this doesn't seem to work properly
             * * when accessing an empty CDROM device --jsf 
             */
#ifdef O_NDELAY                 /* I'm sure everything has it, but just in case...  --Wes */
            fd = open(string, O_RDONLY | O_NDELAY);
#else
            fd = open(string, O_RDONLY);
#endif
            if (fd != -1) {
                result = Query_Disk(fd, string);
                close(fd);
                if (result != -1) {
                    HRD_history[iindex] = 0;
                    return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) + iindex);
                }
                DEBUGMSGTL(("host/hr_disk",
                            "Get_Next_HR_Disk: can't query %s\n", string));
            }
            else {
                DEBUGMSGTL(("host/hr_disk",
                            "Get_Next_HR_Disk: can't open %s\n", string));
            }
            HRD_history[iindex] = now;
            HRD_index++;
        }
        HRD_type_index++;
        HRD_index = 0;
    }
    HRD_index = -1;
    return -1;
}

int
Get_Next_HR_Disk_Partition(char *string, size_t str_len, int HRP_index)
{
    DEBUGMSGTL(("host/hr_disk", "Next_Partition type %d/%d:%d\n",
                HRD_type_index, HRD_index, HRP_index));

    /*
     * no more partition names => return -1 
     */
    if (disk_devices[HRD_type_index].disk_partition_last -
        disk_devices[HRD_type_index].disk_partition_first + 1
        <= HRP_index) {
        return -1;
    }

    /*
     * Construct the partition name in "string" 
     */
    if (disk_devices[HRD_type_index].disk_controller != -1) {
        snprintf(string, str_len-1,
                disk_devices[HRD_type_index].disk_devpart_string,
                disk_devices[HRD_type_index].disk_controller,
                disk_devices[HRD_type_index].disk_device_first + HRD_index,
                disk_devices[HRD_type_index].disk_partition_first +
                HRP_index);
    } else {
        snprintf(string, str_len-1,
                disk_devices[HRD_type_index].disk_devpart_string,
                disk_devices[HRD_type_index].disk_device_first + HRD_index,
                disk_devices[HRD_type_index].disk_partition_first +
                HRP_index);
    }
    string[ str_len-1 ] = 0;

    DEBUGMSGTL(("host/hr_disk",
                "Get_Next_HR_Disk_Partition: %s (%d/%d:%d)\n", string,
                HRD_type_index, HRD_index, HRP_index));

    return 0;
}

static const char *
describe_disk(int idx)
{
    if (HRD_savedModel[0] == '\0')
        return ("some sort of disk");
    else
        return (HRD_savedModel);
}
