/*
 *  Template MIB group interface - disk.h
 *
 */
#ifndef _MIBGROUP_DISK_H
#define _MIBGROUP_DISK_H

void            init_disk(void);

config_require(util_funcs)

     extern FindVarMethod var_extensible_disk;

/*
 * config file parsing routines 
 */
void            disk_free_config(void);
void            disk_parse_config(const char *, char *);
void            disk_parse_config_all(const char *, char *);
void            find_and_add_allDisks(int minpercent);
void            add_device(char *path, char *device,
			   int minspace, int minpercent, int override);
void            modify_disk_parameters(int index, int minspace, 
				       int minpercent);
int             find_disk_and_modify(char *path, int minspace, 
				     int minpercent);
int             disk_exists(char *path);
u_char    *     find_device(char *path);


#include "mibdefs.h"

#define DISKDEVICE 3
#define DISKMINIMUM 4
#define DISKMINPERCENT 5
#define DISKTOTAL 6
#define DISKAVAIL 7
#define DISKUSED 8
#define DISKPERCENT 9
#define DISKPERCENTNODE 10

     struct diskpart {
         char            device[STRMAX];
         char            path[STRMAX];
         int             minimumspace;
         int             minpercent;
     };

#endif                          /* _MIBGROUP_DISK_H */
