/*
 *  Template MIB group interface - file.h
 *
 */
#ifndef _MIBGROUP_FILE_H
#define _MIBGROUP_FILE_H

extern u_char *var_file_table();

/* config file parsing routines */
void file_free_config __P((void));
void file_parse_config __P((char *, char *));
config_parse_dot_conf("file", file_parse_config, file_free_config);

#include "mibdefs.h"
#include "../humlan.h"

struct filestat
{
    char name[256];
    int size;
    int max;
};

#define FILE_ERROR_MSG  "%s: size exceeds %d (%d)"

#define FILE_INDEX      1
#define FILE_NAME       2
#define FILE_SIZE       3
#define FILE_MAX        4
#define FILE_ERROR      100
#define FILE_MSG        101

#ifdef IN_SNMP_VARS_C

struct variable2 file_table[] = 
{
    {FILE_INDEX,  ASN_INTEGER,   RONLY, var_file_table, 1, {1}},
    {FILE_NAME,   ASN_OCTET_STR, RONLY, var_file_table, 1, {2}},
    {FILE_SIZE,   ASN_INTEGER,   RONLY, var_file_table, 1, {3}},
    {FILE_MAX,    ASN_INTEGER,   RONLY, var_file_table, 1, {4}},
    {FILE_ERROR,  ASN_INTEGER,   RONLY, var_file_table, 1, {100}},
    {FILE_MSG,    ASN_OCTET_STR, RONLY, var_file_table, 1, {101}}
};

config_load_mib(EXTENSIBLEMIB.14.1, EXTENSIBLENUM+2, file_table);

#endif
#endif /* _MIBGROUP_FILE_H */
