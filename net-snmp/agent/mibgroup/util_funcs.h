/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

#ifdef IN_UCD_SNMP_SOURCE
#include "struct.h"
#else
#include <ucd-snmp/struct.h>
#endif

void Exit (int);
int shell_command (struct extensible *);
int exec_command (struct extensible *);
int get_exec_output (struct extensible *);
int get_exec_pipes (char *cmd, int *fdIn, int *fdOut, int *pid);
WriteMethod clear_cache;
RETSIGTYPE restart_doit (int);
WriteMethod restart_hook;
void print_mib_oid (oid *, size_t);
void sprint_mib_oid (char *, oid *, size_t);
int header_simple_table (struct variable *, oid *,  size_t *, int,  size_t *, WriteMethod **write_method, int);
int header_generic (struct variable *,oid *,  size_t *, int,  size_t *, WriteMethod **);
int checkmib (struct variable *, oid *,  size_t *, int,  size_t *, WriteMethod **write_method, int);
char *find_field (char *, int);
int parse_miboid (const char *, oid *);
void string_append_int (char *, int);
void wait_on_exec (struct extensible *);

#define     satosin(x)      ((struct sockaddr_in *) &(x))
#define     SOCKADDR(x)     (satosin(x)->sin_addr.s_addr)
#ifndef MIB_STATS_CACHE_TIMEOUT
#define MIB_STATS_CACHE_TIMEOUT 5
#endif

typedef void * mib_table_t;
typedef int(RELOAD)( mib_table_t );
typedef int(COMPARE)(const void*, const void* );
mib_table_t Initialise_Table( int, int, RELOAD, COMPARE);
int  Search_Table( mib_table_t, void*, int);
int  Add_Entry( mib_table_t, void*);
void *Retrieve_Table_Data( mib_table_t, int*);

int marker_uptime( marker_t pm );
int marker_tticks( marker_t pm );
int timeval_uptime( struct timeval *tv );
int timeval_tticks( struct timeval *tv );
#endif /* _MIBGROUP_UTIL_FUNCS_H */
