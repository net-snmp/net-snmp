/*
 *  Process watching mib group
 */
#ifndef _MIBGROUP_PROC_H
#define _MIBGROUP_PROC_H

config_require(util_funcs);

     void            init_proc(void);

     extern FindVarMethod var_extensible_proc;
     extern WriteMethod fixProcError;
     int sh_count_myprocs(struct myproc *);
     int             sh_count_procs(char *);
#if defined(HAVE_PCRE2_H) || defined(HAVE_PCRE_H)
     int sh_count_procs_by_regex(char *, netsnmp_regex_ptr);
#endif

/*
 * config file parsing routines 
 */
     void            proc_free_config(void);
     void            proc_parse_config(const char *, char *);
     void            procfix_parse_config(const char *, char *);

#endif                          /* _MIBGROUP_PROC_H */
