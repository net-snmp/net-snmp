#ifndef NET_SNMP_MIB_API_H
#define NET_SNMP_MIB_API_H

    /**
     *  Library API routines concerned with MIB files and objects, and OIDs
     */

#include <net-snmp/types.h>

#ifdef __cplusplus
extern          "C" {
#endif

    /* Initialisation and Shutdown */
    void            netsnmp_init_mib(void);
#ifndef NETSNMP_NO_LEGACY_DEFINITIONS
    void            init_mib(void);
    void            init_mib_internals(void);
#endif
    void            shutdown_mib(void);

     /* Reading and Parsing MIBs */
    int             add_mibdir(const char *);
    struct tree    *netsnmp_read_module(const char *);
#ifndef NETSNMP_NO_LEGACY_DEFINITIONS
    struct tree    *read_module(const char *);
#endif
    struct tree    *read_mib(const char *);
    struct tree    *read_all_mibs(void);
    void            add_module_replacement(const char *, const char *,
                                           const char *, int);

         /* from ucd-compat.h */
    void            snmp_set_mib_warnings(int);
    void            snmp_set_mib_errors(int);
    void            snmp_set_save_descriptions(int);


     /* Searching the MIB Tree */
    oid            *snmp_parse_oid(const char *, oid *, size_t *);
    int             read_objid(const char *, oid *, size_t *);
    int             get_module_node(const char *, const char *, oid *, size_t *);

     /* Output */
    void            print_mib(FILE * fp);

    void            print_objid(const oid * objid, size_t objidlen);
    void           fprint_objid(FILE * fp,
                                const oid * objid, size_t objidlen);
    int           snprint_objid(char *buf, size_t buf_len,
                                const oid * objid, size_t objidlen);

    void            print_description(oid * objid, size_t objidlen, int width);
    void           fprint_description(FILE * fp,
                                oid * objid, size_t objidlen, int width);
    int           snprint_description(char *buf, size_t buf_len,
                                oid * objid, size_t objidlen, int width);

#ifdef __cplusplus
}
#endif

    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/mib.h>
#ifndef NETSNMP_DISABLE_MIB_LOADING
#include <net-snmp/library/parse.h>
#endif
#include <net-snmp/library/callback.h>
#include <net-snmp/library/oid_stash.h>
#include <net-snmp/library/ucd_compat.h>

#endif                          /* NET_SNMP_MIB_API_H */
