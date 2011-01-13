#ifndef NET_SNMP_VARBIND_API_H
#define NET_SNMP_VARBIND_API_H

    /**
     *  Library API routines concerned with variable bindings and values.
     */

#include <net-snmp/types.h>

#ifdef __cplusplus
extern          "C" {
#endif

    /* Creation */
    netsnmp_variable_list *
       snmp_pdu_add_variable(netsnmp_pdu *pdu,
                                 const oid * name, size_t name_length,
                                 u_char type,
                                 const void * value, size_t len);
    netsnmp_variable_list *
       snmp_varlist_add_variable(netsnmp_variable_list ** varlist,
                                 const oid * name, size_t name_length,
                                 u_char type,
                                 const void * value, size_t len);
    netsnmp_variable_list *
       snmp_add_null_var(netsnmp_pdu *pdu,
                                 const oid * name, size_t name_length);
    netsnmp_variable_list *
       snmp_clone_varbind(netsnmp_variable_list * varlist);

    /* Setting Values */
    int             snmp_set_var_value(netsnmp_variable_list * var,
                                       const void * value, size_t len);
    int             snmp_set_var_objid(netsnmp_variable_list * var,
                                       const oid * name, size_t name_length);
    int             snmp_set_var_typed_value(netsnmp_variable_list * var,
                                       u_char type,
                                       const void * value, size_t len);
    int             snmp_set_var_typed_integer(netsnmp_variable_list * var,
                                       u_char type, long val);

     /* Output */
    void            print_variable(const oid * objid, size_t objidlen,
                                   const netsnmp_variable_list * variable);
    void           fprint_variable(FILE * fp,
                                   const oid * objid, size_t objidlen,
                                   const netsnmp_variable_list * variable);
    int           snprint_variable(char *buf, size_t buf_len,
                                   const oid * objid, size_t objidlen,
                                   const netsnmp_variable_list * variable);

    void             print_value(const oid * objid, size_t objidlen,
                                 const netsnmp_variable_list * variable);
    void            fprint_value(FILE * fp,
                                 const oid * objid, size_t objidlen,
                                 const netsnmp_variable_list * variable);
    int            snprint_value(char *buf, size_t buf_len,
                                 const oid * objid, size_t objidlen,
                                 const netsnmp_variable_list * variable);

    /* Deletion */
    void            snmp_free_var(    netsnmp_variable_list *var);     /* frees just this one */
    void            snmp_free_varbind(netsnmp_variable_list *varlist); /* frees all in list */

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
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/mib.h>

#endif                          /* NET_SNMP_VARBIND_API_H */
