/*
 * table_iterator.h 
 */
#ifndef _TABLE_DATA2_HANDLER_H_
#define _TABLE_DATA2_HANDLER_H_

#ifdef __cplusplus
extern          "C" {
#endif

    /*
     * This helper is designed to completely automate the task of storing
     * tables of data within the agent that are not tied to external data
     * sources (like the kernel, hardware, or other processes, etc).  IE,
     * all rows within a table are expected to be added manually using
     * functions found below.
     */

#define TABLE_DATA2_NAME "table_data2"
#define TABLE_DATA2_ROW  "table_data2"
#define TABLE_DATA2_TABLE "table_data2_table"

    /*
     * The (table-independent) per-row data structure
     * This is a wrapper round the table-specific per-row data
     *   structure, which is referred to as a "table entry"
     */
    typedef struct netsnmp_tdata_row_s {
        netsnmp_index   oid_index;      /* table_container index format */
        netsnmp_variable_list *indexes; /* stored permanently if store_indexes = 1 */
        void           *data;   /* the data to store */

        struct netsnmp_tdata_row_s *next, *prev;        /* if used in a list */
    } netsnmp_tdata_row;

    /*
     * The data structure to hold a complete table.
     */
    typedef struct netsnmp_tdata_s {
        netsnmp_variable_list *indexes_template;        /* containing only types */
        char           *name;   /* if !NULL, it's registered globally */
        int             flags;  /* not currently used */
        int             store_indexes;
        netsnmp_container *container;
    } netsnmp_tdata;

/* Backwards compatability with the previous (poorly named) data structures */
typedef  struct netsnmp_tdata_row_s netsnmp_table_data2row;
typedef  struct netsnmp_tdata_s     netsnmp_table_data2;


/*
 * APIs for constructing and manipulating a 'tdata' table
 */
    void            netsnmp_tdata_generate_index_oid(netsnmp_tdata_row *row);
    int             netsnmp_tdata_add_row(      netsnmp_tdata     *table,
                                                netsnmp_tdata_row *row);
    netsnmp_tdata_row *netsnmp_tdata_remove_row(netsnmp_tdata     *table,
                                                netsnmp_tdata_row *row);
    void           *netsnmp_tdata_delete_row(   netsnmp_tdata_row *row);
    void   *netsnmp_tdata_remove_and_delete_row(netsnmp_tdata     *table,
                                                netsnmp_tdata_row *row);

    NETSNMP_INLINE void
       netsnmp_tdata_replace_row(netsnmp_tdata *table,
                                 netsnmp_tdata_row *origrow,
                                 netsnmp_tdata_row *newrow);

    netsnmp_tdata     *netsnmp_tdata_create(const char *name);
    netsnmp_tdata_row *netsnmp_tdata_create_row(void);
    netsnmp_tdata_row *netsnmp_tdata_clone_row(netsnmp_tdata_row *row);

#define netsnmp_tdata_add_index(thetable, type) snmp_varlist_add_variable(&thetable->indexes_template, NULL, 0, type, NULL, 0)
#define netsnmp_tdata_row_add_index(row, type, value, value_len) snmp_varlist_add_variable(&row->indexes, NULL, 0, type, (const u_char *) value, value_len)

/*
 * APIs for working with MIBs built using a 'tdata' table
 */
    netsnmp_mib_handler *netsnmp_get_tdata_handler(netsnmp_tdata *table);
    Netsnmp_Node_Handler netsnmp_tdata_helper_handler;

    int netsnmp_register_tdata(netsnmp_handler_registration *reginfo,
                               netsnmp_tdata                *table,
                               netsnmp_table_registration_info *table_info);
    int netsnmp_register_read_only_tdata(netsnmp_handler_registration *reginfo,
                               netsnmp_tdata                *table,
                               netsnmp_table_registration_info *table_info);

    netsnmp_tdata      *netsnmp_tdata_extract(          netsnmp_request_info *);
    netsnmp_container  *netsnmp_tdata_extract_container(netsnmp_request_info *);
    netsnmp_tdata_row  *netsnmp_tdata_extract_row(      netsnmp_request_info *);
    void               *netsnmp_tdata_extract_entry(    netsnmp_request_info *);

    void netsnmp_insert_tdata_row(netsnmp_request_info *, netsnmp_tdata_row *);


/*
 * APIs for working with the contents of a 'tdata' table
 */
    netsnmp_tdata_row *netsnmp_tdata_get(    netsnmp_tdata         *table,
                                             netsnmp_variable_list *indexes);
    netsnmp_tdata_row *netsnmp_tdata_getnext(netsnmp_tdata         *table,
                                             netsnmp_variable_list *indexes);
    netsnmp_tdata_row *netsnmp_tdata_get_from_oid(netsnmp_tdata    *table,
                                                  oid   *searchfor,
                                                  size_t searchfor_len);
    netsnmp_tdata_row *netsnmp_tdata_get_from_row(netsnmp_tdata     *table,
                                                  netsnmp_tdata_row *row);
    netsnmp_tdata_row *netsnmp_tdata_getnext_from_oid(netsnmp_tdata *table,
                                                  oid   *searchfor,
                                                  size_t searchfor_len);

    netsnmp_tdata_row* netsnmp_tdata_get_first_row(netsnmp_tdata *table);
    netsnmp_tdata_row* netsnmp_tdata_get_next_row( netsnmp_tdata *table,
                                                   netsnmp_tdata_row *row);

    int netsnmp_tdata_compare(            netsnmp_tdata_row     *row,
                                          netsnmp_variable_list *indexes);
    int netsnmp_tdata_compare_subtree(    netsnmp_tdata_row     *row,
                                          netsnmp_variable_list *indexes);
    int netsnmp_tdata_compare_oid(        netsnmp_tdata_row     *row,
                                          oid *compareto, size_t compareto_len);
    int netsnmp_tdata_compare_subtree_oid(netsnmp_tdata_row     *row,
                                          oid *compareto, size_t compareto_len);

    void * netsnmp_tdata_row_entry( netsnmp_tdata_row *row );

    int netsnmp_tdata_num_rows(netsnmp_tdata *table);


#ifdef __cplusplus
}
#endif

#endif                          /* _TABLE_DATA2_HANDLER_H_ */
