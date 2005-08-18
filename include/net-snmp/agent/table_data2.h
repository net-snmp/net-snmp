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

    typedef struct netsnmp_table_data2row_s {
        netsnmp_index   oid_index;      /* table_container index format */
        netsnmp_variable_list *indexes; /* stored permanently if store_indexes = 1 */
        void           *data;   /* the data to store */

        struct netsnmp_table_row_s *next, *prev;        /* if used in a list */
    } netsnmp_table_data2row;

    typedef struct netsnmp_table_data2_s {
        netsnmp_variable_list *indexes_template;        /* containing only types */
        char           *name;   /* if !NULL, it's registered globally */
        int             flags;  /* not currently used */
        int             store_indexes;
        netsnmp_container *container;
    } netsnmp_table_data2;

    netsnmp_mib_handler *netsnmp_get_table_data2_handler(netsnmp_table_data2
                                                        *table);
    void            netsnmp_table_data2_generate_index_oid(netsnmp_table_data2row
                                                          *row);
    int             netsnmp_table_data2_add_row(netsnmp_table_data2 *table,
                                               netsnmp_table_data2row *row);
    netsnmp_table_data2row *netsnmp_table_data2_remove_row(netsnmp_table_data2
                                                     *table,
                                                     netsnmp_table_data2row
                                                     *row);
    void           *netsnmp_table_data2_delete_row(netsnmp_table_data2row *row);
    void          
        *netsnmp_table_data2_remove_and_delete_row(netsnmp_table_data2
                                                  *table,
                                                  netsnmp_table_data2row *row);

    netsnmp_table_data2row *netsnmp_table_data2_get(netsnmp_table_data2 *table,
                                              netsnmp_variable_list *
                                              indexes);

    netsnmp_table_data2row *netsnmp_table_data2_get_from_oid(netsnmp_table_data2
                                                       *table,
                                                       oid * searchfor,
                                                       size_t
                                                       searchfor_len);

    netsnmp_table_data2row*
        netsnmp_table_data2_get_first_row(netsnmp_table_data2 *table);
    netsnmp_table_data2row*
        netsnmp_table_data2_get_next_row(netsnmp_table_data2 *table,
                                        netsnmp_table_data2row *row);

    int            
        netsnmp_register_table_data2(netsnmp_handler_registration *reginfo,
                                    netsnmp_table_data2 *table,
                                    netsnmp_table_registration_info
                                    *table_info);
    int            
        netsnmp_register_read_only_table_data2(netsnmp_handler_registration
                                              *reginfo,
                                              netsnmp_table_data2 *table,
                                              netsnmp_table_registration_info
                                              *table_info);

    netsnmp_table_data2row  *netsnmp_extract_table_data2row(netsnmp_request_info *);
    netsnmp_table_data2 *netsnmp_extract_table_data2(    netsnmp_request_info *);
    void           *netsnmp_extract_table_data2row_data2(netsnmp_request_info *request);
    void netsnmp_insert_table_data2row(netsnmp_request_info *, netsnmp_table_data2row *);
    netsnmp_table_data2 *netsnmp_create_table_data2(const char *name);
    netsnmp_table_data2row *netsnmp_create_table_data2_row(void);
    netsnmp_table_data2row *netsnmp_table_data2_clone_row(netsnmp_table_data2row
                                                    *row);
    NETSNMP_INLINE void
       netsnmp_table_data2_replace_row(netsnmp_table_data2 *table,
                                      netsnmp_table_data2row *origrow,
                                      netsnmp_table_data2row *newrow);

    int            
        netsnmp_table_data2_build_result(netsnmp_handler_registration
                                        *reginfo,
                                        netsnmp_agent_request_info
                                        *reqinfo,
                                        netsnmp_request_info *request,
                                        netsnmp_table_data2row *row, int column,
                                        u_char type, u_char * result_data2,
                                        size_t result_data2_len);
    int netsnmp_table_data2_num_rows(netsnmp_table_data2 *table);


#define netsnmp_table_data2_add_index(thetable, type) snmp_varlist_add_variable(&thetable->indexes_template, NULL, 0, type, NULL, 0)
#define netsnmp_table_data2row_add_index(row, type, value, value_len) snmp_varlist_add_variable(&row->indexes, NULL, 0, type, (const u_char *) value, value_len)


    Netsnmp_Node_Handler netsnmp_table_data2_helper_handler;

#ifdef __cplusplus
}
#endif

#endif                          /* _TABLE_DATA2_HANDLER_H_ */
