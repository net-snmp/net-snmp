/*
 * table_array.h
 * $Id$
 */
#ifndef _TABLE_ARRAY_HANDLER_H_
#define _TABLE_ARRAY_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* The table array helper is designed to simplify the task of
   writing a table handler for the net-snmp agent when the data being
   accessed is in an oid sorted form and must be accessed externally.

   Functionally, it is a specialized version of the more
   generic table helper but easies the burden of GETNEXT processing by
   retrieving the appropriate row for ead index through
   function calls which should be supplied by the module that wishes
   help.  The module the table_array helps should, afterwards,
   never be called for the case of "MODE_GETNEXT" and only for the GET
   and SET related modes instead.
 */

#include <net-snmp/agent/table.h>

#define TABLE_ARRAY_NAME "table_array"

/*
 * group_item is to allow us to keep a list of requests without
 * disrupting the actual netsnmp_request_info list.
 */
typedef struct netsnmp_netsnmp_array_group_item_s {
    netsnmp_request_info              *ri;
    netsnmp_table_request_info        *tri;
    struct netsnmp_netsnmp_array_group_item_s *next;
} netsnmp_netsnmp_array_group_item;

/*
 * structure to keep a list of requests for each unique index
 */
typedef struct netsnmp_array_group_s {
    netsnmp_oid_array_header   index;

    oid_array          table;

    netsnmp_oid_array_header   *old_row;
    netsnmp_oid_array_header   *new_row;

    netsnmp_netsnmp_array_group_item   *list;

    int                status;

    void               *myvoid;
} netsnmp_array_group;

typedef int (Netsnmp_User_Oid_Compare)(void *lhs, void *rhs);
typedef int (Netsnmp_User_Get_Processor)(netsnmp_request_info *, netsnmp_oid_array_header *,
                               netsnmp_table_request_info *);
typedef netsnmp_oid_array_header * (UserRowMethod)(netsnmp_oid_array_header *);
typedef int (Netsnmp_User_Row_Action)(netsnmp_oid_array_header *, netsnmp_oid_array_header *, netsnmp_array_group *);
typedef void (Netsnmp_User_Group_Method)( netsnmp_array_group * );

/*
 * structure for array callbacks
 */
typedef struct netsnmp_table_array_callbacks_s {
    /*
     * XXX-rks: Netsnmp_User_Oid_Compare         *compare;
     */
    Netsnmp_User_Get_Processor       *get_value;

    Netsnmp_User_Row_Action          *can_activate;
    Netsnmp_User_Row_Action          *can_deactivate;
    Netsnmp_User_Row_Action          *can_delete;

    UserRowMethod          *create_row;
    UserRowMethod          *duplicate_row;
    UserRowMethod          *delete_row;

    Netsnmp_User_Group_Method        *set_reserve1;
    Netsnmp_User_Group_Method        *set_reserve2;
    Netsnmp_User_Group_Method        *set_action;
    Netsnmp_User_Group_Method        *set_commit;
    Netsnmp_User_Group_Method        *set_free;
    Netsnmp_User_Group_Method        *set_undo;

} netsnmp_table_array_callbacks;


int netsnmp_netsnmp_register_table_array(netsnmp_handler_registration *reginfo,
                         netsnmp_table_registration_info *tabreq,
                         netsnmp_table_array_callbacks   *cb,
                         int                     group_rows);

oid_array *netsnmp_extract_array_context(netsnmp_request_info *);

Netsnmp_Node_Handler netsnmp_table_array_helper_handler;

const netsnmp_oid_array_header*
netsnmp_table_array_get_by_index(netsnmp_handler_registration *reginfo,
                         netsnmp_oid_array_header * hdr);

const netsnmp_oid_array_header**
netsnmp_table_array_get_subset(netsnmp_handler_registration *reginfo,
                       netsnmp_oid_array_header * hdr, int * len);


#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ARRAY_HANDLER_H_ */
