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

#include "table.h"

#define TABLE_ARRAY_NAME "table_array"

/*
 * group_item is to allow us to keep a list of requests without
 * disrupting the actual request_info list.
 */
typedef struct array_group_item_s {
    request_info              *ri;
    table_request_info        *tri;
    struct array_group_item_s *next;
} array_group_item;

/*
 * structure to keep a list of requests for each unique index
 */
typedef struct array_group_s {
    oid_array_header   index;

    oid_array          table;

    oid_array_header   *old_row;
    oid_array_header   *new_row;

    array_group_item   *list;

    int                status;

} array_group;

typedef int (UserOidCompare)(void *lhs, void *rhs);
typedef int (UserGetProcessor)(request_info *, oid_array_header *,
                               table_request_info *);
typedef oid_array_header * (UserRowMethod)(oid_array_header *);
typedef void (UserGroupMethod)( array_group * );

/*
 * structure for array callbacks
 */
typedef struct table_array_callbacks_s {
    /*
     * XXX-rks: UserOidCompare         *compare;
     */
    UserGetProcessor       *get_value;

    UserRowMethod          *create_row;
    UserRowMethod          *duplicate_row;
    UserRowMethod          *delete_row;

    UserGroupMethod        *set_reserve1;
    UserGroupMethod        *set_reserve2;
    UserGroupMethod        *set_action;
    UserGroupMethod        *set_commit;
    UserGroupMethod        *set_free;
    UserGroupMethod        *set_undo;

} table_array_callbacks;


int register_table_array(handler_registration *reginfo,
                         table_registration_info *tabreq,
                         table_array_callbacks   *cb,
                         int                     group_rows);

oid_array *extract_array_context(request_info *);

NodeHandler table_array_helper_handler;

const oid_array_header*
table_array_get_by_index(handler_registration *reginfo,
                         oid_array_header * hdr);

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ARRAY_HANDLER_H_ */
