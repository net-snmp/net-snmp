#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "testhandler.h"
#include "snmp_agent.h"

#include "snmp_api.h"
#include "snmp_client.h"
#include "helpers/table.h"
#include "helpers/instance.h"
#include "helpers/table_data.h"
#include "helpers/table_dataset.h"

static oid my_test_oid[4] = {1,2,3,4};
static oid my_table_oid[4] = {1,2,3,5};
static oid my_instance_oid[5] = {1,2,3,6,1};
static oid my_data_table_oid[4] = {1,2,3,7};
static oid my_data_table_set_oid[4] = {1,2,3,8};
static oid my_data_ulong_instance[4] = {1,2,3,9};

u_long my_ulong=0;

void
init_testhandler(void) {
    /* we're registering at .1.2.3.4 */
    handler_registration *my_test;
    table_registration_info *table_info;
    u_long ind1;
    table_data *table;
    table_data_set *table_set;
    table_row *row;
    
    DEBUGMSGTL(("testhandler", "initializing\n"));

    /*
     * basic handler test
     */
    register_handler(create_handler_registration("myTest", my_test_handler,
                                                 my_test_oid, 4,
                                                 HANDLER_CAN_RONLY));

    /*
     * instance handler test
     */

    register_instance(create_handler_registration("myInstance",
                                                  my_test_instance_handler,
                                                  my_instance_oid, 5,
                                                  HANDLER_CAN_RWRITE));

    register_ulong_instance("myulong",
                            my_data_ulong_instance, 4,
                            &my_ulong);
    
    /*
     * table helper test
     */

    my_test = create_handler_registration("myTable",
                                          my_test_table_handler,
                                          my_table_oid, 4,
                                          HANDLER_CAN_RONLY);
    if (!my_test)
        return;

    table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);

    table_helper_add_index(table_info, ASN_INTEGER);
    table_helper_add_index(table_info, ASN_INTEGER);
    table_info->min_column = 3;
    table_info->max_column = 3;
    register_table(my_test, table_info);

    /*
     * data table helper test
     */
    /* we'll construct a simple table here with two indexes: an
       integer and a string (why not).  It'll contain only one
       column so the data pointer is merely the data in that
       column. */
        
    table = create_table_data("data_table_test");

    table_data_add_index(table, ASN_INTEGER);
    table_data_add_index(table, ASN_OCTET_STR);

    /* 1 partridge in a pear tree */
    row = create_table_data_row();
    ind1 = 1;
    table_row_add_index(row, ASN_INTEGER, &ind1, sizeof(ind1));
    table_row_add_index(row, ASN_OCTET_STR, "partridge",\
                        strlen("partridge"));
    row->data = (void *) "pear tree";
    table_data_add_row(table, row);

    /* 2 turtle doves */
    row = create_table_data_row();
    ind1 = 2;
    table_row_add_index(row, ASN_INTEGER, &ind1, sizeof(ind1));
    table_row_add_index(row, ASN_OCTET_STR, "turtle",\
                        strlen("turtle"));
    row->data = (void *) "doves";
    table_data_add_row(table, row);

    /* we're going to register it as a normal table too, so we get the
       automatically parsed column and index information */
    table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);

    table_helper_add_index(table_info, ASN_INTEGER);
    table_helper_add_index(table_info, ASN_OCTET_STR);
    table_info->min_column = 3;
    table_info->max_column = 3;

    register_read_only_table_data(
        create_handler_registration("12days",
                                    my_data_table_handler,
                                    my_data_table_oid,
                                    4, HANDLER_CAN_RONLY),
        table,
        table_info);

    /*
     * register a full featured, I don't care about the data afterwards table.
     */
    /* It's going to be the "working group chairs" table, since I'm
       sitting at an IETF convention while I'm writing this.

        column 1 = index = string = WG name
        column 2 = string = chair #1
        column 3 = string = chair #2  (most WGs have 2 chairs now)
    */
    table_set = create_table_data_set("chairs");
    
    /* set up what a row "should" look like */
    table_dataset_add_index(table_set, ASN_OCTET_STR);
    table_set_add_default_row(table_set, 2, ASN_OCTET_STR, 1);
    table_set_add_default_row(table_set, 3, ASN_OCTET_STR, 1);

    /* register the table */
    register_table_data_set(create_handler_registration("chairs",
                                                        NULL,
                                                        my_data_table_set_oid,
                                                        4, HANDLER_CAN_RWRITE),
                            table_set, NULL);

    /* add the data, for the first row */
    row = create_table_data_row();
    table_row_add_index(row, ASN_OCTET_STR, "snmpv3",\
                        strlen("snmpv3"));
    set_row_column(row, 2, ASN_OCTET_STR, "Russ Mundy", strlen("Russ Mundy"));
    mark_row_column_writable(row, 2, 1); /* make writable */
    set_row_column(row, 3, ASN_OCTET_STR, "David Harrington",
                   strlen("David Harrington"));
    mark_row_column_writable(row, 3, 1); /* make writable */
    table_dataset_add_row(table_set, row);

    /* add the data, for the second row */
    row = create_table_data_row();
    table_row_add_index(row, ASN_OCTET_STR, "snmpconf",\
                        strlen("snmpconf"));
    set_row_column(row, 2, ASN_OCTET_STR, "David Partain",
                   strlen("David Partain"));
    mark_row_column_writable(row, 2, 1); /* make writable */
    set_row_column(row, 3, ASN_OCTET_STR, "Jon Saperia",
                   strlen("Jon Saperia"));
    mark_row_column_writable(row, 3, 1); /* make writable */
    table_dataset_add_row(table_set, row);
}

int
my_test_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    oid myoid1[] = {1,2,3,4,5,6};
    static u_long accesses = 0;

    DEBUGMSGTL(("testhandler", "Got request:\n"));
    /* loop through requests */
    while(requests) {
        struct variable_list *var = requests->requestvb;

        DEBUGMSGTL(("testhandler", "  oid:"));
        DEBUGMSGOID(("testhandler", var->name,
                     var->name_length));
        DEBUGMSG(("testhandler", "\n"));

        switch(reqinfo->mode) {
            case MODE_GET:
                if (snmp_oid_compare(var->name, var->name_length, myoid1, 6)
                    == 0) {
                    snmp_set_var_typed_value(var, ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                    return SNMP_ERR_NOERROR;
                }
                break;

            case MODE_GETNEXT:
                if (snmp_oid_compare(var->name, var->name_length, myoid1, 6)
                    < 0) {
                    snmp_set_var_objid(var, myoid1, 6);
                    snmp_set_var_typed_value(var, ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                    return SNMP_ERR_NOERROR;
                }
                break;
                
            default:
                set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
                break;
        }

        requests = requests->next;
    }
    return SNMP_ERR_NOERROR;
}

/*
 * functionally this is a simply a multiplication table for 12x12
 */

#define MAX_COLONE 12
#define MAX_COLTWO 12
#define RESULT_COLUMN 3
int
my_test_table_handler(mib_handler               *handler,
                      handler_registration      *reginfo,
                      agent_request_info        *reqinfo,
                      request_info              *requests) {

    table_registration_info
        *handler_reg_info = (table_registration_info *) handler->prev->myvoid;
    table_request_info *table_info;
    u_long result;
    int x, y;
    
    
    while(requests) {
        struct variable_list *var = requests->requestvb;

        if (requests->processed != 0)
            continue;

        DEBUGMSGTL(("testhandler_table", "Got request:\n"));
        DEBUGMSGTL(("testhandler_table", "  oid:"));
        DEBUGMSGOID(("testhandler_table", var->name, var->name_length));
        DEBUGMSG(("testhandler_table", "\n"));

        table_info = extract_table_info(requests);
        if (table_info==NULL) {
            requests = requests->next;
            continue;
        }

        switch(reqinfo->mode) {
            case MODE_GETNEXT:
                /* beyond our search range? */
                if (table_info->colnum > RESULT_COLUMN)
                    break;

                /* below our minimum column? */
                if (table_info->colnum < RESULT_COLUMN ||
                    /* or no index specified */
                    table_info->indexes->val.integer == 0) {
                    table_info->colnum = RESULT_COLUMN;
                    x = 0;
                    y = 0;
                } else {
                    x = *(table_info->indexes->val.integer);
                    y = *(table_info->indexes->next_variable->val.integer);
                }

                if (table_info->number_indexes == handler_reg_info->number_indexes) {
                y++; /* GETNEXT is basically just y+1 for this table */
                if (y > MAX_COLTWO) { /* (with wrapping) */
                    y = 0;
                    x++;
                }
				}
                if (x <= MAX_COLONE) {
                    result = x * y;

                    *(table_info->indexes->val.integer) = x;
                    *(table_info->indexes->next_variable->val.integer) = y;
                    table_build_result(reginfo, requests,
                                       table_info, ASN_INTEGER,
                                       (u_char *) &result,
                                       sizeof(result));
                }
                
                break;
                
            case MODE_GET:
                if (var->type == ASN_NULL) { /* valid request if ASN_NULL */
                    /* is it the right column? */
                    if (table_info->colnum == RESULT_COLUMN &&
                        /* and within the max boundries? */
                        *(table_info->indexes->val.integer) <= MAX_COLONE &&
                        *(table_info->indexes->next_variable->val.integer)
                        <= MAX_COLTWO) {

                        /* then, the result is column1 * column2 */
                        result = *(table_info->indexes->val.integer) *
                            *(table_info->indexes->next_variable->val.integer);
                        snmp_set_var_typed_value(var, ASN_INTEGER,
                                                 (u_char *) &result,
                                                 sizeof(result));
                    }
                }
                break;

        }

        requests = requests->next;
    }

    return SNMP_ERR_NOERROR;
}

#define TESTHANDLER_SET_NAME "my_test"
int
my_test_instance_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    static u_long accesses = 0;
    u_long *accesses_cache = NULL;

    DEBUGMSGTL(("testhandler", "Got instance request:\n"));

    switch(reqinfo->mode) {
        case MODE_GET:
            accesses++;
            snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED,
                                     (u_char *) &accesses,
                                     sizeof(accesses));
            break;

        case MODE_SET_RESERVE1:
            if (requests->requestvb->type != ASN_UNSIGNED)
                set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
            break;

        case MODE_SET_RESERVE2:
            /* store old info for undo later */
            memdup((u_char **) &accesses_cache,
                   (u_char *) &accesses, sizeof(accesses));
            if (accesses_cache == NULL) {
                set_request_error(reqinfo, requests,
                                  SNMP_ERR_RESOURCEUNAVAILABLE);
                return SNMP_ERR_NOERROR;
            }
            request_add_list_data(requests,
                                  create_data_list(TESTHANDLER_SET_NAME,
                                                   accesses_cache, free));
            break;

        case MODE_SET_ACTION:
            /* update current */
            accesses = *(requests->requestvb->val.integer);
            DEBUGMSGTL(("testhandler","updated accesses -> %d\n", accesses));
            break;
            
        case MODE_SET_UNDO:
            accesses =
                *((u_long *) request_get_list_data(requests,
                                                   TESTHANDLER_SET_NAME));
            break;

        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
                /* nothing to do */
            break;
    }
    
    return SNMP_ERR_NOERROR;
}

int
my_data_table_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    char *column3;
    table_request_info *table_info;
    table_row *row;
    
    while(requests) {
        if (requests->processed)
            continue;

        /* extract our stored data and table info */
        row = extract_table_row(requests);
        table_info = extract_table_info(requests);
        if (row)
            column3 = (char *) row->data;
        if (!row || !table_info || !column3)
            continue;
        
        /* there's only one column, we don't need to check if it's right */
        table_data_build_result(reginfo, reqinfo, requests, row,
                                table_info->colnum,
                                ASN_OCTET_STR, column3, strlen(column3));
        requests = requests->next;
    }
    return SNMP_ERR_NOERROR;
}
