#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "vacm_context.h"
#include "snmp_agent.h"

#include "snmp_api.h"
#include "snmp_client.h"
#include "helpers/table.h"
#include "helpers/table_iterator.h"

static oid vacm_context_oid[] = {1,3,6,1,6,3,16,1,1};

#define CONTEXTNAME_COLUMN 1

/*
 * return the index data from the first node in the agent's
 * subtree_context_cache list.
 */
struct variable_list *
get_first_context(void **my_loop_context, void **my_data_context,
                  struct variable_list *put_data) {
    subtree_context_cache *context_ptr;
    context_ptr = get_top_context_cache();

    if (!context_ptr)
        return NULL;

    *my_loop_context = context_ptr;
    *my_data_context = context_ptr;

    snmp_set_var_value(put_data, context_ptr->context_name,
                       strlen(context_ptr->context_name));
    return put_data;
}

/*
 * return the next index data from the first node in the agent's
 * subtree_context_cache list.
 */
struct variable_list *
get_next_context(void **my_loop_context,
                 void **my_data_context,
                 struct variable_list *put_data) {
    subtree_context_cache *context_ptr;

    if (!my_loop_context || !*my_loop_context)
        return NULL;
    
    context_ptr = (subtree_context_cache *) (*my_loop_context);
    context_ptr = context_ptr->next;
    *my_loop_context = context_ptr;
    *my_data_context = context_ptr;

    if (!context_ptr)
        return NULL;
    
    snmp_set_var_value(put_data, context_ptr->context_name,
                       strlen(context_ptr->context_name));
    return put_data;
}

void
init_vacm_context(void) {
    /*
     * table vacm_context
     */
    handler_registration *my_handler;
    table_registration_info *table_info;

    my_handler = create_handler_registration("vacm_context",
                                          vacm_context_handler,
                                          vacm_context_oid,
                                          sizeof(vacm_context_oid)/sizeof(oid),
					  HANDLER_CAN_RONLY);
    
    if (!my_handler)
        return;

    table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);

    if (!table_info)
        return;

    table_helper_add_index(table_info, ASN_OCTET_STR)
    table_info->min_column = 1;
    table_info->max_column = 1;
    table_info->get_first_data_point = get_first_context;
    table_info->get_next_data_point = get_next_context;
    register_table_iterator(my_handler, table_info);
}

/*
 * returns a list of known context names
 */

int
vacm_context_handler(mib_handler               *handler,
                     handler_registration      *reginfo,
                     agent_request_info        *reqinfo,
                     request_info              *requests) {
    subtree_context_cache *context_ptr;

    while(requests) {
        struct variable_list *var = requests->requestvb;
        
        if (requests->processed != 0)
            continue;

        
        context_ptr = (subtree_context_cache *)
            extract_iterator_context(requests);
        
        if (context_ptr==NULL) {
            snmp_log(LOG_ERR, "vacm_context_handler called without data\n");
            requests = requests->next;
            continue;
        }

        switch(reqinfo->mode) {
            case MODE_GET:
                /* if here we should have a context_ptr passed in already */
                /* only one column should ever reach us, so don't check it */
                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                         context_ptr->context_name,
                                         strlen(context_ptr->context_name));

                break;

            default:
                /* We should never get here, getnext already have been
                   handled by the table_iterator and we're read_only */
                snmp_log(LOG_ERR, "vacm_context table accessed as mode=%d.  We're improperly registered!", reqinfo->mode);
                break;
                

        }

        requests = requests->next;
    }

    return SNMP_ERR_NOERROR;
}
