/* table_iterator.c */

#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "table.h"
#include "serialize.h"
#include "table_iterator.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/* doesn't work yet, but shouldn't be serialized (for efficiency) */
#undef NOT_SERIALIZED

mib_handler *
get_table_iterator_handler(table_registration_info *tabreq) {
    mib_handler *me=
        create_handler(TABLE_ITERATOR_NAME, table_iterator_helper_handler);
    me->myvoid = tabreq; /* we need it too, but it really is not ours */
    return me;
}

    
int
register_table_iterator(handler_registration *reginfo,
                        table_registration_info *tabreq) {
#ifndef NOT_SERIALIZED
    inject_handler(reginfo, get_serialize_handler());
#endif
    inject_handler(reginfo, get_table_iterator_handler(tabreq));
    return register_table(reginfo, tabreq);
}

int
table_iterator_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {
  
    table_registration_info   *tbl_info;
    oid coloid[MAX_OID_LEN];
    size_t coloid_len;
    int ret;
    static oid myname[MAX_OID_LEN];
    static int myname_len;
    int oldmode;
    
    tbl_info = (table_registration_info *) handler->myvoid;

    /* copy in the table registration oid for later use */
    coloid_len = reginfo->rootoid_len+2;
    memcpy(coloid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));
    coloid[reginfo->rootoid_len] = 1; /* table.entry node */
    
    /* illegally got here if these functions aren't defined */
    if (tbl_info->get_first_data_point == NULL ||
        tbl_info->get_next_data_point == NULL) {
        snmp_log(LOG_ERR, "table_iterator helper called without data accessor functions\n");
        return SNMP_ERR_GENERR;
    }

    /* XXXWWW: deal with SET caching */

#ifdef NOT_SERIALIZED
    while(requests) /* XXX: currently only serialized */
#endif
        {
        /* XXXWWW: optimize by reversing loops (look through data only once) */
        struct variable_list *results = NULL;
        struct variable_list *index_search = NULL; /* WWW: move up? */
        table_request_info *table_info =
            extract_table_info(requests);
        void *callback_loop_context = NULL;
        void *callback_data_context = NULL;
        void *callback_data_keep = NULL;
        
        if (requests->processed != 0) {
#ifdef NOT_SERIALIZED
            continue;
#else
            return SNMP_ERR_NOERROR;
#endif
        }

        if (table_info->colnum > tbl_info->max_column) {
            requests->processed = 1;
#ifdef NOT_SERIALIZED
            break;
#else
            return SNMP_ERR_NOERROR;
#endif
        }
        
        index_search = snmp_clone_varbind(table_info->indexes);

        /* below our minimum column? */
        if (table_info->colnum < tbl_info->min_column) {
            /* XXX: mem leak, index_search vs results */
            results = (tbl_info->get_first_data_point)(&callback_loop_context,
                                                       &callback_data_context,
                                                       index_search);
            if (tbl_info->free_loop_context)
                (tbl_info->free_loop_context)(callback_loop_context);
            goto got_results;
        }

        /* XXX: do "only got some indexes" */
        
        /* find the next legal result to return */
        /* XXX: if loop through everything, these are never free'd
           since iterator returns NULL and thus we forget about
           these */
        index_search = snmp_clone_varbind(table_info->indexes);
        
        /* find the first node */
        index_search = (tbl_info->get_first_data_point)(&callback_loop_context,
                                                        &callback_data_context,
                                                        index_search);

        /* table.entry.column node */
        coloid[reginfo->rootoid_len+1] = table_info->colnum;

        switch(reqinfo->mode) {
            case MODE_GETNEXT:
            case MODE_GETBULK: /* XXXWWW */
                /* loop through all data and find next one */
                while(index_search) {
                    /* compare the node with previous results */
                    if (check_getnext_reply(requests, coloid, coloid_len,
                                            index_search, &results)) {

                        /* result is our current choice, so keep a pointer to
                           the data that the lower handler wants us to
                           remember (possibly freeing the last known "good"
                           result data pointer) */
                        if (callback_data_keep &&
                            tbl_info->free_data_context) {
                            (tbl_info->free_data_context)(callback_data_keep);
                        }
                        callback_data_keep = callback_data_context;

                    } else {
                        if (callback_data_context && tbl_info->free_data_context)
                            (tbl_info->free_data_context)(callback_data_context);
                    }

                    /* get the next node in the data chain */
                    index_search =
                        (tbl_info->get_next_data_point)(&callback_loop_context,
                                                        &callback_data_context,
                                                        index_search);

                    if (!index_search && !results &&
                        tbl_info->max_column > table_info->colnum) {
                        /* restart loop.  XXX: Should cache this better */
                        table_info->colnum++;
                        coloid[reginfo->rootoid_len+1] = table_info->colnum;
                        /* XXX: free old contexts first? */
                        index_search = snmp_clone_varbind(table_info->indexes);
                        index_search =
                            (tbl_info->get_first_data_point)(&callback_loop_context,
                                                             &callback_data_context,
                                                             index_search);
                    }
                }

                break;

            default: /* GET, SET, all the same...  exact search */
                /* loop through all data till exact results are found */
    
                while(index_search) {
                    build_oid_noalloc(myname, MAX_OID_LEN, &myname_len,
                                      coloid, coloid_len, index_search);
                    if (snmp_oid_compare(myname, myname_len,
                                         requests->requestvb->name,
                                         requests->requestvb->name_length) == 0) {
                        /* found the exact match, so we're done */
                        callback_data_keep = callback_data_context;
                        results = snmp_clone_varbind(index_search);
                        snmp_set_var_objid(results, myname, myname_len);
                        goto got_results;
                    } else {
                        /* free not-needed data context */
                        if (callback_data_context && tbl_info->free_data_context)
                            (tbl_info->free_data_context)(callback_data_context);
                    }
                    
                    /* get the next node in the data chain */
                    index_search =
                        (tbl_info->get_next_data_point)(&callback_loop_context,
                                                        &callback_data_context,
                                                        index_search);
                }
        }
        
        /* XXX: free index_search? */
        if (callback_loop_context && tbl_info->free_loop_context)
            (tbl_info->free_loop_context)(callback_loop_context);

      got_results: /* not milk */
        
        if (!results) {
            /* no results found. */
            /* XXX: check for at least one entry at the very top */
#ifdef NOT_SERIALIZED
            break;
#else
            return SNMP_ERR_NOERROR;
#endif
        }
        
        /* OK, here index_search should be a pointer to the data that
                                   we actually need to GET */
        snmp_set_var_objid(requests->requestvb, results->name,
                           results->name_length);
        
        oldmode = reqinfo->mode;
        if (oldmode == MODE_GETNEXT)
            reqinfo->mode = MODE_GET;
        request_add_list_data(requests, create_data_list(TABLE_ITERATOR_NAME, callback_data_keep, NULL));
        ret = call_next_handler(handler, reginfo, reqinfo, requests);
        if (oldmode == MODE_GETNEXT)
            reqinfo->mode = oldmode;

        if (callback_data_keep && tbl_info->free_data_context)
            (tbl_info->free_data_context)(callback_data_keep);
        
#ifdef NOT_SERIALIZED
        return ret;
#else
        requests = requests->next;
#endif
        }
    return SNMP_ERR_NOERROR;
}

inline void *
extract_iterator_context(request_info *request) 
{
    return request_get_list_data(request, TABLE_ITERATOR_NAME);
}
