/*
 * table_iterator.c 
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/** @defgroup table_iterator table_iterator: The table iterator helper is designed to simplify the task of writing a table handler for the net-snmp agent when the data being accessed is not in an oid sorted form and must be accessed externally.
 *  @ingroup table
    Functionally, it is a specialized version of the more
    generic table helper but easies the burden of GETNEXT processing by
    manually looping through all the data indexes retrieved through
    function calls which should be supplied by the module that wishes
    help.  The module the table_iterator helps should, afterwards,
    never be called for the case of "MODE_GETNEXT" and only for the GET
    and SET related modes instead.
 
    The fundamental notion between the table iterator is that it
    allows your code to iterate over each "row" within your data
    storage mechanism, without requiring that it be sorted in a
    SNMP-index-compliant manner.  Through the get_first_data_point and
    get_next_data_point hooks, the table_iterator helper will
    repeatedly call your hooks to find the "proper" row of data that
    needs processing.  The following concepts are important:

      - A loop context is a pointer which indicates where in the
        current processing of a set of rows you currently are.  Allows
	the get_*_data_point routines to move from one row to the next,
	once the iterator handler has identified the appropriate row for
	this request, the job of the loop context is done.  The
        most simple example would be a pointer to an integer which
        simply counts rows from 1 to X.  More commonly, it might be a
        pointer to a linked list node, or someother internal or
        external reference to a data set (file seek value, array
        pointer, ...).  If allocated during iteration, either the
        free_loop_context_at_end (preferably) or the free_loop_context
        pointers should be set.

      - A data context is something that your handler code can use
        in order to retrieve the rest of the data for the needed
        row.  This data can be accessed in your handler via
	netsnmp_extract_iterator_context api with the netsnmp_request_info
	structure that's passed in.
	The important difference between a loop context and a
        data context is that multiple data contexts can be kept by the
        table_iterator helper, where as only one loop context will
        ever be held by the table_iterator helper.  If allocated
        during iteration the free_data_context pointer should be set
        to an appropriate function.
 
    The table iterator operates in a series of steps that call your
    code hooks from your netsnmp_iterator_info registration pointer.
 
      - the get_first_data_point hook is called at the beginning of
        processing.  It should set the variable list to a list of
        indexes for the given table.  It should also set the
        loop_context and maybe a data_context which you will get a
        pointer back to when it needs to call your code to retrieve
        actual data later.  The list of indexes should be returned
        after being update.

      - the get_next_data_point hook is then called repeatedly and is
        passed the loop context and the data context for it to update.
        The indexes, loop context and data context should all be
        updated if more data is available, otherwise they should be
        left alone and a NULL should be returned.  Ideally, it should
        update the loop context without the need to reallocate it.  If
        reallocation is necessary for every iterative step, then the
        free_loop_context function pointer should be set.  If not,
        then the free_loop_context_at_end pointer should be set, which
        is more efficient since a malloc/free will only be performed
        once for every iteration.
 *
 *  @{
 */

#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/serialize.h>
#include <net-snmp/agent/table_iterator.h>
#include <net-snmp/agent/stash_cache.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** returns a netsnmp_mib_handler object for the table_iterator helper */
netsnmp_mib_handler *
netsnmp_get_table_iterator_handler(netsnmp_iterator_info *iinfo)
{
    netsnmp_mib_handler *me =
        netsnmp_create_handler(TABLE_ITERATOR_NAME,
                               netsnmp_table_iterator_helper_handler);

    if (!me || !iinfo)
        return NULL;

    me->myvoid = iinfo;
    return me;
}


/** 
 * Creates and registers a table iterator helper handler calling 
 * netsnmp_create_handler with a handler name set to TABLE_ITERATOR_NAME 
 * and access method, netsnmp_table_iterator_helper_handler.
 *
 * If NOT_SERIALIZED is not defined the function injects the serialize
 * handler into the calling chain prior to calling netsnmp_register_table.
 *
 * @param reginfo is a pointer to a netsnmp_handler_registration struct
 *
 * @param iinfo is a pointer to a netsnmp_iterator_info struct
 *
 * @return MIB_REGISTERED_OK is returned if the registration was a success.
 *	Failures are MIB_REGISTRATION_FAILED, MIB_DUPLICATE_REGISTRATION.
 *	If iinfo is NULL, SNMPERR_GENERR is returned.
 *
 */
int
netsnmp_register_table_iterator(netsnmp_handler_registration *reginfo,
                                netsnmp_iterator_info *iinfo)
{
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_table_iterator_handler(iinfo));
    if (!iinfo)
        return SNMPERR_GENERR;

    return netsnmp_register_table(reginfo, iinfo->table_reginfo);
}

/** extracts the table_iterator specific data from a request.
 * This function extracts the table iterator specific data from a 
 * netsnmp_request_info object.  Calls netsnmp_request_get_list_data
 * with request->parent_data set with data from a request that was added 
 * previously by a module and TABLE_ITERATOR_NAME handler name.
 *
 * @param request the netsnmp request info structure
 *
 * @return a void pointer(request->parent_data->data), otherwise NULL is
 *         returned if request is NULL or request->parent_data is NULL or
 *         request->parent_data object is not found.the net
 *
 */
NETSNMP_INLINE void    *
netsnmp_extract_iterator_context(netsnmp_request_info *request)
{
    return netsnmp_request_get_list_data(request, TABLE_ITERATOR_NAME);
}

/** inserts table_iterator specific data for a newly
 *  created row into a request */
NETSNMP_INLINE void
netsnmp_insert_iterator_context(netsnmp_request_info *request, void *data)
{
    netsnmp_request_info       *req;
    netsnmp_table_request_info *table_info = NULL;
    netsnmp_variable_list      *this_index = NULL;
    netsnmp_variable_list      *that_index = NULL;
    oid      base_oid[] = {0, 0};	/* Make sure index OIDs are legal! */
    oid      this_oid[MAX_OID_LEN];
    oid      that_oid[MAX_OID_LEN];
    size_t   this_oid_len, that_oid_len;

    if (!request)
        return;

    /*
     * We'll add the new row information to any request
     * structure with the same index values as the request
     * passed in (which includes that one!).
     *
     * So construct an OID based on these index values.
     */

    table_info = netsnmp_extract_table_info(request);
    this_index = table_info->indexes;
    build_oid_noalloc(this_oid, MAX_OID_LEN, &this_oid_len,
                      base_oid, 2, this_index);

    /*
     * We need to look through the whole of the request list
     * (as received by the current handler), as there's no
     * guarantee that this routine will be called by the first
     * varbind that refers to this row.
     *   In particular, a RowStatus controlled row creation
     * may easily occur later in the variable list.
     *
     * So first, we rewind to the head of the list....
     */
    for (req=request; req->prev; req=req->prev)
        ;

    /*
     * ... and then start looking for matching indexes
     * (by constructing OIDs from these index values)
     */
    for (; req; req=req->next) {
        table_info = netsnmp_extract_table_info(req);
        that_index = table_info->indexes;
        build_oid_noalloc(that_oid, MAX_OID_LEN, &that_oid_len,
                          base_oid, 2, that_index);
      
        /*
         * This request has the same index values,
         * so add the newly-created row information.
         */
        if (snmp_oid_compare(this_oid, this_oid_len,
                             that_oid, that_oid_len) == 0) {
            netsnmp_request_add_list_data(req,
                netsnmp_create_data_list(TABLE_ITERATOR_NAME, data, NULL));
        }
    }
}

#define TI_REQUEST_CACHE "ti_cache"

typedef struct ti_cache_info_s {
   oid best_match[MAX_OID_LEN];
   size_t best_match_len;
   void *data_context;
   Netsnmp_Free_Data_Context *free_context;
   netsnmp_iterator_info *iinfo;
   netsnmp_variable_list *results;
} ti_cache_info;

static void
netsnmp_free_ti_cache(void *it) {
    ti_cache_info *beer = it;
    if (!it) return;
    if (beer->data_context && beer->free_context) {
            (beer->free_context)(beer->data_context, beer->iinfo);
    }
    if (beer->results) {
        snmp_free_varbind(beer->results);
    }
    free(beer);
}

/* caches information (in the request) we'll need at a later point in time */
static ti_cache_info *
netsnmp_iterator_remember(netsnmp_request_info *request,
                          oid *oid_to_save,
                          size_t oid_to_save_len,
                          void *callback_data_context,
                          void *callback_loop_context,
                          netsnmp_iterator_info *iinfo)
{
    ti_cache_info *ti_info;

    if (!request || !oid_to_save || oid_to_save_len > MAX_OID_LEN)
        return NULL;

    /* extract existing cached state */
    ti_info = netsnmp_request_get_list_data(request, TI_REQUEST_CACHE);

    /* no existing cached state.  make a new one. */
    if (!ti_info) {
        ti_info = SNMP_MALLOC_TYPEDEF(ti_cache_info);
        netsnmp_request_add_list_data(request,
                                      netsnmp_create_data_list
                                      (TI_REQUEST_CACHE,
                                       ti_info,
                                       netsnmp_free_ti_cache));
    }

    /* free existing cache before replacing */
    if (ti_info->data_context && ti_info->free_context)
        (ti_info->free_context)(ti_info->data_context, iinfo);

    /* maybe generate it from the loop context? */
    if (iinfo->make_data_context && !callback_data_context) {
        callback_data_context =
            (iinfo->make_data_context)(callback_loop_context, iinfo);

    }

    /* save data as requested */
    ti_info->data_context = callback_data_context;
    ti_info->free_context = iinfo->free_data_context;
    ti_info->best_match_len = oid_to_save_len;
    ti_info->iinfo = iinfo;
    if (oid_to_save_len)
        memcpy(ti_info->best_match, oid_to_save, oid_to_save_len * sizeof(oid));

    return ti_info;
}    

#define TABLE_ITERATOR_NOTAGAIN 255
/** implements the table_iterator helper */
int
netsnmp_table_iterator_helper_handler(netsnmp_mib_handler *handler,
                                      netsnmp_handler_registration *reginfo,
                                      netsnmp_agent_request_info *reqinfo,
                                      netsnmp_request_info *requests)
{

    netsnmp_table_registration_info *tbl_info;
    netsnmp_table_request_info *table_info = NULL;
    oid             coloid[MAX_OID_LEN];
    size_t          coloid_len;
    int             ret;
    static oid      myname[MAX_OID_LEN];
    size_t          myname_len;
    int             oldmode = 0;
    netsnmp_iterator_info *iinfo;
    int notdone;
    netsnmp_request_info *request, *reqtmp = NULL;
    netsnmp_variable_list *index_search = NULL;
    netsnmp_variable_list *free_this_index_search = NULL;
    void           *callback_loop_context = NULL, *last_loop_context;
    void           *callback_data_context = NULL;
    ti_cache_info  *ti_info = NULL;
    int             request_count = 0;
    netsnmp_oid_stash_node **cinfo = NULL;
    netsnmp_variable_list *old_indexes = NULL, *vb;
    netsnmp_table_registration_info *table_reg_info = NULL;
    int i;
    netsnmp_data_list    *ldata;
    
    iinfo = (netsnmp_iterator_info *) handler->myvoid;
    if (!iinfo || !reginfo || !reqinfo)
        return SNMPERR_GENERR;

    tbl_info = iinfo->table_reginfo;

    /*
     * copy in the table registration oid for later use 
     */
    coloid_len = reginfo->rootoid_len + 2;
    memcpy(coloid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));
    coloid[reginfo->rootoid_len] = 1;   /* table.entry node */

    /*
     * illegally got here if these functions aren't defined 
     */
    if (iinfo->get_first_data_point == NULL ||
        iinfo->get_next_data_point == NULL) {
        snmp_log(LOG_ERR,
                 "table_iterator helper called without data accessor functions\n");
        return SNMP_ERR_GENERR;
    }

    /* preliminary analysis */
    switch (reqinfo->mode) {
    case MODE_GET_STASH:
        cinfo = netsnmp_extract_stash_cache(reqinfo);
        table_reg_info = netsnmp_find_table_registration_info(reginfo);

        /* XXX: move this malloc to stash_cache handler? */
        reqtmp = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
        reqtmp->subtree = requests->subtree;
        table_info = netsnmp_extract_table_info(requests);
        netsnmp_request_add_list_data(reqtmp,
                                      netsnmp_create_data_list
                                      (TABLE_HANDLER_NAME,
                                       (void *) table_info, NULL));

        /* remember the indexes that were originally parsed. */
        old_indexes = table_info->indexes;
        break;

    case MODE_GETNEXT:
        for(request = requests ; request; request = request->next) {
            if (request->processed)
                continue;
            table_info = netsnmp_extract_table_info(request);
            if (table_info->colnum < tbl_info->min_column - 1) {
                /* XXX: optimize better than this */
                /* for now, just increase to colnum-1 */
                /* we need to jump to the lowest result of the min_column
                   and take it, comparing to nothing from the request */
                table_info->colnum = tbl_info->min_column - 1;
            } else if (table_info->colnum > tbl_info->max_column) {
                request->processed = TABLE_ITERATOR_NOTAGAIN;
            }

            ti_info =
                netsnmp_request_get_list_data(request, TI_REQUEST_CACHE);
            if (!ti_info) {
                ti_info = SNMP_MALLOC_TYPEDEF(ti_cache_info);
                netsnmp_request_add_list_data(request,
                                              netsnmp_create_data_list
                                              (TI_REQUEST_CACHE,
                                               ti_info,
                                               netsnmp_free_ti_cache));
            }

            /* XXX: if no valid requests, don't even loop below */
        }
        break;
    }

    /*
     * collect all information for each needed row
     */
    if (reqinfo->mode == MODE_GET ||
        reqinfo->mode == MODE_GETNEXT ||
        reqinfo->mode == MODE_GET_STASH ||
        reqinfo->mode == MODE_SET_RESERVE1) {
        /*
         * Count the number of request in the list,
         *   so that we'll know when we're finished
         */
        for(request = requests ; request; request = request->next)
            request_count++;
        notdone = 1;
        while(notdone) {
            notdone = 0;

            /* find first data point */
            if (!index_search) {
                if (free_this_index_search) {
                    /* previously done */
                    index_search = free_this_index_search;
                } else {
                    table_info = netsnmp_extract_table_info(requests);
                    index_search = snmp_clone_varbind(table_info->indexes);
                    free_this_index_search = index_search;

                    /* setup, malloc search data: */
                    if (!index_search) {
                        /*
                         * hmmm....  invalid table? 
                         */
                        snmp_log(LOG_WARNING,
                                 "invalid index list or failed malloc for table %s\n",
                                 reginfo->handlerName);
                        return SNMP_ERR_NOERROR;
                    }
                }
            }

            index_search =
                (iinfo->get_first_data_point) (&callback_loop_context,
                                               &callback_data_context,
                                               index_search, iinfo);

            /* loop over each data point */
            while(index_search) {

                /* remember to free this later */
                free_this_index_search = index_search;
            
                /* compare against each request*/
                for(request = requests ; request; request = request->next) {
                    if (request->processed)
                        continue;

                    /* XXX: store in an array for faster retrival */
                    table_info = netsnmp_extract_table_info(request);
                    coloid[reginfo->rootoid_len + 1] = table_info->colnum;

                    ti_info =
                        netsnmp_request_get_list_data(request, TI_REQUEST_CACHE);

                    switch(reqinfo->mode) {
                    case MODE_GET:
                    case MODE_SET_RESERVE1:
                        /* looking for exact matches */
                        build_oid_noalloc(myname, MAX_OID_LEN, &myname_len,
                                          coloid, coloid_len, index_search);
                        if (snmp_oid_compare(myname, myname_len,
                                             request->requestvb->name,
                                             request->requestvb->name_length) == 0) {
                            /* keep this */
                            netsnmp_iterator_remember(request,
                                                      myname, myname_len,
                                                      callback_data_context,
                                                      callback_loop_context, iinfo);
                            request_count--;   /* One less to look for */
                        } else {
                            if (iinfo->free_data_context && callback_data_context) {
                                (iinfo->free_data_context)(callback_data_context,
                                                           iinfo);
                            }
                        }
                        break;

                    case MODE_GET_STASH:
                        /* collect data for each column for every row */
                        build_oid_noalloc(myname, MAX_OID_LEN, &myname_len,
                                          coloid, coloid_len, index_search);
                        reqinfo->mode = MODE_GET;
                        ldata =
                            netsnmp_get_list_node(reqtmp->parent_data,
                                                  TABLE_ITERATOR_NAME);
                        if (!ldata) {
                            netsnmp_request_add_list_data(reqtmp,
                                                          netsnmp_create_data_list
                                                          (TABLE_ITERATOR_NAME,
                                                           callback_data_context,
                                                           NULL));
                        } else {
                            /* may have changed */
                            ldata->data = callback_data_context;
                        }

                        table_info->indexes = index_search;
                        for(i = table_reg_info->min_column;
                            i <= (int)table_reg_info->max_column; i++) {
                            myname[reginfo->rootoid_len + 1] = i;
                            table_info->colnum = i;
                            vb = reqtmp->requestvb =
                                SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
                            vb->type = ASN_NULL;
                            snmp_set_var_objid(vb, myname, myname_len);
                            netsnmp_call_next_handler(handler, reginfo,
                                                      reqinfo, reqtmp);
                            reqtmp->requestvb = NULL;
                            reqtmp->processed = 0;
                            if (vb->type != ASN_NULL) { /* XXX, not all */
                                netsnmp_oid_stash_add_data(cinfo, myname,
                                                           myname_len, vb);
                            } else {
                                snmp_free_var(vb);
                            }
                        }
                        reqinfo->mode = MODE_GET_STASH;
                        break;

                    case MODE_GETNEXT:
                        /* looking for "next" matches */
                        if (netsnmp_check_getnext_reply
                            (request, coloid, coloid_len, index_search,
                             &ti_info->results)) {
                            netsnmp_iterator_remember(request,
                                                      ti_info->results->name,
                                                      ti_info->results->name_length,
                                                      callback_data_context,
                                                      callback_loop_context, iinfo);
                            /*
                             *  If we've been told that the rows are sorted,
                             *   then the first valid one we find
                             *   must be the right one.
                             */
                            if (iinfo->flags & NETSNMP_ITERATOR_FLAG_SORTED)
                                request_count--;
                        
                        } else {
                            if (iinfo->free_data_context && callback_data_context) {
                                (iinfo->free_data_context)(callback_data_context,
                                                           iinfo);
                            }
                        }
                        break;

                    case MODE_SET_RESERVE2:
                    case MODE_SET_FREE:
                    case MODE_SET_UNDO:
                    case MODE_SET_COMMIT:
                        /* needed processing already done in RESERVE1 */
                        break;

                    default:
                        snmp_log(LOG_ERR,
                                 "table_iterator called with unsupported mode\n");
                        break;  /* XXX return */
                
                    }
                }

                /* Is there any point in carrying on? */
                if (!request_count)
                    break;
                /* get the next search possibility */
                last_loop_context = callback_loop_context;
                index_search =
                    (iinfo->get_next_data_point) (&callback_loop_context,
                                                  &callback_data_context,
                                                  index_search, iinfo);
                if (iinfo->free_loop_context && last_loop_context &&
                    callback_data_context != last_loop_context) {
                    (iinfo->free_loop_context) (last_loop_context, iinfo);
                    last_loop_context = NULL;
                }
            }

            /* free loop context before going on */
            if (callback_loop_context && iinfo->free_loop_context_at_end) {
                (iinfo->free_loop_context_at_end) (callback_loop_context,
                                                   iinfo);
                callback_loop_context = NULL;
            }

            /* decide which (GETNEXT) requests are not yet filled */
            if (reqinfo->mode == MODE_GETNEXT) {
                for(request = requests ; request; request = request->next) {
                    if (request->processed)
                        continue;
                    ti_info =
                        netsnmp_request_get_list_data(request,
                                                      TI_REQUEST_CACHE);
                    if (!ti_info->results) {
                        table_info = netsnmp_extract_table_info(request);
                        if (table_info->colnum == tbl_info->max_column) {
                            coloid[reginfo->rootoid_len+1] = table_info->colnum+1;
                            snmp_set_var_objid(request->requestvb,
                                               coloid, reginfo->rootoid_len+2);
                            request->processed = TABLE_ITERATOR_NOTAGAIN;
                            break;
                        } else {
                            table_info->colnum++;
                            notdone = 1;
                        }
                    }
                }
            }
        }
    }

    if (reqinfo->mode == MODE_GET ||
        reqinfo->mode == MODE_GETNEXT ||
        reqinfo->mode == MODE_SET_RESERVE1) {
        /* per request last minute processing */
        for(request = requests ; request; request = request->next) {
            if (request->processed)
                continue;
            ti_info =
                netsnmp_request_get_list_data(request, TI_REQUEST_CACHE);
            table_info =
                netsnmp_extract_table_info(request);

            if (!ti_info)
                continue;
        
            switch(reqinfo->mode) {

            case MODE_GETNEXT:
                if (ti_info->best_match_len)
                    snmp_set_var_objid(request->requestvb, ti_info->best_match,
                                       ti_info->best_match_len);
                else {
                    coloid[reginfo->rootoid_len+1] = table_info->colnum+1;
                    snmp_set_var_objid(request->requestvb,
                                       coloid, reginfo->rootoid_len+2);
                    request->processed = 1;
                }
                snmp_free_varbind(table_info->indexes);
                table_info->indexes = snmp_clone_varbind(ti_info->results);
                /* FALL THROUGH */

            case MODE_GET:
            case MODE_SET_RESERVE1:
                if (ti_info->data_context)
                    /* we don't add a free pointer, since it's in the
                       TI_REQUEST_CACHE instead */
                    netsnmp_request_add_list_data(request,
                                                  netsnmp_create_data_list
                                                  (TABLE_ITERATOR_NAME,
                                                   ti_info->data_context,
                                                   NULL));
                break;
            
            default:
                break;
            }
        }
            
        /* we change all GETNEXT operations into GET operations.
           why? because we're just so nice to the lower levels.
           maybe someday they'll pay us for it.  doubtful though. */
        oldmode = reqinfo->mode;
        if (reqinfo->mode == MODE_GETNEXT) {
            reqinfo->mode = MODE_GET;
        }
    } else if (reqinfo->mode == MODE_GET_STASH) {
        netsnmp_free_request_data_sets(reqtmp);
        SNMP_FREE(reqtmp);
        table_info->indexes = old_indexes;
    }


    /* Finally, we get to call the next handler below us.  Boy, wasn't
       all that simple?  They better be glad they don't have to do it! */
    if (reqinfo->mode != MODE_GET_STASH) {
        DEBUGMSGTL(("table_iterator", "call subhandler for mode: %s\n",
                    se_find_label_in_slist("agent_mode", oldmode)));
        ret =
            netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);
    }

    /* reverse the previously saved mode if we were a getnext */
    if (oldmode == MODE_GETNEXT) {
        reqinfo->mode = oldmode;
    }

    /* cleanup */
    if (free_this_index_search)
        snmp_free_varbind(free_this_index_search);

    return SNMP_ERR_NOERROR;
}

/** @} */
