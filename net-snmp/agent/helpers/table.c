/*
 * table.c 
 */

#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <assert.h>

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "table.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

static void table_helper_cleanup(agent_request_info * reqinfo,
                                 request_info * request, int status);
static void table_data_free_func(void *data);

/** @defgroup table table: Helps you implement a table.
 *  @ingroup handler
 *
 *  This handler helps you implement a table by doing some of the
 *  processing for you.
 *  
 *  This handler truly shows the power of the new handler mechanism.
 *  By creating a table handler and injecting it into your calling
 *  chain, or by using the register_table() function to register your
 *  table, you get access to some pre-parsed information.
 *  Specifically, the table handler pulls out the column number and
 *  indexes from the request oid so that you don't have to do the
 *  complex work to do that parsing within your own code.
 *
 *  To do this, the table handler needs to know up front how your
 *  table is structured.  To inform it about this, you fill in a
 *  table_registeration_info structure that is passed to the table
 *  handler.  It contains the asn index types for the table as well as
 *  the minimum and maximum column that should be used.
 *  
 *  @{
 */

/** Given a table_registration_info object, creates a table handler.
 *  You can use this table handler by injecting it into a calling
 *  chain.  When the handler gets called, it'll do processing and
 *  store it's information into the request->parent_data structure.
 */
mib_handler    *
get_table_handler(table_registration_info * tabreq)
{
    mib_handler    *ret = NULL;

    if (!tabreq) {
        snmp_log(LOG_INFO, "get_table_handler(NULL) called\n");
        return NULL;
    }

    ret = create_handler(TABLE_HANDLER_NAME, table_helper_handler);
    if (ret) {
        ret->myvoid = (void *) tabreq;
        tabreq->number_indexes = count_varbinds(tabreq->indexes);
    }
    return ret;
}


/** creates a table handler given the table_registration_info object,
 *  inserts it into the request chain and then calls
 *  register_handler() to register the table into the agent.
 */
int
register_table(handler_registration * reginfo,
               table_registration_info * tabreq)
{
    inject_handler(reginfo, get_table_handler(tabreq));
    return register_handler(reginfo);
}

/** extracts the processed table information from a given request.
 *  call this from subhandlers on a request to extract the processed
 *  request_info information.  The resulting information includes the
 *  index values and the column number.
 */
inline table_request_info *
extract_table_info(request_info * request)
{
    return (table_request_info *)
        request_get_list_data(request, TABLE_HANDLER_NAME);
}

/** extracts the registered table_registration_info object from a
 *  handler_registration object */
table_registration_info *
find_table_registration_info(handler_registration * reginfo)
{
    return (table_registration_info *)
        find_handler_data_by_name(reginfo, TABLE_HANDLER_NAME);
}

/** implements the table helper handler */
int
table_helper_handler(mib_handler * handler,
                     handler_registration * reginfo,
                     agent_request_info * reqinfo, request_info * requests)
{

    request_info   *request;

    table_registration_info *tbl_info;
    int             oid_index_pos = reginfo->rootoid_len + 2;
    int             oid_column_pos = reginfo->rootoid_len + 1;
    int             tmp_idx, tmp_len;
    int             incomplete, out_of_range;
    int             status = SNMP_ERR_NOERROR, need_processing = 0;
    oid            *tmp_name;
    table_request_info *tbl_req_info;
    struct variable_list *vb;

    tbl_info = (table_registration_info *) handler->myvoid;

    if ((!handler->myvoid) || (!tbl_info->indexes)) {
        snmp_log(LOG_INFO, "improperly registered table found\n");

        /*
         * XXX-rks: unregister table? 
         */
        return SNMP_ERR_GENERR;
    }

    DEBUGMSGTL(("helper:table", "Got request for handler %s: base oid:",
                handler->handler_name));
    DEBUGMSGOID(("helper:table", reginfo->rootoid, reginfo->rootoid_len));
    DEBUGMSG(("helper:table", "\n"));

    /*
     * if the agent request info has a state reference, then this is a 
     * later pass of a set request and we can skip all the lookup stuff.
     *
     * xxx-rks: this might break for handlers which only handle one varbind
     * at a time... those handlers should not save data by their handler_name
     * in the agent_request_info. 
     */
    if (agent_get_list_data(reqinfo,handler->next->handler_name)) {
        if (MODE_IS_SET(reqinfo->mode)) {
            return call_next_handler(handler, reginfo, reqinfo, requests);
        } else {
#pragma warning "XXX-rks: memory leak. add cleanup handler?"
            free_agent_data_sets(reqinfo);
        }
    }


    /*
     * loop through requests
     */

    for (request = requests; request; request = request->next) {
        struct variable_list *var = request->requestvb;

        DEBUGMSGOID(("verbose:table", var->name, var->name_length));
        DEBUGMSG(("verbose:table", "\n"));

        if (request->processed) {
            DEBUGMSG(("helper:table", "already processed\n"));
            continue;
        }
        assert(request->status == SNMP_ERR_NOERROR);

        /*
         * this should probably be handled further up 
         */
        if ((reqinfo->mode == MODE_GET) && (var->type != ASN_NULL)) {
          /* valid request if ASN_NULL */
            DEBUGMSGTL(("helper:table",
                        "  GET var type is not ASN_NULL\n"));
            set_request_error(reqinfo, request, SNMP_ERR_WRONGTYPE);
            continue;
        }

        /*
         * check to make sure its in table range 
         */

        out_of_range = 0;
        /*
         * if our root oid is > var->name and this is not a GETNEXT, 
         * then the oid is out of range. (only compare up to shorter 
         * length) 
         */
        if (reginfo->rootoid_len > var->name_length)
            tmp_len = var->name_length;
        else
            tmp_len = reginfo->rootoid_len;
        if (snmp_oid_compare(reginfo->rootoid, reginfo->rootoid_len,
                             var->name, tmp_len) > 0) {
            if (reqinfo->mode == MODE_GETNEXT) {
                if (var->name != var->name_loc)
                    free(var->name);
                snmp_set_var_objid(var, reginfo->rootoid,
                                   reginfo->rootoid_len);
            } else {
                DEBUGMSGTL(("helper:table", "  oid is out of range.\n"));
                out_of_range = 1;
            }
        }
        /*
         * if var->name is longer than the root, make sure it is 
         * table.1 (table.ENTRY).  
         */
        else if ((var->name_length > reginfo->rootoid_len) &&
                 (var->name[reginfo->rootoid_len] != 1)) {
            if ((var->name[reginfo->rootoid_len] < 1) &&
                (reqinfo->mode == MODE_GETNEXT)) {
                var->name[reginfo->rootoid_len] = 1;
                var->name_length = reginfo->rootoid_len;
            } else {
                out_of_range = 1;
                DEBUGMSGTL(("helper:table", "  oid is out of range.\n"));
            }
        }
        /*
         * if it is not in range, then remove it from the request list 
         * because we can't process it. If the request is not a GETNEXT 
         * then set the error to NOSUCHOBJECT so nobody else wastes time
         * trying to process it.  
         */
        if (out_of_range) {
            DEBUGMSGTL(("helper:table", "  Not processed: "));
            DEBUGMSGOID(("helper:table", var->name, var->name_length));
            DEBUGMSG(("helper:table", "\n"));

            if (reqinfo->mode != MODE_GETNEXT) {
                table_helper_cleanup(reqinfo, request,
                                     SNMP_ERR_NOSUCHNAME);
            }
            continue;
        }


        /*
         * * Check column ranges; set-up to pull out indexes from OID. 
         */

        incomplete = 0;
        tbl_req_info = SNMP_MALLOC_TYPEDEF(table_request_info);
        tbl_req_info->reg_info = tbl_info;
        tbl_req_info->indexes = snmp_clone_varbind(tbl_info->indexes);
        tbl_req_info->number_indexes = 0;       /* none yet */
        request_add_list_data(request,
                              create_data_list(TABLE_HANDLER_NAME,
                                               (void *) tbl_req_info,
                                               table_data_free_func));

        if (var->name_length > oid_column_pos) {
            if (var->name[oid_column_pos] < tbl_info->min_column) {
                if(reqinfo->mode == MODE_GETNEXT) {
                    /*
                     * fix column, truncate useless index info 
                     */
                    var->name_length = oid_column_pos;
                    tbl_req_info->colnum = tbl_info->min_column;
                }
                else
                    out_of_range = 1;
            } else if (var->name[oid_column_pos] > tbl_info->max_column)
                out_of_range = 1;

            if(out_of_range) {
                /*
                 * this is out of range...  remove from requests, free
                 * memory 
                 */
                DEBUGMSGTL(("helper:table",
                            "  oid is out of range. Not processed: "));
                DEBUGMSGOID(("helper:table", var->name, var->name_length));
                DEBUGMSG(("helper:table", "\n"));

                if (reqinfo->mode != MODE_GETNEXT) {
                    table_helper_cleanup(reqinfo, request,
                                         SNMP_ERR_NOSUCHNAME);
                }
                continue;
            }
            /*
             * use column verification 
             */
            else if (tbl_info->valid_columns) {
                tbl_req_info->colnum =
                    closest_column(var->name[oid_column_pos],
                                   tbl_info->valid_columns);
                if (tbl_req_info->colnum == 0)
                    continue;
                if (tbl_req_info->colnum != var->name[oid_column_pos]) {
                    /*
                     * different column! truncate useless index info 
                     */
                    var->name_length = oid_column_pos;
                }
            }
            /*
             * var->name_length may have changed - check again 
             */
            if (var->name_length <= oid_column_pos) { /** none available */
                tbl_req_info->index_oid_len = 0;
            } else {
                tbl_req_info->colnum = var->name[oid_column_pos];
                tbl_req_info->index_oid_len =
                    var->name_length - oid_index_pos;
                assert(tbl_req_info->index_oid_len < MAX_OID_LEN);
                memcpy(tbl_req_info->index_oid, &var->name[oid_index_pos],
                       tbl_req_info->index_oid_len * sizeof(oid));
                tmp_name = tbl_req_info->index_oid;
            }
        } else if (reqinfo->mode != MODE_GETNEXT) {
            table_helper_cleanup(reqinfo, request, SNMP_ERR_NOSUCHNAME);
            continue;
        } else {
            tbl_req_info->index_oid_len = 0;
            tbl_req_info->colnum = tbl_info->min_column;
        }

        if (tbl_req_info->index_oid_len == 0) {
            incomplete = 1;
            tmp_len = -1;
        } else
            tmp_len = tbl_req_info->index_oid_len;


        /*
         * for each index type, try to extract the index from var->name
         */

        for (tmp_idx = 0, vb = tbl_req_info->indexes;
             tmp_idx < tbl_info->number_indexes;
             ++tmp_idx, vb = vb->next_variable) {
            if (incomplete && tmp_len) {
                /*
                 * incomplete/illegal OID, set up dummy 0 to parse 
                 */
                DEBUGMSGTL(("helper:table",
                            "  oid indexes not complete: "));
                DEBUGMSGOID(("helper:table", var->name, var->name_length));
                DEBUGMSG(("helper:table", "\n"));

                /*
                 * no sense in trying anymore if this is a GET/SET. 
                 */
                if (reqinfo->mode != MODE_GETNEXT) {
                    table_helper_cleanup(reqinfo, requests,
                                         SNMP_ERR_NOSUCHNAME);
                }
                tmp_len = 0;
                tmp_name = (oid *) & tmp_len;
                break;
            }
            /*
             * try and parse current index 
             */
            if (parse_one_oid_index(&tmp_name, &tmp_len,
                                    vb, 1) != SNMPERR_SUCCESS) {
                incomplete = 1;
                tmp_len = -1;   /* is this necessary? Better safe than
                                 * sorry */
            } else {
                /*
                 * do not count incomplete indexes 
                 */
                if (incomplete)
                    continue;
                ++tbl_req_info->number_indexes; /** got one ok */
                if (tmp_len <= 0) {
                    incomplete = 1;
                    tmp_len = -1;       /* is this necessary? Better safe
                                         * than sorry */
                }
            }
        }                       /** for loop */


        /*
         * do we have sufficent index info to continue?
         */

        if ((reqinfo->mode != MODE_GETNEXT) &&
            ((tbl_req_info->number_indexes != tbl_info->number_indexes) ||
             (tmp_len != -1))) {
            table_helper_cleanup(reqinfo, request, SNMP_ERR_NOSUCHNAME);
        }

        DEBUGIF("helper:table") {
            int             count;
            char            buf[SPRINT_MAX_LEN];
            DEBUGMSGTL(("helper:table", "  column: %d, indexes: %d",
                        tbl_req_info->colnum,
                        tbl_req_info->number_indexes));
            for (vb = tbl_req_info->indexes, count = 0;
                 vb && count < tbl_info->number_indexes;
                 count++, vb = vb->next_variable) {
                sprint_by_type(buf, vb, 0, 0, 0);
                DEBUGMSG(("helper:table",
                            "    index: type=%d, value=%s", vb->type,
                            buf));
            }
            DEBUGMSG(("helper:table","\n"));
        }

        ++need_processing;

    }                           /* for each request */


    /*
     * * call our child access function 
     */
    if (need_processing)
        status = call_next_handler(handler, reginfo, reqinfo, requests);

    return status;
}

/** Builds the result to be returned to the agent given the table information.
 *  Use this function to return results from lowel level handlers to
 *  the agent.  It takes care of building the proper resulting oid
 *  (containing proper indexing) and inserts the result value into the
 *  returning varbind.
 */
int
table_build_result(handler_registration * reginfo,
                   request_info * reqinfo,
                   table_request_info * table_info, u_char type,
                   u_char * result, size_t result_len)
{

    struct variable_list *var;

    if (!reqinfo || !table_info)
        return SNMPERR_GENERR;

    var = reqinfo->requestvb;

    if (var->name != var->name_loc)
        free(var->name);
    var->name = NULL;

    if (table_build_oid(reginfo, reqinfo, table_info) != SNMPERR_SUCCESS)
        return SNMPERR_GENERR;

    snmp_set_var_typed_value(var, type, result, result_len);

    return SNMPERR_SUCCESS;
}

  
/** given a registration info object, a request object and the table
 *  info object it builds the request->requestvb->name oid from the
 *  index values and column information found in the table_info
 *  object.
 */
int
table_build_oid(handler_registration * reginfo,
                request_info * reqinfo, table_request_info * table_info)
{
    oid             tmpoid[MAX_OID_LEN];
    struct variable_list *var;

    if (!reginfo || !reqinfo || !table_info)
        return SNMPERR_GENERR;

    memcpy(tmpoid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));
    tmpoid[reginfo->rootoid_len] = 1;   /** .Entry */
    tmpoid[reginfo->rootoid_len + 1] = table_info->colnum; /** .column */

    var = reqinfo->requestvb;
    if (build_oid(&var->name, &var->name_length,
                  tmpoid, reginfo->rootoid_len + 2, table_info->indexes)
        != SNMPERR_SUCCESS)
        return SNMPERR_GENERR;

    return SNMPERR_SUCCESS;
}

/** Builds an oid from index information.
 */
int
table_build_oid_from_index(handler_registration * reginfo,
                           request_info * reqinfo,
                           table_request_info * table_info)
{
    oid             tmpoid[MAX_OID_LEN];
    struct variable_list *var;
    int             len;

    if (!reginfo || !reqinfo || !table_info)
        return SNMPERR_GENERR;

    var = reqinfo->requestvb;
    len = reginfo->rootoid_len;
    memcpy(tmpoid, reginfo->rootoid, len * sizeof(oid));
    tmpoid[len++] = 1;          /* .Entry */
    tmpoid[len++] = table_info->colnum; /* .column */
    memcpy(&tmpoid[len], table_info->index_oid,
           table_info->index_oid_len * sizeof(oid));
    len += table_info->index_oid_len;
    snmp_clone_mem((void **) &var->name, tmpoid, len * sizeof(oid));
    var->name_length = len;

    return SNMPERR_SUCCESS;
}

/** parses an OID into table indexses */
int
update_variable_list_from_index(table_request_info * tri)
{
    return parse_oid_indexes(tri->index_oid, tri->index_oid_len,
                             tri->indexes);
}

/** builds an oid given a set of indexes. */
int
update_indexes_from_variable_list(table_request_info * tri)
{
    return build_oid_noalloc(tri->index_oid, sizeof(tri->index_oid),
                             &tri->index_oid_len, NULL, 0, tri->indexes);
}

/**
 * checks the original request against the current data being passed in if 
 * its greater than the request oid but less than the current valid
 * return, set the current valid return to the new value.
 * 
 * returns 1 if outvar was replaced with the oid from newvar (success).
 * returns 0 if not. 
 */
int
check_getnext_reply(request_info * request,
                    oid * prefix,
                    size_t prefix_len,
                    struct variable_list *newvar,
                    struct variable_list **outvar)
{
    static oid      myname[MAX_OID_LEN];
    static int      myname_len;

    build_oid_noalloc(myname, MAX_OID_LEN, &myname_len,
                      prefix, prefix_len, newvar);
    /*
     * is the build of the new indexes less than our current result 
     */
    if ((!(*outvar) || snmp_oid_compare(myname + prefix_len,
                                        myname_len - prefix_len,
                                        (*outvar)->name + prefix_len,
                                        (*outvar)->name_length - prefix_len) <
         0)) {
        /*
         * and greater than the requested oid 
         */
        if (snmp_oid_compare(myname, myname_len,
                             request->requestvb->name,
                             request->requestvb->name_length) > 0) {
            /*
             * the new result must be better than the old 
             */
            if (!*outvar)
                *outvar = snmp_clone_varbind(newvar);
            snmp_set_var_objid(*outvar, myname, myname_len);

            return 1;
        }
    }
    return 0;
}

/** @} */

/* internal routines */
void
table_data_free_func(void *data)
{
    table_request_info *info = (table_request_info *) data;
    if (!info)
        return;
    snmp_free_varbind(info->indexes);
    free(info);
}



static void
table_helper_cleanup(agent_request_info * reqinfo, request_info * request,
                     int status)
{
    set_request_error(reqinfo, request, status);
    free_request_data_sets(request);
    request->parent_data = NULL;
}


unsigned int
closest_column(unsigned int current, column_info * valid_columns)
{
    unsigned int    closest = 0;
    char            done = 0;
    char            idx;

    if(valid_columns == NULL)
        return 0;

    do {

        if (valid_columns->isRange) {

            if (current < valid_columns->details.range[0]) {
                if (valid_columns->details.range[0] < closest) {
                    closest = valid_columns->details.range[0];
                }
            } else if (current <= valid_columns->details.range[1]) {
                closest = current;
                done = 1;       /* can not get any closer! */
            }

        } /* range */
        else {                  /* list */

            if (current < valid_columns->details.list[0]) {
                if (valid_columns->details.list[0] < closest)
                    closest = valid_columns->details.list[0];
                continue;
            }

            if (current >
                valid_columns->details.list[valid_columns->list_count])
                continue;       /* not in list range. */

            for (idx = 0; idx < valid_columns->list_count; ++idx) {
                if (current == valid_columns->details.list[idx]) {
                    closest = current;
                    done = 1;   /* can not get any closer! */
                    break;      /* for */
                } else if (current < valid_columns->details.list[idx]) {
                    if (valid_columns->details.list[idx] < closest)
                        closest = valid_columns->details.list[idx];
                    break;      /* list should be sorted */
                }
            }                   /* for */

        }                       /* list */

        valid_columns = valid_columns->next;

    } while (!done && valid_columns);

    return closest;
}

