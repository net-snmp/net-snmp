
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/watcher.h>

#include "agent/extend.h"
#include "utilities/execute.h"
#include "struct.h"

oid  extend_count_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 1 };
oid  extend_config_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 2 };
oid  extend_out1_oid[]  = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 3 };
oid  extend_out2_oid[]  = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 4 };

netsnmp_table_data                *dinfo;
long number_of_entries = 0;
netsnmp_extend *ehead  = NULL;

        /*************************
         *
         *  Main initialisation routine
         *
         *************************/

void init_extend( void )
{
    netsnmp_table_registration_info   *tinfo;
    netsnmp_watcher_info              *winfo;
    netsnmp_handler_registration      *reg;

    dinfo = netsnmp_create_table_data( "nsExtendTable" );

        /*
         * Register the configuration table
         */
    tinfo = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
    netsnmp_table_helper_add_indexes( tinfo, ASN_OCTET_STR, 0 );
    tinfo->min_column = COLUMN_EXTCFG_FIRST_COLUMN;
    tinfo->max_column = COLUMN_EXTCFG_LAST_COLUMN;
    reg   = netsnmp_create_handler_registration(
                "nsExtendConfigTable", handle_nsExtendConfigTable, 
                extend_config_oid, OID_LENGTH(extend_config_oid),
                HANDLER_CAN_RONLY);
    netsnmp_register_table_data( reg, dinfo, tinfo );

        /*
         * Register the main output table
         *   using the same table_data handle.
         * This is sufficient to link the two tables,
         *   and implement the AUGMENTS behaviour
         */
    tinfo = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
    netsnmp_table_helper_add_indexes( tinfo, ASN_OCTET_STR, 0 );
    tinfo->min_column = COLUMN_EXTOUT1_FIRST_COLUMN;
    tinfo->max_column = COLUMN_EXTOUT1_LAST_COLUMN;
    reg   = netsnmp_create_handler_registration(
                "nsExtendOut1Table", handle_nsExtendOutput1Table, 
                extend_out1_oid,  OID_LENGTH(extend_out1_oid),
                HANDLER_CAN_RONLY);
    netsnmp_register_table_data( reg, dinfo, tinfo );

        /*
         * Register the multi-line output table
         *   using a simple table helper.
         * This handles extracting the indexes from
         *   the request OID, but leaves most of
         *   the work to our handler routine.
         * Still, it was nice while it lasted...
         */
    tinfo = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
    netsnmp_table_helper_add_indexes( tinfo, ASN_OCTET_STR, ASN_INTEGER, 0 );
    tinfo->min_column = COLUMN_EXTOUT2_FIRST_COLUMN;
    tinfo->max_column = COLUMN_EXTOUT2_LAST_COLUMN;
    reg   = netsnmp_create_handler_registration(
                "nsExtendOut2Table", handle_nsExtendOutput2Table, 
                extend_out2_oid,  OID_LENGTH(extend_out2_oid),
                HANDLER_CAN_RONLY);
    netsnmp_register_table( reg, tinfo );

        /*
         * Register a watched scalar to keep track of the number of entries
         */
    reg   = netsnmp_create_handler_registration(
                "nsExtendNumEntries", NULL, 
                extend_count_oid, OID_LENGTH(extend_count_oid),
                HANDLER_CAN_RONLY);
    winfo = netsnmp_create_watcher_info(
                &number_of_entries, sizeof(number_of_entries),
                ASN_INTEGER, WATCHER_FIXED_SIZE);
    netsnmp_register_watched_scalar( reg, winfo );

    snmpd_register_config_handler("exec2", extend_parse_config, NULL, NULL);
    snmpd_register_config_handler("sh2",   extend_parse_config, NULL, NULL);
}

        /*************************
         *
         *  Cached-data hooks
         *  see 'cache_handler' helper
         *
         *************************/

int
extend_load_cache(netsnmp_cache *cache, void *magic)
{
    int  out_len = 1024*100;
    char out_buf[ out_len ];
    int  cmd_len = 255*2 + 2;	/* 2 * DisplayStrings */
    char cmd_buf[ cmd_len ];
    int  ret;
    char *cp;
    char *line_buf[ 1024 ];
    netsnmp_extend *extension = (netsnmp_extend *)magic;

    if (!magic)
        return -1;
    DEBUGMSGTL(( "nsExtendTable:cache", "load %s", extension->token ));
    if ( extension->args )
        snprintf( cmd_buf, cmd_len, "%s %s", extension->command, extension->args );
    else 
        snprintf( cmd_buf, cmd_len, "%s", extension->command );
    if ( extension->flags & NS_EXTEND_FLAGS_SHELL )
        ret = run_shell_command( cmd_buf, extension->input, out_buf, &out_len);
    else
        ret = run_exec_command(  cmd_buf, extension->input, out_buf, &out_len);
    DEBUGMSG(( "nsExtendTable:cache", ": %s : %d\n", cmd_buf, ret));
    if (ret >= 0) {
        if (out_buf[   out_len-1 ] == '\n')
            out_buf[ --out_len   ] =  '\0';	/* Stomp on trailing newline */
        extension->output   = strdup( out_buf );
        extension->out_len  = out_len;
        /*
         * Now we need to pick the output apart into separate lines.
         * Start by counting how many lines we've got, and keeping
         * track of where each line starts in a static buffer
         */
        extension->numlines = 1;
        line_buf[ 0 ] = extension->output;
        for (cp=extension->output; *cp; cp++) {
            if (*cp == '\n') {
                line_buf[ extension->numlines++ ] = cp+1;
            }
        }
        if ( extension->numlines > 1 ) {
            extension->lines = calloc( sizeof(char *), extension->numlines );
            memcpy( extension->lines, line_buf,
                                       sizeof(char *) * extension->numlines );
        }
    }
    extension->result = ret;
    return ret;
}

void
extend_free_cache(netsnmp_cache *cache, void *magic)
{
    netsnmp_extend *extension = (netsnmp_extend *)magic;
    if (!magic)
        return;

    DEBUGMSGTL(( "nsExtendTable:cache", "free %s\n", extension->token ));
    if (extension->output) {
        SNMP_FREE(extension->output);
        extension->output = NULL;
    }
    if (extension->lines) {
        SNMP_FREE(extension->lines);
        extension->lines  = NULL;
    }
    extension->out_len  = 0;
    extension->numlines = 0;
}


        /*************************
         *
         *  Utility routines for setting up a new entry
         *  (either via SET requests, or the config file)
         *
         *************************/


netsnmp_extend *
_new_extension( char *exec_name,  char *exec_command,
                 int  exec_flags, char *exec_args )
{
    netsnmp_extend     *extension;
    netsnmp_table_row  *row;
    netsnmp_extend     *eptr1, *eptr2; 

    if (!exec_name || !exec_command)
        return NULL;
    extension = SNMP_MALLOC_TYPEDEF( netsnmp_extend );
    if (!extension)
        return NULL;
    extension->token    = strdup( exec_name );
    extension->command  = strdup( exec_command );
    if (exec_args)
        extension->args = strdup( exec_args );
    extension->flags    = exec_flags;
    extension->cache    = netsnmp_cache_create( 0, extend_load_cache,
                                                   extend_free_cache, NULL, 0 );
    if (extension->cache)
        extension->cache->magic = extension;

    row = netsnmp_create_table_data_row();
    if (!row || !extension->cache) {
        SNMP_FREE( extension->token );
        SNMP_FREE( extension->command );
        SNMP_FREE( extension->args );
        SNMP_FREE( extension->cache );
        SNMP_FREE( extension );
        SNMP_FREE( row );
        return NULL;
    }
    row->data = (void *)extension;
    netsnmp_table_row_add_index( row, ASN_OCTET_STR,
                                 exec_name, strlen(exec_name));
    netsnmp_table_data_add_row( dinfo, row);

    number_of_entries++;
        /*
         *  Now add this structure to a private linked list.
         *  We don't need this for the main tables - the
         *   'table_data' helper will take care of those.
         *  But it's probably easier to handle the multi-line
         *  output table ourselves, for which we need access
         *  to the underlying data.
         *   So we'll keep a list internally as well.
         */
    for ( eptr1 = ehead, eptr2 = NULL;
          eptr1;
          eptr2 = eptr1, eptr1 = eptr1->next ) {

        if (strlen( eptr1->token )  > strlen( exec_name ))
            break;
        if (strlen( eptr1->token ) == strlen( exec_name ) &&
            strcmp( eptr1->token, exec_name ) > 0 )
            break;
    }
    if ( eptr2 )
        eptr2->next = extension;
    else
        ehead       = extension;
    extension->next = eptr1;
    return extension;
}

void
extend_parse_config(const char *token, char *cptr)
{
    char exec_name[STRMAX];
    char exec_command[STRMAX];
    int  flags;

    cptr = copy_nword(cptr, exec_name,    sizeof(exec_name));
    cptr = copy_nword(cptr, exec_command, sizeof(exec_command));
    flags = (NS_EXTEND_FLAGS_ACTIVE | NS_EXTEND_FLAGS_CONFIG);
    if (!strcmp( token, "sh2" ))
        flags |= NS_EXTEND_FLAGS_SHELL;
    (void)_new_extension( exec_name, exec_command, flags, cptr );
}

        /*************************
         *
         *  Main table handlers
         *  Most of the work is handled
         *   by the 'table_data' helper.
         *
         *************************/

int
handle_nsExtendConfigTable(netsnmp_mib_handler          *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info   *reqinfo,
                     netsnmp_request_info         *requests)
{
    netsnmp_request_info       *request;
    netsnmp_table_request_info *table_info;
    netsnmp_extend             *extension;
    int  i;

    for ( request=requests; request; request=request->next ) {
        if (request->processed)
            continue;
        table_info = netsnmp_extract_table_info( request );
        extension  = (netsnmp_extend*)netsnmp_extract_table_row_data( request );

        DEBUGMSGTL(( "nsExtendTable:config", "varbind: "));
        DEBUGMSGOID(("nsExtendTable:config", request->requestvb->name,
                                             request->requestvb->name_length));
        DEBUGMSG((   "nsExtendTable:config", "\n"));

        switch (reqinfo->mode) {
        case MODE_GET:
            switch (table_info->colnum) {
            case COLUMN_EXTCFG_COMMAND:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->command,
                    (extension->command)?strlen(extension->command):0);
                break;
            case COLUMN_EXTCFG_ARGS:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->args,
                    (extension->args)?strlen(extension->args):0);
                break;
            case COLUMN_EXTCFG_INPUT:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->input,
                    (extension->input)?strlen(extension->input):0);
                break;
            case COLUMN_EXTCFG_CACHETIME:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->cache->timeout, sizeof(int));
                break;
            case COLUMN_EXTCFG_EXECTYPE:
                i = ((extension->flags & NS_EXTEND_FLAGS_SHELL) ?
                                         NS_EXTEND_ETYPE_SHELL :
                                         NS_EXTEND_ETYPE_EXEC);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;
            case COLUMN_EXTCFG_RUNTYPE:
                i = ((extension->flags & NS_EXTEND_FLAGS_WRITEABLE) ?
                                         NS_EXTEND_RTYPE_RWRITE :
                                         NS_EXTEND_RTYPE_RONLY);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;

            case COLUMN_EXTCFG_STORAGE:
                i = ((extension->flags & NS_EXTEND_FLAGS_CONFIG) ?
                                         ST_PERMANENT : ST_VOLATILE);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;
            case COLUMN_EXTCFG_STATUS:
                i = ((extension->flags & NS_EXTEND_FLAGS_ACTIVE) ?
                                         RS_ACTIVE :
                                         RS_NOTINSERVICE);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;

            default:
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                continue;
            }
            break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}


int
handle_nsExtendOutput1Table(netsnmp_mib_handler          *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info   *reqinfo,
                     netsnmp_request_info         *requests)
{
    netsnmp_request_info       *request;
    netsnmp_table_request_info *table_info;
    netsnmp_extend             *extension;
    int len;

    for ( request=requests; request; request=request->next ) {
        if (request->processed)
            continue;
        table_info = netsnmp_extract_table_info( request );
        extension  = (netsnmp_extend*)netsnmp_extract_table_row_data( request );

        DEBUGMSGTL(( "nsExtendTable:output1", "varbind: "));
        DEBUGMSGOID(("nsExtendTable:output1", request->requestvb->name,
                                              request->requestvb->name_length));
        DEBUGMSG((   "nsExtendTable:output1", "\n"));

        switch (reqinfo->mode) {
        case MODE_GET:
            if (!(extension->flags & NS_EXTEND_FLAGS_ACTIVE) ||
               (netsnmp_cache_check_and_reload( extension->cache ) < 0 )) {;
                /*
                 * If this row is inactive, or reloading the output
                 * cache fails, then skip the output-related values
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                continue;
            }

            switch (table_info->colnum) {
            case COLUMN_EXTOUT1_OUTLEN:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->out_len, sizeof(int));
                break;
            case COLUMN_EXTOUT1_OUTPUT1:
                /* 
                 * If we've got more than one line,
                 * find the length of the first one.
                 * Otherwise find the length of the whole string.
                 */
                if (extension->lines) {
                    len = (extension->lines[1])-(extension->output) -1;
                } else if (extension->output) {
                    len = strlen(extension->output);
                } else {
                    len = 0;
                }
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->output, len);
                break;
            case COLUMN_EXTOUT1_OUTPUT2:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->output,
                    (extension->output)?strlen(extension->output):0);
                break;
            case COLUMN_EXTOUT1_NUMLINES:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->numlines, sizeof(int));
                break;
            case COLUMN_EXTOUT1_RESULT:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->result, sizeof(int));
                break;
            default:
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                continue;
            }
            break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}


        /*************************
         *
         *  Multi-line output table handler
         *  Most of the work is handled here.
         *
         *************************/


/*
 *  Locate the appropriate entry for a given request
 */
netsnmp_extend *
_extend_find_entry( netsnmp_request_info       *request,
                    netsnmp_table_request_info *table_info,
                    int mode  )
{
    netsnmp_extend *eptr;
    int line_idx;
    oid oid_buf[MAX_OID_LEN];
    int oid_len;
    int i;
    char *token;

    if (!request || !table_info || !table_info->indexes
                 || !table_info->indexes->next_variable) {
        DEBUGMSGTL(( "nsExtendTable:output2", "invalid invocation\n"));
        return NULL;
    }

    /***
     *  GET handling - find the exact entry being requested
     ***/
    if ( mode == MODE_GET ) {
        DEBUGMSGTL(( "nsExtendTable:output2", "GET: %s / %d\n ",
                      table_info->indexes->val.string,
                     *table_info->indexes->next_variable->val.integer));
        for ( eptr = ehead; eptr; eptr = eptr->next ) {
            if ( !strcmp( eptr->token, table_info->indexes->val.string ))
                break;
        }

        if ( eptr ) {
            /*
             * Ensure the output is available...
             */
            if (!(eptr->flags & NS_EXTEND_FLAGS_ACTIVE) ||
               (netsnmp_cache_check_and_reload( eptr->cache ) < 0 ))
                return NULL;

            /*
             * ...and check the line requested is valid
             */
            line_idx = *table_info->indexes->next_variable->val.integer;
            if (eptr->numlines < line_idx)
                return NULL;
        }
        return eptr;
    }

        /***
         *  GETNEXT handling - find the first suitable entry
         ***/
    else {
        if (!table_info->indexes->val_len ) {
            DEBUGMSGTL(( "nsExtendTable:output2", "GETNEXT: first entry\n"));
            /*
             * Beginning of the table - find the first active
             *  (and successful) entry, and use the first line of it
             */
            for (eptr = ehead; eptr; eptr = eptr->next ) {
                if ((eptr->flags & NS_EXTEND_FLAGS_ACTIVE) &&
                    (netsnmp_cache_check_and_reload( eptr->cache ) >= 0 )) {
                    line_idx = 1;
                    break;
                }
            }
        } else {
            token    =  table_info->indexes->val.string,
            line_idx = *table_info->indexes->next_variable->val.integer;
            DEBUGMSGTL(( "nsExtendTable:output2", "GETNEXT: %s / %d\n ",
                          token, line_idx ));
            /*
             * Otherwise, find the first entry not earlier
             * than the requested token...
             */
            for (eptr = ehead; eptr; eptr = eptr->next ) {
                if ( strlen(eptr->token) > strlen( token ))
                    break;
                if ( strlen(eptr->token) == strlen( token ) &&
                     strcmp(eptr->token, token) >= 0 )
                    break;
            }
            if (!eptr)
                return NULL;    /* (assuming there is one) */

            /*
             * ... and make sure it's active & the output is available
             * (or use the first following entry that is)
             */
            for (    ; eptr; eptr = eptr->next ) {
                if ((eptr->flags & NS_EXTEND_FLAGS_ACTIVE) &&
                    (netsnmp_cache_check_and_reload( eptr->cache ) >= 0 )) {
                    break;
                }
                line_idx = 1;
            }

            /*
             *  If we're working with the same entry that was requested,
             *  see whether we've reached the end of the output...
             */
            if (!strcmp( eptr->token, token )) {
                if ( eptr->numlines <= line_idx ) {
                    /*
                     * ... and if so, move on to the first line
                     * of the next (active and successful) entry.
                     */
                    line_idx = 1;
                    for (eptr = eptr->next ; eptr; eptr = eptr->next ) {
                        if ((eptr->flags & NS_EXTEND_FLAGS_ACTIVE) &&
                            (netsnmp_cache_check_and_reload( eptr->cache ) >= 0 )) {
                            break;
                        }
                    }
                } else {
                    /*
                     * Otherwise just use the next line of this entry.
                     */
                    line_idx++;
                }
            }
        }
        if (eptr) {
            DEBUGMSGTL(( "nsExtendTable:output2", "GETNEXT -> %s / %d\n ",
                          eptr->token, line_idx));
            /*
             * Since we're processing a GETNEXT request,
             * now we've found the appropriate entry (and line),
             * we need to update the varbind OID ...
             */
            memcpy( oid_buf, extend_out2_oid, sizeof(extend_out2_oid));
            oid_len = OID_LENGTH(extend_out2_oid);
            oid_buf[ oid_len++ ] = 1;    /* nsExtendOutput2Entry */
            oid_buf[ oid_len++ ] = COLUMN_EXTOUT2_OUTLINE;
                                         /* string token index */
            oid_buf[ oid_len++ ] = strlen(eptr->token);
            for ( i=0; i<strlen(eptr->token); i++ )
                oid_buf[ oid_len+i ] = eptr->token[i];
            oid_len += strlen( eptr->token );
                                         /* plus line number */
            oid_buf[ oid_len++ ] = line_idx;
            snmp_set_var_objid( request->requestvb, oid_buf, oid_len );
            /*
             * ... and index values to match.
             */
            snmp_set_var_value( table_info->indexes,
                                eptr->token, strlen(eptr->token));
            *table_info->indexes->next_variable->val.integer = line_idx;
        }
        return eptr;  /* Finally, signal success */
    }
    return NULL;
}

/*
 *  Multi-line output handler
 *  Locate the appropriate entry (using _extend_find_entry)
 *  and return the appropriate output line
 */
int
handle_nsExtendOutput2Table(netsnmp_mib_handler          *handler,
                     netsnmp_handler_registration *reginfo,
                     netsnmp_agent_request_info   *reqinfo,
                     netsnmp_request_info         *requests)
{
    netsnmp_request_info       *request;
    netsnmp_table_request_info *table_info;
    netsnmp_extend             *extension;
    char *cp;
    int line_idx;
    int len;

    for ( request=requests; request; request=request->next ) {
        if (request->processed)
            continue;

        table_info = netsnmp_extract_table_info( request );
        extension  = _extend_find_entry( request, table_info, reqinfo->mode );

        DEBUGMSGTL(( "nsExtendTable:output2", "varbind: "));
        DEBUGMSGOID(("nsExtendTable:output2", request->requestvb->name,
                                              request->requestvb->name_length));
        DEBUGMSG((   "nsExtendTable:output2", " (%s)\n",
                                    (extension) ? extension->token : "[none]"));

        if (!extension) {
            if (reqinfo->mode == MODE_GET)
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
            else
                netsnmp_set_request_error(reqinfo, request, SNMP_ENDOFMIBVIEW);
            continue;
        }

        switch (reqinfo->mode) {
        case MODE_GET:
        case MODE_GETNEXT:
            switch (table_info->colnum) {
            case COLUMN_EXTOUT2_OUTLINE:
                /* 
                 * Determine which line we've been asked for....
                 */
                line_idx = *table_info->indexes->next_variable->val.integer;
                if (extension->lines)
                    cp  = extension->lines[line_idx-1];
                else
                    cp  = extension->output;

                /* 
                 * ... and how long it is.
                 */
                if ( extension->numlines > line_idx )
                    len = (extension->lines[line_idx])-cp -1;
                else if (cp)
                    len = strlen(cp);
                else
                    len = 0;

                snmp_set_var_typed_value( request->requestvb,
                                          ASN_OCTET_STR, cp, len );
                break;
            default:
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHOBJECT);
                continue;
            }
            break;
        default:
            netsnmp_set_request_error(reqinfo, request, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}
