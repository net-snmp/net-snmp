
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "agent/extend.h"
#include "utilities/execute.h"
#include "struct.h"

oid  extend_table_oid[]  = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 1 };
oid  extend_output_oid[] = { 1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 2 };

netsnmp_table_data                *dinfo;

void init_extend( void )
{
    netsnmp_table_registration_info   *tinfo;
    netsnmp_handler_registration      *reg;

    tinfo = SNMP_MALLOC_TYPEDEF( netsnmp_table_registration_info );
    netsnmp_table_helper_add_indexes( tinfo, ASN_OCTET_STR, 0 );
    tinfo->min_column = COLUMN_EXTEND_COMMAND;
    tinfo->max_column = COLUMN_EXTEND_LAST_COLUMN;

    dinfo = netsnmp_create_table_data( "nsExtendTable" );
    reg   = netsnmp_create_handler_registration(
                "nsExtendTable",  handle_nsExtendTable, 
                extend_table_oid, OID_LENGTH(extend_table_oid),
                HANDLER_CAN_RONLY);
    netsnmp_register_table_data( reg, dinfo, tinfo );

    snmpd_register_config_handler("exec2", extend_parse_config, NULL, NULL);
    snmpd_register_config_handler("sh2",   extend_parse_config, NULL, NULL);
}

int
extend_load_cache(netsnmp_cache *cache, void *magic)
{
    int  out_len = 1024*100;
    char out_buf[ out_len ];
    int  cmd_len = 255*2 + 2;	/* 2 * DisplayStrings */
    char cmd_buf[ cmd_len ];
    int  ret;
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
        extension->numlines = 1;	/* XXX */
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
        extension->output   = NULL;
    }
    extension->out_len  = 0;
    extension->numlines = 0;
}

void
extend_parse_config(const char *token, char *cptr)
{
    char exec_name[STRMAX];
    char exec_command[STRMAX];
    netsnmp_extend     *extension;
    netsnmp_table_row  *row;

    extension = SNMP_MALLOC_TYPEDEF( netsnmp_extend );
    cptr = copy_nword(cptr, exec_name,    sizeof(exec_name));
    cptr = copy_nword(cptr, exec_command, sizeof(exec_command));
    extension->token    = strdup( exec_name );
    extension->command  = strdup( exec_command );
    if (cptr)
        extension->args = strdup( cptr );
    extension->flags    = (NS_EXTEND_FLAGS_ACTIVE | NS_EXTEND_FLAGS_CONFIG);
    if (!strcmp( token, "sh2" ))
        extension->flags |= NS_EXTEND_FLAGS_SHELL;
    extension->cache    = netsnmp_cache_create( 0, extend_load_cache,
                                                   extend_free_cache, NULL, 0 );
    extension->cache->magic = extension;

    row = netsnmp_create_table_data_row();
    row->data = (void *)extension;
    netsnmp_table_row_add_index( row, ASN_OCTET_STR,
                                 exec_name, strlen(exec_name));
    netsnmp_table_data_add_row( dinfo, row);
}


int
handle_nsExtendTable(netsnmp_mib_handler          *handler,
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

        DEBUGMSGTL(( "nsExtendTable", "varbind: "));
        DEBUGMSGOID(("nsExtendTable", request->requestvb->name,
                                      request->requestvb->name_length));
        DEBUGMSG((   "nsExtendTable", "\n"));

        switch (reqinfo->mode) {
        case MODE_GET:
            if ((table_info->colnum >= COLUMN_EXTEND_OUTLEN) &&
                (table_info->colnum <= COLUMN_EXTEND_RESULT)) {

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
            }

            switch (table_info->colnum) {
            case COLUMN_EXTEND_COMMAND:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->command,
                    (extension->command)?strlen(extension->command):0);
                break;
            case COLUMN_EXTEND_ARGS:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->args,
                    (extension->args)?strlen(extension->args):0);
                break;
            case COLUMN_EXTEND_INPUT:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->input,
                    (extension->input)?strlen(extension->input):0);
                break;
            case COLUMN_EXTEND_CACHETIME:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->cache->timeout, sizeof(int));
                break;
            case COLUMN_EXTEND_EXECTYPE:
                i = ((extension->flags & NS_EXTEND_FLAGS_SHELL) ?
                                         NS_EXTEND_ETYPE_SHELL :
                                         NS_EXTEND_ETYPE_EXEC);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;
            case COLUMN_EXTEND_RUNTYPE:
                i = ((extension->flags & NS_EXTEND_FLAGS_WRITEABLE) ?
                                         NS_EXTEND_RTYPE_RWRITE :
                                         NS_EXTEND_RTYPE_RONLY);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;

            case COLUMN_EXTEND_OUTLEN:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->out_len, sizeof(int));
                break;
            case COLUMN_EXTEND_OUTPUT1:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->output,
                    (extension->output)?strlen(extension->output):0);
                break;
            case COLUMN_EXTEND_OUTPUT2:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_OCTET_STR,
                     extension->output,
                    (extension->output)?strlen(extension->output):0);
                break;
            case COLUMN_EXTEND_NUMLINES:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->numlines, sizeof(int));
                break;
            case COLUMN_EXTEND_RESULT:
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&extension->result, sizeof(int));
                break;
            case COLUMN_EXTEND_STORAGE:
                i = ((extension->flags & NS_EXTEND_FLAGS_CONFIG) ?
                                         ST_PERMANENT : ST_VOLATILE);
                snmp_set_var_typed_value(
                     request->requestvb, ASN_INTEGER,
                    (u_char*)&i, sizeof(i));
                break;
            case COLUMN_EXTEND_STATUS:
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
