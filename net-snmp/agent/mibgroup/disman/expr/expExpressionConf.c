/*
 * DisMan Expression MIB:
 *    Implementation of the expression table configuration handling.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "utilities/iquery.h"
#include "disman/expr/expExpression.h"
#include "disman/expr/expExpressionConf.h"

/* Initializes the expExpressionConf module */
void
init_expExpressionConf(void)
{
    init_expr_table_data();

    /*
     * Register config handler for user-level (fixed) expressions...
     *    XXX - TODO
     */

    /*
     * ... and persistent storage of dynamically configured entries.
     */
    snmpd_register_config_handler("_expETable", parse_expETable, NULL, NULL);

    /*
     * Register to save (non-fixed) entries when the agent shuts down
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
                           store_expETable, NULL);
}



/* ================================================
 *
 *  Handlers for loading/storing persistent expression entries
 *
 * ================================================ */

char *
_parse_expECols( char *line, struct expExpression *entry )
{
    void  *vp;
    size_t tmp;
    size_t len;

    len  = EXP_STR3_LEN; vp = entry->expExpression;
    line = read_config_read_data(ASN_OCTET_STR, line,  &vp, &len);

    line = read_config_read_data(ASN_UNSIGNED,  line, &tmp, NULL);
    entry->expValueType = tmp;

    len  = EXP_STR2_LEN; vp = entry->expComment;
    line = read_config_read_data(ASN_OCTET_STR, line,  &vp, &len);

    line = read_config_read_data(ASN_UNSIGNED,  line, &tmp, NULL);
    entry->expDeltaInterval = tmp;

    vp   = entry->expPrefix;
    entry->expPrefix_len = MAX_OID_LEN;
    line = read_config_read_data(ASN_OBJECT_ID, line, &vp,
                                &entry->expPrefix_len);

    line = read_config_read_data(ASN_UNSIGNED, line,  &tmp, NULL);
    entry->flags |= (tmp & EXP_FLAG_ACTIVE);

    return line;
}


void
parse_expETable(const char *token, char *line)
{
    char   owner[EXP_STR1_LEN+1];
    char   ename[EXP_STR1_LEN+1];
    void  *vp;
    size_t len;
    struct expExpression *entry;

    DEBUGMSGTL(("disman:expr:conf", "Parsing mteExpressionTable config...  "));

    /*
     * Read in the index information for this entry
     *  and create a (non-fixed) data structure for it.
     */
    memset( owner, 0, sizeof(owner));
    memset( ename, 0, sizeof(ename));
    len   = EXP_STR1_LEN; vp = owner;
    line  = read_config_read_data(ASN_OCTET_STR, line, &vp,  &len);
    len   = EXP_STR1_LEN; vp = ename;
    line  = read_config_read_data(ASN_OCTET_STR, line, &vp,  &len);
    entry = expExpression_createEntry( owner, ename, 0 );

    DEBUGMSG(("disman:expr:conf", "(%s, %s) ", owner, ename));
    
    /*
     * Read in the accessible column values.
     */
    line = _parse_expECols( line, entry );
    /*
     * XXX - Will need to read in the 'iquery' access information
     */
    entry->flags |= EXP_FLAG_VALID;

    DEBUGMSG(("disman:expr:conf", "\n"));
}


int
store_expETable(int majorID, int minorID, void *serverarg, void *clientarg)
{
    char                  line[SNMP_MAXBUF];
    char                 *cptr;
    void                 *vp;
    size_t                tint;
    netsnmp_tdata_row    *row;
    struct expExpression *entry;


    DEBUGMSGTL(("disman:expr:conf", "Storing expExpressionTable config:\n"));

    for (row = netsnmp_tdata_row_first( expr_table_data );
         row;
         row = netsnmp_tdata_row_next( expr_table_data, row )) {

        /*
         * Skip entries that were set up via static config directives
         */
        entry = (struct expExpression *)netsnmp_tdata_row_entry( row );
        if ( entry->flags & EXP_FLAG_FIXED )
            continue;

        DEBUGMSGTL(("disman:expr:conf", "  Storing (%s %s)\n",
                         entry->expOwner, entry->expName));

        /*
         * Save the basic expExpression entry
         */
        memset(line, 0, sizeof(line));
        strcat(line, "_expETable ");
        cptr = line + strlen(line);

        vp   = entry->expOwner;          tint = strlen( vp );
        cptr = read_config_store_data(   ASN_OCTET_STR, cptr, &vp,  &tint );
        vp   = entry->expName;           tint = strlen( vp );
        cptr = read_config_store_data(   ASN_OCTET_STR, cptr, &vp,  &tint );

        vp   = entry->expExpression;     tint = strlen( vp );
        cptr = read_config_store_data(   ASN_OCTET_STR, cptr, &vp,  &tint );
        tint = entry->expValueType;
        cptr = read_config_store_data(   ASN_UNSIGNED,  cptr, &tint, NULL );
        vp   = entry->expComment;        tint = strlen( vp );
        cptr = read_config_store_data(   ASN_OCTET_STR, cptr, &vp,  &tint );
        tint = entry->expDeltaInterval;
        cptr = read_config_store_data(   ASN_UNSIGNED,  cptr, &tint, NULL );

        vp   = entry->expPrefix;
        tint = entry->expPrefix_len;
        cptr = read_config_store_data(   ASN_OBJECT_ID, cptr, &vp,  &tint );

        tint = entry->flags;
        cptr = read_config_store_data(   ASN_UNSIGNED,  cptr, &tint, NULL );

        /* XXX - Need to store the 'iquery' access information */
        snmpd_store_config(line);
    }

    DEBUGMSGTL(("disman:expr:conf", "  done.\n"));
    return SNMPERR_SUCCESS;
}
