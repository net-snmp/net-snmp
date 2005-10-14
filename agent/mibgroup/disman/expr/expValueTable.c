/*
 * DisMan Expression MIB:
 *    Implementation of the expValueTable MIB interface
 * See 'expValue.c' for active evaluation of expressions.
 *
 *  (Based roughly on mib2c.raw-table.conf output)
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "expValue.h"
#include "expValueTable.h"

/** Initializes the expValueTable module */
void
init_expValueTable(void)
{
    static oid  expValueTable_oid[]   = { 1, 3, 6, 1, 2, 1, 90, 1, 3, 1 };
    size_t      expValueTable_oid_len = OID_LENGTH(expValueTable_oid);
    netsnmp_handler_registration *reg;
    netsnmp_table_registration_info *table_info;

    reg =
        netsnmp_create_handler_registration("expValueTable",
                                            expValueTable_handler,
                                            expValueTable_oid,
                                            expValueTable_oid_len,
                                            HANDLER_CAN_RONLY);

    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    netsnmp_table_helper_add_indexes(table_info,
                                     ASN_OCTET_STR, /* expExpressionOwner */
                                     ASN_OCTET_STR, /* expExpressionName  */
                                                    /* expValueInstance   */
                                     ASN_PRIV_IMPLIED_OBJECT_ID,
                                     0);

    table_info->min_column = COLUMN_EXPVALUECOUNTER32VAL;
    table_info->max_column = COLUMN_EXPVALUECOUNTER64VAL;

    netsnmp_register_table(reg, table_info);
    DEBUGMSGTL(("disman:expr:init", "Expression Value Table\n"));
}


netsnmp_variable_list *
expValueTable_getEntry(netsnmp_variable_list * indexes,
                       int mode, unsigned int colnum)
{
    struct expExpression  *exp;
    netsnmp_variable_list *res, *vp, *vp2;
    oid nullInstance[] = {0, 0, 0};
    size_t len;
    unsigned int type = colnum-1; /* column object subIDs and type
                                      enumerations are off by one. */

    if (!indexes || !indexes->next_variable ||
        !indexes->next_variable->next_variable ) {
        /* XXX - Shouldn't happen! */
        return 0;
    }

    if (!indexes->val_len || !indexes->next_variable->val_len ) {
        /*
         * Incomplete expression specification
         */
        if (mode == MODE_GETNEXT || mode == MODE_GETBULK) {
            exp = expExpression_getFirstEntry();
        } else {
            return NULL;        /* No match */
        }
    } else {
        exp = expExpression_getEntry( indexes->val.string,
                                      indexes->next_variable->val.string);
    }

    /*
     * We know what type of value was requested,
     *   so ignore any non-matching expressions.
     */
              /* XXX - force string results */
    while (exp && /*exp->expValueType*/ 6 != type) {
        if (mode != MODE_GETNEXT && mode != MODE_GETBULK) {
            return NULL;        /* Wrong type */
        }
        exp = expExpression_getNextEntry( exp->expOwner, exp->expName );
    }
    if (!exp)
        return NULL;    /* No match (of the required type */


    vp  = indexes->next_variable->next_variable;
    if ( mode == MODE_GET ) {
        /*
         * For a GET request, check that the specified value instance
         *   is appropriate, and evaluate the expression using it
         */
        if ( !vp->val_len )
            return NULL;  /* No instance provided */
        if ( vp->val.objid[0] != 0 )
            return NULL;  /* Invalid instance */

        if (exp->expPrefix_len == 0 ) {
            /*
             * The only valid instance for a non-wildcarded
             *     expression is .0.0.0
             */
            if ( vp->val_len != 3*sizeof(oid) ||
                 vp->val.objid[1] != 0 ||
                 vp->val.objid[2] != 0 )
                return NULL;
            res = expValue_evaluateExpression( exp, NULL, 0 );
        } else {
            /*
             *   Skip the leading '.0'
             */
            res = expValue_evaluateExpression( exp, vp->val.objid+1,
                                           vp->val_len/sizeof(oid)-1);
        }
    } else {
        /*
         * For a GETNEXT request, identify the appropriate next
         *   value instance, and evaluate the expression using
         *   that, updating the index list appropriately.
         */
        if ( vp->val_len > 0 && vp->val.objid[0] != 0 ) {
            return NULL;        /* All valid instances start with .0 */
        }
        if (exp->expPrefix_len == 0 ) {
            /*
             * The only valid instances for GETNEXT on a
             *   non-wildcarded expression are .0 and .0.0
             */
            if ((vp->val_len > 2*sizeof(oid)) ||
                (vp->val_len == 2*sizeof(oid) &&
                      vp->val.objid[1] != 0))
                return NULL;        /* Invalid instance */
     
            snmp_set_var_typed_value( indexes, ASN_OCTET_STR,
                             exp->expOwner, strlen(exp->expOwner));
            snmp_set_var_typed_value( indexes->next_variable, ASN_OCTET_STR,
                             exp->expName, strlen(exp->expName));
            snmp_set_var_typed_value( vp, ASN_PRIV_IMPLIED_OBJECT_ID,
                             (u_char*)nullInstance, 3*sizeof(oid));
            res = expValue_evaluateExpression( exp, NULL, 0 );

        } else {
            if ( vp->val_len == 0 )
                 vp2 = exp->pvars;   /* Use the first instance */
            else {
                 /* XXX - TODO: Search pvars list for the next instance */
                 vp2 = exp->pvars;
            }
            len = vp2->name_length - exp->expPrefix_len;
            snmp_set_var_typed_value( indexes, ASN_OCTET_STR,
                             exp->expOwner, strlen(exp->expOwner));
            snmp_set_var_typed_value( indexes->next_variable, ASN_OCTET_STR,
                             exp->expName, strlen(exp->expName));
            snmp_set_var_typed_value( vp, ASN_PRIV_IMPLIED_OBJECT_ID,
                  (u_char*)(vp2->name+exp->expPrefix_len), len);
            res = expValue_evaluateExpression( exp, vp->val.objid+1, len-1);
        }
    }

    /*
     * XXX - Check that the returned varbind is a valid result.
     *   If it's reporting an error, update the expError info,
     *   release the varbind, and return NULL.
     */
    return res;
}

/** handles requests for the expValueTable table */
int
expValueTable_handler(netsnmp_mib_handler *handler,
                      netsnmp_handler_registration *reginfo,
                      netsnmp_agent_request_info *reqinfo,
                      netsnmp_request_info *requests)
{

    netsnmp_request_info       *request;
    netsnmp_table_request_info *tinfo;
    netsnmp_variable_list      *value;
    oid    expValueOID[] = { 1, 3, 6, 1, 2, 1, 90, 1, 3, 1, 1, 99 };
    size_t expValueOID_len = OID_LENGTH(expValueOID);
    oid   *name_ptr;
    size_t name_buf_len = MAX_OID_LEN;

    DEBUGMSGTL(("disman:expr:mib", "Expression Value Table handler (%d)\n",
                                    reqinfo->mode));
    switch (reqinfo->mode) {
    case MODE_GET:
    case MODE_GETNEXT:
        for (request = requests; request; request = request->next) {
            tinfo = netsnmp_extract_table_info(request);
            value = expValueTable_getEntry(tinfo->indexes,
                                           reqinfo->mode,
                                           tinfo->colnum);
            if (!value) {
                netsnmp_set_request_error(reqinfo, request,
                                         (reqinfo->mode == MODE_GET) ? 
                                                 SNMP_NOSUCHINSTANCE :
                                                 SNMP_ENDOFMIBVIEW);
                continue;
            }
            if ( reqinfo->mode == MODE_GETNEXT ) {
                 /*
                  * Need to update the request varbind OID
                  *   to match the instance just evaluated.
                  * (XXX - Is this the appropriate mechanism?)
                  */
                build_oid( &name_ptr, &name_buf_len,
                           expValueOID, expValueOID_len,
                           tinfo->indexes );
                name_ptr[ expValueOID_len -1 ] = tinfo->colnum;
                snmp_set_var_objid(request->requestvb, name_ptr, name_buf_len);
                SNMP_FREE(name_ptr);
            }

            switch (tinfo->colnum) {
            case COLUMN_EXPVALUECOUNTER32VAL:
                snmp_set_var_typed_integer(request->requestvb, ASN_COUNTER,
                                          *value->val.integer);
                break;
            case COLUMN_EXPVALUEUNSIGNED32VAL:
                snmp_set_var_typed_integer(request->requestvb, ASN_UNSIGNED,
                                          *value->val.integer);
                break;
            case COLUMN_EXPVALUETIMETICKSVAL:
                snmp_set_var_typed_integer(request->requestvb, ASN_TIMETICKS,
                                          *value->val.integer);
                break;
            case COLUMN_EXPVALUEINTEGER32VAL:
                snmp_set_var_typed_integer(request->requestvb, ASN_INTEGER,
                                          *value->val.integer);
                break;
            case COLUMN_EXPVALUEIPADDRESSVAL:
                snmp_set_var_typed_integer(request->requestvb, ASN_IPADDRESS,
                                          *value->val.integer);
                break;
            case COLUMN_EXPVALUEOCTETSTRINGVAL:
                snmp_set_var_typed_value(  request->requestvb, ASN_OCTET_STR,
                                           value->val.string,  value->val_len);
                break;
            case COLUMN_EXPVALUEOIDVAL:
                snmp_set_var_typed_value(  request->requestvb, ASN_OBJECT_ID,
                                   (char *)value->val.objid,   value->val_len);
                break;
            case COLUMN_EXPVALUECOUNTER64VAL:
                snmp_set_var_typed_value(  request->requestvb, ASN_COUNTER64,
                                 (char *)value->val.counter64, value->val_len);
                break;
            }
        }
        break;

    }
    DEBUGMSGTL(("disman:expr:mib", "Expression Value handler - done \n"));
    return SNMP_ERR_NOERROR;
}
