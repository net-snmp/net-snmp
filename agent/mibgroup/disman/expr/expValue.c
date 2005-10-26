/*
 * DisMan Expression MIB:
 *    Core implementation of expression evaluation
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "disman/expr/expExpression.h"
#include "disman/expr/expObject.h"
#include "disman/expr/expValue.h"

#include <ctype.h>


netsnmp_variable_list *
_expValue_evalParam( netsnmp_variable_list *expIdx, int param,
                     oid *suffix, size_t suffix_len )
{
    netsnmp_variable_list *var =
       (netsnmp_variable_list *)SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
    struct expObject  *obj;
    netsnmp_variable_list *val_var  = NULL, *oval_var = NULL;  /* values  */
    netsnmp_variable_list *dd_var   = NULL,  *odd_var = NULL;  /* deltaDs */
    netsnmp_variable_list *cond_var = NULL;               /* conditionals */
    int n;

    /*
     * Retrieve the expObject entry for the requested parameter ...
     */
    if ( !var || !expIdx || !expIdx->next_variable ||
                 !expIdx->next_variable->next_variable )
        return NULL;

    *expIdx->next_variable->next_variable->val.integer = param;
    obj = (struct expObject *)
               netsnmp_tdata_row_entry(
                   netsnmp_tdata_row_get_byidx( expObject_table_data, expIdx ));
    if (!obj) {
        /*
         * No such parameter configured for this expression
         *
         * XXX - Report this (or any other) error via 'var'
         */
        return NULL;
    }
    if ( obj->expObjectSampleType != 1 && obj->old_vars == NULL ) {
        /*
         * Can't calculate delta values until the second pass
         */
        return NULL;
    }


    /*
     * ... locate the varbind(s) relating to the specified suffix ...
     */
    val_var = obj->vars;
    if ( obj->flags & EXP_OBJ_FLAG_OWILD ) {
        /*
         * For a wildcarded object, search for the matching
         *   suffix, walking any other wildcarded values in
         *   parallel at the same time.
         *
         * This relies on the various varbind lists being set
         *   up with exactly the same entries.  A little extra
         *   preparation during the data gathering simplifies
         *   this evaluation code significantly!
         */
        if ( obj->expObjectSampleType != 1 )
            oval_var = obj->old_vars;
        if ( obj->flags & EXP_OBJ_FLAG_DWILD ) {
            dd_var   = obj->dvars;
            odd_var  = obj->old_dvars;
        }
        if ( obj->flags & EXP_OBJ_FLAG_CWILD )
            cond_var = obj->cvars;
       
        n = obj->expObjectID_len;
        while ( val_var ) {
            if ( snmp_oid_compare( val_var->name+n, val_var->name_length-n,
                                   suffix, suffix_len ))
                break;
            val_var = val_var->next_variable;
            if (oval_var)
                oval_var = oval_var->next_variable;
            if (dd_var) {
                dd_var   =  dd_var->next_variable;
                odd_var  = odd_var->next_variable;
            }
            if (cond_var)
                cond_var = cond_var->next_variable;
        }

    }
    if (!val_var) {
        /*
         * No matching entry
         */
        return NULL;
    }
        /*
         * Set up any non-wildcarded values - some
         *   of which may be null. That's fine.
         */
    if (!oval_var)
        oval_var = obj->old_vars;
    if (!dd_var) {
        dd_var   = obj->dvars;
        odd_var  = obj->old_dvars;
    }
    if (!cond_var)
        cond_var = obj->cvars;
    

    /*
     * ... and return the appropriate value.
     */
    if (obj->expObjCond_len &&
        (!cond_var || *cond_var->val.integer == 0)) {
        /*
         * expObjectConditional says no
         */
        return NULL;
    }
    if (dd_var && odd_var &&
        *dd_var->val.integer != *odd_var->val.integer) {
        /*
         * expObjectDeltaD says no
         */
        return NULL;
    }

    /*
     * XXX - May need to check sysUpTime discontinuities
     *            (unless this is handled earlier....)
     */
    switch ( obj->expObjectSampleType ) {
    case 1:
        snmp_clone_var( val_var, var );
        break;
    case 2:
        snmp_set_var_typed_integer( var, ASN_INTEGER /* or UNSIGNED? */,
                              *val_var->val.integer - *oval_var->val.integer );
        break;
    case 3:
        if ( val_var->val_len != oval_var->val_len )
            n = 1;
        else if (memcmp( val_var->val.string, oval_var->val.string,
                                               val_var->val_len ) != 0 )
            n = 1;
        else
            n = 0;
        snmp_set_var_typed_integer( var, ASN_UNSIGNED, n );
    }
    return var;
}

char *
_expValue_insertVar( char *buf, netsnmp_variable_list *var )
{
    char *cp;

    if (!buf || !var)
        return NULL;

    /*
     * XXX - Check how to ensure a "clean" output,
     *       and the OID-related parameters
     */
    if (snprint_value(buf, EXP_STR3_LEN, NULL, 0, var ) < 0) {
        /*
         * Update 'var' with details of the error
         */
        return NULL;  
    }
    
    for (cp=buf; *cp; cp++)
        ;
    return cp;
}

netsnmp_variable_list *
_expValue_evalExpr(  netsnmp_variable_list *expIdx, char *exprRaw,
                     oid *suffix, size_t suffix_len )
{
    char exprAlDente[ EXP_STR3_LEN+1 ];
    char *cp1, *cp2, *cp3;
    netsnmp_variable_list *var = NULL;
    int   n, level;

    if (!expIdx || !exprRaw)
        return NULL;

    /*
     * The expression is evaluated in two stages.
     * First, we simplify ("parboil") the raw expression,
     *   inserting parameter values, and (recursively)
     *   evaluating any parenthesised sub-expressions...
     */

    memset(exprAlDente, 0, sizeof(exprAlDente));
    for (cp1=exprRaw, cp2=exprAlDente; *cp1; ) {
        switch (*cp1) {
        case '$':
            /*
             * Locate the appropriate instance of the specified
             * parameter, and insert the corresponding value.
             */
            cp1++;
            n = atoi( cp1 );
            while (isdigit( *cp1 ))
                cp1++;
            var = _expValue_evalParam( expIdx, n, suffix, suffix_len );
            cp2 = _expValue_insertVar( cp2, var );
            if (var /* && noError */) {
                snmp_free_varbind( var );
                var = NULL;
            }
            break;
        case '(':
            /*
             * Find the matching closing parenthesis,
             * isolate the sub-expression, and recurse.
             */
            level = 1;
            for (cp3=cp1+1; *cp3; cp3++) {
                switch (*cp3) {
                case '(':
                    level++;
                    break;
                case ')':
                    level--;
                    if (level == 0) {
                        /*
                         * Found end of sub-expression, so evaluate it
                         *   and pick up immediately afterwards.
                         */
                        *cp3 = '\0';
                        var = _expValue_evalExpr( expIdx, cp1+1,
                                                  suffix, suffix_len );
                        cp1 = cp3+1;
                    }
                    break;
                }
            }
            if ( level != 0 ) {
                /*
                 * Unbalanced parenthesis - Shouldn't happen
                 */
            }
            cp2 = _expValue_insertVar( cp2, var );
            if (var /* && noError */) {
                snmp_free_varbind( var );
                var = NULL;
            }
            break;
        case ')':
            /*
             * Unbalanced parenthesis - Shouldn't happen
             */
            break;
        default:
            *cp2++ = *cp1++;
            break;
        }
    }

    /*
     * ... then we evaluate the resulting simplified ("al dente")
     *   expression, in the usual manner.
     */
/* XXX - placeholder "evaluation" */
var = (netsnmp_variable_list *)SNMP_MALLOC_TYPEDEF( netsnmp_variable_list );
snmp_set_var_typed_value( var, ASN_OCTET_STR, exprAlDente, strlen(exprAlDente));

    return var;
}



netsnmp_variable_list *
expValue_evaluateExpression( struct expExpression *exp,
                             oid *suffix, size_t suffix_len )
{
    char exprRaw[     EXP_STR3_LEN+1 ];
    netsnmp_variable_list *var;
    netsnmp_variable_list owner_var, name_var, param_var;
    long n;

    if (!exp)
        return NULL;

    /*
     * Set up a varbind list containing the various index values
     *   (including a placeholder for expObjectIndex).
     *
     * This saves having to construct the same index list repeatedly
     */
    memset(&owner_var, 0, sizeof(netsnmp_variable_list));
    memset(&name_var,  0, sizeof(netsnmp_variable_list));
    memset(&param_var, 0, sizeof(netsnmp_variable_list));
    snmp_set_var_typed_value( &owner_var, ASN_OCTET_STR,
                           exp->expOwner, strlen(exp->expOwner));
    snmp_set_var_typed_value( &name_var,  ASN_OCTET_STR,
                           exp->expName,  strlen(exp->expName));
    n = 99; /* dummy value */
    snmp_set_var_typed_value( &param_var, ASN_INTEGER,
                             (u_char*)&n, sizeof(long));
    owner_var.next_variable = &name_var;
    name_var.next_variable  = &param_var;

    /*
     * Make a working copy of the expression, and evaluate it.
     */
    memset(exprRaw, 0,                  sizeof(exprRaw));
    memcpy(exprRaw, exp->expExpression, sizeof(exprRaw));

    var = _expValue_evalExpr( &owner_var, exprRaw, suffix, suffix_len );
    /*
     * Check for errors - and do what ??
     */
    if (var->type != exp->expValueType /* or equivalents */ ) {
        /* XXX - Cast type or throw error ?? */
    }
    return var;
}
