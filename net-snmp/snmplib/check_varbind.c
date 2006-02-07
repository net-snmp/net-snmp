#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/library/check_varbind.h>

NETSNMP_INLINE int
netsnmp_check_vb_type(netsnmp_variable_list *var, int type )
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if (var->type != type) {
        rc = SNMP_ERR_WRONGTYPE;
    }

    return rc;
}

NETSNMP_INLINE int
netsnmp_check_vb_size(netsnmp_variable_list *var, size_t size )
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    else if (var->val_len != size) {
        rc = SNMP_ERR_WRONGLENGTH;
    }

    return rc;
}

NETSNMP_INLINE int
netsnmp_check_vb_size_range(netsnmp_variable_list *var,
                            size_t low, size_t high )
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((var->val_len < low) || (var->val_len > high)) {
        rc = SNMP_ERR_WRONGLENGTH;
    }

    return rc;
}

NETSNMP_INLINE int
netsnmp_check_vb_type_and_size(netsnmp_variable_list *var,
                               int type, size_t size)
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_type(var,type)))
        ;
    else
        rc = netsnmp_check_vb_size(var, size);

    return rc;
}

NETSNMP_INLINE int
netsnmp_check_vb_int_range(netsnmp_variable_list *var, int low, int high)
{
    register int rc = SNMP_ERR_NOERROR;
    
    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_type_and_size(var, ASN_INTEGER, sizeof(int))))
        return rc;
    
    if ((*var->val.integer < low) || (*var->val.integer > high)) {
        rc = SNMP_ERR_WRONGVALUE;
    }

    return rc;
}

int
netsnmp_check_vb_truthvalue(netsnmp_variable_list *var)
{
    register int rc = SNMP_ERR_NOERROR;
    
    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_type_and_size(var, ASN_INTEGER, sizeof(int))))
        return rc;
    
    return netsnmp_check_vb_int_range(var, 1, 2);
}

NETSNMP_INLINE int
netsnmp_check_vb_rowstatus_value(netsnmp_variable_list *var)
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_type_and_size(var, ASN_INTEGER, sizeof(int))))
        return rc;
    
    return netsnmp_check_vb_int_range(var, SNMP_ROW_NONEXISTENT,
                                      SNMP_ROW_DESTROY);
}

int
netsnmp_check_vb_rowstatus(netsnmp_variable_list *var, int old_value)
{
    register int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_rowstatus_value(var)))
        return rc;

    return check_rowstatus_transition(old_value, *var->val.integer);
}

int
netsnmp_check_vb_storagetype(netsnmp_variable_list *var, int old_value)
{
    int rc = SNMP_ERR_NOERROR;

    if (NULL == var)
        return SNMP_ERR_GENERR;
    
    if ((rc = netsnmp_check_vb_type_and_size(var, ASN_INTEGER, sizeof(int))))
        return rc;
    
    if ((rc = netsnmp_check_vb_int_range(var, SNMP_STORAGE_NONE,
                                        SNMP_STORAGE_READONLY)))
        return rc;
        
    return check_storage_transition(old_value, *var->val.integer);
}
