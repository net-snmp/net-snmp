/*
 * MIBs For Dummies header
 *
 * $Id$
 */
#ifndef NETSNMP_MFD_H
#define NETSNMP_MFD_H

/*----------------------------------------------------------------------
 * general success/failure
 */
#define MFD_SUCCESS              SNMP_ERR_NOERROR
#define MFD_ERROR                SNMP_ERR_GENERR

/*
 * object not currently available
 */
#define MFD_SKIP                 SNMP_NOSUCHINSTANCE

/*
 * no more data in table (get-next)
 */
#define MFD_END_OF_DATA          SNMP_ENDOFMIBVIEW

/*----------------------------------------------------------------------
 * set processing errors
 */
/*
 * row creation errors
 */
#define MFD_CANNOT_CREATE_NOW    SNMP_ERR_INCONSISTENTNAME
#define MFD_CANNOT_CREATE_EVER   SNMP_ERR_NOCREATION

/*
 * not writable or resource unavailable
 */
#define MFD_NOT_WRITABLE         SNMP_ERR_NOTWRITABLE
#define MFD_RESOURCE_UNAVAILABLE SNMP_ERR_RESOURCEUNAVAILABLE

/*
 * new value errors
 */
#define MFD_NOT_VALID_NOW        SNMP_ERR_INCONSISTENTVALUE
#define MFD_NOT_VALID_EVER       SNMP_ERR_WRONGVALUE


#endif                          /* NETSNMP_MFD_H */
