/*++

Copyright (C) 1992-1999 Microsoft Corporation

Module Name:

    snmp.h

Abstract:

    Definitions for SNMP development.

--*/

#ifndef _INC_SNMP
#define _INC_SNMP

#if _MSC_VER > 1000
#pragma once
#endif

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Additional Header Files                                                   //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Type Definitions                                                     //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#include <pshpack4.h>

typedef struct {
    BYTE * stream;
    UINT   length;
    BOOL   dynamic;
} AsnOctetString;

typedef struct {
    UINT   idLength;
    UINT * ids;
} AsnObjectIdentifier;

typedef LONG                    AsnInteger32;
typedef ULONG                   AsnUnsigned32;
typedef ULARGE_INTEGER          AsnCounter64;
typedef AsnUnsigned32           AsnCounter32;
typedef AsnUnsigned32           AsnGauge32;
typedef AsnUnsigned32           AsnTimeticks;
typedef AsnOctetString          AsnBits;
typedef AsnOctetString          AsnSequence;
typedef AsnOctetString          AsnImplicitSequence;
typedef AsnOctetString          AsnIPAddress;
typedef AsnOctetString          AsnNetworkAddress;
typedef AsnOctetString          AsnDisplayString;
typedef AsnOctetString          AsnOpaque;

typedef struct {
    BYTE asnType;
    union {
        AsnInteger32            number;     // MS_ASN_INTEGER
                                            // MS_ASN_INTEGER32
        AsnUnsigned32           unsigned32; // MS_ASN_UNSIGNED32
        AsnCounter64            counter64;  // MS_ASN_COUNTER64
        AsnOctetString          string;     // MS_ASN_OCTETSTRING
        AsnBits                 bits;       // MS_ASN_BITS
        AsnObjectIdentifier     object;     // MS_ASN_OBJECTIDENTIFIER
        AsnSequence             sequence;   // MS_ASN_SEQUENCE
        AsnIPAddress            address;    // MS_ASN_IPADDRESS
        AsnCounter32            counter;    // MS_ASN_COUNTER32
        AsnGauge32              gauge;      // MS_ASN_GAUGE32
        AsnTimeticks            ticks;      // MS_ASN_TIMETICKS
        AsnOpaque               arbitrary;  // MS_ASN_OPAQUE
    } asnValue;
} AsnAny;

typedef AsnObjectIdentifier     AsnObjectName;
typedef AsnAny                  AsnObjectSyntax;

typedef struct {
    AsnObjectName    name;
    AsnObjectSyntax  value;
} SnmpVarBind;

typedef struct {
    SnmpVarBind * list;
    UINT          len;
} SnmpVarBindList;

#include <poppack.h>

#ifndef _INC_WINSNMP

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// ASN/BER Base Types                                                        //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define MS_ASN_UNIVERSAL                   0x00
#define MS_ASN_APPLICATION                 0x40
#define MS_ASN_CONTEXT                     0x80
#define MS_ASN_PRIVATE                     0xC0

#define MS_ASN_PRIMITIVE                   0x00
#define MS_ASN_CONSTRUCTOR                 0x20

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// PDU Type Values                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_PDU_GET                (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x0)
#define SNMP_PDU_GETNEXT            (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x1)
#define SNMP_PDU_RESPONSE           (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x2)
#define SNMP_PDU_SET                (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x3)
#define SNMP_PDU_V1TRAP             (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x4)
#define SNMP_PDU_GETBULK            (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x5)
#define SNMP_PDU_INFORM             (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x6)
#define SNMP_PDU_TRAP               (MS_ASN_CONTEXT | MS_ASN_CONSTRUCTOR | 0x7)

#endif // _INC_WINSNMP

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Simple Syntax Values                                                 //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define MS_ASN_INTEGER                 (MS_ASN_UNIVERSAL | MS_ASN_PRIMITIVE | 0x02)
#define MS_ASN_BITS                    (MS_ASN_UNIVERSAL | MS_ASN_PRIMITIVE | 0x03)
#define MS_ASN_OCTETSTRING             (MS_ASN_UNIVERSAL | MS_ASN_PRIMITIVE | 0x04)
#define MS_ASN_NULL                    (MS_ASN_UNIVERSAL | MS_ASN_PRIMITIVE | 0x05)
#define MS_ASN_OBJECTIDENTIFIER        (MS_ASN_UNIVERSAL | MS_ASN_PRIMITIVE | 0x06)
#define MS_ASN_INTEGER32               MS_ASN_INTEGER

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Constructor Syntax Values                                            //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define MS_ASN_SEQUENCE                (MS_ASN_UNIVERSAL | MS_ASN_CONSTRUCTOR | 0x10)
#define MS_ASN_SEQUENCEOF              MS_ASN_SEQUENCE

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Application Syntax Values                                            //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define MS_ASN_IPADDRESS               (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x00)
#define MS_ASN_COUNTER32               (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x01)
#define MS_ASN_GAUGE32                 (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x02)
#define MS_ASN_TIMETICKS               (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x03)
#define MS_ASN_OPAQUE                  (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x04)
#define MS_ASN_COUNTER64               (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x06)
#define MS_ASN_UINTEGER32              (MS_ASN_APPLICATION | MS_ASN_PRIMITIVE | 0x07)
#define MS_ASN_RFC2578_UNSIGNED32      MS_ASN_GAUGE32

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Exception Conditions                                                 //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_EXCEPTION_NOSUCHOBJECT     (MS_ASN_CONTEXT | MS_ASN_PRIMITIVE | 0x00)
#define SNMP_EXCEPTION_NOSUCHINSTANCE   (MS_ASN_CONTEXT | MS_ASN_PRIMITIVE | 0x01)
#define SNMP_EXCEPTION_ENDOFMIBVIEW     (MS_ASN_CONTEXT | MS_ASN_PRIMITIVE | 0x02)

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Request Types (used in SnmpExtensionQueryEx)                         //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_EXTENSION_GET          SNMP_PDU_GET
#define SNMP_EXTENSION_GET_NEXT     SNMP_PDU_GETNEXT
#define SNMP_EXTENSION_GET_BULK     SNMP_PDU_GETBULK
#define SNMP_EXTENSION_SET_TEST     (MS_ASN_PRIVATE | MS_ASN_CONSTRUCTOR | 0x0)
#define SNMP_EXTENSION_SET_COMMIT   SNMP_PDU_SET
#define SNMP_EXTENSION_SET_UNDO     (MS_ASN_PRIVATE | MS_ASN_CONSTRUCTOR | 0x1)
#define SNMP_EXTENSION_SET_CLEANUP  (MS_ASN_PRIVATE | MS_ASN_CONSTRUCTOR | 0x2)

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Error Codes                                                          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_ERRORSTATUS_NOERROR                0
#define SNMP_ERRORSTATUS_TOOBIG                 1
#define SNMP_ERRORSTATUS_NOSUCHNAME             2
#define SNMP_ERRORSTATUS_BADVALUE               3
#define SNMP_ERRORSTATUS_READONLY               4
#define SNMP_ERRORSTATUS_GENERR                 5
#define SNMP_ERRORSTATUS_NOACCESS               6
#define SNMP_ERRORSTATUS_WRONGTYPE              7
#define SNMP_ERRORSTATUS_WRONGLENGTH            8
#define SNMP_ERRORSTATUS_WRONGENCODING          9
#define SNMP_ERRORSTATUS_WRONGVALUE             10
#define SNMP_ERRORSTATUS_NOCREATION             11
#define SNMP_ERRORSTATUS_INCONSISTENTVALUE      12
#define SNMP_ERRORSTATUS_RESOURCEUNAVAILABLE    13
#define SNMP_ERRORSTATUS_COMMITFAILED           14
#define SNMP_ERRORSTATUS_UNDOFAILED             15
#define SNMP_ERRORSTATUS_AUTHORIZATIONERROR     16
#define SNMP_ERRORSTATUS_NOTWRITABLE            17
#define SNMP_ERRORSTATUS_INCONSISTENTNAME       18

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMPv1 Trap Types                                                         //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_GENERICTRAP_COLDSTART              0
#define SNMP_GENERICTRAP_WARMSTART              1
#define SNMP_GENERICTRAP_LINKDOWN               2
#define SNMP_GENERICTRAP_LINKUP                 3
#define SNMP_GENERICTRAP_AUTHFAILURE            4
#define SNMP_GENERICTRAP_EGPNEIGHLOSS           5
#define SNMP_GENERICTRAP_ENTERSPECIFIC          6

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Access Types                                                         //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_ACCESS_NONE                        0
#define SNMP_ACCESS_NOTIFY                      1
#define SNMP_ACCESS_READ_ONLY                   2
#define SNMP_ACCESS_READ_WRITE                  3
#define SNMP_ACCESS_READ_CREATE                 4

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP API Return Code Definitions                                          //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMPAPI                                 INT
#define SNMP_FUNC_TYPE                          WINAPI

#define SNMPAPI_NOERROR                         TRUE
#define SNMPAPI_ERROR                           FALSE

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Extension API Prototypes                                             //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

BOOL
SNMP_FUNC_TYPE
SnmpExtensionInit(
    DWORD                 dwUptimeReference,
    HANDLE *              phSubagentTrapEvent,
    AsnObjectIdentifier * pFirstSupportedRegion
    );

BOOL
SNMP_FUNC_TYPE
SnmpExtensionInitEx(
    AsnObjectIdentifier * pNextSupportedRegion
    );

BOOL
SNMP_FUNC_TYPE
SnmpExtensionMonitor(
    LPVOID            pAgentMgmtData
    );

BOOL
SNMP_FUNC_TYPE
SnmpExtensionQuery(
    BYTE              bPduType,
    SnmpVarBindList * pVarBindList,
    AsnInteger32 *    pErrorStatus,
    AsnInteger32 *    pErrorIndex
    );

BOOL
SNMP_FUNC_TYPE
SnmpExtensionQueryEx(
    UINT              nRequestType,
    UINT              nTransactionId,
    SnmpVarBindList * pVarBindList,
    AsnOctetString *  pContextInfo,
    AsnInteger32 *    pErrorStatus,
    AsnInteger32 *    pErrorIndex
    );

BOOL
SNMP_FUNC_TYPE
SnmpExtensionTrap(
    AsnObjectIdentifier * pEnterpriseOid,
    AsnInteger32 *        pGenericTrapId,
    AsnInteger32 *        pSpecificTrapId,
    AsnTimeticks *        pTimeStamp,
    SnmpVarBindList *     pVarBindList
    );

VOID
SNMP_FUNC_TYPE
SnmpExtensionClose(
    );

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Extension API Type Definitions                                       //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONINIT)(
    DWORD                 dwUpTimeReference,
    HANDLE *              phSubagentTrapEvent,
    AsnObjectIdentifier * pFirstSupportedRegion
    );

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONINITEX)(
    AsnObjectIdentifier * pNextSupportedRegion
    );

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONMONITOR)(
    LPVOID            pAgentMgmtData
    );

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONQUERY)(
    BYTE              bPduType,
    SnmpVarBindList * pVarBindList,
    AsnInteger32 *    pErrorStatus,
    AsnInteger32 *    pErrorIndex
    );

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONQUERYEX)(
    UINT              nRequestType,
    UINT              nTransactionId,
    SnmpVarBindList * pVarBindList,
    AsnOctetString *  pContextInfo,
    AsnInteger32 *    pErrorStatus,
    AsnInteger32 *    pErrorIndex
    );

typedef BOOL (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONTRAP)(
    AsnObjectIdentifier * pEnterpriseOid,
    AsnInteger32 *        pGenericTrapId,
    AsnInteger32 *        pSpecificTrapId,
    AsnTimeticks *        pTimeStamp,
    SnmpVarBindList *     pVarBindList
    );

typedef VOID (SNMP_FUNC_TYPE * PFNSNMPEXTENSIONCLOSE)(
    );

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP API Prototypes                                                       //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidCpy(
    AsnObjectIdentifier * pOidDst,
    AsnObjectIdentifier * pOidSrc
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidAppend(
    AsnObjectIdentifier * pOidDst,
    AsnObjectIdentifier * pOidSrc
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidNCmp(
    AsnObjectIdentifier * pOid1,
    AsnObjectIdentifier * pOid2,
    UINT                  nSubIds
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidCmp(
    AsnObjectIdentifier * pOid1,
    AsnObjectIdentifier * pOid2
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilOidFree(
    AsnObjectIdentifier * pOid
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOctetsCmp(
    AsnOctetString * pOctets1,
    AsnOctetString * pOctets2
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOctetsNCmp(
    AsnOctetString * pOctets1,
    AsnOctetString * pOctets2,
    UINT             nChars
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOctetsCpy(
    AsnOctetString * pOctetsDst,
    AsnOctetString * pOctetsSrc
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilOctetsFree(
    AsnOctetString * pOctets
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilAsnAnyCpy(
    AsnAny * pAnyDst,
    AsnAny * pAnySrc
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilAsnAnyFree(
    AsnAny * pAny
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilVarBindCpy(
    SnmpVarBind * pVbDst,
    SnmpVarBind * pVbSrc
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilVarBindFree(
    SnmpVarBind * pVb
    );

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilVarBindListCpy(
    SnmpVarBindList * pVblDst,
    SnmpVarBindList * pVblSrc
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilVarBindListFree(
    SnmpVarBindList * pVbl
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilMemFree(
    LPVOID pMem
    );

LPVOID
SNMP_FUNC_TYPE
SnmpUtilMemAlloc(
    UINT nBytes
    );

LPVOID
SNMP_FUNC_TYPE
SnmpUtilMemReAlloc(
    LPVOID pMem,
    UINT   nBytes
    );

LPSTR
SNMP_FUNC_TYPE
SnmpUtilOidToA(
    IN AsnObjectIdentifier *Oid
    );

LPSTR
SNMP_FUNC_TYPE
SnmpUtilIdsToA(
    IN UINT *Ids,
    IN UINT IdLength
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilPrintOid(
    IN AsnObjectIdentifier *Oid
    );

VOID
SNMP_FUNC_TYPE
SnmpUtilPrintAsnAny(
    AsnAny * pAny
    );

DWORD
SNMP_FUNC_TYPE
SnmpSvcGetUptime(
    );

VOID
SNMP_FUNC_TYPE
SnmpSvcSetLogLevel(
    INT nLogLevel
    );

VOID
SNMP_FUNC_TYPE
SnmpSvcSetLogType(
    INT nLogType
    );

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Debugging Definitions                                                //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_LOG_SILENT                 0x0
#define SNMP_LOG_FATAL                  0x1
#define SNMP_LOG_ERROR                  0x2
#define SNMP_LOG_WARNING                0x3
#define SNMP_LOG_TRACE                  0x4
#define SNMP_LOG_VERBOSE                0x5

#define SNMP_OUTPUT_TO_CONSOLE          0x1
#define SNMP_OUTPUT_TO_LOGFILE          0x2
#define SNMP_OUTPUT_TO_EVENTLOG         0x4  // no longer supported
#define SNMP_OUTPUT_TO_DEBUGGER         0x8

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// SNMP Debugging Prototypes                                                 //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

VOID
SNMP_FUNC_TYPE
SnmpUtilDbgPrint(
    IN INT nLogLevel,   // see log levels above...
    IN LPSTR szFormat,
    IN ...
    );

#if DBG
#define SNMPDBG(_x_)                    SnmpUtilDbgPrint _x_
#else
#define SNMPDBG(_x_)
#endif

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Miscellaneous definitions                                                 //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define DEFINE_SIZEOF(Array)        (sizeof(Array)/sizeof((Array)[0]))
#define DEFINE_OID(SubIdArray)      {DEFINE_SIZEOF(SubIdArray),(SubIdArray)}
#define DEFINE_NULLOID()            {0,NULL}
#define DEFINE_NULLOCTETS()         {NULL,0,FALSE}

#define DEFAULT_SNMP_PORT_UDP       161
#define DEFAULT_SNMP_PORT_IPX       36879
#define DEFAULT_SNMPTRAP_PORT_UDP   162
#define DEFAULT_SNMPTRAP_PORT_IPX   36880

#define SNMP_MAX_OID_LEN            128

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// API Error Code Definitions                                                //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#define SNMP_MEM_ALLOC_ERROR            1
#define SNMP_BERAPI_INVALID_LENGTH      10
#define SNMP_BERAPI_INVALID_TAG         11
#define SNMP_BERAPI_OVERFLOW            12
#define SNMP_BERAPI_SHORT_BUFFER        13
#define SNMP_BERAPI_INVALID_OBJELEM     14
#define SNMP_PDUAPI_UNRECOGNIZED_PDU    20
#define SNMP_PDUAPI_INVALID_ES          21
#define SNMP_PDUAPI_INVALID_GT          22
#define SNMP_AUTHAPI_INVALID_VERSION    30
#define SNMP_AUTHAPI_INVALID_MSG_TYPE   31
#define SNMP_AUTHAPI_TRIV_AUTH_FAILED   32

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Support for old definitions (support disabled via SNMPSTRICT)             //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

#ifndef SNMPSTRICT

#define SNMP_oidcpy                     SnmpUtilOidCpy
#define SNMP_oidappend                  SnmpUtilOidAppend
#define SNMP_oidncmp                    SnmpUtilOidNCmp
#define SNMP_oidcmp                     SnmpUtilOidCmp
#define SNMP_oidfree                    SnmpUtilOidFree

#define SNMP_CopyVarBindList            SnmpUtilVarBindListCpy
#define SNMP_FreeVarBindList            SnmpUtilVarBindListFree
#define SNMP_CopyVarBind                SnmpUtilVarBindCpy
#define SNMP_FreeVarBind                SnmpUtilVarBindFree

#define SNMP_printany                   SnmpUtilPrintAsnAny

#define SNMP_free                       SnmpUtilMemFree
#define SNMP_malloc                     SnmpUtilMemAlloc
#define SNMP_realloc                    SnmpUtilMemReAlloc

#define SNMP_DBG_free                   SnmpUtilMemFree
#define SNMP_DBG_malloc                 SnmpUtilMemAlloc
#define SNMP_DBG_realloc                SnmpUtilMemReAlloc

#define MS_ASN_RFC1155_IPADDRESS           MS_ASN_IPADDRESS
#define MS_ASN_RFC1155_COUNTER             MS_ASN_COUNTER32
#define MS_ASN_RFC1155_GAUGE               MS_ASN_GAUGE32
#define MS_ASN_RFC1155_TIMETICKS           MS_ASN_TIMETICKS
#define MS_ASN_RFC1155_OPAQUE              MS_ASN_OPAQUE
#define MS_ASN_RFC1213_DISPSTRING          MS_ASN_OCTETSTRING

#define MS_ASN_RFC1157_GETREQUEST          SNMP_PDU_GET
#define MS_ASN_RFC1157_GETNEXTREQUEST      SNMP_PDU_GETNEXT
#define MS_ASN_RFC1157_GETRESPONSE         SNMP_PDU_RESPONSE
#define MS_ASN_RFC1157_SETREQUEST          SNMP_PDU_SET
#define MS_ASN_RFC1157_TRAP                SNMP_PDU_V1TRAP

#define MS_ASN_CONTEXTSPECIFIC             MS_ASN_CONTEXT
#define MS_ASN_PRIMATIVE                   MS_ASN_PRIMITIVE

#define RFC1157VarBindList              SnmpVarBindList
#define RFC1157VarBind                  SnmpVarBind
#define AsnInteger                      AsnInteger32
#define AsnCounter                      AsnCounter32
#define AsnGauge                        AsnGauge32
#define MS_ASN_UNSIGNED32                  MS_ASN_UINTEGER32

#endif // SNMPSTRICT

#ifdef __cplusplus
}
#endif

#endif // _INC_SNMP
