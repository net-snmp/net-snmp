/*
 *  winExtDLL Net-SNMP extension
 *  (c) 2006 Alex Burger
 *
 *  Created 9/9/06
 *
 * Purpose:  To use existing extensiono (MIB) DLLs used by the Windows SNMP 
 *           service to allow Net-SNMP to be a replacement for the Windows 
 *           SNMP service.
 *
 * Notes:    This extension requires the PSDK including the Snmp.h header file.
 *           Including Snmp.h will conflict with existing Net-SNMP defines for
 *           ASN_OCTETSTRING etc.  To resolve this, create a copy of Snmp.h in
 *           the PSDK include/ folder called Snmp-winExtDLL.h and change all
 *           occurances of ASN_ to MS_ASN_
 */

#include <windows.h>
#include <cstdio>
#include <Snmp-WinExtDLL.h>                  // Modified Windows SDK snmp.h.  See Notes above
#include <mgmtapi.h>

/*
 * include important headers 
 */
#include <net-snmp/net-snmp-config.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * needed by util_funcs.h 
 */
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "util_funcs.h"

#include "winExtDLL.h"

#define SZBUF_MAX               1024
#define SZBUF_DLLNAME_MAX       32
#define MAX_WINEXT_DLLS         100
#define MAX_KEY_LENGTH          255
#define MAX_VALUE_NAME          16383

/* Structure to hold name, pointers to functions and MIB tree supported by
 * each Windows SNMP Extension DLL */
typedef struct {
  char          dll_name[SZBUF_DLLNAME_MAX];
  DWORD (WINAPI *xSnmpExtensionInit)(DWORD, HANDLE*, AsnObjectIdentifier*);
  DWORD (WINAPI *xSnmpExtensionInitEx)(AsnObjectIdentifier*);
  DWORD (WINAPI *xSnmpExtensionQuery)(BYTE, SnmpVarBindList* ,AsnInteger32* ,AsnInteger32*);
  DWORD (WINAPI *xSnmpExtensionQueryEx)(DWORD, DWORD, SnmpVarBindList*, AsnOctetString*, AsnInteger32*, AsnInteger32*);
  netsnmp_handler_registration *my_handler;
  oid           name[MAX_OID_LEN];
  size_t        name_length;
} winExtensionAgents;

winExtensionAgents winExtensionAgent[MAX_WINEXT_DLLS];
winExtensionAgents winExtensionAgent_temp;      /* For sorting */

/* List of agents: HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents
 * This will be changed so that the list is loaded from the registry or from snmpd.conf */

char *extDLLs[MAX_WINEXT_DLLS];
int extDLLs_index = 0;


void printAsnObjectIdentifier(AsnObjectIdentifier myAsnObjectIdentifier);
void winExtDLL_parse_config_winExtDLL(const char *token, char *cptr);
void winExtDLL_free_config_winExtDLL(void);

void read_ExtensionAgents_list();
void read_ExtensionAgents_list2(const TCHAR *);

void init_winExtDLL(void)
{
  DEBUGMSGTL(("winExtDLL", "init_winExtDLL called\n"));
  
  snmpd_register_config_handler("winExtDLL",
      winExtDLL_parse_config_winExtDLL,
      winExtDLL_free_config_winExtDLL,
      "winExtDLL value");

}

void printAsnObjectIdentifier(AsnObjectIdentifier myAsnObjectIdentifier) {
  int i;
  
  DEBUGMSGTL(("winExtDLL","AsnObjectIdentifier length: %d\n",myAsnObjectIdentifier.idLength));
    
  DEBUGMSGTL(("winExtDLL","AsnObjectIdentifier:        "));

    for (i = 0; i < myAsnObjectIdentifier.idLength; i++) {
      DEBUGMSGTL(("winExtDLL",".%d",myAsnObjectIdentifier.ids[i]));
    }
  DEBUGMSGTL(("winExtDLL","\n"));
}


int
var_winExtDLL(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{

    netsnmp_request_info *request = requests;
    u_char         *configured = NULL;
    netsnmp_variable_list *var;
    
    static char     ret_szbuf_temp[SZBUF_MAX];          // Holder for return strings
    static oid      ret_oid[MAX_OID_LEN];               // Holder for return OIDs
    static size_t   ret_oid_length = 0;                 // Holder for return OIDs
    static long     ret_long;                           // Holder for all other returns

    static char     set_szbuf_temp[SZBUF_MAX];          // Holder for set strings    
    static oid      set_oid[MAX_OID_LEN];               // Holder for set OIDs
    static size_t   set_oid_length = 0;                 // Holder for set OIDs
    oid             *temp_oid;
    size_t          temp_oid_length;
    
    static int      temp;
    static u_long   accesses = 7;
    u_char          netsnmp_ASN_type;
    u_char          windows_ASN_type;

    // WinSNMP variables:
    BOOL result;   
    SnmpVarBind *mySnmpVarBind;
    AsnInteger32 pErrorStatus;
    AsnInteger32 pErrorIndex;
    SnmpVarBindList pVarBindList;  
    int i=0;

    DWORD (WINAPI *xSnmpExtensionQuery)(BYTE, SnmpVarBindList* ,AsnInteger32* ,AsnInteger32*);
    DWORD (WINAPI *xSnmpExtensionQueryEx)(DWORD, DWORD, SnmpVarBindList*, AsnOctetString*, AsnInteger32*, AsnInteger32*);
    
    DEBUGMSGTL(("winExtDLL", "-----------------------------------------\n"));
    DEBUGMSGTL(("winExtDLL", "var_winExtDLL handler starting, mode = %d\n",
                reqinfo->mode));
   
    switch (reqinfo->mode) {
    case MODE_GET:
    case MODE_GETNEXT:

      if (reqinfo->mode == MODE_GET)
        DEBUGMSGTL(("winExtDLL", "GET requested\n"));
      else if (reqinfo->mode == MODE_GETNEXT)
        DEBUGMSGTL(("winExtDLL", "GETNEXT requested\n"));
      
      for (request = requests; request; request=request->next) {

        var = request->requestvb;
        
        DEBUGMSGTL(("winExtDLL", "\nrequested:"));
        DEBUGMSGOID(("winExtDLL", var->name, var->name_length));
        DEBUGMSGTL(("\nwinExtDLL", "---\n"));       

        DEBUGMSGTL(("winExtDLL", "Var type requested: %d\n",var->type));

        /* Loop through all the winExtensionAgent's looking for a matching handler */
        xSnmpExtensionQuery = NULL;
        xSnmpExtensionQueryEx = NULL;
        for (i=0; winExtensionAgent[i].xSnmpExtensionInit && i < MAX_WINEXT_DLLS; i++) {
          DEBUGMSGTL(("winExtDLL", "Looping through all the winExtensionAgent's looking for a matching handler.\n"));
          
          if (snmp_oidtree_compare(var->name, var->name_length, winExtensionAgent[i].name, 
                winExtensionAgent[i].name_length) >= 0) {
            DEBUGMSGTL(("winExtDLL", "Found match:\n"));
            DEBUGMSGOID(("winExtDLL", winExtensionAgent[i].name, winExtensionAgent[i].name_length));
            DEBUGMSGTL(("winExtDLL", "\n"));
            xSnmpExtensionQuery = winExtensionAgent[i].xSnmpExtensionQuery;
            xSnmpExtensionQueryEx = winExtensionAgent[i].xSnmpExtensionQueryEx;
            break;
          }
        }
        if (! (xSnmpExtensionQuery || xSnmpExtensionQueryEx)) {
          DEBUGMSGTL(("winExtDLL","Could not find a handler for the requested OID.  This should never happen!!\n"));
          return SNMP_ERR_GENERR;
        }
        
        // Query
	mySnmpVarBind = (SnmpVarBind *) SnmpUtilMemAlloc(sizeof (SnmpVarBind));
	if (mySnmpVarBind) {

          // Convert OID from Net-SNMP to Windows         

          mySnmpVarBind->name.ids = (UINT *) SnmpUtilMemAlloc(sizeof (UINT) *var->name_length);

          if (mySnmpVarBind->name.ids) {
            // Actual copy
            for (i = 0; i < var->name_length; i++) {
              mySnmpVarBind->name.ids[i] = (UINT)var->name[i];
            }
            mySnmpVarBind->name.idLength = i;

            // Print OID
            DEBUGMSGTL(("winExtDLL","Windows OID length: %d\n",mySnmpVarBind->name.idLength));
            DEBUGMSGTL(("winExtDLL","Windows OID: "));
            for (i = 0; i < mySnmpVarBind->name.idLength; i++) {
              DEBUGMSGTL(("winExtDLL",".%d",mySnmpVarBind->name.ids[i]));
            }
            DEBUGMSGTL(("winExtDLL","\n"));
          }
          else {
            DEBUGMSGTL(("winExtDLL", "\nyCould not allocate memory for Windows SNMP varbind.\n"));
            return (0);
          }
        }

        pVarBindList.list = (SnmpVarBind *) SnmpUtilMemAlloc(sizeof (SnmpVarBind));
        if (pVarBindList.list) {
          pVarBindList.list = mySnmpVarBind;
          pVarBindList.len = 1;          
	}
        else {
          DEBUGMSGTL(("winExtDLL", "\nyCould not allocate memory for Windows SNMP varbind list.\n"));
          return (0);
        }        
		
        if (reqinfo->mode == MODE_GET) {
          DEBUGMSGTL(("winExtDLL", "win: MODE_GET\n"));
/*          if (xSnmpExtensionQueryEx) {
            DEBUGMSGTL(("winExtDLL", "Calling xSnmpExtensionQueryEx\n"));
            result = xSnmpExtensionQueryEx(SNMP_PDU_GET, 1, &pVarBindList, NULL, &pErrorStatus, &pErrorIndex);
          }
          else { */
            DEBUGMSGTL(("winExtDLL", "Calling xSnmpExtensionQuery\n"));
            result = xSnmpExtensionQuery(SNMP_PDU_GET, &pVarBindList, &pErrorStatus, &pErrorIndex);
/*          } */
        }
        else if (reqinfo->mode == MODE_GETNEXT) {
          DEBUGMSGTL(("winExtDLL", "win: MODE_GETNEXT\n"));
          result = xSnmpExtensionQuery(SNMP_PDU_GETNEXT, &pVarBindList, &pErrorStatus, &pErrorIndex);

          // Convert OID from Windows to Net-SNMP so Net-SNMP has the new 'next' OID
          // FIXME:  Do we need to realloc var->name or is is MAX_OID_LEN?
          for (i = 0; i < (mySnmpVarBind->name.idLength > MAX_OID_LEN?MAX_OID_LEN:mySnmpVarBind->name.idLength); i++) {
            var->name[i] = (oid)mySnmpVarBind->name.ids[i];
          }
          var->name_length = i;

          DEBUGMSGTL(("winExtDLL", "\nOID to return because request was a GETNEXT:"));
          DEBUGMSGOID(("winExtDLL", var->name, var->name_length));
          DEBUGMSGTL(("\nwinExtDLL", "---\n"));                 
          DEBUGMSGTL(("winExtDLL", "Var type to return: %d\n",var->type));

        }       

        DEBUGMSGTL(("winExtDLL", "win: Result of xSnmpExtensionQuery: %d\n",result));
        
        DEBUGMSGTL(("winExtDLL", "win: Error status of xSnmpExtensionQuery: %d\n",pErrorStatus));

        DEBUGMSGTL(("winExtDLL", "win: asnType: %d\n",mySnmpVarBind->value.asnType));
      
        // Set Net-SNMP ASN type based on closest match to Windows ASN type
        switch (mySnmpVarBind->value.asnType) {
          case MS_ASN_OCTETSTRING:
            netsnmp_ASN_type = ASN_OCTET_STR;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OCTETSTRING = ASN_OCTET_STR\n"));
            break;
          case MS_ASN_INTEGER:          // And MS_ASN_INTEGER32
            netsnmp_ASN_type = ASN_INTEGER;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_INTEGER = ASN_INTEGER\n"));
            break;
          case MS_ASN_UNSIGNED32:       // SNMP v2
            netsnmp_ASN_type = ASN_UNSIGNED;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_UNSIGNED32 = ASN_UNSIGNED\n"));
            break;
          case MS_ASN_COUNTER64:       // SNMP v2
            netsnmp_ASN_type = ASN_COUNTER64;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_COUNTER64 = ASN_COUNTER64\n"));
            break;
          case MS_ASN_BITS:
            netsnmp_ASN_type = ASN_BIT_STR;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_BITS = ASN_BIT_STR\n"));
            break;
          case MS_ASN_OBJECTIDENTIFIER:
            netsnmp_ASN_type = ASN_OBJECT_ID;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OBJECTIDENTIFIER = ASN_OBJECT_ID\n"));
            break;
          case MS_ASN_SEQUENCE:
            netsnmp_ASN_type = ASN_SEQUENCE;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_SEQUENCE = ASN_SEQUENCE\n"));
            break;
          case MS_ASN_IPADDRESS:
            netsnmp_ASN_type = ASN_IPADDRESS;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_IPADDRESS = ASN_IPADDRESS\n"));
            break;
          case MS_ASN_COUNTER32:
            netsnmp_ASN_type = ASN_COUNTER;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_COUNTER32 = ASN_COUNTER\n"));
            break;
          case MS_ASN_GAUGE32:
            netsnmp_ASN_type = ASN_GAUGE;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_GAUGE32 = ASN_GAUGE\n"));
            break;
          case MS_ASN_TIMETICKS:
            netsnmp_ASN_type = ASN_TIMETICKS;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_TIMETICKS = ASN_TIMETICKS\n"));
            break;
          case MS_ASN_OPAQUE:
            netsnmp_ASN_type = ASN_OPAQUE;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OPAQUE = ASN_OPAQUE\n"));
            break;
          default:
            netsnmp_ASN_type = ASN_INTEGER;
            break;
        }

        DEBUGMSGTL(("winExtDLL", "Net-SNMP object type for returned value: %d\n",netsnmp_ASN_type));

        switch (mySnmpVarBind->value.asnType) {
          case MS_ASN_OCTETSTRING:           
            
            strncpy(ret_szbuf_temp, mySnmpVarBind->value.asnValue.string.stream, (mySnmpVarBind->value.asnValue.string.length > 
                  SZBUF_MAX?SZBUF_MAX:mySnmpVarBind->value.asnValue.string.length));
           
            if (mySnmpVarBind->value.asnValue.string.length < SZBUF_MAX) 
              ret_szbuf_temp[mySnmpVarBind->value.asnValue.string.length] = '\0';
            else
              ret_szbuf_temp[SZBUF_MAX-1] = '\0';

            // Printing strings that have a comma in them via DEBUGMSGTL doesn't work..
            DEBUGMSGTL(("winExtDLL", "win: String: %s\n",ret_szbuf_temp));
            DEBUGMSGTL(("winExtDLL", "win: length of string response: %d\n",strlen(ret_szbuf_temp)));
            
            snmp_set_var_typed_value(var, netsnmp_ASN_type,
                ret_szbuf_temp,
                strlen(ret_szbuf_temp));
            //return SNMP_ERR_NOERROR;           
            break;

          case MS_ASN_INTEGER:          // And MS_ASN_INTEGER32
          case MS_ASN_UNSIGNED32:
          case MS_ASN_COUNTER64:
          case MS_ASN_BITS:
          case MS_ASN_SEQUENCE:
          case MS_ASN_IPADDRESS:
          case MS_ASN_COUNTER32:
          case MS_ASN_GAUGE32:
          case MS_ASN_TIMETICKS:
          case MS_ASN_OPAQUE:

            DEBUGMSGTL(("winExtDLL", "win: Long: %ld\n",mySnmpVarBind->value.asnValue.number));

            ret_long = mySnmpVarBind->value.asnValue.number;

            // Return results
            snmp_set_var_typed_value(var, netsnmp_ASN_type,
                &ret_long,
                sizeof(ret_long));
            //return SNMP_ERR_NOERROR;           
            break;


          case MS_ASN_OBJECTIDENTIFIER:
            // Convert OID to Net-SNMP

            DEBUGMSGTL(("winExtDLL", "Printing returned OID\n"));
            printAsnObjectIdentifier(mySnmpVarBind->value.asnValue.object);
           
            // Convert OID from Windows to Net-SNMP
            for (i = 0; i < (mySnmpVarBind->value.asnValue.object.idLength > MAX_OID_LEN?MAX_OID_LEN:
                  mySnmpVarBind->value.asnValue.object.idLength); i++) {
              ret_oid[i] = (oid)mySnmpVarBind->value.asnValue.object.ids[i];
            }
            ret_oid_length = i;
           
            DEBUGMSGTL(("winExtDLL", "\n!Windows OID converted to Net-SNMP:"));
            DEBUGMSGOID(("winExtDLL", ret_oid, ret_oid_length));
            DEBUGMSGTL(("winExtDLL", "---\n"));
                      
            snmp_set_var_typed_value(var, netsnmp_ASN_type,
                ret_oid,
                ret_oid_length  * sizeof(oid));
            //return SNMP_ERR_NOERROR;           
            
            break;

            
          default:
            break;
        }        
      }  
      break;

    case MODE_SET_RESERVE1:     
    case MODE_SET_RESERVE2:
    case MODE_SET_ACTION:

      DEBUGMSGTL(("winExtDLL", "SET requested\n"));
      
      for (request = requests; request; request=request->next) {

        var = request->requestvb;
        
        DEBUGMSGTL(("winExtDLL", "\nrequested:"));
        DEBUGMSGOID(("winExtDLL", var->name, var->name_length));
        DEBUGMSGTL(("\nwinExtDLL", "---\n"));       

        DEBUGMSGTL(("winExtDLL", "Var type requested: %d\n",var->type));

        /* Loop through all the winExtensionAgent's looking for a matching handler */
        xSnmpExtensionQuery = NULL;
        for (i=0; winExtensionAgent[i].xSnmpExtensionInit && i < MAX_WINEXT_DLLS; i++) {
          DEBUGMSGTL(("winExtDLL", "Looping through all the winExtensionAgent's looking for a matching handler.\n"));
          
          if (snmp_oidtree_compare(var->name, var->name_length, winExtensionAgent[i].name, 
                winExtensionAgent[i].name_length) >= 0) {
            DEBUGMSGTL(("winExtDLL", "Found match:\n"));
            DEBUGMSGOID(("winExtDLL", winExtensionAgent[i].name, winExtensionAgent[i].name_length));
            DEBUGMSGTL(("winExtDLL", "\n"));
            xSnmpExtensionQuery = winExtensionAgent[i].xSnmpExtensionQuery;
            break;
          }
        }
        if (! (xSnmpExtensionQuery)) {
          DEBUGMSGTL(("winExtDLL","Could not find a handler for the requested OID.  This should never happen!!\n"));
          return SNMP_ERR_GENERR;
        }
        
        // Set Windows ASN type based on closest match to Net-SNMP ASN type
        switch (var->type) {
          case ASN_OCTET_STR:
            windows_ASN_type = MS_ASN_OCTETSTRING;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OCTETSTRING = ASN_OCTET_STR\n"));
            break;
          case ASN_INTEGER:          // And MS_ASN_INTEGER32
            windows_ASN_type = MS_ASN_INTEGER;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_INTEGER = ASN_INTEGER\n"));
            break;
          case ASN_UNSIGNED:
            windows_ASN_type = MS_ASN_UNSIGNED32;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_UNSIGNED32 = ASN_UNSIGNED\n"));
            break;
          case ASN_COUNTER64:
            windows_ASN_type = MS_ASN_COUNTER64;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_COUNTER64 = ASN_COUNTER64\n"));
            break;
          case ASN_BIT_STR:
            windows_ASN_type = MS_ASN_BITS;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_BITS = ASN_BIT_STR\n"));
            break;
          case ASN_OBJECT_ID:
            windows_ASN_type = MS_ASN_OBJECTIDENTIFIER;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OBJECTIDENTIFIER = ASN_OBJECT_ID\n"));
            break;
          case ASN_SEQUENCE:
            windows_ASN_type = MS_ASN_SEQUENCE;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_SEQUENCE = ASN_SEQUENCE\n"));
            break;
          case ASN_IPADDRESS:
            windows_ASN_type = MS_ASN_IPADDRESS;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_IPADDRESS = ASN_IPADDRESS\n"));
            break;
          case ASN_COUNTER:
            windows_ASN_type = MS_ASN_COUNTER32;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_COUNTER32 = ASN_COUNTER\n"));
            break;
//          case ASN_GAUGE:                     // Same as UNSIGNED
//            windows_ASN_type = MS_ASN_GAUGE32;
//            DEBUGMSGTL(("winExtDLL", "MS_ASN_GAUGE32 = ASN_GAUGE\n"));
//          break;
          case ASN_TIMETICKS:
            windows_ASN_type = MS_ASN_TIMETICKS;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_TIMETICKS = ASN_TIMETICKS\n"));
            break;
          case ASN_OPAQUE:
            windows_ASN_type = MS_ASN_OPAQUE;
            DEBUGMSGTL(("winExtDLL", "MS_ASN_OPAQUE = ASN_OPAQUE\n"));
            break;
          default:
            windows_ASN_type = MS_ASN_INTEGER;
            break;
        }

        DEBUGMSGTL(("winExtDLL", "Net-SNMP object type for returned value: %d\n",windows_ASN_type));

        // Query
	mySnmpVarBind = (SnmpVarBind *) SnmpUtilMemAlloc(sizeof (SnmpVarBind));
	if (mySnmpVarBind) {
        
          // Convert OID from Net-SNMP to Windows         
          mySnmpVarBind->name.ids = (UINT *) SnmpUtilMemAlloc(sizeof (UINT) *var->name_length);

          if (mySnmpVarBind->name.ids) {
            // Actual copy
            for (i = 0; i < var->name_length; i++) {
              mySnmpVarBind->name.ids[i] = (UINT)var->name[i];
            }
            mySnmpVarBind->name.idLength = i;

            // Print OID
            DEBUGMSGTL(("winExtDLL","Windows OID length: %d\n",mySnmpVarBind->name.idLength));
            DEBUGMSGTL(("winExtDLL","Windows OID: "));
            for (i = 0; i < mySnmpVarBind->name.idLength; i++) {
              DEBUGMSGTL(("winExtDLL",".%d",mySnmpVarBind->name.ids[i]));
            }
            DEBUGMSGTL(("winExtDLL","\n"));
          }
          else {
            DEBUGMSGTL(("winExtDLL", "\nyCould not allocate memory for Windows SNMP varbind.\n"));
            return (0);
          }
        }
        pVarBindList.list = (SnmpVarBind *) SnmpUtilMemAlloc(sizeof (SnmpVarBind));
        if (pVarBindList.list) {
          pVarBindList.list = mySnmpVarBind;
          pVarBindList.len = 1;          
	}
        else {
          DEBUGMSGTL(("winExtDLL", "\nyCould not allocate memory for Windows SNMP varbind list.\n"));
          return (0);
        }
		        
        // Set Windows ASN type
        mySnmpVarBind->value.asnType = windows_ASN_type;
          
        switch (var->type) {
          case ASN_OCTET_STR:            

            strncpy(set_szbuf_temp, var->val.string, strlen(var->val.string) * sizeof(var->val.string));           // FIXME: overflow

            DEBUGMSGTL(("winExtDLL", "String to write: %s\n",set_szbuf_temp));
            DEBUGMSGTL(("winExtDLL", "Length of string to write: %d\n",strlen(set_szbuf_temp)));

            mySnmpVarBind->value.asnValue.string.stream = set_szbuf_temp;
            mySnmpVarBind->value.asnValue.string.length = strlen(set_szbuf_temp);
            mySnmpVarBind->value.asnValue.string.dynamic = 0;
            
            break;

          case ASN_INTEGER:          // And MS_ASN_INTEGER32
          case ASN_UNSIGNED:
          case ASN_COUNTER64:
          case ASN_BIT_STR:
          case ASN_SEQUENCE:
          case ASN_IPADDRESS:
          case ASN_COUNTER:
          case ASN_TIMETICKS:
          case ASN_OPAQUE:        
            
            mySnmpVarBind->value.asnValue.number = *(var->val.integer);
            break;
              
          case ASN_OBJECT_ID:
            
            // Convert OID from Net-SNMP to Windows
            temp_oid = var->val.objid;
            temp_oid_length = var->val_len / sizeof(oid);           
            
            DEBUGMSGTL(("winExtDLL","Sizeof var->val.objid: %d\n", temp_oid_length));
            DEBUGMSGTL(("winExtDLL","OID: from user\n"));
            DEBUGMSGOID(("winExtDLL", temp_oid, temp_oid_length));
            
            mySnmpVarBind->name.ids = (UINT *) SnmpUtilMemAlloc(sizeof (UINT) * temp_oid_length);

            if (mySnmpVarBind->name.ids) {
              // Actual copy
              for (i = 0; i < temp_oid_length; i++) {
                mySnmpVarBind->name.ids[i] = (UINT)temp_oid[i];
              }
              mySnmpVarBind->name.idLength = i;
              
              // Print OID
              DEBUGMSGTL(("winExtDLL","Windows OID length: %d\n",mySnmpVarBind->name.idLength));
              DEBUGMSGTL(("winExtDLL","Windows OID: "));
              for (i = 0; i < mySnmpVarBind->name.idLength; i++) {
                DEBUGMSGTL(("winExtDLL",".%d",mySnmpVarBind->name.ids[i]));
              }
              DEBUGMSGTL(("winExtDLL","\n"));
            }
            else {
              DEBUGMSGTL(("winExtDLL", "\nyCould not allocate memory for Windows SNMP varbind.\n"));
              return SNMP_ERR_GENERR;
            }
            
          default:
            break;      
        }  

        
        result = xSnmpExtensionQuery(SNMP_PDU_SET, &pVarBindList, &pErrorStatus, &pErrorIndex);
        DEBUGMSGTL(("winExtDLL", "win: Result of xSnmpExtensionQuery: %d\n",result));        
        DEBUGMSGTL(("winExtDLL", "win: Error status of xSnmpExtensionQuery: %d\n",pErrorStatus));
        DEBUGMSGTL(("winExtDLL", "win: asnType: %d\n",mySnmpVarBind->value.asnType));

        if (result == 0) {
          DEBUGMSGTL(("winExtDLL", "\nyxWindows SnmpExtensionQuery failure.\n"));
          return SNMP_ERR_GENERR;
        }
        
        if (pErrorStatus) {
          switch (pErrorStatus) {
            case SNMP_ERRORSTATUS_INCONSISTENTNAME:
              return SNMP_ERR_GENERR;
            default:
              return pErrorStatus;
              break;
          }
        }
      }
      break;     


    case MODE_SET_UNDO:
    case MODE_SET_COMMIT:
    case MODE_SET_FREE:

      break;
      
    default:
        snmp_log(LOG_WARNING, "unsupported mode for winExtDLL called (%d)\n",
                               reqinfo->mode);
        return SNMP_ERR_NOERROR;
    }

    return SNMP_ERR_NOERROR;
}

void
winExtDLL_parse_config_winExtDLL(const char *token, char *cptr)
{
  // Windows SNMP
  DWORD dwUptimeReference = 0;
  HANDLE subagentTrapEvent;
  AsnObjectIdentifier pSupportedView;
  BOOL result;

  // Net-SNMP
  oid name[MAX_OID_LEN];
  size_t length = 0;
  int i;
  int DLLnum = 0;
  int winExtensionAgent_num = 0;
  
  int iter, indx;
  
  netsnmp_handler_registration *my_handler;

  HANDLE hInst = NULL;

  DEBUGMSGTL(("winExtDLL", "winExtDLL_parse_config_winExtDLL called\n"));        

  read_ExtensionAgents_list();  
  
  if (atoi(cptr) == 0) {
    DEBUGMSGTL(("winExtDLL", "winExtDLL in snmpd.conf not set to 1.  Aborting initialization.\n"));        
    return 0;
  }

  DEBUGMSGTL(("winExtDLL", "winExtDLL enabled.\n"));        
  
  DEBUGMSGTL(("winExtDLL", "Size of winExtensionAgent: %d\n",sizeof(winExtensionAgent) / sizeof(winExtensionAgents)));

  for(i=0; i <= sizeof(winExtensionAgent) / sizeof(winExtensionAgents); i++) {
    winExtensionAgent[0].xSnmpExtensionInit = NULL;
    winExtensionAgent[0].xSnmpExtensionInitEx = NULL;
  }

  /* Load all the DLLs */
  for (DLLnum = 0; DLLnum <= extDLLs_index; DLLnum++) {

    DEBUGMSGTL(("winExtDLL", "---------------------------------\n"));
    DEBUGMSGTL(("winExtDLL", "DLL to load: %s, DLL number: %d, winExtensionAgent_num: %d\n", extDLLs[DLLnum], DLLnum,
          winExtensionAgent_num));
    
    hInst = LoadLibrary(extDLLs[DLLnum]);
    
    //hInst = LoadLibrary("hostmib.dll");
    //HANDLE hInst = LoadLibrary("inetmib1.dll");       // RFC1156Agent
    //HANDLE hInst = LoadLibrary("lmmib2.dll");         // LANManagerMIB2Agent
    //HANDLE hInst = LoadLibrary("snmpmib.dll");
    if (hInst == NULL)
    {
      DEBUGMSGTL(("winExtDLL","Could not load Windows extension DLL %s.\n", extDLLs[DLLnum]));
      snmp_log(LOG_ERR,
          "Could not load Windows extension DLL: %s.\n", extDLLs[DLLnum]);
      continue;
    }
    else {
      DEBUGMSGTL(("winExtDLL","DLL loaded.\n"));
    }
    
    strncpy(winExtensionAgent[winExtensionAgent_num].dll_name, extDLLs[DLLnum], SZBUF_DLLNAME_MAX-1);
    winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInit = (DWORD (WINAPI *)(DWORD, HANDLE*, AsnObjectIdentifier*)) 
      GetProcAddress ((HMODULE) hInst, "SnmpExtensionInit");

    winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInitEx = (DWORD (WINAPI *)(AsnObjectIdentifier*)) 
      GetProcAddress ((HMODULE) hInst, "SnmpExtensionInitEx");

    winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQuery = 
      (DWORD (WINAPI *)(BYTE, SnmpVarBindList* ,AsnInteger32* ,AsnInteger32*)) 
      GetProcAddress ((HMODULE) hInst, "SnmpExtensionQuery");

    winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQueryEx = 
      (DWORD (WINAPI *)(DWORD, DWORD, SnmpVarBindList*, AsnOctetString*, AsnInteger32*, AsnInteger32*))
      GetProcAddress ((HMODULE) hInst, "SnmpExtensionQueryEx");

    if (winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQuery)
      DEBUGMSGTL(("winExtDLL", "xSnmpExtensionQuery found\n"));
    if (winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQueryEx)
      DEBUGMSGTL(("winExtDLL", "xSnmpExtensionQueryEx found\n"));

    // Init and get first supported view from Windows SNMP extension DLL  
    result = winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInit(dwUptimeReference, &subagentTrapEvent, &pSupportedView);

    printAsnObjectIdentifier(pSupportedView);

    // Convert OID from Windows 'supported view' to Net-SNMP
    for (i = 0; i < (pSupportedView.idLength > MAX_OID_LEN?MAX_OID_LEN:pSupportedView.idLength); i++) {
      name[i] = (oid)pSupportedView.ids[i];
    }
    length = i;

    memcpy(winExtensionAgent[winExtensionAgent_num].name, name, sizeof(name));
    winExtensionAgent[winExtensionAgent_num].name_length = length;
 
    DEBUGMSGTL(("winExtDLL", "\nWindows OID converted to Net-SNMP:"));
    DEBUGMSGOID(("winExtDLL", name, length));
    DEBUGMSGTL(("winExtDLL", "---\n"));
    
    winExtensionAgent[winExtensionAgent_num].my_handler = netsnmp_create_handler_registration("winExtDLL",
        var_winExtDLL,
        name,
        length,
        HANDLER_CAN_RWRITE);
    
    if (!winExtensionAgent[winExtensionAgent_num].my_handler) {
      snmp_log(LOG_ERR,
          "malloc failed registering handler for winExtDLL");
      DEBUGMSGTL(("winExtDLL", "malloc failed registering handler for winExtDLL"));
      return (-1);
    }
    else {
      DEBUGMSGTL(("winExtDLL", "handler registered\n"));
    }
    
    netsnmp_register_handler(winExtensionAgent[winExtensionAgent_num].my_handler);

    // Check for additional supported views and register them with the same handler
    if (winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInitEx) {
      DEBUGMSGTL(("winExtDLL", "xSnmpExtensionInitEx found\n"));

      winExtensionAgent_num++;

      strncpy(winExtensionAgent[winExtensionAgent_num].dll_name, winExtensionAgent[winExtensionAgent_num-1].dll_name, SZBUF_DLLNAME_MAX-1);
      winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInit = winExtensionAgent[winExtensionAgent_num-1].xSnmpExtensionInit;
      winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInitEx = winExtensionAgent[winExtensionAgent_num-1].xSnmpExtensionInitEx;
      winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQuery = winExtensionAgent[winExtensionAgent_num-1].xSnmpExtensionQuery;
      winExtensionAgent[winExtensionAgent_num].xSnmpExtensionQueryEx = winExtensionAgent[winExtensionAgent_num-1].xSnmpExtensionQueryEx;
      
      result = winExtensionAgent[winExtensionAgent_num].xSnmpExtensionInitEx(&pSupportedView);
      
      printAsnObjectIdentifier(pSupportedView);
      
      // Convert OID from Windows 'supported view' to Net-SNMP
      for (i = 0; i < (pSupportedView.idLength > MAX_OID_LEN?MAX_OID_LEN:pSupportedView.idLength); i++) {
        name[i] = (oid)pSupportedView.ids[i];
      }
      length = i;

      memcpy(winExtensionAgent[winExtensionAgent_num].name, name, sizeof(name));
      winExtensionAgent[winExtensionAgent_num].name_length = length;

      DEBUGMSGTL(("winExtDLL", "\nWindows OID converted to Net-SNMP:"));
      DEBUGMSGOID(("winExtDLL", name, length));
      DEBUGMSGTL(("winExtDLL", "---\n"));
      
      winExtensionAgent[winExtensionAgent_num].my_handler = netsnmp_create_handler_registration("winExtDLL",
          var_winExtDLL,
          name,
          length,
          HANDLER_CAN_RWRITE);
      
      if (!winExtensionAgent[winExtensionAgent_num].my_handler) {
        snmp_log(LOG_ERR,
            "malloc failed registering handler for winExtDLL");
        DEBUGMSGTL(("winExtDLL", "malloc failed registering handler for winExtDLL"));
        return (-1);
      }
      else {
        DEBUGMSGTL(("winExtDLL", "handler registered\n"));
      }
      netsnmp_register_handler(winExtensionAgent[winExtensionAgent_num].my_handler);
    }
    winExtensionAgent_num++;
    
  }
  DEBUGMSGTL(("winExtDLL", "\n\nDumping Windows extension OIDs\n"));
  for (i=0; winExtensionAgent[i].xSnmpExtensionInit; i++) {
    DEBUGMSGTL(("winExtDLL", "DLL name: %s\n",winExtensionAgent[i].dll_name));
    DEBUGMSGOID(("winExtDLL", winExtensionAgent[i].name, winExtensionAgent[i].name_length));
    DEBUGMSGTL(("winExtDLL", "\n"));
  }
  DEBUGMSGTL(("winExtDLL", "\n"));

  /* Reverse sort array of winExtensionAgents */
  i = sizeof(winExtensionAgent) / sizeof(winExtensionAgents);
  DEBUGMSGTL(("winExtDLL", "\nSorting...\n"));
  for (iter=0; iter < i-1; iter++) {
    for (indx=0; indx < i-1; indx++) {
      if (snmp_oidtree_compare(winExtensionAgent[indx].name, winExtensionAgent[indx].name_length,
            winExtensionAgent[indx+1].name, winExtensionAgent[indx+1].name_length) < 0) {
        winExtensionAgent_temp = winExtensionAgent[indx];
        winExtensionAgent[indx] = winExtensionAgent[indx+1];
        winExtensionAgent[indx+1] = winExtensionAgent_temp;
      }
    }
  }
  DEBUGMSGTL(("winExtDLL", "\n\nDumping Windows extension OIDs\n"));
  for (i=0; winExtensionAgent[i].xSnmpExtensionInit; i++) {
    DEBUGMSGTL(("winExtDLL", "DLL name: %s\n",winExtensionAgent[i].dll_name));
    DEBUGMSGOID(("winExtDLL", winExtensionAgent[i].name, winExtensionAgent[i].name_length));
    DEBUGMSGTL(("winExtDLL", "\n"));
  }
  DEBUGMSGTL(("winExtDLL", "\n"));

}

void winExtDLL_free_config_winExtDLL(void) {
}

void read_ExtensionAgents_list() {
  HKEY          hKey; 
  unsigned char * key_value = NULL;
  DWORD         key_value_size = 0;
  DWORD         key_value_type = 0;
  DWORD         valueSize = MAX_VALUE_NAME; 
  int           i;
  TCHAR         valueName[MAX_VALUE_NAME];
  TCHAR         valueName2[MAX_VALUE_NAME];
  DWORD         retCode;
  
  DEBUGMSGTL(("winExtDLL", "read_ExtensionAgents_list called\n"));

  /* The Windows SNMP service stores the list of extension agents to be loaded in the
   * registry under HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents.
   * This list contains a list of other keys that contain the actual file path to the DLL.
   */

  /* Open SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ExtensionAgent */
  retCode = RegOpenKeyExA(
      HKEY_LOCAL_MACHINE, 
      "SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ExtensionAgents", 
      0, 
      KEY_QUERY_VALUE, 
      &hKey);
  
  if (retCode == ERROR_SUCCESS) {
    /* Enumerate list of extension agents.  This is a list of other keys that contain the
     * actual filename of the extension agent.  */
    for (i=0; retCode==ERROR_SUCCESS; i++) 
    { 
      valueSize = MAX_VALUE_NAME; 
      valueName[0] = '\0'; 
      retCode = RegEnumValue(
          hKey,
          i,
          valueName, 
          &valueSize, 
          NULL, 
          NULL,
          NULL,
          NULL);
      
      if (retCode == ERROR_SUCCESS ) 
      { 
        /* Get key name that contains the actual filename of the extension agent */
        DEBUGMSGTL(("winExtDLL", "Registry: (%d) %s\n", i+1, valueName));
        
        key_value_size = MAX_VALUE_NAME;
        if (RegQueryValueExA(
              hKey, 
              valueName, 
              NULL, 
              &key_value_type, 
              valueName2, 
              &key_value_size) == ERROR_SUCCESS) {
        }
        DEBUGMSGTL(("winExtDLL", "key_value: %s\n",valueName2));
        read_ExtensionAgents_list2(valueName2);
        extDLLs_index++;
      }
    }
    if (extDLLs_index)
      extDLLs_index--;
  }
}

void read_ExtensionAgents_list2(const TCHAR *keyName) {
  HKEY          hKey; 
  unsigned char * key_value = NULL;
  DWORD         key_value_size = 0;
  DWORD         key_value_type = 0;
  DWORD         valueSize = MAX_VALUE_NAME; 
  TCHAR         valueName[MAX_VALUE_NAME];
  TCHAR         valueNameExpanded[MAX_VALUE_NAME];
  int           i;
  DWORD         retCode;
  
  DEBUGMSGTL(("winExtDLL", "read_ExtensionAgents_list2 called\n"));
  DEBUGMSGTL(("winExtDLL", "Registry: Opening key %s\n", keyName));

  /* Open extension agent's key */
  retCode = RegOpenKeyExA(
      HKEY_LOCAL_MACHINE, 
      keyName, 
      0, 
      KEY_QUERY_VALUE, 
      &hKey);
  
  if (retCode == ERROR_SUCCESS) {
    /* Read Pathname value */

    DEBUGMSGTL(("winExtDLL", "Registry: Reading value for %s\n", keyName));
       
    key_value_size = MAX_VALUE_NAME;
    retCode = RegQueryValueExA(
        hKey, 
        "Pathname", 
        NULL, 
        &key_value_type, 
        valueName, 
        &key_value_size);
    
    if (retCode == ERROR_SUCCESS) {
      valueName[key_value_size-1] = NULL;               /* Make sure last element is a NULL */        
      DEBUGMSGTL(("winExtDLL", "Extension agent Pathname size: %d\n",key_value_size));
      DEBUGMSGTL(("winExtDLL", "Extension agent Pathname: %s\n",valueName));

      if (ExpandEnvironmentStrings(valueName, valueNameExpanded, MAX_VALUE_NAME)) {
        DEBUGMSGTL(("winExtDLL", "Extension agent Pathname expanded: %s\n",valueNameExpanded));
        if (extDLLs_index < MAX_WINEXT_DLLS) {

          extDLLs[extDLLs_index] = (char *) malloc((sizeof(char) * strlen(valueNameExpanded)));         
          
          if (extDLLs[extDLLs_index]) {
            strcpy(extDLLs[extDLLs_index], valueNameExpanded );
            DEBUGMSGTL(("winExtDLL", "Extension agent Pathname expanded extDLLs: %s\n",extDLLs[extDLLs_index]));
          }
          else {
            DEBUGMSGTL(("winExtDLL", "Could not allocate memory for extDLLs[%d]\n",extDLLs_index));
          }
        }
      }      
    }
  }
}

