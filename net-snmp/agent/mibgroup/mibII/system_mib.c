/*
 *  System MIB group implementation - system.c
 *
 */

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <ctype.h>
#if HAVE_UTSNAME_H
#include <utsname.h>
#else
#if HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "mibincl.h"
#include "util_funcs.h"
#include "system_mib.h"
#include "struct.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "system.h"
#include "sysORTable.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#define SYS_STRING_LEN	256
char version_descr[ SYS_STRING_LEN ] = VERS_DESC;
char sysContact[    SYS_STRING_LEN ] = SYS_CONTACT;
char sysName[       SYS_STRING_LEN ] = SYS_NAME;
char sysLocation[   SYS_STRING_LEN ] = SYS_LOC;

char oldversion_descr[ SYS_STRING_LEN ];
char oldsysContact[    SYS_STRING_LEN ];
char oldsysName[       SYS_STRING_LEN ];
char oldsysLocation[   SYS_STRING_LEN ];

int sysServices=72;
int sysServicesConfiged=0;

extern oid version_id[];
extern int version_id_len;


WriteMethod writeSystem;
int header_system(struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);

	/*********************
	 *
	 *  snmpd.conf config parsing
	 *
	 *********************/

void system_parse_config_sysloc(const char *token, 
				char *cptr)
{
  char tmpbuf[1024];
  
  if (strlen(cptr) < sizeof(sysLocation)) {
    strcpy(sysLocation,cptr);
  } else {
    sprintf(tmpbuf, "syslocation token too long (must be < %d):\n\t%s",
		 sizeof(sysLocation), cptr);
    config_perror(tmpbuf);
  }
}

void system_parse_config_sysServices(const char *token, char *cptr)
{
  sysServices = atoi(cptr);
  sysServicesConfiged = 1;
}

void system_parse_config_syscon(const char *token, 
				char *cptr)
{
  char tmpbuf[1024];

  if (strlen(cptr) < sizeof(sysContact)) {
    strcpy(sysContact,cptr);
  } else {
    sprintf(tmpbuf, "syscontact token too long (must be < %d):\n\t%s",
                 sizeof(sysContact), cptr);
    config_perror(tmpbuf);
  }
}


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 system_variables[] = {
    {VERSION_DESCR, ASN_OCTET_STR, RONLY, var_system, 1, {1}},
    {VERSIONID, ASN_OBJECT_ID, RONLY, var_system, 1, {2}},
    {UPTIME, ASN_TIMETICKS, RONLY, var_system, 1, {3}},
    {SYSCONTACT, ASN_OCTET_STR, RWRITE, var_system, 1, {4}},
    {SYSTEMNAME, ASN_OCTET_STR, RWRITE, var_system, 1, {5}},
    {SYSLOCATION, ASN_OCTET_STR, RWRITE, var_system, 1, {6}},
    {SYSSERVICES, ASN_INTEGER, RONLY, var_system, 1, {7}},
    {SYSORLASTCHANGE, ASN_TIMETICKS, RONLY, var_system, 1, {8}}
};
/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid system_variables_oid[] = { SNMP_OID_MIB2,1 };
oid system_module_oid[]    = { SNMP_OID_SNMPMODULES,1 };
int system_module_oid_len  = sizeof( system_module_oid ) / sizeof( oid );
int system_module_count    = 0;

void init_system_mib(void)
{

#ifdef HAVE_UNAME
  struct utsname utsName;

  uname(&utsName);
  sprintf(version_descr, "%s %s %s %s %s", utsName.sysname, utsName.nodename,
          utsName.release, utsName.version, utsName.machine);
#else
#if HAVE_EXECV
  struct extensible extmp;

  /* set default values of system stuff */
  sprintf(extmp.command,"%s -a",UNAMEPROG);
  /* setup defaults */
  extmp.type = EXECPROC;
  extmp.next = NULL;
  exec_command(&extmp);
  strncpy(version_descr,extmp.output, sizeof(version_descr));
  version_descr[strlen(version_descr)-1] = 0; /* chomp new line */
#else
  strcpy(version_descr, "unknown" );
#endif
#endif

#ifdef HAVE_GETHOSTNAME
  gethostname(sysName,sizeof(sysName));
#else
#ifdef HAVE_UNAME
  strncpy(sysName,utsName.nodename,sizeof(sysName));
#else
  sprintf(extmp.command,"%s -n",UNAMEPROG);
  /* setup defaults */
  extmp.type = EXECPROC;
  extmp.next = NULL;
  exec_command(&extmp);
  strncpy(sysName,extmp.output, sizeof(sysName));
  sysName[strlen(sysName)-1] = 0; /* chomp new line */
#endif /* HAVE_UNAME */
#endif /* HAVE_GETHOSTNAME */

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/system", system_variables, variable2, \
               system_variables_oid);

  if ( ++system_module_count == 3 )
	REGISTER_SYSOR_ENTRY( system_module_oid,
		"The MIB module for SNMPv2 entities");
  
  /* register our config handlers */
  snmpd_register_config_handler("syslocation", system_parse_config_sysloc,
                                NULL, "location");
  snmpd_register_config_handler("syscontact", system_parse_config_syscon,
                                NULL,"contact-name");
  snmpd_register_config_handler("sysservices", system_parse_config_sysServices,
                                NULL,"NUMBER");

}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

#ifdef USING_MIBII_SYSORTABLE_MODULE
extern struct timeval sysOR_lastchange;
#endif

u_char	*
var_system(struct variable *vp,
	   oid *name,
	   size_t *length,
	   int exact,
	   size_t *var_len,
	   WriteMethod **write_method)
{

    struct timeval now;

    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
        case VERSION_DESCR:
            *var_len = strlen(version_descr);
            *write_method = writeSystem;
            return (u_char *)version_descr;
        case VERSIONID:
            *var_len = version_id_len*sizeof(version_id[0]);
            return (u_char *)version_id;
        case UPTIME:
            gettimeofday(&now, NULL);
	    long_return = timeval_uptime( &now );
            return ((u_char *) &long_return);
        case SYSCONTACT:
            *var_len = strlen(sysContact);
            *write_method = writeSystem;
            return (u_char *)sysContact;
        case SYSTEMNAME:
            *var_len = strlen(sysName);
            *write_method = writeSystem;
            return (u_char *)sysName;
        case SYSLOCATION:
            *var_len = strlen(sysLocation);
            *write_method = writeSystem;
            return (u_char *)sysLocation;
        case SYSSERVICES:
#if NO_DUMMY_VALUES
            if (!sysServicesConfiged)
                return NULL;
#endif
            long_return = sysServices;
            return (u_char *)&long_return;

#ifdef USING_MIBII_SYSORTABLE_MODULE
        case SYSORLASTCHANGE:
	      long_return = timeval_uptime( &sysOR_lastchange );
              return ((u_char *) &long_return);
#endif
              
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_system\n", vp->magic));
    }
    return NULL;
}



int
writeSystem(int action,	     
	    u_char *var_val,
	    u_char var_val_type,
	    size_t var_val_len,
	    u_char *statP,
	    oid *name,
	    size_t name_len)
{
    u_char *cp;
    char *buf = NULL, *oldbuf = NULL;
    int count;

    switch((char)name[7]){
      case VERSION_DESCR:
        buf    = version_descr;
        oldbuf = oldversion_descr;
        break;
      case SYSCONTACT:
        buf    = sysContact;
        oldbuf = oldsysContact;
        break;
      case SYSTEMNAME:
        buf    = sysName;
        oldbuf = oldsysName;
        break;
      case SYSLOCATION:
        buf    = sysLocation;
        oldbuf = oldsysLocation;
        break;
      default:
	return SNMP_ERR_GENERR;		/* ??? */
    }

    switch ( action ) {
	case RESERVE1:		/* Check values for acceptability */
	    if (var_val_type != ASN_OCTET_STR){
                snmp_log(LOG_ERR, "not string\n");
		return SNMP_ERR_WRONGTYPE;
	    }
	    if (var_val_len > sizeof(version_descr)-1){
                snmp_log(LOG_ERR, "bad length\n");
		return SNMP_ERR_WRONGLENGTH;
	    }
	    
	    for(cp = var_val, count = 0; count < (int)var_val_len; count++, cp++){
		if (!isprint(*cp)){
                    snmp_log(LOG_ERR, "not print %x\n", *cp);
		    return SNMP_ERR_WRONGVALUE;
		}
	    }
	    break;

	case RESERVE2:		/* Allocate memory and similar resources */

		/* Using static strings, so nothing needs to be done */
	    break;

	case ACTION:		/* Perform the SET action (if reversible) */

		/* Save the old value, in case of UNDO */
	    strcpy( oldbuf, buf);
	    memcpy( buf, var_val, var_val_len);
	    buf[var_val_len] = 0;
	    break;

	case UNDO:		/* Reverse the SET action and free resources */

	    strcpy( buf, oldbuf);
	    oldbuf[0] = 0;
	    break;

	case COMMIT:		/* Confirm the SET, performing any irreversible actions,
					and free resources */
	case FREE:		/* Free any resources allocated */

		/* No resources have been allocated, but "empty" the 'oldbuf' */
	    oldbuf[0] = 0;
	    break;
    }
    return SNMP_ERR_NOERROR;
} /* end of writeSystem */

	/*********************
	 *
	 *  Internal implementation functions - None
	 *
	 *********************/

