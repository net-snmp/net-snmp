/*
 *  System MIB group implementation - system.c
 *
 */

#include <config.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "../mibincl.h"

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

#include "system_mib.h"
#include "../struct.h"
#include "../util_funcs.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "../../../snmplib/system.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

char version_descr[256] = VERS_DESC;
char sysContact[128] = SYS_CONTACT;
char sysName[128] = SYS_NAME;
char sysLocation[128] = SYS_LOC;

extern oid version_id[];
extern int version_id_len;

extern struct timeval starttime;

WriteMethod writeVersion;
WriteMethod writeSystem;
int header_system(struct variable *,oid *, int *, int, int *, WriteMethod **);

/* snmpd.conf config parsing */

void system_parse_config_sysloc(char *word, 
				char *cptr)
{
  char tmpbuf[1024];
  
  if (strlen(cptr) < 128) {
    strcpy(sysLocation,cptr);
  } else {
    sprintf(tmpbuf, "syslocation token too long (must be < 128):\n\t%s", cptr);
    config_perror(tmpbuf);
  }
}

void system_parse_config_syscon(char *word, 
				char *cptr)
{
  char tmpbuf[1024];

  if (strlen(cptr) < 128) {
    strcpy(sysContact,cptr);
  } else {
    sprintf(tmpbuf, "syscontact token too long (must be < 128):\n\t%s", cptr);
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
    {VERSION_DESCR, ASN_OCTET_STR, RWRITE, var_system, 1, {1}},
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
oid system_variables_oid[] = { 1,3,6,1,2,1,1 };

void init_system_mib(void)
{

#ifdef HAVE_UNAME
  struct utsname utsname;

  uname(&utsname);
  sprintf(version_descr, "%s %s %s %s %s", utsname.sysname, utsname.nodename,
          utsname.release, utsname.version, utsname.machine);
#else
  struct extensible extmp;

  /* set default values of system stuff */
  sprintf(extmp.command,"%s -a",UNAMEPROG);
  /* setup defaults */
  extmp.type = EXECPROC;
  extmp.next = NULL;
  exec_command(&extmp);
  strncpy(version_descr,extmp.output, 128);
  version_descr[strlen(version_descr)-1] = 0; /* chomp new line */
#endif

#ifdef HAVE_GETHOSTNAME
  gethostname(sysName,128);
#else
#ifdef HAVE_UNAME
  strncpy(sysName,utsname.nodename,128);
#else
  sprintf(extmp.command,"%s -n",UNAMEPROG);
  /* setup defaults */
  extmp.type = EXECPROC;
  extmp.next = NULL;
  exec_command(&extmp);
  strncpy(sysName,extmp.output, 128);
  sysName[strlen(sysName)-1] = 0; /* chomp new line */
#endif /* HAVE_UNAME */
#endif /* HAVE_GETHOSTNAME */

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/system", system_variables, variable2, \
               system_variables_oid);
  
  /* register our config handlers */
  snmpd_register_config_handler("syslocation", system_parse_config_sysloc,
                                NULL, "location");
  snmpd_register_config_handler("syscontact", system_parse_config_syscon,
                                NULL,"contact-name");

}

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/*
  header_system(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

int
header_system(struct variable *vp,
	      oid *name,
	      int *length,
	      int exact,
	      int *var_len,
	      WriteMethod **write_method)
{
#define SYSTEM_NAME_LENGTH	8
    oid newname[MAX_OID_LEN];
    int result;
    char c_oid[SPRINT_MAX_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("mibII/system", "var_system: %s %d\n", c_oid, exact));
      DEBUGMSGTL(("mibII/system", "vp len: %d / %d\n", vp->namelen, 8));
    }

    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[SYSTEM_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

	/*********************
	 *
	 *  System specific implementation functions
	 *	(actually common!)
	 *
	 *********************/

#ifdef USING_MIBII_SYSORTABLE_MODULE
extern struct timeval sysOR_lastchange;
#endif

u_char	*
var_system(struct variable *vp,
	   oid *name,
	   int *length,
	   int exact,
	   int *var_len,
	   WriteMethod **write_method)
{

  struct timeval now, diff;

    if (header_system(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
        case VERSION_DESCR:
            *var_len = strlen(version_descr);
            *write_method = writeVersion;
            return (u_char *)version_descr;
        case VERSIONID:
            *var_len = version_id_len*sizeof(version_id[0]);
            return (u_char *)version_id;
        case UPTIME:
            gettimeofday(&now, NULL);
            now.tv_sec--;
            now.tv_usec += 1000000L;
            diff.tv_sec = now.tv_sec - starttime.tv_sec;
            diff.tv_usec = now.tv_usec - starttime.tv_usec;
            if (diff.tv_usec > 1000000L){
                diff.tv_usec -= 1000000L;
                diff.tv_sec++;
            }
            long_return = ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
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
            long_return = 72;
            return (u_char *)&long_return;

#ifdef USING_MIBII_SYSORTABLE_MODULE
        case SYSORLASTCHANGE:
              diff.tv_sec = sysOR_lastchange.tv_sec - 1 - starttime.tv_sec;
              diff.tv_usec =
                sysOR_lastchange.tv_usec + 1000000L - starttime.tv_usec;
              if (diff.tv_usec > 1000000L){
                diff.tv_usec -= 1000000L;
                diff.tv_sec++;
              }
              if ((diff.tv_sec * 100) + (diff.tv_usec / 10000) < 0)
                long_return = 0;
              else
                long_return = ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
              return ((u_char *) &long_return);
#endif
              
	default:
	    ERROR_MSG("");
    }
    return NULL;
}


int
writeVersion(int action,	     
	     u_char *var_val,
	     u_char var_val_type,
	     int var_val_len,
	     u_char *statP,
	     oid *name,
	     int name_len)
{
    int bigsize = 1000;
    u_char buf[sizeof(version_descr)], *cp;
    int count, size;

    if (var_val_type != ASN_OCTET_STR){
	printf("not string\n");
	return SNMP_ERR_WRONGTYPE;
    }
    if (var_val_len > sizeof(version_descr)-1){
	printf("bad length\n");
	return SNMP_ERR_WRONGLENGTH;
    }
    size = sizeof(buf);
    asn_parse_string(var_val, &bigsize, &var_val_type, buf, &size);
    for(cp = buf, count = 0; count < size; count++, cp++){
	if (!isprint(*cp)){
	    printf("not print %x\n", *cp);
	    return SNMP_ERR_WRONGVALUE;
	}
    }
    buf[size] = 0;
    if (action == COMMIT){
	strcpy(version_descr, (char *) buf);
	
    }
    return SNMP_ERR_NOERROR;
} /* end of writeVersion */


int
writeSystem(int action,	     
	    u_char *var_val,
	    u_char var_val_type,
	    int var_val_len,
	    u_char *statP,
	    oid *name,
	    int name_len)
{
    int bigsize = 1000;
    u_char buf[sizeof(version_descr)], *cp;
    int count, size;

    if (var_val_type != ASN_OCTET_STR){
	printf("not string\n");
	return SNMP_ERR_WRONGTYPE;
    }
    if (var_val_len > sizeof(version_descr)-1){
	printf("bad length\n");
	return SNMP_ERR_WRONGLENGTH;
    }
    size = sizeof(buf);
    asn_parse_string(var_val, &bigsize, &var_val_type, buf, &size);
    for(cp = buf, count = 0; count < size; count++, cp++){
	if (!isprint(*cp)){
	    printf("not print %x\n", *cp);
	    return SNMP_ERR_WRONGVALUE;
	}
    }
    buf[size] = 0;
    if (action == COMMIT){
	switch((char)name[7]){
	  case 1:
	    strcpy(version_descr, (char *) buf);
	    break;
	  case 4:
	    strcpy(sysContact, (char *) buf);
	    break;
	  case 5:
	    strcpy(sysName, (char *) buf);
	    break;
	  case 6:
	    strcpy(sysLocation, (char *) buf);
	    break;
	}
    }
    return SNMP_ERR_NOERROR;
} /* end of writeSystem */

	/*********************
	 *
	 *  Internal implementation functions - None
	 *
	 *********************/

