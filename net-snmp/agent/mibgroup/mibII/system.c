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
/* #include "../common_header.h" */

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

#include "system.h"
#include "../struct.h"
#include "../util_funcs.h"
#include "read_config.h"
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

int writeVersion __P((int, u_char *,u_char, int, u_char *,oid*, int));
int writeSystem __P((int, u_char *,u_char, int, u_char *,oid*, int));
int header_system __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

/* snmpd.conf config parsing */

void system_parse_config_sysloc(word, cptr)
  char *word;
  char *cptr;
{
  char tmpbuf[1024];
  
  if (strlen(cptr) < 128) {
    strcpy(sysLocation,cptr);
  } else {
    sprintf(tmpbuf, "syslocation token too long (must be < 128):\n\t%s", cptr);
    config_perror(tmpbuf);
  }
}

void system_parse_config_syscon(word, cptr)
  char *word;
  char *cptr;
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

void init_system()
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

}

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_system(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define SYSTEM_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_system: %s %d\n", c_oid, exact);
      DEBUGP ("vp len: %d / %d\n", vp->namelen, 8);
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
var_system(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
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
            long_return = calculate_time_diff(&now, &starttime);
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
writeVersion(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
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
writeSystem(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
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

