/*
 *  System MIB group implementation - system.c
 *
 */

#include "../common_header.h"

#include <ctype.h>
#if HAVE_UTSNAME_H
#include <utsname.h>
#else
#if HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#endif

#include "system.h"
#include "util_funcs.h"
#include "../../snmplib/system.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

char version_descr[128] = VERS_DESC;
char sysContact[128] = SYS_CONTACT;
char sysName[128] = SYS_NAME;
char sysLocation[128] = SYS_LOC;

oid version_id[] = {EXTENSIBLEMIB,AGENTID,OSTYPE};
int version_id_len = sizeof(version_id)/sizeof(version_id[0]);

struct timeval starttime;

int writeVersion __P((int, u_char *,u_char, int, u_char *,oid*, int));
int writeSystem __P((int, u_char *,u_char, int, u_char *,oid*, int));
int header_system __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));


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

  gettimeofday(&starttime, NULL);
  starttime.tv_sec--;
  starttime.tv_usec += 1000000L;

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
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_system: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[SYSTEM_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
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
            *var_len = sizeof(version_id);
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

    if (var_val_type != STRING){
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

    if (var_val_type != STRING){
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

