#include <config.h>

#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "mibincl.h"
#include "struct.h"
#include "versioninfo.h"
#include "util_funcs.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "../../../snmplib/system.h"

#include "version.h"

unsigned char *var_extensible_version(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid	*name;
/* IN/OUT - input name requested, output name found */
    register int	*length;
/* IN/OUT - length of input and output oid's */
    int			exact;
/* IN - TRUE if an exact match was requested. */
    int			*var_len;
/* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *,u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  static long long_ret;
  static char errmsg[300];
  char *cptr;
  time_t curtime;
  char c_oid[MAX_NAME_LEN];
#ifdef CONFIGURE_OPTIONS
  static char *config_opts = CONFIGURE_OPTIONS;
#endif

  if (snmp_get_do_debugging()) {
    sprint_objid (c_oid, name, *length);
    DEBUGMSGTL(("ucd-snmp/versioninfo", "versionMib: %s %d\n", c_oid, exact));
  }

  if (header_generic(vp,name,length,exact,var_len,write_method))
    return(NULL);
  
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = name[8];
      return((u_char *) (&long_ret));
    case VERTAG:
      sprintf(errmsg,VersionInfo);
      *var_len = strlen(errmsg);
      return((u_char *) errmsg); 
    case VERDATE:
      sprintf(errmsg,"$Date$");
      *var_len = strlen(errmsg);
      return((u_char *) errmsg); 
    case VERCDATE:
      curtime = time(NULL);
      cptr = ctime(&curtime);
      sprintf(errmsg,cptr);
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
    case VERIDENT:
      sprintf(errmsg,"$Id$");
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
    case VERCONFIG:
#ifdef CONFIGURE_OPTIONS
      *var_len = strlen(config_opts);
      return (u_char *) config_opts;
#else
      sprintf(errmsg,"");
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
#endif
    case VERCLEARCACHE:
      *write_method = clear_cache;
      long_ret = 0;
      return((u_char *) &long_ret);
    case VERUPDATECONFIG:
      *write_method = update_hook;
      long_ret = 0;
      return((u_char *) &long_ret);
    case VERRESTARTAGENT:
      *write_method = restart_hook;
      long_ret = 0;
      return((u_char *) &long_ret);
    case VERDEBUGGING:
      *write_method = debugging_hook;
      long_ret = snmp_get_do_debugging();
      return((u_char *) &long_ret);
  }      
  return NULL;
}

int
update_hook(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  long tmp=0;
  int tmplen=1000;

  if (var_val_type != ASN_INTEGER) {
    printf("Wrong type != int\n");
    return SNMP_ERR_WRONGTYPE;
  }
  asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
  if (tmp == 1 && action == COMMIT) {
    update_config(0);
  } 
  return SNMP_ERR_NOERROR;
}

int
debugging_hook(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  long tmp=0;
  int tmplen=1000;

  if (var_val_type != ASN_INTEGER) {
    printf("Wrong type != int\n");
    return SNMP_ERR_WRONGTYPE;
  }
  asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
  if (action == COMMIT) {
    snmp_set_do_debugging(tmp);
  } 
  return SNMP_ERR_NOERROR;
}

