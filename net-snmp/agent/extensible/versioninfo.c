#include <config.h>

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

#include "mibdefs.h"
#include "mibincl.h"

char *VersionInfo="NetBSD.3.1.0.1.merge.1";

int clear_cache();
int update_hook();
int restart_hook();

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
    int			(**write_method)();
/* OUT - pointer to function to set variable, otherwise 0 */
{

  oid newname[30];
  int count, result,i, rtest=0;
  register int interface;
  struct myproc *proc;
  static long long_ret;
  static char errmsg[300];
  char *cptr;
  time_t curtime;

  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,1))
    return(NULL);
  
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = newname[8];
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
  }      
  return NULL;
}
