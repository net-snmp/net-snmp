#include <sys/time.h>

#include "mibdefs.h"
#include "mibincl.h"
#include "../../config.h"

static char *VersionInfo="Ext2-7-3";

int clear_cache();

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
  long long_ret;
  char errmsg[300], *cptr;
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
      return((u_char *) long_ret);
  }      
  return NULL;
}
