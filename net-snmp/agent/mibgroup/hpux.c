/* HP specific stuff that OpenView recognizes */

#include <config.h>

#include <signal.h>
#include <nlist.h>
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif

#include "mibincl.h"
#include "hpux.h"

#ifdef RESERVED_FOR_FUTURE_USE
int writeHP(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  printf("Gotto:  writeHP\n");
  return SNMP_ERR_NOERROR;
}
#endif

unsigned char *var_hp(vp, name, length, exact, var_len, write_method)
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
  char errmsg[300];

  bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
  newname[*length] = 0;
  result = compare(name, *length, newname, (int)vp->namelen + 1);
  if ((exact && (result != 0)) || (!exact && (result >= 0)))
    return NULL;
  bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
  *length = *length+1; 
  *var_len = sizeof(long);	/* default length */
  switch (vp->magic){
    case HPFLAG:
    case HPCONF:
    case HPSTATUS:
    case HPRECONFIG:
      long_ret = 1;
      return (u_char *) &long_ret;   /* remove trap */
    case HPLOGMASK:
      long_ret = 3;
      return (u_char *) &long_ret;   
    case HPTRAP:
      newname[*length-1] = 128;
      newname[*length] = 120;
      newname[*length+1] = 57;
      newname[*length+2] = 92;
      *length = *length + 3;
      bcopy((char *)newname, (char *)name, *length * sizeof(oid));
      long_ret = ((((((128 << 8) + 120) << 8) + 57) <<8) + 92);
      return (u_char *) &long_ret;   
  }
  return NULL;
}

