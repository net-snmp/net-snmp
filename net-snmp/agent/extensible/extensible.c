#include <stdio.h>
#include <sys/types.h>
#include "../../snmplib/asn1.h"
#include "../../snmplib/snmp_impl.h"
#include "../snmp_vars.h"
#include "../var_struct.h"
#define u_char unsigned char
#define u_short unsigned short

#include "wes.h"

static struct myproc *procwatch;
int numprocs;

unsigned char *var_wes_proc(vp, name, length, exact, var_len, write_method)
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
  char errmsg[300];

  fprintf(stderr,"Wes stuff\t");

  if (*length == 8) {
#ifdef DEBUG
    printf("here: -\n");
#endif
    bcopy((char *) vp->name, (char *)newname,
          (int)vp->namelen * sizeof (oid));
    newname[8] = 1;
    *length = vp->namelen+1;
  }
  else if (*length != 9) {
#ifdef DEBUG
    printf("Too long...  ret\n");
#endif
    *var_len = NULL;
    return NULL;
  }
  else {
#ifdef DEBUG
    printf("here: %d\n",name[8]);
#endif
    bcopy((char *) vp->name, (char *)newname, (int)vp->namelen * sizeof (oid));
    for(i=0,rtest=0; i < *length-1; i++) {
#ifdef DEBUG
      printf(".%d",name[i]);
#endif
      if (name[i] != vp->name[i]) {
        rtest = 1;
      }
    }
#ifdef DEBUG
    printf(".%d: len=%d,%d\n",name[i],*length,vp->namelen);
#endif
    if (rtest || name[8] >= numprocs) {
#ifdef DEBUG
      printf("test1:  %d\n",rtest);
#endif
      return NULL;
    }

    if (!exact) newname[8] = name[8] + 1;
#ifdef DEBUG
    printf("in:%d\ttest: %d\texact:%d\tnumproc:%d\n",name[8],rtest,exact,
           numprocs);
#endif
  }  
  bcopy((char *)newname, (char *)name, (*length) * sizeof(oid));
  *write_method = 0;
  *var_len = sizeof(long);   /* default */
  if (proc = get_proc_instance(procwatch,newname[8])) {
    switch (vp->magic) {
      case WESINDEX:
        long_ret = newname[8];
        return((u_char *) (&long_ret));
      case WESNAMES:
        *var_len = strlen(proc->name);
        return((u_char *) (proc->name));
      case WESMIN:
        long_ret = proc->min;
        return((u_char *) (&long_ret));
      case WESMAX:
        long_ret = proc->max;
        return ((u_char *) (&long_ret));
      case WESCOUNT:
        long_ret = sh_count_procs(proc->name);
        return ((u_char *) (& long_ret));
      case WESERROR:
        long_ret = sh_count_procs(proc->name);
        if ((proc->min && long_ret < proc->min) || 
            (proc->max && long_ret > proc->max) ||
            (proc->min == 0 && proc->max == 0 && long_ret < 1)) {
          long_ret = 1;
        }
        else {
          long_ret = 0;
        }
        return ((u_char *) (& long_ret));
      case WESERRORMSG:
        long_ret = sh_count_procs(proc->name);
        if (proc->min && long_ret < proc->min) {
          sprintf(errmsg,"Too few copies of %s running (# = %d)",
                  proc->name, long_ret);
        }
        else if (proc->max && long_ret > proc->max) {
          sprintf(errmsg,"Too many copies of %s running (# = %d)",
                  proc->name, long_ret);
        }
        else if (proc->min == 0 && proc->max == 0 && long_ret < 1) {
          sprintf(errmsg,"No %s process running.", proc->name);
        }
        else {
          errmsg[0] = NULL;
        }
        *var_len = strlen(errmsg);
        return((u_char *) errmsg);
    }
    return NULL;
  }
  return NULL;
}


init_wes() {
  numprocs = read_config (DEFPROCFILE,&procwatch);
}
