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
static struct exstensible *extens;
int numprocs, numextens;

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


  if (*length == 8) {
    bcopy((char *) vp->name, (char *)newname,
          (int)vp->namelen * sizeof (oid));
    newname[8] = 1;
    *length = vp->namelen+1;
  }
  else if (*length != 9) {
    *var_len = NULL;
    return NULL;
  }
  else {
    bcopy((char *) vp->name, (char *)newname, (int)vp->namelen * sizeof (oid));
    for(i=0,rtest=0; i < *length-1; i++) {
      if (name[i] != vp->name[i]) {
        rtest = 1;
      }
    }
    if (rtest || name[8] >= numprocs) {
      return NULL;
    }

    if (!exact) newname[8] = name[8] + 1;
  }  
  bcopy((char *)newname, (char *)name, (*length) * sizeof(oid));
  *write_method = 0;
  *var_len = sizeof(long);   /* default */
  if (proc = get_proc_instance(procwatch,newname[8])) {
    switch (vp->magic) {
      case PROCINDEX:
        long_ret = newname[8];
        return((u_char *) (&long_ret));
      case PROCNAMES:
        *var_len = strlen(proc->name);
        return((u_char *) (proc->name));
      case PROCMIN:
        long_ret = proc->min;
        return((u_char *) (&long_ret));
      case PROCMAX:
        long_ret = proc->max;
        return ((u_char *) (&long_ret));
      case PROCCOUNT:
        long_ret = sh_count_procs(proc->name);
        return ((u_char *) (& long_ret));
      case PROCERROR:
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
      case PROCERRORMSG:
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

unsigned char *var_wes_shell(vp, name, length, exact, var_len, write_method)
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
  struct extensible *exten;
  long long_ret;
  char errmsg[300];

  if (*length == 8) {
    bcopy((char *) vp->name, (char *)newname,
          (int)vp->namelen * sizeof (oid));
    newname[8] = 1;
    *length = vp->namelen+1;
  }
  else if (*length != 9) {
    *var_len = NULL;
    return NULL;
  }
  else {
    bcopy((char *) vp->name, (char *)newname, (int)vp->namelen * sizeof (oid));
    for(i=0,rtest=0; i < 7; i++) {
/*      printf(".%d",name[i]); */
      if (name[i] != vp->name[i]) {
        rtest = 1;
      }
    }
/*    printf("\nrtest:  %d, name[8]:  %d, num:  %d, exact:  %d\n",rtest,name[8],numextens,exact); */
    if (!exact) newname[8] = name[8] + 1;
    if (rtest || newname[8] > numextens)
      return NULL;

  }  
  bcopy((char *)newname, (char *)name, (*length) * sizeof(oid));
  *write_method = 0;
  *var_len = sizeof(long);   /* default */
  if (exten = get_exten_instance(extens,newname[8])) {
    switch (vp->magic) {
      case SHELLINDEX:
        long_ret = newname[8];
        return((u_char *) (&long_ret));
      case SHELLNAMES:
        *var_len = strlen(exten->name);
        return((u_char *) (exten->name));
      case SHELLCOMMAND:
        *var_len = strlen(exten->command);
        return((u_char *) (exten->command));
      case SHELLRESULT:
        if (exten->type == EXECPROC)
          exec_command(exten);
        else
          shell_command(exten);
        return((u_char *) (&exten->result));
        return((u_char *) (&long_ret));
      case SHELLOUTPUT:
        if (exten->type == EXECPROC)
          exec_command(exten);
        else
          shell_command(exten);
        *var_len = strlen(exten->output);
        return((u_char *) (exten->output));
    }
    return NULL;
  }
  return NULL;
}


init_wes() {
  read_config (DEFPROCFILE,&procwatch,&numprocs,&extens,&numextens);
}
