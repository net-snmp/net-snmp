#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <nlist.h>
#include <machine/param.h>
#include <sys/vmmeter.h>
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
static int pageshift;           /* log base 2 of the pagesize */

unsigned char *checkmib(vp,name,length,exact,var_len,write_method,newname,max)
    register struct variable *vp;
    register oid	*name;
    register int	*length;
    int			exact;
    int			*var_len;
    int			(**write_method)();
    oid                 *newname;
    int                 max;
{
  int i, rtest;
  
  for(i=0,rtest=0; i < *length-1; i++) {
    if (name[i] != vp->name[i]) {
      rtest = 1;
    }
  }
  if (rtest) {
    *var_len = NULL;
    return NULL;
  }
  if (*length == vp->namelen) {
    bcopy((char *) vp->name, (char *)newname,
          (int)vp->namelen * sizeof (oid));
    newname[*length] = 1;
    *length = vp->namelen+1;
  }
  else if (*length != vp->namelen+1) {
    *var_len = NULL;
    return NULL;
  }
  else {
    bcopy((char *) vp->name, (char *)newname, (int)vp->namelen * sizeof (oid));
    if (!exact)
      newname[*length-1] = name[*length-1] + 1;
    else
      newname[*length-1] = name[*length-1];
    if (newname[*length-1] > max) {
      *var_len = NULL;
      return NULL;
    }
  }  
  bcopy((char *)newname, (char *)name, (*length) * sizeof(oid));
  *write_method = 0;
  *var_len = sizeof(long);   /* default */
}

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


  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,numprocs))
    return(NULL);
  
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

  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,numextens))
    return(NULL);

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

#define pagetok(size) ((size) << pageshift)
#define NL_TOTAL 0
#define  KNLookup(nl_which, buf, s)   (klookup((int) nl[nl_which].n_value, buf, s))

static struct nlist nl[] = {
#ifndef hpux
  { "_total"}
#else
  { "total"}
#endif
};

unsigned char *var_wes_mem(vp, name, length, exact, var_len, write_method)
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

  struct vmtotal total;

  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,1))
    return(NULL);
  if (KNLookup(NL_TOTAL, (int *)&total, sizeof(total)) == NULL) {
    return(0);
  }
  switch (vp->magic) {
    case MEMTOTALSWAP:
      long_ret = pagetok(total.t_vm);
      return((u_char *) (&long_ret));
    case MEMUSEDSWAP:
      long_ret = pagetok(total.t_avm);
      return((u_char *) (&long_ret));
    case MEMTOTALREAL:
      long_ret = pagetok((int) total.t_rm);
      return((u_char *) (&long_ret));
    case MEMUSEDREAL:
      long_ret = pagetok((int) total.t_arm);
      return((u_char *) (&long_ret));
    case MEMTOTALSWAPTXT:
      long_ret = pagetok(total.t_vmtxt);
      return((u_char *) (&long_ret));
    case MEMUSEDSWAPTXT:
      long_ret = pagetok(total.t_avmtxt);
      return((u_char *) (&long_ret));
    case MEMTOTALREALTXT:
      long_ret = pagetok(total.t_rmtxt);
      return((u_char *) (&long_ret));
    case MEMUSEDREALTXT:
      long_ret = pagetok(total.t_armtxt);
      return((u_char *) (&long_ret));
    case MEMTOTALFREE:
      long_ret = pagetok(total.t_free);
      return((u_char *) (&long_ret));
  }
}

int update_config()
{
  free_config(&procwatch,&extens);
  read_config (DEFPROCFILE,&procwatch,&numprocs,&extens,&numextens);
  signal(SIGHUP,update_config);
}

extern char version_descr[];

init_wes() {
  
  struct extensible extmp;
  int ret,pagesize;

  
#ifdef mips
  strcpy(extmp.command,"/bin/uname -m -n -r -s -v");
#else
  strcpy(extmp.command,"/bin/uname -m -n -r -s -v -i");
#endif
  extmp.type = EXECPROC;
  extmp.next = NULL;

  read_config (DEFPROCFILE,&procwatch,&numprocs,&extens,&numextens);
  /* set default values of system stuff */
  exec_command(&extmp);
  strcpy(version_descr,extmp.output);
  signal(SIGHUP,update_config);

  /* nlist stuff */

  if ((ret = nlist("/hp-ux",nl)) == -1) {
    ERROR("nlist");
    exit(1);
  }
  for(ret = 0; nl[ret].n_name != NULL; ret++) {
    if (nl[ret].n_type == 0) {
      fprintf(stderr, "nlist err:  %s not found\n",nl[ret].n_name);
    }
  }

  pagesize = 1 << PGSHIFT;
  pageshift = 0;
  while (pagesize > 1) {
    pageshift++;
    pagesize >>= 1;
  }
  pageshift -= 10;
}

