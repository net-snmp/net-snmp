#include <config.h>

#include "mibincl.h"
#include "proc.h"
#include "util_funcs.h"


struct myproc *get_proc_instance __P((struct myproc *,int));
struct myproc *procwatch;
static struct extensible fixproc;
int numprocs=0;

unsigned char *var_extensible_proc(vp, name, length, exact, var_len, write_method)
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

  oid newname[30];
  struct myproc *proc;
  static long long_ret;
  static char errmsg[300];


  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,numprocs))
    return(NULL);
  
  if ((proc = get_proc_instance(procwatch,newname[*length-1]))) {
    switch (vp->magic) {
      case MIBINDEX:
        long_ret = newname[*length-1];
        return((u_char *) (&long_ret));
      case ERRORNAME:   /* process name to check for */
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
      case ERRORFLAG:
        long_ret = sh_count_procs(proc->name);
        if (long_ret >= 0 &&
            ((proc->min && long_ret < proc->min) || 
            (proc->max && long_ret > proc->max) ||
            (proc->min == 0 && proc->max == 0 && long_ret < 1))) {
          long_ret = 1;
        }
        else {
          long_ret = 0;
        }
        return ((u_char *) (& long_ret));
      case ERRORMSG:
        long_ret = sh_count_procs(proc->name);
        if (long_ret < 0) {
          errmsg[0] = 0;   /* catch out of mem errors return 0 count */
        } else if (proc->min && long_ret < proc->min) {
          sprintf(errmsg,"Too few %s running (# = %d)",
                  proc->name, (int) long_ret);
        }
        else if (proc->max && long_ret > proc->max) {
          sprintf(errmsg,"Too many %s running (# = %d)",
                  proc->name, (int) long_ret);
        }
        else if (proc->min == 0 && proc->max == 0 && long_ret < 1) {
          sprintf(errmsg,"No %s process running.", proc->name);
        }
        else {
          errmsg[0] = 0;
        }
        *var_len = strlen(errmsg);
        return((u_char *) errmsg);
      case ERRORFIX:
        *write_method = fixProcError;
        long_return = fixproc.result;
        return ((u_char *) &long_return);
    }
    return NULL;
  }
  return NULL;
}

int
fixProcError(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  
  struct myproc *proc;
  long tmp=0;
  int tmplen=1000;

  if ((proc = get_proc_instance(procwatch,name[8]))) {
    if (var_val_type != INTEGER) {
      printf("Wrong type != int\n");
      return SNMP_ERR_WRONGTYPE;
    }
    asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
    if (tmp == 1 && action == COMMIT) {
#ifdef PROCFIXCMD
      sprintf(fixproc.command,PROCFIXCMD,proc->name);
      exec_command(&fixproc);
#endif
    } 
    return SNMP_ERR_NOERROR;
  }
  return SNMP_ERR_WRONGTYPE;
}

struct myproc *get_proc_instance(proc,inst)
     int inst;
     struct myproc *proc;
{
  int i;
  
  if (proc == NULL) return(NULL);
  for (i=1;i != inst && proc != NULL; i++) proc = proc->next;
  return(proc);
}

#ifdef bsdi2
#include <sys/param.h>
#include <sys/sysctl.h>

#define PP(pp, field) ((pp)->kp_proc . field)
#define EP(pp, field) ((pp)->kp_eproc . field)
#define VP(pp, field) ((pp)->kp_eproc.e_vm . field)

/* these are for keeping track of the proc array */

static int nproc = 0;
static int onproc = -1;
static struct kinfo_proc *pbase = 0;

int sh_count_procs(procname)
  char *procname;
{
  register int i,ret = 0;
  register struct kinfo_proc *pp;
  static int mib[] = { CTL_KERN, KERN_PROC , KERN_PROC_ALL };

  if (sysctl(mib, 3, NULL, &nproc, NULL, 0) < 0) return 0;

  if(nproc > onproc || !pbase) {
    if((pbase = (struct kinfo_proc*) realloc(pbase, 
                                             nproc + sizeof(struct kinfo_proc))) == 0) return -1;
    onproc = nproc;
    memset(pbase,0,nproc + sizeof(struct kinfo_proc));
  }

  if (sysctl(mib, 3, pbase, &nproc, NULL, 0) < 0) return -1;
   
  for (pp = pbase, i = 0; i < nproc / sizeof(struct kinfo_proc); pp++, i++)
    {
      if (PP(pp, p_stat) != 0 && (((PP(pp, p_flag) & P_SYSTEM) == 0)))
	{
          if (PP(pp, p_stat) != SZOMB && !strcmp(PP(pp,p_comm),procname)) ret++;
	}
    }
  return ret;
}
#else
int sh_count_procs(procname)
     char *procname;
{
  char line[STRMAX], *cptr;
  int ret=0, fd;
  FILE *file;
#ifndef EXCACHETIME
#endif
  struct extensible ex;
  
  if ((fd = get_ps_output(&ex)) > 0) {
    if ((file = fdopen(fd,"r")) == NULL) {
      setPerrorstatus("fdopen");
      return (-1);
    }
    while(fgets(line,STRMAX,file) != NULL)
      {
        if ((cptr = find_field(line,LASTFIELD)) == NULL)
          continue;
        copy_word(cptr,line);
        if (!strcmp(line,procname)) ret++;
      }
#ifdef USEERRORMIB
    if (ftell(file) < 2) {
      seterrorstatus("process list unreasonable short (mem?)",2);
      ret = -1;
    }
#endif
    fclose(file);
    close(fd);
#ifndef EXCACHETIME
    printf("waitpid:  %d\n",ex.pid);
    if (ex.pid && waitpid(ex.pid,&ex.result,0) < 0) {
      setPerrorstatus("waitpid");
    }
    ex.pid = 0;
#endif
  } else {
    ret = -1;
  }
  return(ret);
}
#endif

int get_ps_output(ex)
  struct extensible *ex;
{
  int fd;

  strcpy(ex->command,PSCMD);
  fd = get_exec_output(ex);
  return(fd);
} 

