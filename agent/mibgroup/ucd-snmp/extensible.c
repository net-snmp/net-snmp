#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
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
#include <signal.h>
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#if !(defined(bsdi2) || defined(netbsd1))
#include <sys/vmmeter.h>
#endif
#endif
#if HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#if HAVE_SYS_SWAP_H
#include <sys/swap.h>
#endif
#if HAVE_SYS_FS_H
#include <sys/fs.h>
#else
#if HAVE_UFS_FS_H
#include <ufs/fs.h>
#else
#if HAVE_UFS_UFS_DINODE_H
#include <ufs/ufs/dinode.h>
#endif
#if HAVE_UFS_FFS_FS_H
#include <ufs/ffs/fs.h>
#endif
#endif
#endif
#if HAVE_MTAB_H
#include <mtab.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if (!defined(HAVE_STATVFS)) && defined(HAVE_STATFS)
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#define statvfs statfs
#endif
#if HAVE_VM_SWAP_PAGER_H
#include <vm/swap_pager.h>
#endif
#if HAVE_SYS_FIXPOINT_H
#include <sys/fixpoint.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#if STDC_HEADERS
#include <string.h>
#endif
#include <ctype.h>

#include "mibincl.h"
#include "struct.h"
#include "extensible.h"
#include "util_funcs.h"
#include "read_config.h"
#include "auto_nlist.h"

extern struct myproc *procwatch;         /* moved to proc.c */
extern int numprocs;                     /* ditto */
extern struct extensible *extens;       /* In exec.c */
extern struct extensible *relocs;       /* In exec.c */
extern int numextens;                    /* ditto */
extern int numrelocs;                    /* ditto */
extern struct extensible *passthrus;    /* In pass.c */
extern int numpassthrus;                 /* ditto */
extern char sysName[];
extern struct subtree *subtrees,subtrees_old[];
extern struct variable2 extensible_relocatable_variables[];
extern struct variable2 extensible_passthru_variables[];

void extensible_parse_config(word,cptr)
  char *word;
  char *cptr;
{

  struct extensible **pptmp;
  struct extensible **pprelocs = &relocs;
  struct extensible **ppexten = &extens;
  char *tcptr;
  
  if (*cptr == '.') cptr++;
  if (isdigit(*cptr)) {
    /* its a relocatable extensible mib */
    while(*pprelocs != NULL)
      pprelocs = &((*pprelocs)->next);
    numrelocs++;
    (*pprelocs) = (struct extensible *) malloc(sizeof(struct extensible));
    pptmp = pprelocs;
  } else {
    /* it goes in with the general extensible table */
    while(*ppexten != NULL)
      ppexten = &((*ppexten)->next);
    numextens++;
    (*ppexten) =
      (struct extensible *) malloc(sizeof(struct extensible));
    pptmp = ppexten;
  }
  /* the rest is pretty much handled the same */
  if (!strncasecmp(word,"sh",2)) 
    (*pptmp)->type = SHPROC;
  else
    (*pptmp)->type = EXECPROC;
  if (isdigit(*cptr)) {
    (*pptmp)->miblen = parse_miboid(cptr,(*pptmp)->miboid);
    while (isdigit(*cptr) || *cptr == '.') cptr++;
  }
  else {
    (*pptmp)->miboid[0] = -1;
    (*pptmp)->miblen = 0;
  }
  /* name */
  cptr = skip_white(cptr);
  copy_word(cptr,(*pptmp)->name);
  cptr = skip_not_white(cptr);
  cptr = skip_white(cptr);
  /* command */
  if (cptr == NULL) {
    config_perror("No command specified on line");
    (*pptmp)->command[0] = 0;
  } else {
    for(tcptr=cptr; *tcptr != 0 && *tcptr != '#' && *tcptr != ';';
        tcptr++);
    strncpy((*pptmp)->command,cptr,tcptr-cptr);
    (*pptmp)->command[tcptr-cptr] = 0;
    (*pptmp)->next = NULL;
  }
  if ((*pptmp)->miblen > 0) {
    register_mib(word, (struct variable *) extensible_relocatable_variables,
                 sizeof(struct variable2),
                 6, (*pptmp)->miboid, (*pptmp)->miblen);
  }
}

void extensible_free_config __P((void)) {
  struct extensible *etmp, *etmp2;

  for (etmp = extens; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    free(etmp2);
  }

  for (etmp = relocs; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    unregister_mib(etmp2->miboid, etmp2->miblen);
    free(etmp2);
  }

  relocs = NULL;
  extens = NULL;
  numextens = 0;
  numrelocs = 0;
}


struct extensible *get_exten_instance(exten,inst)
     int inst;
     struct extensible *exten;
{
  int i;
  
  if (exten == NULL) return(NULL);
  for (i=1;i != inst && exten != NULL; i++) exten = exten->next;
  return(exten);
}

#define MAXMSGLINES 1000

struct extensible *extens=NULL;  /* In exec.c */
struct extensible *relocs=NULL;  /* In exec.c */
int numextens=0,numrelocs=0;                    /* ditto */

unsigned char *var_extensible_shell(vp, name, length, exact, var_len, write_method)
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
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  static struct extensible *exten = 0;
  static long long_ret;

  if (!checkmib(vp,name,length,exact,var_len,write_method,numextens))
    return(NULL);

  if ((exten = get_exten_instance(extens,name[*length-1]))) {
    switch (vp->magic) {
      case MIBINDEX:
        long_ret = name[*length-1];
        return((u_char *) (&long_ret));
      case ERRORNAME: /* name defined in config file */
        *var_len = strlen(exten->name);
        return((u_char *) (exten->name));
      case SHELLCOMMAND:
        *var_len = strlen(exten->command);
        return((u_char *) (exten->command));
      case ERRORFLAG:  /* return code from the process */
        if (exten->type == EXECPROC)
          exec_command(exten);
        else
          shell_command(exten);
        long_ret = exten->result;
        return((u_char *) (&long_ret));
      case ERRORMSG:   /* first line of text returned from the process */
        if (exten->type == EXECPROC)
          exec_command(exten);
        else
          shell_command(exten);
        *var_len = strlen(exten->output);
        return((u_char *) (exten->output));
      case ERRORFIX:
        *write_method = fixExecError;
        long_return = 0;
        return ((u_char *) &long_return);
    }
    return NULL;
  }
  return NULL;
}

int
fixExecError(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  
  struct extensible *exten;
  long tmp=0;
  int tmplen=1000, fd;
  static struct extensible ex;
  FILE *file;

  if ((exten = get_exten_instance(extens,name[10]))) {
    if (var_val_type != ASN_INTEGER) {
      printf("Wrong type != int\n");
      return SNMP_ERR_WRONGTYPE;
    }
    asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
#ifdef EXECFIXCMD
    if (tmp == 1 && action == COMMIT) {
      sprintf(ex.command,EXECFIXCMD,exten->name);
      if ((fd = get_exec_output(&ex))) {
        file = fdopen(fd,"r");
        while (fgets(ex.output,STRMAX,file) != NULL);
        fclose(file);
        close(fd);
        wait_on_exec(&ex);
      }
    } 
#endif
    return SNMP_ERR_NOERROR;
  }
  return SNMP_ERR_WRONGTYPE;
}

/* the relocatable extensible commands variables */
struct variable2 extensible_relocatable_variables[] = {
  {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_relocatable, 1, {MIBINDEX}},
  {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_relocatable, 1, {ERRORNAME}}, 
  {SHELLCOMMAND, ASN_OCTET_STR, RONLY, var_extensible_relocatable, 1, {SHELLCOMMAND}}, 
  {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_relocatable, 1, {ERRORFLAG}},
  {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_relocatable, 1, {ERRORMSG}},
  {ERRORFIX, ASN_INTEGER, RWRITE, var_extensible_relocatable, 1, {ERRORFIX }}
};

unsigned char *var_extensible_relocatable(vp, name, length, exact, var_len, write_method)
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
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  int i, fd;
  FILE *file;
  struct extensible *exten = 0;
  static long long_ret;
  static char errmsg[STRMAX];
  struct variable myvp;
  oid tname[30];

  memcpy(&myvp,vp,sizeof(struct variable));

  long_ret = *length;
  for(i=1; i<= numrelocs; i++) {
    exten = get_exten_instance(relocs,i);
    if (exten->miblen == vp->namelen-1){
      memcpy(myvp.name,exten->miboid,exten->miblen*sizeof(oid));
      myvp.namelen = exten->miblen;
      *length = vp->namelen;
      memcpy(tname,vp->name,vp->namelen*sizeof(oid));
      if (checkmib(&myvp,tname,length,-1,var_len,write_method, -1))
        break;
      else
        exten = NULL;
    }
  }
  if (i > numrelocs || exten == NULL) {
    *length = long_ret;
    *var_len = 0;
    *write_method = NULL;
    return(NULL);
  }

  *length = long_ret;
  if (!checkmib(vp,name,length,exact,var_len,write_method,
               ((vp->magic == ERRORMSG) ? MAXMSGLINES : 1)))
    return(NULL);
  
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = name[*length-1];
      return((u_char *) (&long_ret));
    case ERRORNAME: /* name defined in config file */
      *var_len = strlen(exten->name);
      return((u_char *) (exten->name));
    case SHELLCOMMAND:
      *var_len = strlen(exten->command);
      return((u_char *) (exten->command));
    case ERRORFLAG:  /* return code from the process */
      if (exten->type == EXECPROC)
        exec_command(exten);
      else
        shell_command(exten);
      long_ret = exten->result;
      return((u_char *) (&long_ret));
    case ERRORMSG:   /* first line of text returned from the process */
      if (exten->type == EXECPROC) {
        if ((fd = get_exec_output(exten))){
          file = fdopen(fd,"r");
          for (i=0;i != name[*length-1];i++) {
            if (fgets(errmsg,STRMAX,file) == NULL) {
              *var_len = 0;
              fclose(file);
              close(fd);
              wait_on_exec(exten);
              return(NULL);
            }
          }
          fclose(file);
          close(fd);
          wait_on_exec(exten);
        } else
          errmsg[0] = 0;
      }
      else {
        if (*length > 1) {
          *var_len = 0;
          return(NULL);
        }
        shell_command(exten);
        strcpy(errmsg,exten->output);
      }
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case ERRORFIX:
      *write_method = fixExecError;
      long_return = 0;
      return ((u_char *) &long_return);
  }
  return NULL;
}

struct subtree *find_extensible(tp,tname,tnamelen,exact)
  register struct subtree	*tp;
  oid tname[];
  int tnamelen,exact;
{
  int i,tmp;
  struct extensible *exten = 0;
  struct variable myvp;
  oid name[30];
  static struct subtree mysubtree[2];

  for(i=1; i<= numrelocs; i++) {
    exten = get_exten_instance(relocs,i);
    if (exten->miblen != 0){
      memcpy(myvp.name,exten->miboid,exten->miblen*sizeof(oid));
      memcpy(name,tname,tnamelen*sizeof(oid));
      myvp.name[exten->miblen] = name[exten->miblen];
      myvp.namelen = exten->miblen+1;
      tmp = exten->miblen+1;
      if (checkmib(&myvp,name,&tmp,-1,NULL,NULL, numrelocs))
        break;
    }
  }
  if (i > numrelocs || exten == NULL)
    return(tp);
  memcpy(mysubtree[0].name,exten->miboid,exten->miblen*sizeof(oid));
  mysubtree[0].namelen = exten->miblen;
  mysubtree[0].variables = (struct variable *)extensible_relocatable_variables;
  mysubtree[0].variables_len =
    sizeof(extensible_relocatable_variables)/sizeof(*extensible_relocatable_variables);
  mysubtree[0].variables_width = sizeof(*extensible_relocatable_variables);
  mysubtree[1].namelen = 0;
  return(mysubtree);
}
