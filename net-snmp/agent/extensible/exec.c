#include <config.h>

#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "mibincl.h"
#include "mibdefs.h"
#include "extproto.h"

#define MAXMSGLINES 1000

struct subtree *find_extensible __P((struct subtree *, oid *, int, int));

struct extensible *extens=NULL;  /* In exec.c */
struct extensible *relocs=NULL;  /* In exec.c */
int numextens=0,numrelocs=0;                    /* ditto */

#ifdef USESHELLMIB

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

  oid newname[30];
  static struct extensible *exten = 0;
  static long long_ret;

  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,numextens))
    return(NULL);

  if ((exten = get_exten_instance(extens,newname[*length-1]))) {
    switch (vp->magic) {
      case MIBINDEX:
        long_ret = newname[*length-1];
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

#endif

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

  if ((exten = get_exten_instance(extens,name[8]))) {
    if (var_val_type != INTEGER) {
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
      }
    } 
#endif
    return SNMP_ERR_NOERROR;
  }
  return SNMP_ERR_WRONGTYPE;
}


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

  oid newname[30];
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
      if (checkmib(&myvp,tname,length,-1,var_len,write_method,newname,
                   -1))
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
  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,
               ((vp->magic == ERRORMSG) ? MAXMSGLINES : 1)))
    return(NULL);
  
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = newname[*length-1];
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
              return(NULL);
            }
          }
          fclose(file);
          close(fd);
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

/* the relocatable extensible commands variables */
struct variable2 extensible_relocatable_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_relocatable, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_relocatable, 1, {ERRORNAME}}, 
    {SHELLCOMMAND, STRING, RONLY, var_extensible_relocatable, 1, {SHELLCOMMAND}}, 
    {ERRORFLAG, INTEGER, RONLY, var_extensible_relocatable, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_relocatable, 1, {ERRORMSG}},
  {ERRORFIX, INTEGER, RWRITE, var_extensible_relocatable, 1, {ERRORFIX }}
};

struct subtree *find_extensible(tp,tname,tnamelen,exact)
  register struct subtree	*tp;
  oid tname[];
  int tnamelen,exact;
{
  int i,tmp;
  struct extensible *exten = 0;
  struct variable myvp;
  oid newname[30], name[30];
  static struct subtree mysubtree[2];

  for(i=1; i<= numrelocs; i++) {
    exten = get_exten_instance(relocs,i);
    if (exten->miblen != 0){
      memcpy(myvp.name,exten->miboid,exten->miblen*sizeof(oid));
      memcpy(name,tname,tnamelen*sizeof(oid));
      myvp.name[exten->miblen] = name[exten->miblen];
      myvp.namelen = exten->miblen+1;
      tmp = exten->miblen+1;
      if (checkmib(&myvp,name,&tmp,-1,NULL,NULL,newname,
                   numrelocs))
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

