#include <config.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <sys/types.h>
#ifdef __alpha
#ifndef _BSD
#define _BSD
#define _myBSD
#endif
#endif
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef __alpha
#ifdef _myBSD
#undef _BSD
#undef _myBSD
#endif
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
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
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>
#include <signal.h>

#include "mibincl.h"

#include "extproto.h"

#ifdef EXCACHETIME
static long cachetime;
#endif

extern int numprocs, numextens;

void
Exit(var)
  int var;
{
  fprintf(stderr, "Server Exiting with code %d\n",var);
  fclose (stderr);
  exit(var);
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

struct extensible *get_exten_instance(exten,inst)
     int inst;
     struct extensible *exten;
{
  int i;
  
  if (exten == NULL) return(NULL);
  for (i=1;i != inst && exten != NULL; i++) exten = exten->next;
  return(exten);
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

int shell_command(ex)
  struct extensible *ex;
{
  char shellline[STRMAX];
  FILE *shellout;
  
  sprintf(shellline,"%s > /tmp/shoutput",ex->command);
  ex->result = system(shellline);
  ex->result = WEXITSTATUS(ex->result);
  shellout = fopen("/tmp/shoutput","r");
  if (fgets(ex->output,STRMAX,shellout) == NULL) {
    ex->output[0] = 0;
  }
  fclose(shellout);
  unlink("/tmp/shoutput");
  return(ex->result);
}

#define MAXOUTPUT 300

int exec_command(ex)
     struct extensible *ex;
{
  int fd;
  FILE *file;
  
  if ((fd = get_exec_output(ex))) {
    
    file = fdopen(fd,"r");
    if (fgets(ex->output,STRMAX,file) == NULL) {
      ex->output[0] = 0;
    }
    fclose(file);
    close(fd);
#ifndef EXCACHETIME
    if (ex->pid && waitpid(ex->pid,&ex->result,0) < 0) {
      setPerrorstatus("waitpid");
    }
    ex->pid = 0;
#endif
  } else {
    ex->output[0] = 0;
    ex->result = 0;
  }
  return(ex->result);
}

#define MAXARGS 30

int get_exec_output(ex)
  struct extensible *ex;
{
  int fd[2],i, cnt;
  char ctmp[STRMAX], *cptr1, *cptr2, argvs[STRMAX], **argv, **aptr;
#ifdef EXCACHETIME
  char cache[MAXCACHESIZE];
  long cachebytes;
  long curtime;
  static char lastcmd[STRMAX];
  int cfd;
  static int lastresult;
  int readcount;
#endif

#ifdef EXCACHETIME
  curtime = time(NULL);
  if (curtime > (cachetime + EXCACHETIME) ||
      strcmp(ex->command, lastcmd) != 0) {
    strcpy(lastcmd,ex->command);
    cachetime = curtime;
#endif
    if (pipe(fd)) 
      {
        setPerrorstatus("pipe");
#ifdef EXCACHETIME
        cachetime = 0;
#endif
        return 0;
      }
    if ((ex->pid = fork()) == 0) 
      {
        close(1);
        if (dup(fd[1]) != 1)
          {
            setPerrorstatus("dup");
            return 0;
          }
        close(fd[1]);
        close(fd[0]);
        for(cnt=1,cptr1 = ex->command, cptr2 = argvs; *cptr1 != 0;
            cptr2++, cptr1++) {
          *cptr2 = *cptr1;
          if (*cptr1 == ' ') {
            *(cptr2++) = 0;
            cptr1 = skip_white(cptr1);
            *cptr2 = *cptr1;
            if (*cptr1 != 0) cnt++;
          }
        }
        *cptr2 = 0;
        *(cptr2+1) = 0;
        argv = (char **) malloc((cnt+2) * sizeof(char *));
        aptr = argv;
        *(aptr++) = argvs;
        for (cptr2 = argvs, i=1; i != cnt; cptr2++)
          if (*cptr2 == 0) {
            *(aptr++) = cptr2 + 1;
            i++;
          }
        while (*cptr2 != 0) cptr2++;
        *(aptr++) = NULL;
        copy_word(ex->command,ctmp);
        execv(ctmp,argv);
        perror("execv");
        exit(1);
      }
    else
      {
        close(fd[1]);
        if (ex->pid < 0) {
          close(fd[0]);
          setPerrorstatus("fork");
#ifdef EXCACHETIME
          cachetime = 0;
#endif
          return 0;
        }
#ifdef EXCACHETIME
        unlink(CACHEFILE);
        if ((cfd = open(CACHEFILE,O_WRONLY|O_TRUNC|O_CREAT,0644)) < 0) {
          setPerrorstatus("open");
          cachetime = 0;
          return 0;
        }
        fcntl(fd[0],F_SETFL,O_NONBLOCK);  /* don't block on reads */
        for (readcount = 0; readcount <= MAXREADCOUNT &&
                         (cachebytes = read(fd[0],(void *) cache,MAXCACHESIZE));
                       readcount++) {
          if (cachebytes > 0)
            write(cfd,(void *) cache, cachebytes);
          else if (cachebytes == -1 && errno != EAGAIN) {
            setPerrorstatus("read");
            break;
          }
          else
            sleep (1);
        }
        close(cfd);
        close(fd[0]);
        /* wait for the child to finish */
        if (ex->pid > 0 && waitpid(ex->pid,&ex->result,0) < 0) {
          setPerrorstatus("waitpid()");
          cachetime = 0;
          return 0;
        }
        ex->pid = 0;
        ex->result = WEXITSTATUS(ex->result);
        lastresult = ex->result;
#else
        return(fd[0]);
#endif
      }
#ifdef EXCACHETIME
  }
  else {
      ex->result = lastresult;
  }
  if ((cfd = open(CACHEFILE,O_RDONLY)) < 0) {
    setPerrorstatus("open");
    return 0;
  }
  return(cfd);
#endif
}

int
clear_cache(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  
  int tmp=0, tmplen=1000;

  if (var_val_type != INTEGER) {
    printf("Wrong type != int\n");
    return SNMP_ERR_WRONGTYPE;
  }
  asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
  if (tmp == 1 && action == COMMIT) {
#ifdef EXCACHETIME
    cachetime = 0;                      /* reset the cache next read */
#endif 
  } 
  return SNMP_ERR_NOERROR;
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
  int tmp=0, tmplen=1000;

  if (var_val_type != INTEGER) {
    printf("Wrong type != int\n");
    return SNMP_ERR_WRONGTYPE;
  }
  asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
  if (tmp == 1 && action == COMMIT) {
    update_config();
  } 
  return SNMP_ERR_NOERROR;
}

extern char **argvrestartp, *argvrestartname;

RETSIGTYPE restart_doit(a)
int a;
{
  int i;
  
  /* close everything open */
  for (i=0; i<= 2; i++)
    close(i);

  /* do the exec */
  execv(argvrestartname,argvrestartp);
  setPerrorstatus("execv");
}

int
restart_hook(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  
  int tmp=0, tmplen=1000;

  if (var_val_type != INTEGER) {
    printf("Wrong type != int\n");
    return SNMP_ERR_WRONGTYPE;
  }
  asn_parse_int(var_val,&tmplen,&var_val_type,&tmp,sizeof(int));
  if (tmp == 1 && action == COMMIT) {
    signal(SIGALRM,restart_doit);
    alarm(RESTARTSLEEP);
  } 
  return SNMP_ERR_NOERROR;
}

int get_ps_output(ex)
  struct extensible *ex;
{
  int fd;

  strcpy(ex->command,PSCMD);
  fd = get_exec_output(ex);
  return(fd);
} 

void
print_mib_oid(name,len)
  oid name[];
  int len;
{
  int i;
  printf("Mib:  ");
  for(i=0; i < len; i++) {
    printf(".%d",(int) name[i]);
  }
}

void
sprint_mib_oid(buf,name,len)
  char *buf;
  oid name[];
  int len;
{
  int i;
  for(i=0; i < len; i++) {
    sprintf(buf,".%d",(int) name[i]);
    while (*buf != 0)
      buf++;
  }
}
