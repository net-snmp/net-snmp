#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "../../config.h"
#include "mibincl.h"

char *find_field();
char *skip_white();

#ifdef EXCACHETIME
static long cachetime;
#endif

extern int numprocs, numextens;

int random()
{
  return(rand());
}

void srandom (seed)
  unsigned int seed;
{
  srand(seed);
}

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

int sh_count_procs(procname)
     char *procname;
{
  char line[STRMAX], *cptr;
  int ret=0, fd;
  FILE *file;
#ifndef EXCACHETIME
#ifdef hpux
  int status;
#else
  union wait status;
#endif
#endif
  struct extensible ex;
  
  if (fd = get_ps_output(&ex)) {
    file = fdopen(fd,"r");
    while(fgets(line,STRMAX,file) != NULL)
      {
        if ((cptr = find_field(line,LASTFIELD)) == NULL)
          continue;
        copy_word(cptr,line);
        if (!strcmp(line,procname)) ret++;
      }
#ifdef ERRORMIBNUM
    if (ftell(file) < 2) {
      seterrorstatus("process list unreasonable short (mem?)");
      ret = -1;
    }
#endif
    fclose(file);
    close(fd);
#ifndef EXCACHETIME
    printf("waitpid:  %d\n",ex.pid);
    if (ex.pid && waitpid(ex.pid,&ex.result,0) < 0) {
      perror("waitpid():");
    }
    ex.pid = 0;
#endif
  } else {
    ret = -1;
  }
  return(ret);
}

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
    ex->output[0] = NULL;
  }
  fclose(shellout);
  unlink("/tmp/shoutput");
  return(ex->result);
}

#define MAXOUTPUT 300

int exec_command(ex)
     struct extensible *ex;
{
  char line[STRMAX], *cptr;
  int ret=0, fd,i;
  FILE *file;
#ifdef hpux
  int status;
#else
  union wait status;
#endif
  
  if (fd = get_exec_output(ex)) {
    
    file = fdopen(fd,"r");
    if (fgets(ex->output,STRMAX,file) == NULL) {
      ex->output[0] = NULL;
    }
    fclose(file);
    close(fd);
#ifndef EXCACHETIME
    if (ex->pid && waitpid(ex->pid,&ex->result,0) < 0) {
      perror("waitpid():");
    }
    ex->pid = 0;
#endif
  } else {
    ex->output[0] = NULL;
    ex->result = 0;
  }
  return(ex->result);
}

#define MAXARGS 30

int get_exec_output(ex)
  struct extensible *ex;
{
  int fd[2],i, cnt, fpid;
  FILE *ret;
  FILE *tmpout;
  char ctmp[STRMAX], *cptr1, *cptr2, argvs[STRMAX], **argv, **aptr;
#ifdef EXCACHETIME
  char cache[MAXCACHESIZE];
  long cachebytes;
  long curtime;
  static struct extensible excompare;
  static char lastcmd[STRMAX];
  int cfd;
  int lastresult;
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
        return NULL;
      }
    if ((ex->pid = fork()) == 0) 
      {
        close(1);
        if (dup(fd[1]) != 1)
          {
            setPerrorstatus("dup");
            return NULL;
          }
        close(fd[1]);
        close(fd[0]);
        for(cnt=1,cptr1 = ex->command, cptr2 = argvs; *cptr1 != NULL;
                                                      cptr2++, cptr1++) {
          *cptr2 = *cptr1;
          if (*cptr1 == ' ') {
            *(cptr2++) = NULL;
            cptr1 = skip_white(cptr1);
            *cptr2 = *cptr1;
            if (*cptr1 != NULL) cnt++;
          }
        }
        *cptr2 = NULL;
        *(cptr2+1) = NULL;
        argv = (char **) malloc((cnt+2) * sizeof(char *));
        aptr = argv;
        *(aptr++) = argvs;
        for (cptr2 = argvs, i=1; i != cnt; cptr2++)
          if (*cptr2 == NULL) {
            *(aptr++) = cptr2 + 1;
            i++;
          }
        while (*cptr2 != NULL) cptr2++;
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
          setPerrorstatus("fork");
          return (NULL);
        }
/*      ret = fdopen(fd[0],"r"); */
#ifdef EXCACHETIME
        unlink(CACHEFILE);
        if ((cfd = open(CACHEFILE,O_WRONLY|O_TRUNC|O_CREAT,0644)) < 0) {
          setPerrorstatus("open");
          return(NULL);
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
        if (ex->pid && waitpid(ex->pid,&ex->result,0) < 0) {
          setPerrorstatus("waitpid()");
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
    return(NULL);
  }
  return(cfd);
#endif
}

clear_cache(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  
  struct myproc *proc;
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

int get_ps_output(ex)
  struct extensible *ex;
{
  int fd;
  FILE *ret;

  strcpy(ex->command,PSCMD);
  fd = get_exec_output(ex);
  return(fd);
} 

int print_mib_oid(name,len)
  oid name[];
  int len;
{
  int i;
  printf("Mib:  ");
  for(i=0; i < len; i++) {
    printf(".%d",name[i]);
  }
}
