#include <stdio.h>
#include <sys/wait.h>
#include "struct.h"

char *find_field();
char *skip_white();

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
  fprintf(fprintf, "Server Exiting with code %d\n",var);
  fclose (fprintf);
  exit(var);
}

struct myproc *get_proc_instance(proc,inst)
     int inst;
     struct myproc *proc;
{
  int i;
  
  if (proc == NULL) return(NULL);
  for (i=1;i != inst && i < numprocs && proc != NULL; i++) proc = proc->next;
  return(proc);
}

struct extensible *get_exten_instance(exten,inst)
     int inst;
     struct extensible *exten;
{
  int i;
  
  if (exten == NULL) return(NULL);
  for (i=1;i != inst && i < numextens && exten != NULL; i++) exten = exten->next;
  return(exten);
}

int sh_count_procs(procname)
     char *procname;
{
  char line[STRMAX], *cptr;
  int ret=0, fd;
  FILE *file;
#ifdef hpux
  int status;
#else
  union wait status;
#endif
  
  fd = get_ps_output();
  file = fdopen(fd,"r");
  while(fgets(line,STRMAX,file) != NULL)
    {
#ifdef hpux
      if ((cptr = find_field(line,4)) == NULL)
#else
      if ((cptr = find_field(line,5)) == NULL)
#endif
        continue;
      copy_word(cptr,line);
      if (!strcmp(line,procname)) ret++;
    }
  fclose(file);
  close(fd);
  while(wait3(&status,WNOHANG,0) > 0);
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

int exec_command(ex)
     struct extensible *ex;
{
  char line[STRMAX], *cptr;
  int ret=0, fd;
  FILE *file;
#ifdef hpux
  int status;
#else
  union wait status;
#endif
  
  fd = get_exec_output(ex);
  file = fdopen(fd,"r");
  if (fgets(ex->output,STRMAX,file) == NULL) {
    ex->output[0] = NULL;
  }
  fclose(file);
  close(fd);
  while(wait3(&ex->result,0,0) > 0);
  ex->result = WEXITSTATUS(ex->result);
  return(ex->result);
}

#define MAXARGS 30

int get_exec_output(ex)
  struct extensible *ex;
{
  int fd[2],i, cnt;
  FILE *ret;
  FILE *tmpout;
  char ctmp[STRMAX], *cptr1, *cptr2, argvs[STRMAX], **argv, **aptr;
  
  if (pipe(fd)) 
    {
      perror("pipe");
    }
  if (fork() == 0) 
    {
      close(1);
      if (dup(fd[1]) != 1)
	{
	  perror("dup");
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
/*      ret = fdopen(fd[0],"r"); */
      return(fd[0]);
    }
}

int get_ps_output()
{
  int fd[2];
  FILE *ret;
  
  if (pipe(fd)) 
    {
      perror("pipe");
    }
  if (fork() == 0) 
    {
      close(1);
      if (dup(fd[1]) != 1)
	{
	  perror("dup");
	}
      close(fd[1]);
      close(fd[0]);
#ifdef hpux
      execl("/bin/ps","ps","-e",NULL);
#else
      execl("/bin/ps","ps","-xac",NULL);
#endif
      perror("execl");
      exit(1);
    }
  else
    {
      close(fd[1]);
      return(fd[0]);
    }
} 
