#include <stdio.h>
#include <sys/wait.h>
#include "struct.h"

extern int numprocs;

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
/*      ret = fdopen(fd[0],"r"); */
      return(fd[0]);
    }
} 
