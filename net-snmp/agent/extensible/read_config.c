#include <stdio.h>
#include <strings.h>
#include "struct.h"

#define ofile stderr
#define debug 0

extern int numprocs;

char *skip_white();
char *skip_not_white();
void copy_word();

int read_config(filename, procp)
     char *filename;
     struct myproc **procp;
{

  FILE *ifile;
  char line[STRMAX];
  char *cptr;
  int num=0;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    fprintf(ofile, "couldn't open %s for reading\n",filename);
    Exit(21);
  }

  (*procp) = NULL;
  while (fgets(line,STRMAX,ifile) != NULL) 
    {
      cptr = line;
      /* check blank line or # comment */
      if (cptr = skip_white(cptr))
	{
	  (*procp) = (struct myproc *) malloc(sizeof(struct myproc));
	  (*procp)->next = NULL;
	  numprocs++;
	  /* not blank and not a comment */
	  copy_word(cptr,(*procp)->name);
	  cptr = skip_not_white(cptr);
	  if (cptr = skip_white(cptr)) 
	    {
	      (*procp)->max = atoi(cptr);
	      cptr = skip_not_white(cptr);
	      if (cptr = skip_white(cptr))
		(*procp)->min = atoi(cptr);
	      else 
		(*procp)->min = 0;
	    }
	  else
	    {
	      (*procp)->max = 0;
	      (*procp)->min = 0;
	    }
          num++;
	  if (debug) fprintf (ofile,"Read:  %s (%d) (%d)\n",
			     (*procp)->name, (*procp)->max, (*procp)->min);
	  procp = &((*procp)->next);
	}
    }
  close(ifile);
  return num;
}

/* skip all white spaces and return 1 if found something either end of
   line or a comment character */

char *skip_white(ptr)
  char *ptr;
{
  
  while (*ptr != NULL && isspace(*ptr)) ptr++;
  if (*ptr == NULL || *ptr == '#') return (NULL);
  return (ptr);
}

char *skip_not_white(ptr)
  char *ptr;
{
  
  while (*ptr != NULL && !isspace(*ptr)) ptr++;
  if (*ptr == NULL || *ptr == '#') return (NULL);
  return (ptr);
}

void copy_word(from, to)
     char *from, *to;
{
  while (*from != NULL && !isspace(*from)) *(to++) = *(from++);
  *to = NULL;
}

char *find_field(ptr,field)
     char *ptr;
     int field;
{
  int i;
  
  if ((ptr = skip_white(ptr)) == NULL) return(NULL);
  for (i=1; *ptr != NULL && i != field; i++) 
    {
      if ((ptr = skip_not_white(ptr)) == NULL) return(NULL);
      if ((ptr = skip_white(ptr)) == NULL) return(NULL);
    }
  if (*ptr != NULL && i == field) return(ptr);
  return (NULL);
}

