#include <stdio.h>
#include <strings.h>
#include "struct.h"

#define ofile stderr
#define debug 0

char *skip_white();
char *skip_not_white();
void copy_word();

int read_config(filename, procp, numps, ppexten, numexs)
     char *filename;
     struct myproc **procp;
     struct extensible **ppexten;
     int *numexs, *numps;
{

  FILE *ifile;
  char line[STRMAX], word[STRMAX];
  char *cptr, *tcptr;
  int linecount=0;;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    fprintf(ofile, "couldn't open %s for reading\n",filename);
    Exit(21);
  }

  (*procp) = NULL;
  (*ppexten) = NULL;
  while (fgets(line,STRMAX,ifile) != NULL) 
    {
      linecount++;
      cptr = line;
      /* check blank line or # comment */
      if (cptr = skip_white(cptr))
	{
          copy_word(cptr,word);
          cptr = skip_not_white(cptr);
          cptr = skip_white(cptr);
          if (cptr == NULL) {
            fprintf(stderr,"snmpd: Blank line following %s command in %s:%d",
                    word,filename,linecount);
          }
          else if (!strncmp(word,"sh",2) || !strncmp(word,"exec",4)) {
            (*ppexten) = (struct extensiblea *) malloc(sizeof(struct extensible));
            (*ppexten)->next = NULL;
            (*numexs)++;
            /* determine type */
            if (!strncmp(word,"sh",2))
              (*ppexten)->type = SHPROC;
            else
              (*ppexten)->type = EXECPROC;
            /* name */
            copy_word(cptr,(*ppexten)->name);
            /* command */
            cptr = skip_not_white(cptr);
            cptr = skip_white(cptr);
            for(tcptr=cptr;*tcptr != NULL && *tcptr != '#' && *tcptr != ';';
                           tcptr++);
            strncpy((*ppexten)->command,cptr,tcptr-cptr);
            (*ppexten)->command[tcptr-cptr-1]=NULL;
            ppexten = &((*ppexten)->next);
          }
          else if (!strncmp(word,"proc",4)) {
            (*procp) = (struct myproc *) malloc(sizeof(struct myproc));
            (*procp)->next = NULL;
            (*numps)++;
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
            if (debug) fprintf (ofile,"Read:  %s (%d) (%d)\n",
                                (*procp)->name, (*procp)->max, (*procp)->min);
            procp = &((*procp)->next);
          }
          else {
            fprintf(stderr,"snmpd: Unknown command in %s:%d  %s",
                    filename,linecount,word);
          }
	}
    }
  close(ifile);
}

free_config(procp,ppexten)
     struct myproc **procp;
     struct extensible **ppexten;
{
  struct myproc *ptmp, *ptmp2;
  struct extensible *etmp, *etmp2;

  for (ptmp = *procp; ptmp != NULL;) {
    ptmp2 = ptmp;
    ptmp = ptmp->next;
    free(ptmp2);
  }

  for (etmp = *ppexten; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    free(etmp2);
  }

  *procp = NULL;
  *ppexten = NULL;

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

