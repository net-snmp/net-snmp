#include <stdio.h>
#include <strings.h>
#include <sys/stat.h>
#include <fstab.h>
#include "wes.h"

#define ofile stderr
#define debug 0

char *skip_white();
char *skip_not_white();
void copy_word();

int read_config(filename, procp, numps, ppexten, numexs,minimumswap,disk,numdisks)
     char *filename;
     struct myproc **procp;
     struct extensible **ppexten;
     int *numexs, *numps;
     int *minimumswap;
     struct diskpart disk[];
     int *numdisks;
{

  FILE *ifile;
  char line[STRMAX], word[STRMAX];
  char *cptr, *tcptr;
  int linecount=0,i;
  struct stat stat1, stat2;
  struct fstab *fstab;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    fprintf(ofile, "couldn't open %s for reading\n",filename);
    return(1);
  }

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
          else if (!strncasecmp(word,"sh",2) || !strncasecmp(word,"exec",4)) {
            (*ppexten) =
              (struct extensible *) malloc(sizeof(struct extensible));
            (*ppexten)->next = NULL;
            (*numexs)++;
            /* determine type */
            if (!strncmp(word,"sh",2))
              (*ppexten)->type = SHPROC;
            else
              (*ppexten)->type = EXECPROC;
            if (word[0] == 'S' || word[0] == 'E') {
              for(i=0; isdigit(*cptr); i++) {
                (*ppexten)->miboid[i] = atoi(cptr);
                while(isdigit(*cptr++));
                if (*cptr == '.') cptr++;
              }
              (*ppexten)->miboid[i] = -1;
            }
            else {
              (*ppexten)->miboid[0] = -1;
            }
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
          else if (!strncmp(word,"disk",4)) {
            if (*numdisks == MAXDISKS) {
              fprintf(stderr,"Too many disks specified in %s\n",filename);
              fprintf(stderr,"\tignoring:  %s\n",cptr);
            }
            else {
              /* read disk path (eg, /1 or /usr) */
              copy_word(cptr,disk[*numdisks].path);
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
              /* read optional minimum disk usage spec */
              if (*cptr != NULL) {
                disk[*numdisks].minimumspace = atoi(cptr);
              }
              else {
                disk[*numdisks].minimumspace = DEFDISKMINIMUMSPACE;
              }
              /* find the device associated with the directory */
              stat(disk[*numdisks].path,&stat1);
              setfsent();
              if (fstab = getfsfile(disk[*numdisks].path)) {
                copy_word(fstab->fs_spec,disk[*numdisks].device);
                *numdisks += 1;
              }
              else {
                fprintf(stderr,"Error:  couldn't find device for disk %s",
                        disk[*numdisks].path);
                disk[*numdisks].minimumspace = -1;
                disk[*numdisks].path[0] = NULL;
              }
              endfsent();
            }
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
          else if (!strncmp(word,"swap",4)) {
            *minimumswap = atoi(cptr);
          }
          else {
            fprintf(stderr,"snmpd: Unknown command in %s:%d  %s",
                    filename,linecount,word);
          }
	}
    }
  close(ifile);
  return(0);
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

