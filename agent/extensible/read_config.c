#include <config.h>

#include <stdio.h>
#ifdef SVR4
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#include <math.h>
#include <snmp.h>
#include <asn1.h>
#include <snmp_impl.h>

#define ofile stderr
#define debug 0

char *skip_white();
char *skip_not_white();
void copy_word();

/* communities from agent/snmp_agent.c */
extern char communities[NUM_COMMUNITIES][COMMUNITY_MAX_LEN];

int read_config(filename, procp, numps, pprelocs, numrelocs, ppexten,
                numexs,minimumswap,disk, numdisks,maxload)
     char *filename;
     struct myproc **procp;
     struct extensible **ppexten;
     struct extensible **pprelocs;
     int *numexs, *numps, *numrelocs;
     int *minimumswap;
     struct diskpart disk[];
     int *numdisks;
     double *maxload;
{

  FILE *ifile;
  char line[STRMAX], word[STRMAX];
  char *cptr, *tcptr;
  int linecount=0,i;
  struct stat stat1, stat2;
#if HAVE_FSTAB_H
  struct fstab *fstab;
#endif
  struct extensible **pptmp;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    fprintf(ofile, "couldn't open %s for reading\n",filename);
    return(1);
  }

  /* skip past set procp/ppexten */
  while (*ppexten != NULL) ppexten = &((*ppexten)->next);
  while (*pprelocs != NULL) pprelocs = &((*pprelocs)->next);
  while (*procp != NULL) procp = &((*procp)->next);

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
            /* determine type */
            if (*cptr == '.') cptr++;
            if (isdigit(*cptr)) {
              (*numrelocs) = (*numrelocs)+1;
              (*pprelocs) =
                (struct extensible *) malloc(sizeof(struct extensible));
              pptmp = pprelocs;
              pprelocs = &((*pprelocs)->next);
            }
            else {
              (*numexs) = (*numexs)+1;
              (*ppexten) =
                (struct extensible *) malloc(sizeof(struct extensible));
              pptmp = ppexten;
              ppexten = &((*ppexten)->next);
            }
            if (!strncasecmp(word,"sh",2)) 
              (*pptmp)->type = SHPROC;
            else
              (*pptmp)->type = EXECPROC;
            if (isdigit(*cptr)) {
              for(i=0; isdigit(*cptr); i++) {
                (*pptmp)->miboid[i] = atoi(cptr);
                while(isdigit(*cptr++));
                if (*cptr == '.') cptr++;
              }
              (*pptmp)->miboid[i] = -1;
              (*pptmp)->miblen = i;
            }
            else {
              (*pptmp)->miboid[0] = -1;
              (*pptmp)->miblen = 0;
            }
            /* name */
            copy_word(cptr,(*pptmp)->name);
            /* command */
            cptr = skip_not_white(cptr);
            cptr = skip_white(cptr);
            if (cptr == NULL) {
              fprintf(stderr,"No command specified on line:  %s\n",line);
            } else {
              for(tcptr=cptr;*tcptr != NULL && *tcptr != '#' && *tcptr != ';';
                  tcptr++);
              strncpy((*pptmp)->command,cptr,tcptr-cptr);
              (*pptmp)->command[tcptr-cptr-1]=NULL;
              (*pptmp)->next = NULL;
            }
          }
          else if (!strncmp(word,"disk",4)) {
#if HAVE_FSTAB_H
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
              if (cptr != NULL) {
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
                fprintf(stderr,"Error:  couldn't find device for disk %s\n",
                        disk[*numdisks].path);
                disk[*numdisks].minimumspace = -1;
                disk[*numdisks].path[0] = NULL;
              }
              endfsent();
            }
#else
            fprintf(stderr,
                    "'disk' checks not supported for this arcitecture.\n");
#endif
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
          else if (!strncmp(word,"load",4)) {
            for(i=0;i<=2;i++) {
              if (cptr != NULL)
                *maxload++ = atof(cptr);
              else
                *maxload++ = maxload[i-1];
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
            }
          }
          else if (!strncmp(word,"community",9)) {
            i = atoi(cptr);
            if (i < NUM_COMMUNITIES) {
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
              if (cptr != NULL) {
                if (strlen(cptr) < COMMUNITY_MAX_LEN) {
                  copy_word(cptr,communities[i-1]);
                } else {
                  fprintf(stderr,"snmpd.conf:  comminity %s too long\n",cptr);
                }
              } else {
                fprintf(stderr,"snmpd.conf:  no community name found\n");
              }
            } else {
              fprintf(stderr,"snmpd: community number invalid:  %d\n",i);
              fprintf(stderr,"       must be > 0 and < %d\n",NUM_COMMUNITIES+1);
            }
          }
          else {
            fprintf(stderr,"snmpd: Unknown command in %s:%d  %s",
                    filename,linecount,word);
          }
	}
    }
  fclose(ifile);
  return(0);
}

free_config(procp,ppexten,pprelocs)
     struct myproc **procp;
     struct extensible **ppexten, **pprelocs;
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

  for (etmp = *pprelocs; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    free(etmp2);
  }

  *procp = NULL;
  *ppexten = NULL;
  *pprelocs = NULL;

}
/* skip all white spaces and return 1 if found something either end of
   line or a comment character */

char *skip_white(ptr)
  char *ptr;
{

  if (ptr == NULL) return (NULL);
  while (*ptr != NULL && isspace(*ptr)) ptr++;
  if (*ptr == NULL || *ptr == '#') return (NULL);
  return (ptr);
}

char *skip_not_white(ptr)
  char *ptr;
{
  
  if (ptr == NULL) return (NULL);
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
  char *init=ptr;
  
  if (field == LASTFIELD) {
    /* skip to end */
    while (*ptr++);
    ptr = ptr - 2;
    /* rewind a field length */
    while (*ptr != NULL && isspace(*ptr) && init <= ptr) ptr--;
    while (*ptr != NULL && !isspace(*ptr) && init <= ptr) ptr--;
    if (isspace(*ptr)) ptr++;  /* past space */
    if (ptr < init) ptr = init;
    if (!isspace(*ptr) && *ptr != NULL) return(ptr);
  } else {
    if ((ptr = skip_white(ptr)) == NULL) return(NULL);
    for (i=1; *ptr != NULL && i != field; i++) 
      {
        if ((ptr = skip_not_white(ptr)) == NULL) return (NULL);
        if ((ptr = skip_white(ptr)) == NULL) return (NULL);
      }
    if (*ptr != NULL && i == field) return(ptr);
    return (NULL);
  }
}

