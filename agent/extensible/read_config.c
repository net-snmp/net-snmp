#include <config.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#if STDC_HEADERS
#include <string.h>
#endif
#endif
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <math.h>
#include <asn1.h>
#include <snmp_impl.h>
#include <snmp.h>
#include <ctype.h>
#include "extproto.h"

/* communities from agent/snmp_agent.c */
extern char communities[NUM_COMMUNITIES][COMMUNITY_MAX_LEN];

/* contact/locaction from agent/snmp_vars.c */
extern char sysContact[];
extern char sysLocation[];

extern int snmp_enableauthentraps;
extern char *snmp_trapsink;
extern char *snmp_trapcommunity;

int read_config(filename, procp, numps, pprelocs, numrelocs, pppassthrus,
                numpassthrus, ppexten, numexs, minimumswap, disk, numdisks,
                maxload)
     char *filename;
     struct myproc **procp;
     struct extensible **ppexten;
     struct extensible **pprelocs;
     struct extensible **pppassthrus;
     int *numexs, *numps, *numrelocs, *numpassthrus;
     int *minimumswap;
     struct diskpart disk[];
     int *numdisks;
     double *maxload;
{

  FILE *ifile;
  char line[STRMAX], word[STRMAX];
  char *cptr, *tcptr;
  int linecount=0,i;
#if HAVE_GETMNTENT
#if HAVE_SYS_MNTTAB_H
  struct mnttab mnttab;
#else
  struct mntent *mntent;
#endif
  FILE *mntfp;
#else
#if HAVE_FSTAB_H
  struct fstab *fstab;
  struct stat stat1, stat2;
#endif
#endif
  struct extensible **pptmp;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    fprintf(stderr, "couldn't open %s for reading\n",filename);
    return(1);
  }

  /* skip past set procp/ppexten */
  while (*ppexten != NULL) ppexten = &((*ppexten)->next);
  while (*pprelocs != NULL) pprelocs = &((*pprelocs)->next);
  while (*pppassthrus != NULL) pppassthrus = &((*pppassthrus)->next);
  while (*procp != NULL) procp = &((*procp)->next);

  while (fgets(line,STRMAX,ifile) != NULL) 
    {
      linecount++;
      cptr = line;
      /* check blank line or # comment */
      if ((cptr = skip_white(cptr)))
	{
          copy_word(cptr,word);
          cptr = skip_not_white(cptr);
          cptr = skip_white(cptr);
          if (cptr == NULL) {
            fprintf(stderr,"snmpd: Blank line following %s command in %s:%d",
                    word,filename,linecount);
          }
          else if (!strncasecmp(word,"sh",2) || !strncasecmp(word,"exec",4) ||
            !strncasecmp(word,"pass",4)) {
            /* determine type */
            if (*cptr == '.') cptr++;
            if (isdigit(*cptr)) {
              if (!strncasecmp(word,"pass",4)) {
                (*numpassthrus) = (*numpassthrus)+1;
                (*pppassthrus) =
                  (struct extensible *) malloc(sizeof(struct extensible));
                pptmp = pppassthrus;
                pppassthrus = &((*pppassthrus)->next);
              } else {
                (*numrelocs) = (*numrelocs)+1;
                (*pprelocs) =
                  (struct extensible *) malloc(sizeof(struct extensible));
                pptmp = pprelocs;
                pprelocs = &((*pprelocs)->next);
              }
            } else {
              (*numexs) = (*numexs)+1;
              (*ppexten) =
                (struct extensible *) malloc(sizeof(struct extensible));
              pptmp = ppexten;
              ppexten = &((*ppexten)->next);
            }
            if (!strncasecmp(word,"sh",2)) 
              (*pptmp)->type = SHPROC;
            else if (!strncasecmp(word,"pass",2)) 
              (*pptmp)->type = PASSTHRU;
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
            if ((*pptmp)->type != PASSTHRU) {
              copy_word(cptr,(*pptmp)->name);
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
            }
            if (cptr == NULL) {
              fprintf(stderr,"No command specified on line:  %s\n",line);
              fflush(stderr);
            } else {
              for(tcptr=cptr; *tcptr != 0 && *tcptr != '#' && *tcptr != ';';
                  tcptr++);
              strncpy((*pptmp)->command,cptr,tcptr-cptr);
              (*pptmp)->command[tcptr-cptr-1] = 0;
              (*pptmp)->next = NULL;
            }
            if ((*pptmp)->type == PASSTHRU) {
              strcpy((*pptmp)->name, (*pptmp)->command);
            }
          }
          else if (!strncasecmp(word,"disk",4)) {
#if HAVE_FSTAB_H || HAVE_GETMNTENT
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
#if HAVE_GETMNTENT
#if HAVE_SETMNTENT
              mntfp = setmntent(ETC_MNTTAB, "r");
	      disk[*numdisks].device[0] = 0;
              while ((mntent = getmntent (mntfp)))
		if (strcmp (disk[*numdisks].path, mntent->mnt_dir) == 0) {
                  copy_word (mntent->mnt_fsname, disk[*numdisks].device);
                  DEBUGP1("Disk:  %s\n",mntent->mnt_fsname);
		  break;
                }
#ifdef DODEBUG
		else {
                  printf ("%s != %s\n", disk[*numdisks].path,
                          mntent->mnt_dir);
                }
#endif
              endmntent(mntfp);
              if (disk[*numdisks].device[0] != 0) {
                /* dummy clause for else below */
                *numdisks += 1;  /* but inc numdisks here after test */
              }
#else /* getmentent but not setmntent */
	      mntfp = fopen (ETC_MNTTAB, "r");
	      while ((i = getmntent (mntfp, &mnttab)) == 0)
		if (strcmp (disk[*numdisks].path, mnttab.mnt_mountp) == 0)
		  break;
		else {
#ifdef DODEBUG
                  printf ("%s != %s\n", disk[*numdisks].path, mnttab.mnt_mountp);
#endif
                }
	      fclose (mntfp);
	      if (i == 0) {
		copy_word (mnttab.mnt_special, disk[*numdisks].device);
		*numdisks += 1;
	      }
#endif /* HAVE_SETMNTENT */
#else
#if HAVE_FSTAB_H
              stat(disk[*numdisks].path,&stat1);
              setfsent();
              if (fstab = getfsfile(disk[*numdisks].path)) {
                copy_word(fstab->fs_spec,disk[*numdisks].device);
                *numdisks += 1;
              }
#endif
#endif
              else {
                fprintf(stderr,"Error:  couldn't find device for disk %s\n",
                        disk[*numdisks].path);
                disk[*numdisks].minimumspace = -1;
                disk[*numdisks].path[0] = 0;
              }
#if HAVE_FSTAB_H
              endfsent();
#endif
            }
#else
            fprintf(stderr,
                    "'disk' checks not supported for this architecture.\n");
#endif
          }
          else if (!strncasecmp(word,"proc",4)) {
            (*procp) = (struct myproc *) malloc(sizeof(struct myproc));
            (*procp)->next = NULL;
            (*numps)++;
            /* not blank and not a comment */
            copy_word(cptr,(*procp)->name);
            cptr = skip_not_white(cptr);
            if ((cptr = skip_white(cptr))) 
              {
                (*procp)->max = atoi(cptr);
                cptr = skip_not_white(cptr);
                if ((cptr = skip_white(cptr)))
                  (*procp)->min = atoi(cptr);
                else 
                  (*procp)->min = 0;
              }
            else
              {
                (*procp)->max = 0;
                (*procp)->min = 0;
              }
#ifdef DODEBUG
            fprintf (stderr,"Read:  %s (%d) (%d)\n",
                     (*procp)->name, (*procp)->max, (*procp)->min);
#endif
            procp = &((*procp)->next);
          }
          else if (!strncasecmp(word,"swap",4)) {
            *minimumswap = atoi(cptr);
          }
          else if (!strncasecmp(word,"load",4)) {
            for(i=0;i<=2;i++) {
              if (cptr != NULL)
                *maxload++ = atof(cptr);
              else
                *maxload++ = maxload[i-1];
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
            }
          }
          else if (!strncasecmp(word,"community",9)) {
            i = atoi(cptr);
            if (i > 0 && i <= NUM_COMMUNITIES) {
              cptr = skip_not_white(cptr);
              cptr = skip_white(cptr);
              if (cptr != NULL) {
                if (((int) strlen(cptr)) < COMMUNITY_MAX_LEN) {
                  copy_word(cptr,communities[i-1]);
                } else {
                  fprintf(stderr,"%s:  community %s too long\n",filename,cptr);
                }
              } else {
                fprintf(stderr,"%s:  no community name found\n",filename);
              }
            } else {
              fprintf(stderr,"snmpd: community number invalid:  %d\n",i);
              fprintf(stderr,"       must be > 0 and < %d\n",NUM_COMMUNITIES+1);
            }
	  } else if (!strncasecmp(word,"authtrap", 8)) {
	    i = atoi(cptr);
	    if (i < 1 || i > 2)
	      fprintf(stderr,"snmpd: authtrapenable must be 1 or 2\n");
	    else
	      snmp_enableauthentraps = i;
	  } else if (!strncasecmp(word, "trapsink", 8)) {
	    snmp_trapsink = malloc (strlen (cptr));
	    copy_word(cptr, snmp_trapsink);
	  } else if (!strncasecmp(word, "trapcomm", 8)) {
	    snmp_trapcommunity = malloc (strlen(cptr));
	    copy_word(cptr, snmp_trapcommunity);
          } else if (!strncasecmp(word,"syscon",6)) {
            if (strlen(cptr) < 128) {
              strcpy(sysContact,cptr);
              sysContact[strlen(sysContact)-1] = 0;  /* chomp new line */
            } else
              fprintf(stderr,
                      "syscontact token too long (must be < 128):\n\t%s\n",
                      cptr);
          } else if (!strncasecmp(word,"sysloc",6)) {
            if (strlen(cptr) < 128) {
              strcpy(sysLocation,cptr);
              sysLocation[strlen(sysLocation)-1] = 0; /* chomp new line */
            } else
              fprintf(stderr,
                      "syslocation token too long (must be < 128):\n\t%s\n",
                      cptr);
          } else {
            fprintf(stderr,"snmpd: Unknown command in %s:%d - %s\n",
                    filename,linecount,word);
          }
	}
    }
  fclose(ifile);
  return(0);
}

void
free_config(procp,ppexten,pprelocs,pppassthrus)
     struct myproc **procp;
     struct extensible **ppexten, **pprelocs, **pppassthrus;
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

  for (etmp = *pppassthrus; etmp != NULL;) {
    etmp2 = etmp;
    etmp = etmp->next;
    free(etmp2);
  }

  *procp = NULL;
  *ppexten = NULL;
  *pprelocs = NULL;
  *pppassthrus = NULL;

}

/* skip all white spaces and return 1 if found something either end of
   line or a comment character */
char *skip_white(ptr)
  char *ptr;
{

  if (ptr == NULL) return (NULL);
  while (*ptr != 0 && isspace(*ptr)) ptr++;
  if (*ptr == 0 || *ptr == '#') return (NULL);
  return (ptr);
}

char *skip_not_white(ptr)
  char *ptr;
{
  
  if (ptr == NULL) return (NULL);
  while (*ptr != 0 && !isspace(*ptr)) ptr++;
  if (*ptr == 0 || *ptr == '#') return (NULL);
  return (ptr);
}

void copy_word(from, to)
     char *from, *to;
{
  while (*from != 0 && !isspace(*from)) *(to++) = *(from++);
  *to = 0;
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
    while (*ptr != 0 && isspace(*ptr) && init <= ptr) ptr--;
    while (*ptr != 0 && !isspace(*ptr) && init <= ptr) ptr--;
    if (isspace(*ptr)) ptr++;  /* past space */
    if (ptr < init) ptr = init;
    if (!isspace(*ptr) && *ptr != 0) return(ptr);
  } else {
    if ((ptr = skip_white(ptr)) == NULL) return(NULL);
    for (i=1; *ptr != 0 && i != field; i++) 
      {
        if ((ptr = skip_not_white(ptr)) == NULL) return (NULL);
        if ((ptr = skip_white(ptr)) == NULL) return (NULL);
      }
    if (*ptr != 0 && i == field) return(ptr);
    return (NULL);
  }
  return(NULL);
}

int parse_miboid(buf,oidout)
char *buf;
oid *oidout;
{
  int i;
  
  if (!buf)
    return 0;
  if (*buf == '.') buf++;
  for(i=0;isdigit(*buf);i++) {
    oidout[i] = atoi(buf);
    while(isdigit(*buf++));
    if (*buf == '.') buf++;
  }
  oidout[i] = -1;
  return i;
}
