#include <config.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <signal.h>
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
#include <ctype.h>

#include "mibincl.h"
#include "read_config.h"
#include "util_funcs.h"

#define DEFAULTMINIMUMSWAP 16000  /* kilobytes */

/* communities from agent/snmp_agent.c */
extern char communities[NUM_COMMUNITIES][COMMUNITY_MAX_LEN];

/* contact/locaction from agent/snmp_vars.c */
extern char sysContact[];
extern char sysLocation[];

extern int snmp_enableauthentraps;
extern char *snmp_trapsink;
extern char *snmp_trapcommunity;

extern struct myproc *procwatch;         /* moved to proc.c */
extern int numprocs;                     /* ditto */
extern struct extensible *extens;       /* In exec.c */
extern struct extensible *relocs;       /* In exec.c */
extern int numextens;                    /* ditto */
extern int numrelocs;                    /* ditto */
extern struct extensible *passthrus;    /* In pass.c */
extern int numpassthrus;                 /* ditto */
extern double maxload[3];
extern int numdisks;
extern struct diskpart disks[MAXDISKS];

int minimumswap;
char dontReadConfigFiles;
char *optconfigfile;

void init_read_config()
{
  update_config(0);
  signal(SIGHUP,update_config);
}

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

RETSIGTYPE update_config(a)
int a;
{
  extern struct subtree *subtrees;
  int i;
  char configfile[300];
  struct extensible **etmp, *ptmp;
  char *envconfpath;
  char *cptr1, *cptr2;

  free_config(&procwatch,&extens,&relocs,&passthrus);
  numprocs = numextens = numrelocs = numpassthrus = 0;
  /* restore defaults */
  minimumswap = DEFAULTMINIMUMSWAP;
  for (i=0; i<=2;i++)
    maxload[i] = DEFMAXLOADAVE;
  numdisks = 0;
  for(i=0;i<MAXDISKS;i++) {           /* init/erase disk db */
    disks[i].device[0] = 0;
    disks[i].path[0] = 0;
    disks[i].minimumspace = -1;
  }

  if (!dontReadConfigFiles) {  /* don't read if -C present on command line */
    /* read the config files */
    sprintf(configfile,"%s/snmpd.conf",SNMPLIBPATH);
    read_config (configfile,&procwatch,&numprocs,&relocs,&numrelocs,&passthrus,&numpassthrus,&extens,&numextens,&minimumswap,disks,&numdisks,maxload);
    sprintf(configfile,"%s/snmpd.local.conf",SNMPLIBPATH);
    read_config (configfile,&procwatch,&numprocs,&relocs,&numrelocs,&passthrus,&numpassthrus,&extens,&numextens,&minimumswap,disks,&numdisks,maxload);

    if ((envconfpath = getenv("SNMPCONFPATH"))) {
      envconfpath = strdup(envconfpath);  /* prevent actually writting in env */
      cptr1 = cptr2 = envconfpath;
      i = 1;
      while (i && *cptr2 != 0) {
        while(*cptr1 != 0 && *cptr1 != ':')
          cptr1++;
        if (*cptr1 == 0)
          i = 0;
        else
          *cptr1 = 0;
        sprintf(configfile,"%s/snmpd.conf",cptr2);
        read_config (configfile,&procwatch,&numprocs,&relocs,&numrelocs,&passthrus,&numpassthrus,&extens,&numextens,&minimumswap,disks,&numdisks,maxload);
        sprintf(configfile,"%s/snmpd.local.conf",cptr2);
        read_config (configfile,&procwatch,&numprocs,&relocs,&numrelocs,&passthrus,&numpassthrus,&extens,&numextens,&minimumswap,disks,&numdisks,maxload);
        cptr2 = ++cptr1;
      }
      free(envconfpath);
    }
  }
  
  /* read all optional config files */
  /* last is -c from command line */
  /* always read this one even if -C is present (ie both -c and -C) */
  if (optconfigfile != NULL) {
    read_config (optconfigfile,&procwatch,&numprocs,&relocs,&numrelocs,&passthrus,&numpassthrus,&extens,&numextens,&minimumswap,disks,&numdisks,maxload);
  }

  /* argggg -- pasthrus must be sorted */
  if (numpassthrus > 0) {
    etmp = (struct extensible **)
      malloc(((sizeof(struct extensible *)) * numpassthrus));
    for(i=0,ptmp = (struct extensible *) passthrus;
        i < numpassthrus && ptmp != 0;
        i++, ptmp = ptmp->next)
      etmp[i] = ptmp;
    qsort(etmp, numpassthrus, sizeof(struct extensible *),pass_compare);
    passthrus = (struct extensible *) etmp[0];
    ptmp = (struct extensible *) etmp[0];
    
    for(i=0; i < numpassthrus-1; i++) {
      ptmp->next = etmp[i+1];
      ptmp = ptmp->next;
    }
    ptmp->next = NULL;
  }

  if (subtrees)
    free(subtrees);
  setup_tree();
  
  signal(SIGHUP,update_config);
}

int pass_compare(a, b)
  void *a, *b;
{
  struct extensible **ap, **bp;
  ap = (struct extensible **) a;
  bp = (struct extensible **) b;

  return compare((*ap)->miboid,(*ap)->miblen,(*bp)->miboid,(*bp)->miblen);
}

