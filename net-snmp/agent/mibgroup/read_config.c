#include <config.h>

#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif

#include "common_header.h"
#include "mib_module_includes.h"
#include "../snmp_agent.h"
#include "../snmpd.h"

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

struct config_line config_handlers[] = {
#include "mib_module_dot_conf.h"
  {"community", snmp_agent_parse_config, NULL},
  {"authtrapenable", snmpd_parse_config_authtrap, NULL},
  {"trapsink", snmpd_parse_config_trapsink, NULL},
  {"trapcommunity", snmpd_parse_config_trapcommunity, NULL}
};

void init_read_config __P((void))
{
  
  update_config(0);
  signal(SIGHUP,update_config);
}

int linecount;
char *curfilename;

int read_config(filename)
     char *filename;
{

  FILE *ifile;
  char line[STRMAX], word[STRMAX], tmpbuf[1024];
  char *cptr;
  int i;

  linecount = 0;
  curfilename = filename;
  
  if ((ifile = fopen(filename,"r")) == NULL) {
    return(1);
  }

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
            sprintf(tmpbuf,"Blank line following %s token.", word);
            config_perror(tmpbuf);
          } else {
            for(i=0; i < sizeof(config_handlers)/sizeof(struct config_line);
                i++) {
              if (!strcasecmp(word,config_handlers[i].config_token)) {
                (*(config_handlers[i].parse_line))(word,cptr);
                i += sizeof(config_handlers);
              }
            }
            if (i < sizeof(config_handlers)) {
              sprintf(tmpbuf,"Unknown token:  %s.", word);
              config_perror(tmpbuf);
            }
          }
	}
    }
  fclose(ifile);
  return(0);
}

void
free_config __P((void))
{
  int i;

  for(i=0; i < sizeof(config_handlers)/sizeof(struct config_line);i++) {
    if (config_handlers[i].free_func != NULL)
      (*(config_handlers[i].free_func))();
  }
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

  free_config();

  if (!dontReadConfigFiles) {  /* don't read if -C present on command line */
    /* read the config files */
    sprintf(configfile,"%s/snmpd.conf",SNMPLIBPATH);
    read_config (configfile);
    sprintf(configfile,"%s/snmpd.local.conf",SNMPLIBPATH);
    read_config (configfile);

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
        read_config (configfile);
        sprintf(configfile,"%s/snmpd.local.conf",cptr2);
        read_config (configfile);
        cptr2 = ++cptr1;
      }
      free(envconfpath);
    }
  }
  
  /* read all optional config files */
  /* last is -c from command line */
  /* always read this one even if -C is present (ie both -c and -C) */
  if (optconfigfile != NULL) {
    read_config (optconfigfile);
  }

  /* argggg -- pasthrus must be sorted */
#if USING_PASS_MODULE
  if (numpassthrus > 0) {
    etmp = (struct extensible **)
      malloc(((sizeof(struct extensible *)) * numpassthrus));
    for(i=0,ptmp = (struct extensible *) passthrus;
        i < numpassthrus && ptmp != 0;
        i++, ptmp = ptmp->next)
      etmp[i] = ptmp;
    qsort(etmp, numpassthrus, sizeof(struct extensible *),
	  pass_compare);
    passthrus = (struct extensible *) etmp[0];
    ptmp = (struct extensible *) etmp[0];
    
    for(i=0; i < numpassthrus-1; i++) {
      ptmp->next = etmp[i+1];
      ptmp = ptmp->next;
    }
    ptmp->next = NULL;
  }
#endif

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

void config_perror(char *string) {
  fprintf(stderr, "snmpd: %s: line %d: %s\n", curfilename, linecount, string);
}
