#include <config.h>

#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#else
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif
#include <signal.h>
#include <ctype.h>

#include <sys/time.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include "m2m.h"
#include "mibincl.h"

/* #include "common_header.h" */

#include "read_config.h"
#include "mib_module_includes.h"
#include "mib_module_config.h"
#include "../snmp_agent.h"
#include "../snmpd.h"

extern struct extensible *passthrus;    /* In pass.c */
extern int numpassthrus;                 /* ditto */

int minimumswap;
char dontReadConfigFiles;
char *optconfigfile;

struct config_line config_handlers[] = {
#include "mibgroup/mib_module_dot_conf.h"
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
#ifdef __STDC__
         (int (*)(const void *, const void *)) pass_compare
#else
	  pass_compare
#endif
          
      );
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

void config_perror(string)
  char *string;
{
  fprintf(stderr, "snmpd: %s: line %d: %s\n", curfilename, linecount, string);
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


int tree_compare(a, b)
  const void *a, *b;
{
  struct subtree *ap, *bp;
  ap = (struct subtree *) a;
  bp = (struct subtree *) b;

  return compare(ap->name,ap->namelen,bp->name,bp->namelen);
}

void setup_tree __P((void))
{
  extern struct subtree *subtrees,subtrees_old[];
  struct subtree *sb;
  int old_treesz;
#if defined(USING_EXTENSIBLE_MODULE) || defined(USING_PASS_MODULE)
  int i;
  static struct subtree mysubtree[1];
  struct extensible *exten;
#ifdef USING_EXTENSIBLE_MODULE
  extern int numrelocs;
  extern struct extensible *relocs;
  extern struct variable2 extensible_relocatable_variables[];
#endif
#ifdef USING_PASS_MODULE
  extern int numpassthrus;
  extern struct extensible *passthrus;
  extern struct variable2 extensible_passthru_variables[];
#endif
#endif
    
  /* Malloc new space at the end of the mib tree for the new
     extensible mibs and add them in. */

  old_treesz = subtree_old_size();

  subtrees = (struct subtree *) malloc ((old_treesz
#if USING_EXTENSIBLE_MODULE
                                         + numrelocs
#endif
#if USING_PASS_MODULE
                                         + numpassthrus
#endif
    )*sizeof(struct subtree));
  memmove(subtrees, subtrees_old, old_treesz *sizeof(struct subtree));
  sb = subtrees;
  sb += old_treesz;

#if USING_EXTENSIBLE_MODULE
  /* add in relocatable mibs */
  for(i=1;i<=numrelocs;i++, sb++) {
    exten = get_exten_instance(relocs,i);
    memcpy(mysubtree[0].name,exten->miboid,exten->miblen*sizeof(long));
    mysubtree[0].namelen = exten->miblen;
    mysubtree[0].variables = (struct variable *)extensible_relocatable_variables;
    mysubtree[0].variables_len = 6;
    mysubtree[0].variables_width = sizeof(*extensible_relocatable_variables);
    memcpy(sb,mysubtree,sizeof(struct subtree));
  }
#endif
#ifdef USING_PASS_MODULE
  /* add in pass thrus */
  for(i=1;i<=numpassthrus;i++, sb++) {
    exten = get_exten_instance(passthrus,i);
    memcpy(mysubtree[0].name,exten->miboid,exten->miblen*sizeof(long));
    mysubtree[0].namelen = exten->miblen;
    mysubtree[0].variables = (struct variable *)extensible_passthru_variables;
    mysubtree[0].variables_len = 1;
    mysubtree[0].variables_width = sizeof(*extensible_passthru_variables);
    memcpy(sb,mysubtree,sizeof(struct subtree));
  }
#endif
  
  /* Here we sort the mib tree so it can insert new extensible mibs
     and also double check that our mibs were in the proper order in
     the first place */

  qsort(subtrees,old_treesz
#if USING_EXTENSIBLE_MODULE
        + numrelocs 
#endif
#ifdef USING_PASS_MODULE
        + numpassthrus
#endif
        , sizeof(struct subtree),
#ifdef __STDC__
        (int (*)(const void *, const void *)) tree_compare
#else
        tree_compare
#endif
    );

}

