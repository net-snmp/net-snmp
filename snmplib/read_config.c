#include <config.h>

#include <sys/types.h>
#include <stdio.h>
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
#include <errno.h>

#include <sys/time.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#include "read_config.h"
#include "system.h"

int config_errors;

struct config_files *config_files = NULL;

void
register_config_handler(type, token, parser, releaser)
  char *type;
  char *token;
  void (*parser) __P((char *, char *));
  void (*releaser) __P((void));
{
  struct config_files **ctmp = &config_files;
  struct config_line **ltmp;

  /* find type in current list */
  while (*ctmp != NULL && strcmp((*ctmp)->fileHeader,type)) {
    ctmp = &((*ctmp)->next);
  }

  if (*ctmp == NULL) {
    /* Not found, create a new one. */
    *ctmp = (struct config_files *) malloc(sizeof(struct config_files));
    (*ctmp)->next = NULL;
    (*ctmp)->start = NULL;
    (*ctmp)->fileHeader = strdup(type);
  }

  ltmp = &((*ctmp)->start);

  while (*ltmp != NULL && strcmp((*ltmp)->config_token,token)) {
    ltmp = &((*ltmp)->next);
  }

  if (*ltmp == NULL) {
    /* Not found, create a new one. */
    *ltmp = (struct config_line *) malloc(sizeof(struct config_line));
    (*ltmp)->next = NULL;
    (*ltmp)->parse_line = 0;
    (*ltmp)->free_func = 0;
    (*ltmp)->config_token = strdup(token);
  }

  /* Found the handler for this token.  Add/Replace the functions with */
  /* the newly registered ones: */

  (*ltmp)->parse_line = parser;
  (*ltmp)->free_func = releaser;
}


#ifdef TESTING
void print_config_handlers __P((void))
{
  struct config_files *ctmp = config_files;
  struct config_line *ltmp;

  for(;ctmp != NULL; ctmp = ctmp->next) {
    DEBUGP("read_conf: %s\n", ctmp->fileHeader);
    for(ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next)
      DEBUGP("                   %s\n", ltmp->config_token);
  }
}
#endif

int linecount;
char *curfilename;

void read_config_with_type(filename, type)
  char *filename;
  char *type;
{
  struct config_files *ctmp = config_files;
  for(;ctmp != NULL && strcmp(ctmp->fileHeader,"snmpd"); ctmp = ctmp->next);
  if (ctmp)
    read_config(filename, ctmp->start);
  else
    fprintf(stderr, "snmpd: %s: %s\n", filename, strerror(errno));
}

void read_config(filename, line_handler)
  char *filename;
  struct config_line *line_handler;
{

  FILE *ifile;
  char line[STRINGMAX], word[STRINGMAX], tmpbuf[STRINGMAX];
  char *cptr;
  int i, done;
  struct config_line *lptr;

  linecount = 0;
  curfilename = filename;
  
  if ((ifile = fopen(filename, "r")) == NULL) {
    fprintf(stderr, "snmpd: %s: %s\n", filename, strerror(errno));
    return;
  } else {
    DEBUGP("snmpd: Reading configuration %s\n", filename);
  }

  while (fgets(line, STRINGMAX, ifile) != NULL) 
    {
      lptr = line_handler;
      linecount++;
      cptr = line;
      i = strlen(line)-1;
      if (line[i] == '\n')
        line[i] = 0;
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
            for(lptr = line_handler, done=0;
                lptr != NULL && !done;
                lptr = lptr->next) {
              if (!strcasecmp(word,lptr->config_token)) {
                (*(lptr->parse_line))(word,cptr);
                done = 1;
              }
            }
            if (!done) {
              sprintf(tmpbuf,"Unknown token: %s.", word);
              config_pwarn(tmpbuf);
            }
          }
	}
    }
  fclose(ifile);
  return;
}

void
free_config __P((void))
{
  struct config_files *ctmp = config_files;
  struct config_line *ltmp;

  for(;ctmp != NULL; ctmp = ctmp->next)
    for(ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next)
      if (ltmp->free_func)
        (*(ltmp->free_func))();
}

int
read_configs __P((void))
{
  int i;
  char configfile[300];
  char *envconfpath;
  char *cptr1, *cptr2;
  char defaultPath[1024];

  struct config_files *ctmp = config_files;
  struct config_line *ltmp;
  
  free_config();

  /* read all config file types */
  for(;ctmp != NULL; ctmp = ctmp->next) {

    ltmp = ctmp->start;

    /* read the config files */
    if ((envconfpath = getenv("SNMPCONFPATH")) == NULL) {
      sprintf(defaultPath,"%s:%s",SNMPSHAREPATH,SNMPLIBPATH);
      envconfpath = defaultPath;
    }
    envconfpath = strdup(envconfpath);  /* prevent actually writing in env */
    cptr1 = cptr2 = envconfpath;
    i = 1;
    while (i && *cptr2 != 0) {
      while(*cptr1 != 0 && *cptr1 != ':')
        cptr1++;
      if (*cptr1 == 0)
        i = 0;
      else
        *cptr1 = 0;
      sprintf(configfile,"%s/%s.conf",cptr2, ctmp->fileHeader);
      read_config (configfile, ltmp);
      sprintf(configfile,"%s/%s.local.conf",cptr2, ctmp->fileHeader);
      read_config (configfile, ltmp);
      cptr2 = ++cptr1;
    }
    free(envconfpath);
  }
  
  if (config_errors) {
    fprintf(stderr, "snmpd: errors in config file - abort.\n");
    exit(1);
  }

  return 0;
}

void config_perror(string)
  char *string;
{
  config_pwarn(string);
  config_errors++;
}

void config_pwarn(string)
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
