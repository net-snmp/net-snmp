#include <config.h>

#include <stdio.h>
#include <ctype.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <errno.h>
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif


#include "asn1.h"
#include "mib.h"
#include "parse.h"
#include "system.h"
#include "snmp_api.h"
#include "snmp_debug.h"

#include "read_config.h"

int config_errors;

struct config_files *config_files = NULL;

struct config_line *
register_premib_handler(char *type,
			char *token,
			void (*parser) (char *, char *),
			void (*releaser) (void),
			char *help)
{
  struct config_line *ltmp;
  ltmp = register_config_handler(type, token, parser, releaser, help);
  if (ltmp != NULL)
    ltmp->config_time = PREMIB_CONFIG;
  return (ltmp);
}

struct config_line *
register_config_handler(char *type,
			char *token,
			void (*parser) (char *, char *),
			void (*releaser) (void),
			char *help)
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
    (*ltmp)->config_time = NORMAL_CONFIG;
    (*ltmp)->parse_line = 0;
    (*ltmp)->free_func = 0;
    (*ltmp)->config_token = strdup(token);
    if (help != NULL)
      (*ltmp)->help = strdup(help);
    else
      (*ltmp)->help = strdup("");
  }

  /* Found the handler for this token.  Add/Replace the functions with */
  /* the newly registered ones: */

  (*ltmp)->parse_line = parser;
  (*ltmp)->free_func = releaser;
  return (*ltmp);
}

void
unregister_config_handler(char *type, 
			  char *token)
{
  struct config_files **ctmp = &config_files;
  struct config_line **ltmp, *ltmp2;

  /* find type in current list */
  while (*ctmp != NULL && strcmp((*ctmp)->fileHeader,type)) {
    ctmp = &((*ctmp)->next);
  }

  if (*ctmp == NULL) {
    /* Not found, return. */
    return;
  }
  
  ltmp = &((*ctmp)->start);
  if (*ltmp == NULL) {
    /* Not found, return. */
    return;
  }
  if (strcmp((*ltmp)->config_token,token) == 0) {
    /* found it at the top of the list */
    (*ctmp)->start = (*ltmp)->next;
    free((*ltmp)->config_token);
    free((*ltmp)->help);
    free(*ltmp);
    return;
  }
  while ((*ltmp)->next != NULL && strcmp((*ltmp)->next->config_token,token)) {
    ltmp = &((*ltmp)->next);
  }
  if (*ltmp == NULL) {
    free((*ltmp)->config_token);
    free((*ltmp)->help);
    ltmp2 = (*ltmp)->next->next;
    free((*ltmp)->next);
    (*ltmp)->next = ltmp2;
  }
}

#ifdef TESTING
void print_config_handlers (void)
{
  struct config_files *ctmp = config_files;
  struct config_line *ltmp;

  for(;ctmp != NULL; ctmp = ctmp->next) {
    DEBUGMSGTL(("read_config", "read_conf: %s\n", ctmp->fileHeader));
    for(ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next)
      DEBUGMSGTL(("read_config", "                   %s\n", ltmp->config_token));
  }
}
#endif

int linecount;
char *curfilename;

void read_config_with_type(char *filename, 
			   char *type)
{
  struct config_files *ctmp = config_files;
  for(;ctmp != NULL && strcmp(ctmp->fileHeader,type); ctmp = ctmp->next);
  if (ctmp)
    read_config(filename, ctmp->start, EITHER_CONFIG);
  else
    DEBUGMSGTL(("read_config", "read_config: I have no registrations for type:%s,file:%s\n",
           type, filename));
}

void read_config(char *filename,
		 struct config_line *line_handler,
		 int when)
{

  FILE *ifile;
  char line[STRINGMAX], word[STRINGMAX], tmpbuf[STRINGMAX];
  char *cptr;
  int i, done;
  struct config_line *lptr;

  linecount = 0;
  curfilename = filename;
  
  if ((ifile = fopen(filename, "r")) == NULL) {
    DEBUGMSGTL(("read_config", "%s: %s\n", filename, strerror(errno)));
    return;
  } else {
    DEBUGMSGTL(("read_config", "Reading configuration %s\n", filename));
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
                if (when == EITHER_CONFIG || lptr->config_time == when)
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
free_config (void)
{
  struct config_files *ctmp = config_files;
  struct config_line *ltmp;

  for(;ctmp != NULL; ctmp = ctmp->next)
    for(ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next)
      if (ltmp->free_func)
        (*(ltmp->free_func))();
}

void
read_configs (void)
{
  read_config_files(NORMAL_CONFIG);
}

void
read_premib_configs (void)
{
  read_config_files(PREMIB_CONFIG);
}

void
read_config_files (int when)
{
  int i;
  char configfile[300];
  char *envconfpath, *homepath;
  char *cptr1, *cptr2;
  char defaultPath[1024];

  struct config_files *ctmp = config_files;
  struct config_line *ltmp;
  
  if (when == PREMIB_CONFIG)
    free_config();

  /* read all config file types */
  for(;ctmp != NULL; ctmp = ctmp->next) {

    ltmp = ctmp->start;

    /* read the config files */
    if ((envconfpath = getenv("SNMPCONFPATH")) == NULL) {
      homepath=getenv("HOME");
      sprintf(defaultPath,"%s:%s%s%s%s",SNMPSHAREPATH,SNMPLIBPATH,
              ((homepath == NULL) ? "" : ":"),
              ((homepath == NULL) ? "" : homepath),
              ((homepath == NULL) ? "" : "/.snmp"));
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
      read_config (configfile, ltmp, when);
      sprintf(configfile,"%s/%s.local.conf",cptr2, ctmp->fileHeader);
      read_config (configfile, ltmp, when);
      cptr2 = ++cptr1;
    }
    free(envconfpath);
  }
  
  if (config_errors) {
    fprintf(stderr, "snmpd: errors in config file - abort.\n");
    exit(1);
  }
}

void read_config_print_usage(char *lead)
{
  struct config_files *ctmp = config_files;
  struct config_line *ltmp;

  if (lead == NULL)
    lead = "";

  for(ctmp = config_files; ctmp != NULL; ctmp = ctmp->next) {
    fprintf(stderr, "%sIn %s.conf and %s.local.conf:\n", lead, ctmp->fileHeader,
            ctmp->fileHeader);
    for(ltmp = ctmp->start; ltmp != NULL; ltmp = ltmp->next) {
      fprintf(stderr, "%s%s%-15s %s\n", lead, lead, ltmp->config_token,
              ltmp->help);
    }
  }
}

void config_perror(char *string)
{
  config_pwarn(string);
  config_errors++;
}

void config_pwarn(char *string)
{
  fprintf(stderr, "snmpd: %s: line %d: %s\n", curfilename, linecount, string);
}

/* skip all white spaces and return 1 if found something either end of
   line or a comment character */
char *skip_white(char *ptr)
{

  if (ptr == NULL) return (NULL);
  while (*ptr != 0 && isspace(*ptr)) ptr++;
  if (*ptr == 0 || *ptr == '#') return (NULL);
  return (ptr);
}

char *skip_not_white(char *ptr)
{
  
  if (ptr == NULL) return (NULL);
  while (*ptr != 0 && !isspace(*ptr)) ptr++;
  if (*ptr == 0 || *ptr == '#') return (NULL);
  return (ptr);
}

char *skip_token(char *ptr)
{
  ptr = skip_white(ptr);
  ptr = skip_not_white(ptr);
  ptr = skip_white(ptr);
  return (ptr);
}

char *copy_word(char *from, char *to)
     
{
  while (*from != 0 && !isspace(*from)) *(to++) = *(from++);
  *to = 0;
  return skip_white(from);
}


/* read_config_save_octet_string(): saves an octet string as a length
   followed by a string of hex */
char *read_config_save_octet_string(char *saveto, u_char *str, int len) {
  int i;
  if (str != NULL) {
    sprintf(saveto, "%d ", len);
    saveto += strlen(saveto);
    for(i = 0; i < len; i++) {
      sprintf(saveto,"%02x", str[i]);
      saveto = saveto + 2;
    }
    return saveto;
  } else {
    sprintf(saveto, "0 ");
    return saveto+strlen(saveto);
  }
}

/* read_config_read_octet_string(): reads an octet string that was
   saved by the read_config_save_octet_string() function */
char *read_config_read_octet_string(char *readfrom, u_char **str, int *len) {
  u_char *cptr=NULL;
  u_int tmp;
  int i;
  
  *len = atoi(readfrom);
  if (*len > 0 && (str == NULL ||
      (cptr = (u_char *)malloc(*len * sizeof(u_char))) == NULL))
    return NULL;
  *str = cptr;
  readfrom = skip_token(readfrom);
  for(i = 0; i < *len; i++) {
    sscanf(readfrom,"%2x",&tmp);
    *cptr++ = (u_char) tmp;
    readfrom += 2;
  }
  readfrom = skip_white(readfrom);
  return readfrom;
}


/* read_config_save_objid(): saves an objid as a numerical string */
char *read_config_save_objid(char *saveto, oid *objid, int len) {
  int i;
  
  /* in case len=0, this makes it easier to read it back in */
  sprintf(saveto, "%d ", len);
  saveto += strlen(saveto);
  
  for(i=0; i < len; i++) {
    sprintf(saveto,".%d", objid[i]);
    saveto += strlen(saveto);
  }
  return saveto;
}

/* read_config_read_objid(): reads an objid from a format saved by the above */
char *read_config_read_objid(char *readfrom, oid **objid, int *len) {
  u_int tmp;  /* oids are 'char's on some systems */
  int i;
  
  *len = atoi(readfrom);
  
  if (*len > 0 &&
      (objid == NULL || (*objid = malloc(*len * sizeof(oid))) == NULL))
    return NULL;

  readfrom = skip_token(readfrom);
  for(i = 0; i < *len; i++) {
    sscanf(readfrom,".%d",&tmp);
    (*objid)[i] = tmp;
    if (i != *len - 1)
      readfrom = strchr(readfrom+1, '.'); /* no more dots */
  }
  if (*len > 0)
    readfrom = skip_token(readfrom); /* we're staring at the last .%d */
  return readfrom;
}
