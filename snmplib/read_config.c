/*
 * read_config.c
 */

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
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
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
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETDB_H
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
#include "snmp_impl.h"

#include "read_config.h"
#include "tools.h"

int config_errors;

struct config_files *config_files = NULL;

struct config_line *
register_premib_handler(const char *type,
			const char *token,
			void (*parser) (char *, char *),
			void (*releaser) (void),
			const char *help)
{
  struct config_line *ltmp;
  ltmp = register_config_handler(type, token, parser, releaser, help);
  if (ltmp != NULL)
    ltmp->config_time = PREMIB_CONFIG;
  return (ltmp);
}

/*******************************************************************-o-******
 * register_config_handler
 *
 * Parameters:
 *	*type
 *	*token
 *	*parser
 *	*releaser
 *      
 * Returns:
 *	Pointer to a new config line entry  -OR-  NULL on error.
 */
struct config_line *
register_config_handler(const char *type,
			const char *token,
			void (*parser) (char *, char *),
			void (*releaser) (void),
			const char *help)
{
  struct config_files **ctmp = &config_files;
  struct config_line **ltmp;

  /* 
   * Find type in current list  -OR-  create a new file type.
   */
  while (*ctmp != NULL && strcmp((*ctmp)->fileHeader, type)) {
    ctmp = &((*ctmp)->next);
  }

  if (*ctmp == NULL) {
    *ctmp = (struct config_files *)
      malloc(sizeof(struct config_files));
    if ( !*ctmp ) {
      return NULL;
    }

    (*ctmp)->next		 = NULL;
    (*ctmp)->start		 = NULL;
    (*ctmp)->fileHeader	 = strdup(type);
  }

  /* 
   * Find parser type in current list  -OR-  create a new
   * line parser entry.
   */
  ltmp = &((*ctmp)->start);

  while (*ltmp != NULL && strcmp((*ltmp)->config_token, token)) {
    ltmp = &((*ltmp)->next);
  }

  if (*ltmp == NULL) {
    *ltmp = (struct config_line *)
      malloc(sizeof(struct config_line));
    if ( !*ltmp ) {
      return NULL;
    }

    (*ltmp)->next		 = NULL;
    (*ltmp)->config_time	 = NORMAL_CONFIG;
    (*ltmp)->parse_line	 = 0;
    (*ltmp)->free_func	 = 0;
    (*ltmp)->config_token	 = strdup(token);
    if (help != NULL)
      (*ltmp)->help = strdup(help);
    else
      (*ltmp)->help = strdup("");

  }

  /* 
   * Add/Replace the parse/free functions for the given line type
   * in the given file type.
   */
  (*ltmp)->parse_line = parser;
  (*ltmp)->free_func  = releaser;

  return (*ltmp);

}  /* end register_config_handler() */

void
unregister_config_handler(const char *type, 
			  const char *token)
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
const char *curfilename;

void read_config_with_type(const char *filename, 
			   const char *type)
{
  struct config_files *ctmp = config_files;
  for(;ctmp != NULL && strcmp(ctmp->fileHeader,type); ctmp = ctmp->next);
  if (ctmp)
    read_config(filename, ctmp->start, EITHER_CONFIG);
  else
    DEBUGMSGTL(("read_config", "read_config: I have no registrations for type:%s,file:%s\n",
           type, filename));
}

/*******************************************************************-o-******
 * read_config
 *
 * Parameters:
 *	*filename
 *	*line_handler
 *	 when
 *
 * Read <filename> and process each line in accordance with the list of
 * <line_handler> functions.
 *
 *
 * For each line in <filename>, search the list of <line_handler>'s 
 * for an entry that matches the first token on the line.  This comparison is
 * case insensitive.
 *
 * For each match, check that <when> is the designated time for the
 * <line_handler> function to be executed before processing the line.
 */
void read_config(const char *filename,
		 struct config_line *line_handler,
		 int when)
{

  FILE *ifile;
  char line[STRINGMAX], token[STRINGMAX], tmpbuf[STRINGMAX];
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

  while (fgets(line, sizeof(line), ifile) != NULL) 
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
          DEBUGMSGTL(("read_config",
                      "%s:%d Parsing: %s\n", filename, linecount, line));
          cptr = copy_word(cptr,token);
          if (cptr == NULL) {
            sprintf(tmpbuf,"Blank line following %s token.", token);
            config_perror(tmpbuf);
          } else {
            for(lptr = line_handler, done=0;
                lptr != NULL && !done;
                lptr = lptr->next) {
              if (!strcasecmp(token,lptr->config_token)) {
                if (when == EITHER_CONFIG || lptr->config_time == when)
                  (*(lptr->parse_line))(token,cptr);
                done = 1;
              }
            }
            if (!done) {
              sprintf(tmpbuf,"Unknown token: %s.", token);
              config_pwarn(tmpbuf);
            }
          }
	}
    }
  fclose(ifile);
  return;

}  /* end read_config() */



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




/*******************************************************************-o-******
 * read_config_files
 *
 * Parameters:
 *	when	== PREMIB_CONFIG, NORMAL_CONFIG  -or-  EITHER_CONFIG
 *
 *
 * Traverse the list of config file types, performing the following actions
 * for each --
 *
 * First, build a search path for config files.  If the contents of 
 * environment variable SNMPCONFPATH are NULL, then use the following
 * path list (where the last entry exists only if HOME is non-null):
 *
 *	SNMPSHAREPATH:SNMPLIBPATH:${HOME}/.snmp
 *
 * Then, In each of these directories, read config files by the name of:
 *
 *	<dir>/<fileHeader>.conf		-AND-
 *	<dir>/<fileHeader>.local.conf
 *
 * where <fileHeader> is taken from the config file type structure.
 *
 *
 * PREMIB_CONFIG causes free_config() to be invoked prior to any other action.
 *
 *
 * EXITs if any 'config_errors' are logged while parsing config file lines.
 */
void
read_config_files (int when)
{
  int i;
  char configfile[300];
  char *envconfpath, *homepath;
  char *cptr1, *cptr2;
  char defaultPath[SPRINT_MAX_LEN];

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
      sprintf(defaultPath,"%s:%s%s%s%s:%s",SNMPSHAREPATH,SNMPLIBPATH,
              ((homepath == NULL) ? "" : ":"),
              ((homepath == NULL) ? "" : homepath),
              ((homepath == NULL) ? "" : "/.snmp"),
              PERSISTENT_DIRECTORY);
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
    fprintf(stderr, "ucd-snmp: errors in config file - abort.\n");
/*    exit(1); */
  }
}

void read_config_print_usage(const char *lead)
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

/*******************************************************************-o-******
 * read_config_store
 *
 * Parameters:
 *	*type
 *	*line
 *      
 * 
 * Append line to a file named either ENV(SNMP_PERSISTENT_FILE) or
 *   "<PERSISTENT_DIRECTORY>/<type>.persistent.conf".
 * Add a trailing newline to the stored file if necessary.
 *
 * Intended for use by applications to store permenant configuration 
 * information generated by sets or persistent counters.
 *
 */
void
read_config_store(const char *type, const char *line)
{
#ifdef PERSISTENT_DIRECTORY
  char file[512], *filep;
  FILE *fout;

  /* store configuration directives in the following order of preference:
     1. ENV variable SNMP_PERSISTENT_FILE
     2. configured <PERSISTENT_DIRECTORY>/<type>.conf
  */
  if ((filep = getenv("SNMP_PERSISTENT_FILE")) == NULL) {
    sprintf(file,"%s/%s.conf",PERSISTENT_DIRECTORY,type);
    filep = file;
  }
  
  if ((fout = fopen(filep, "a")) != NULL) {
    fprintf(fout,line);
    if (line[strlen(line)] != '\n')
      fprintf(fout,"\n");
    DEBUGMSGTL(("read_config","storing: %s\n",line));
    fclose(fout);
  } else {
    snmp_perror(type);
  }
#endif
}  /* end read_config_store() */




/*******************************************************************-o-******
 * snmp_clean_persistent
 *
 * Parameters:
 *	*type
 *      
 *
 * Unlink a file called "<PERSISTENT_DIRECTORY>/<type>.conf".
 *
 * Should be called just before all persistent information is supposed to be
 * written to clean out the existing persistent cache.
 *
 * XXX  Worth overwriting with random bytes first?  This would
 *	ensure that the data is destroyed, even a buffer containing the
 *	data persists in memory or swap.  Only important if secrets
 *	will be stored here.
 */
void
snmp_clean_persistent(const char *type)
{
  char file[512], fileold[512];
  struct stat statbuf;

  sprintf(file,"%s/%s.conf",PERSISTENT_DIRECTORY,type);
  if (stat(file, &statbuf) == 0) {
    sprintf(fileold,"%s/%s.conf.old",PERSISTENT_DIRECTORY,type);
    if (rename(file, fileold)) {
      unlink(file);/* failed, try nuking it */
    }
  }
}



/* config_perror: prints a warning string associated with a file and
   line number of a .conf file and increments the error count. */
void config_perror(const char *string)
{
  config_pwarn(string);
  config_errors++;
}

void config_pwarn(const char *string)
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

/* copy_word
   copies the next 'token' from 'from' into 'to'.
   currently a token is anything seperate by white space
   or within quotes (double or single) (i.e. "the red rose" 
   is one token, \"the red rose\" is three tokens)
   a '\' character will allow a quote character to be treated
   as a regular character 
   It returns a pointer to first non-white space after the end of the token
   being copied or to 0 if we reach the end.*/

char *copy_word(char *from, char *to)
{
  char quote;
  if ( (*from == '\"') || (*from =='\'') ){
    quote = *(from++);
    while ( (*from != quote) && (*from != 0) ) {
      if ((*from == '\\') && (*(from+1) != 0)) {
	*to++ = *(from+1);
	from = from +2;
      }
      else  *to++ = *from++;
    }
    if (*from == 0) {
      DEBUGMSGTL(("read_config_copy_word",
                  "no end quote found in config string\n"));
    } else from++;
  }
  else {
    while (*from != 0 && !isspace(*from)) {
      if ((*from == '\\') && (*(from+1) != 0)) {
	*to++ = *(from+1);
	from = from +2;
      }
      else  *to++ = *from++;
    }
  }
  *to = 0;
  from = skip_white(from);
  return(from);
}  /* copy_word */

/* read_config_save_octet_string(): saves an octet string as a length
   followed by a string of hex */
char *read_config_save_octet_string(char *saveto, u_char *str, size_t len) {
  int i;
  if (str != NULL) {
    sprintf(saveto, "0x");
    saveto += 2;
    for(i = 0; i < (int)len; i++) {
      sprintf(saveto,"%02x", str[i]);
      saveto = saveto + 2;
    }
    return saveto;
  } else {
    sprintf(saveto,"\"\"");
    saveto += 2;
  }
  return saveto;
}

/* read_config_read_octet_string(): reads an octet string that was
   saved by the read_config_save_octet_string() function */
char *read_config_read_octet_string(char *readfrom, u_char **str, size_t *len) {
  u_char *cptr=NULL;
  char *cptr1;
  u_int tmp;
  int i;

  if (readfrom == NULL || str == NULL)
    return NULL;
  
  if (strncasecmp(readfrom,"0x",2) == 0) {
    /* A hex string submitted. How long? */
    readfrom += 2;
    cptr1 = skip_not_white(readfrom);
    if (cptr1)
      *len = (cptr1 - readfrom);
    else
      *len = strlen(readfrom);

    if (*len % 2) {
      DEBUGMSGTL(("read_config_read_octet_string","invalid hex string: wrong length"));
      return NULL;
    }
    *len = *len / 2;

    /* malloc data space if needed */
    if (*str == NULL) {
      if (*len == 0) {
        /* null length string found */
        cptr = NULL;

      } else if (*len > 0 && (str == NULL || (cptr = (u_char *)malloc(*len * sizeof(u_char))) == NULL)) {
        return NULL;
      }
      *str = cptr;
    } else {
      cptr = *str;
    }

    /* copy data */
    for(i = 0; i < (int)*len; i++) {
      sscanf(readfrom,"%2x",&tmp);
      *cptr++ = (u_char) tmp;
      readfrom += 2;
    }
    readfrom = skip_white(readfrom);
  } else {
    /* Normal string */

    /* malloc data space if needed */
    if (*str == NULL) {
      char buf[SNMP_MAXBUF];
      readfrom = copy_word(readfrom, buf);

      *len = strlen(buf);
      /* malloc an extra space to add a null */
      if (*len > 0 && (str == NULL ||
                       (cptr = (u_char *) malloc((1 + *len) * sizeof(u_char)))
                       == NULL))
        return NULL;
      *str = cptr;
      if (cptr)
        memcpy(cptr, buf, (*len+1));
    } else {
      readfrom = copy_word(readfrom, (char *)*str);
    }
  }

  return readfrom;
}


/* read_config_save_objid(): saves an objid as a numerical string */
char *read_config_save_objid(char *saveto, oid *objid, size_t len) {
  int i;
  
  if (len == 0) {
    strcat(saveto, "NULL");
    saveto += strlen(saveto);
    return saveto;
  }

  /* in case len=0, this makes it easier to read it back in */
  for(i=0; i < (int)len; i++) {
    sprintf(saveto,".%ld", objid[i]);
    saveto += strlen(saveto);
  }
  return saveto;
}

/* read_config_read_objid(): reads an objid from a format saved by the above */
char *read_config_read_objid(char *readfrom, oid **objid, size_t *len) {

  if (objid == NULL || readfrom == NULL)
    return NULL;

  if (*objid != NULL) {
    char buf[SPRINT_MAX_LEN];

    if (strncmp(readfrom,"NULL",4) == 0) {
      /* null length oid */
      *len = 0;
    } else {
      /* read_objid is touchy with trailing stuff */
      copy_word(readfrom, buf);

      /* read the oid into the buffer passed to us */
      if (!read_objid(buf, *objid, len)) {
        DEBUGMSGTL(("read_config_read_objid","Invalid OID"));
        return NULL;
      }
    }
    
    readfrom = skip_token(readfrom);
  } else {
    if (strncmp(readfrom,"NULL",4) == 0) {
      /* null length oid */
      *len = 0;
      readfrom = skip_token(readfrom);
    } else {
      /* space needs to be malloced.  Call ourself recursively to figure
       out how long the oid actually is */
      oid obuf[MAX_OID_LEN];
      size_t obuflen = MAX_OID_LEN;
      oid *oidp = obuf;
      oid **oidpp = &oidp;   /* done this way for odd, untrue, gcc warnings */

      readfrom = read_config_read_objid(readfrom, oidpp, &obuflen);

      /* Then malloc and copy the results */
      *len = obuflen;
      if (*len > 0 && (*objid = (oid*)malloc(*len * sizeof(oid))) == NULL)
        return NULL;

      if (obuflen > 0)
        memcpy(*objid, obuf, obuflen*sizeof(oid));
    }
  }
  return readfrom;
}

/* read_config_read_data():
   reads data of a given type from a token(s) on a configuration line.

   Returns: character pointer to the next token in the configuration line.
            NULL if none left.
            NULL if an unknown type.
*/
char *read_config_read_data(int type, char *readfrom, void *dataptr, size_t *len) {

  int *intp;
  char **charpp;
  oid  **oidpp;

  if (dataptr == NULL || readfrom == NULL)
    return NULL;
  
  switch(type) {
    case ASN_INTEGER:
      intp = (int *) dataptr;
      *intp = atoi(readfrom);
      readfrom = skip_token(readfrom);
      return readfrom;
      
    case ASN_OCTET_STR:
      charpp = (char **) dataptr;
      return read_config_read_octet_string(readfrom, (u_char **) charpp, len);

    case ASN_OBJECT_ID:
      oidpp = (oid **) dataptr;
      return read_config_read_objid(readfrom, oidpp, len);

    default:
      DEBUGMSGTL(("read_config_read_data","Fail: Unknown type: %d", type));
      return NULL;
  }
  return NULL;
}

/* read_config_read_data():
   reads data of a given type from a token(s) on a configuration line.

   Returns: character pointer to the next token in the configuration line.
            NULL if none left.
            NULL if an unknown type.
*/
char *read_config_store_data(int type, char *storeto, void *dataptr, size_t *len) {

  int *intp;
  u_char **charpp;
  oid  **oidpp;

  if (dataptr == NULL || storeto == NULL)
    return NULL;
  
  switch(type) {
    case ASN_INTEGER:
      intp = (int *) dataptr;
      sprintf(storeto," %d", *intp);
      return (storeto + strlen(storeto));
      
    case ASN_OCTET_STR:
      charpp = (u_char **) dataptr;
      return read_config_save_octet_string(storeto, *charpp, *len);

    case ASN_OBJECT_ID:
      oidpp = (oid **) dataptr;
      return read_config_save_objid(storeto, *oidpp, *len);

    default:
      DEBUGMSGTL(("read_config_store_data","Fail: Unknown type: %d", type));
      return NULL;
  }
  return NULL;
}
