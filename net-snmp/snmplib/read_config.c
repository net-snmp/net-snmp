/*
 * read_config.c
 */

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
#include <sys/stat.h>

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
#if HAVE_UNISTD_H
# 	include <unistd.h>
#endif

#include "system.h"
#include "parse.h"
#include "asn1.h"
#include "mib.h"
#include "snmp_api.h"

#include "read_config.h"

int config_errors;

struct config_files *config_files = NULL;

struct config_line *
register_premib_handler(type, token, parser, releaser)
  char *type;
  char *token;
  void (*parser) __P((char *, char *));
  void (*releaser) __P((void));
{
  struct config_line *ltmp;
  ltmp = register_config_handler(type, token, parser, releaser);
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
register_config_handler(type, token, parser, releaser)
  char *type;
  char *token;
  void (*parser) __P((char *, char *));
  void (*releaser) __P((void));
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
unregister_config_handler(type, token)
  char *type;
  char *token;
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
    free(*ltmp);
    return;
  }
  while ((*ltmp)->next != NULL && strcmp((*ltmp)->next->config_token,token)) {
    ltmp = &((*ltmp)->next);
  }
  if (*ltmp == NULL) {
    free((*ltmp)->config_token);
    ltmp2 = (*ltmp)->next->next;
    free((*ltmp)->next);
    (*ltmp)->next = ltmp2;
  }
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
  for(;ctmp != NULL && strcmp(ctmp->fileHeader,type); ctmp = ctmp->next);
  if (ctmp)
    read_config(filename, ctmp->start, EITHER_CONFIG);
  else
    DEBUGP("read_config: I have no registrations for type:%s,file:%s\n",
           type, filename);
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
void
read_config(filename, line_handler, when)
  char *filename;
  struct config_line *line_handler;
  int when;
{

  FILE *ifile;
  char line[STRINGMAX], word[STRINGMAX], tmpbuf[STRINGMAX];
  char *cptr;
  int i, done;
  struct config_line *lptr;

  linecount = 0;
  curfilename = filename;
  
  if ((ifile = fopen(filename, "r")) == NULL) {
    DEBUGP("ucd-snmp: %s: %s\n", filename, strerror(errno));
    return;
  } else {
    DEBUGP("ucd-snmp: Reading configuration %s\n", filename);
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
          DEBUGP("%s:%d Parsing: %s\n", filename, linecount, line);
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

}  /* end read_config() */



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

void
read_configs __P((void))
{
  read_config_files(NORMAL_CONFIG);
}

void
read_premib_configs __P((void))
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
read_config_files(when)
  int when;
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
      sprintf(defaultPath,"%s:%s%s%s%s:%s",SNMPSHAREPATH,SNMPLIBPATH,
              ((homepath == NULL) ? "" : ":"),
              ((homepath == NULL) ? "" : homepath),
              ((homepath == NULL) ? "" : "/.snmp"),
              PERSISTENTDIR);
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
    exit(1);
  }

}  /* end read_config_files() */



/*******************************************************************-o-******
 * read_config_store
 *
 * Parameters:
 *	*type
 *	*line
 *      
 * 
 * Append line to a file named "<PERSISTENTDIR>/<type>.persistent.conf".
 * Add a trailing newline if necessary.
 *
 * Intended for use by applications to store permenant configuration 
 * information generated by sets or persistent counters.
 *
 */
void
read_config_store(char *type, char *line)
{
#ifdef PERSISTENTDIR
  char file[512];
  FILE *OUT;
  sprintf(file,"%s/%s.conf",PERSISTENTDIR,type);
  if ((OUT = fopen(file, "a")) != NULL) {
    fprintf(OUT,line);
    if (line[strlen(line)] != '\n')
      fprintf(OUT,"\n");
    DEBUGP("storing: %s\n",line);
    fclose(OUT);
    /* XXX Sync the disk? */
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
 * Unlink a file called "<PERSISTENTDIR>/<type>.conf".
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
snmp_clean_persistent(char *type)
{
  char file[512], fileold[512];
  struct stat statbuf;

  sprintf(file,"%s/%s.conf",PERSISTENTDIR,type);
  if (stat(file, &statbuf) == 0) {
    sprintf(fileold,"%s/%s.conf.old",PERSISTENTDIR,type);
    if (rename(file, fileold)) {
      unlink(file);/* failed, try nuking it */
    }
  }
}



/* config_perror: prints a warning string associated with a file and
   line number of a .conf file and increments the error count. */
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

char *skip_token(char *ptr)
{
  ptr = skip_white(ptr);
  ptr = skip_not_white(ptr);
  ptr = skip_white(ptr);
  return (ptr);
}

char *copy_word(from, to)
     char *from, *to;
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
