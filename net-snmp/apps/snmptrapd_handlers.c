#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "asn1.h"
#include "read_config.h"

struct traphandle {
   char *exec;
   oid trap[MAX_OID_LEN];
   int traplen;
   struct traphandle *next;
};

struct traphandle *traphandlers=0;

/* handles parsing .conf lines of: */
/*   traphandle OID EXEC           */

char *
snmptrapd_get_traphandler(name, namelen)
  oid *name;
  int namelen;
{
  struct traphandle **ttmp;
  DEBUGP("looking for trap handler for ");
  DEBUGPOID(name,namelen);
  DEBUGP("...\n");
  for(ttmp = &traphandlers;
      *ttmp != NULL && compare((*ttmp)->trap, (*ttmp)->traplen, name, namelen);
      ttmp = &((*ttmp)->next));
  if (*ttmp == NULL) {
    DEBUGP("  Didn't find it.\n");
    return NULL;
  }
  DEBUGP("  Found it!\n");
  return (*ttmp)->exec;
}

void
snmptrapd_traphandle(word, line)
  char *word;
  char *line;
{
  struct traphandle **ttmp;
  char buf[STRINGMAX];
  char *cptr;

  /* find the current one, if it exists */
  for(ttmp = &traphandlers; *ttmp != NULL; ttmp = &((*ttmp)->next));

  if (*ttmp == NULL) {
    /* it doesn't, so allocate a new one. */
    *ttmp = (struct traphandle *) malloc(sizeof(struct traphandle));
    (*ttmp)->next = NULL;
    (*ttmp)->exec = NULL;
  } else {
    if ((*ttmp)->exec)
      free((*ttmp)->exec);
  }
  copy_word(line, buf);
  (*ttmp)->traplen = MAX_OID_LEN;
  if (!read_objid(buf,(*ttmp)->trap, &((*ttmp)->traplen))) {
    sprintf(buf,"Invalid object identifier: %s/%s",buf,line);
    config_perror(buf);
    return;
  }
  cptr = skip_not_white(line);
  (*ttmp)->exec = strdup(cptr);
  DEBUGP("registered handler for: ");
  DEBUGPOID((*ttmp)->trap, (*ttmp)->traplen);
  DEBUGP("\n");
}

