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
#include <sys/socket.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "party.h"
#include "context.h"
#include "acl.h"
#include "system.h"
#include "read_config.h"
#include "snmp_debug.h"

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
  DEBUGMSGTL(("snmptrapd:traphandler", "looking for trap handler for "));
  DEBUGMSGOID(("snmptrapd:traphandler", name, namelen));
  DEBUGMSG(("snmptrapd:traphandler", "...\n"));
  for(ttmp = &traphandlers;
      *ttmp != NULL && snmp_oid_compare((*ttmp)->trap, (*ttmp)->traplen, name, namelen);
      ttmp = &((*ttmp)->next));
  if (*ttmp == NULL) {
    DEBUGMSGTL(("snmptrapd:traphandler", "  Didn't find it.\n"));
    return NULL;
  }
  DEBUGMSGTL(("snmptrapd:traphandler", "  Found it!\n"));
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
  DEBUGMSGTL(("read_config:traphandler", "registered handler for: "));
  DEBUGMSGOID(("read_config:traphandler", (*ttmp)->trap, (*ttmp)->traplen));
  DEBUGMSG(("read_config:traphandler", "\n"));
}

