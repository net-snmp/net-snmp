/*
 *  Template MIB group implementation - sysORTable.c
 *
 */

#include <config.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
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
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "../mibincl.h"
#include "../../../snmplib/system.h"
#include "sysORTable.h"
#include "../struct.h"
#include "../util_funcs.h"

extern struct timeval starttime;

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

struct timeval sysOR_lastchange;
static struct sysORTable *table=NULL;
static int numEntries=0;

/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 sysORTable_variables[] = {
    { SYSORTABLEINDEX,   ASN_INTEGER,       RONLY, var_sysORTable, 1, {1}},
    { SYSORTABLEID,      ASN_OBJECT_ID,     RONLY, var_sysORTable, 1, {2}},
    { SYSORTABLEDESCR,   ASN_OCTET_STR,     RONLY, var_sysORTable, 1, {3}},
    { SYSORTABLEUPTIME,  ASN_TIMETICKS,     RONLY, var_sysORTable, 1, {4}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid sysORTable_variables_oid[] = { 1,3,6,1,2,1,1,9,1 };

void
init_sysORTable(void) {
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/sysORTable", sysORTable_variables, variable2, sysORTable_variables_oid);

  gettimeofday(&sysOR_lastchange, NULL);
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char	*
var_sysORTable(struct variable *vp,
		oid *name,
		int *length,
		int exact,
		int *var_len,
		WriteMethod **write_method)
{
  struct timeval diff;
  int i;
  struct sysORTable *ptr;
  static u_long long_return;

  if (!checkmib(vp, name, length, exact, var_len, write_method, numEntries))
    return NULL;

  for(i = 1, ptr=table; ptr != NULL && i < name[*length-1];
      ptr = ptr->next, i++) {
    DEBUGMSGTL(("mibII/sysORTable", "sysORTable -- %d != %d\n",i,name[*length-1]));
  }
  if (ptr == NULL) {
    DEBUGMSGTL(("mibII/sysORTable", "sysORTable -- no match: %d\n",i));
    return NULL;
  }
  DEBUGMSGTL(("mibII/sysORTable", "sysORTable -- match: %d\n",i));
  
  switch (vp->magic){
    case SYSORTABLEINDEX:
      long_return = i;
      return (u_char *)&long_return;

    case SYSORTABLEID:
      *var_len = ptr->OR_oidlen*sizeof(ptr->OR_oid[0]);
      return (u_char *) ptr->OR_oid;

    case SYSORTABLEDESCR:
      *var_len = strlen(ptr->OR_descr);
      return (u_char *) ptr->OR_descr;

    case SYSORTABLEUPTIME:
      ptr->OR_uptime.tv_sec--;
      ptr->OR_uptime.tv_usec += 1000000L;
      diff.tv_sec = ptr->OR_uptime.tv_sec - 1 - starttime.tv_sec;
      diff.tv_usec = ptr->OR_uptime.tv_usec + 1000000L - starttime.tv_usec;
      if (diff.tv_usec > 1000000L){
        diff.tv_usec -= 1000000L;
        diff.tv_sec++;
      }
      if ((diff.tv_sec * 100) + (diff.tv_usec / 10000) < 0)
        long_return = 0;
      else
        long_return = ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
      return ((u_char *) &long_return);

    default:
      ERROR_MSG("");
  }
  return NULL;
}


void register_sysORTable(oid *oidin,
			 int oidlen,
			 char *descr)
{
  char c_oid[MAX_NAME_LEN];
  struct sysORTable **ptr=&table;

  if (snmp_get_do_debugging()) {
    sprint_objid (c_oid, oidin, oidlen);
    DEBUGMSGTL(("mibII/sysORTable", "sysORTable registering: %s\n",c_oid));
  }

  while(*ptr != NULL)
    ptr = &((*ptr)->next);
  *ptr = (struct sysORTable *) malloc(sizeof(struct sysORTable));
  (*ptr)->OR_descr = (char *) malloc(strlen(descr)+1);
  strcpy((*ptr)->OR_descr, descr);
  (*ptr)->OR_oidlen = oidlen;
  (*ptr)->OR_oid = (oid *) malloc(sizeof(oid)*oidlen);
  memcpy((*ptr)->OR_oid, oidin, sizeof(oid)*oidlen);
  gettimeofday(&((*ptr)->OR_uptime), NULL);
  (*ptr)->next = NULL;
  numEntries++;
}
