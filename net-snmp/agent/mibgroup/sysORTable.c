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
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "sysORTable.h"

extern struct timeval starttime;

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

static struct timeval lastchange;
static int numenrties;
static struct sysORTable *table=NULL;
static int numEntries=0;

void
init_sysORTable() {
  gettimeofday(&lastchange, NULL);
}


int
header_sysORTable(vp, name, length, exact, var_len, write_method, max)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
    int max;
{
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_sysORTable: %s %d\n", c_oid, exact);
    }

    memcpy((void *) newname, (void *) vp->name,
           ((int) vp->namelen) * sizeof(oid));
    newname[vp->namelen] = 0;
    result = compare(name, *length, newname, (int)vp->namelen+1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy((void *) name, (void *) newname,
           ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_sysORTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
  struct timeval diff;
  int i;
  struct sysORTable *ptr;
  static u_long long_return;
  oid newname[30];

  if (!checkmib(vp, name, length, exact, var_len, write_method,
                        newname, numEntries))
    return NULL;

  switch (vp->magic){
    case SYSORLASTCHANGE:
      diff.tv_sec = lastchange.tv_sec - 1 - starttime.tv_sec;
      diff.tv_usec = lastchange.tv_usec + 1000000L - starttime.tv_usec;
      if (diff.tv_usec > 1000000L){
        diff.tv_usec -= 1000000L;
        diff.tv_sec++;
      }
      long_return = ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
      return ((u_char *) &long_return);
  }
  
  for(i = 1, ptr=table; ptr != NULL && i < newname[*length-1];
      ptr = ptr->next, i++) {
    DEBUGP("sysORTable -- %d != %d\n",i,newname[*length-1]);
  }
  if (ptr == NULL) {
    DEBUGP("sysORTable -- no match: %d\n",i);
    return NULL;
  }
  DEBUGP("sysORTable -- match: %d\n",i);
  
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
      long_return = ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
      return ((u_char *) &long_return);

    default:
      ERROR_MSG("");
  }
  return NULL;
}


void register_sysORTable(oidin, oidlen, descr)
  oid *oidin;
  int oidlen;
  char *descr;
{
  char c_oid[MAX_NAME_LEN];
  struct sysORTable **ptr=&table;

  if (snmp_get_do_debugging()) {
    sprint_objid (c_oid, oidin, oidlen);
    DEBUGP("sysORTable registering: %s\n",c_oid);
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
