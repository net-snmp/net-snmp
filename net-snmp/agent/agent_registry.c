/*
 * agent_registry.c
 *
 * Maintain a registry of MIB subtrees, together
 *   with related information regarding mibmodule, sessions, etc
 */

#define IN_SNMP_VARS_C

#include <config.h>
#include <signal.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
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

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "mibincl.h"
#include "snmp_client.h"
#include "default_store.h"
#include "ds_agent.h"
#include "callback.h"
#include "agent_callbacks.h"
#include "agent_registry.h"
#include "snmp_alarm.h"

#include "snmpd.h"
#include "mibgroup/struct.h"
#include "mib_module_includes.h"

#ifdef USING_AGENTX_SUBAGENT_MODULE
#include "agentx/subagent.h"
#include "agentx/client.h"
#endif


struct subtree *subtrees;

int tree_compare(const struct subtree *ap, const struct subtree *bp)
{
  return snmp_oid_compare(ap->name,ap->namelen,bp->name,bp->namelen);
}



	/*
	 *  Split the subtree into two at the specified point,
	 *    returning the new (second) subtree
	 */
struct subtree *
split_subtree(struct subtree *current, oid name[], int name_len )
{
    struct subtree *new_sub, *ptr;
    int i;
    char *cp;

    if ( snmp_oid_compare(name, name_len,
			  current->end, current->end_len) > 0 )
	return NULL;	/* Split comes after the end of this subtree */

    new_sub = (struct subtree *)malloc(sizeof(struct subtree));
    if ( new_sub == NULL )
	return NULL;
    memcpy(new_sub, current, sizeof(struct subtree));

	/* Set up the point of division */
    memcpy(current->end,   name, name_len*sizeof(oid));
    memcpy(new_sub->start, name, name_len*sizeof(oid));
    current->end_len   = name_len;
    new_sub->start_len = name_len;

	/*
	 * Split the variables between the two new subtrees
	 */
    i = current->variables_len;
    current->variables_len = 0;

    for ( ; i > 0 ; i-- ) {
		/* Note that the variable "name" field omits
		   the prefix common to the whole registration,
		   hence the strange comparison here */
	if ( snmp_oid_compare( new_sub->variables[0].name,
			       new_sub->variables[0].namelen,
			       name     + current->namelen, 
			       name_len - current->namelen ) >= 0 )
	    break;	/* All following variables belong to the second subtree */

	current->variables_len++;
	new_sub->variables_len--;
	cp = (char *)new_sub->variables;
	new_sub->variables = (struct variable *)(cp + new_sub->variables_width);
    }

	/* Delegated trees should retain their variables regardless */
    if ( current->variables_len > 0 &&
		IS_DELEGATED((u_char)current->variables[0].type)) {
	new_sub->variables_len = 1;
	new_sub->variables     = current->variables;
    }

	/* Propogate this split down through any children */
    if ( current->children )
	new_sub->children = split_subtree(current->children, name, name_len);

	/* Retain the correct linking of the list */
    for ( ptr = current ; ptr != NULL ; ptr=ptr->children )
          ptr->next = new_sub;
    for ( ptr = new_sub ; ptr != NULL ; ptr=ptr->children )
          ptr->prev = current;
    for ( ptr = new_sub->next ; ptr != NULL ; ptr=ptr->children )
          ptr->prev = new_sub;

    return new_sub;
}

int
load_subtree( struct subtree *new_sub )
{
    struct subtree *tree1, *tree2, *new2;
    struct subtree *prev, *next;
    int res;

    if ( new_sub == NULL )
	return MIB_REGISTERED_OK;	/* Degenerate case */

		/*
		 * Find the subtree that contains the start of 
		 *  the new subtree (if any)...
		 */
    tree1 = find_subtree( new_sub->start, new_sub->start_len, NULL );
		/*
		 * ...and the subtree that follows the new one
		 *	(NULL implies this is the final region covered)
		 */  
    if ( tree1 == NULL )
        tree2 = find_subtree_next( new_sub->start, new_sub->start_len, NULL );
    else
	tree2 = tree1->next;


	/*
	 * Handle new subtrees that start in virgin territory.
	 */
    if ( tree1 == NULL ) {
	new2 = NULL;
		/* Is there any overlap with later subtrees ? */
	if ( tree2 && snmp_oid_compare( new_sub->end, new_sub->end_len,
					tree2->start, tree2->start_len ) > 0 )
	    new2 = split_subtree( new_sub, tree2->start, tree2->start_len );

		/*
		 * Link the new subtree (less any overlapping region)
		 *  with the list of existing registrations
		 */
	if ( tree2 ) {
	    new_sub->prev = tree2->prev;
	    tree2->prev       = new_sub;
	}
	else
	    new_sub->prev = find_subtree_previous( new_sub->start, new_sub->start_len, NULL );

	if ( new_sub->prev )
	    new_sub->prev->next = new_sub;
	else
	    subtrees = new_sub;

	new_sub->next     = tree2;

		/*
		 * If there was any overlap,
		 *  recurse to merge in the overlapping region
		 *  (including anything that may follow the overlap)
		 */
	if ( new2 )
	    return load_subtree( new2 );
    }

    else {
	/*
	 *  If the new subtree starts *within* an existing registration
	 *    (rather than at the same point as it), then split the
	 *    existing subtree at this point.
	 */
	if ( snmp_oid_compare( new_sub->start, new_sub->start_len, 
			       tree1->start,   tree1->start_len) != 0 )
	    tree1 = split_subtree( tree1, new_sub->start, new_sub->start_len);
	    if ( tree1 == NULL )
		return MIB_REGISTRATION_FAILED;

	/*  Now consider the end of this existing subtree:
	 *	If it matches the new subtree precisely,
	 *	  simply merge the new one into the list of children
	 *	If it includes the whole of the new subtree,
	 *	  split it at the appropriate point, and merge again
	 *
	 *	If the new subtree extends beyond this existing region,
	 *	  split it, and recurse to merge the two parts.
	 */

	 switch ( snmp_oid_compare( new_sub->end, new_sub->end_len, 
				    tree1->end,   tree1->end_len))  {

		case -1:	/* Existing subtree contains new one */
			(void) split_subtree( tree1,
					new_sub->end, new_sub->end_len);
			/* Fall Through */

		case  0:	/* The two trees match precisely */
			/*
			 * Note: This is the only point where the original
			 *	 registration OID ("name") is used
			 */
			prev = NULL;
			next = tree1;
			while ( next && next->namelen > new_sub->namelen ) {
				prev = next;
				next = next->children;
			}
			while ( next && next->namelen == new_sub->namelen &&
					next->priority < new_sub->priority ) {
				prev = next;
				next = next->children;
			}
			if ( next &&	next->namelen  == new_sub->namelen &&
					next->priority == new_sub->priority )
			   return MIB_DUPLICATE_REGISTRATION;

			if ( prev ) {
			    new_sub->children = next;
			    prev->children    = new_sub;
			    new_sub->prev = prev->prev;
			    new_sub->next = prev->next;
			}
			else {
			    new_sub->children = next;
			    new_sub->prev = next->prev;
			    new_sub->next = next->next;

			    for ( next = new_sub->next ;
			    	  next != NULL ;
				  next = next->children )
					next->prev = new_sub;

			    for ( prev = new_sub->prev ;
			    	  prev != NULL ;
				  prev = prev->children )
					prev->next = new_sub;
			}
			break;

		case  1:	/* New subtree contains the existing one */
	    		new2 = split_subtree( new_sub,
					tree1->end, tree1->end_len);
			res = load_subtree( new_sub );
			if ( res != MIB_REGISTERED_OK ) {
			    free_subtree(new2);
			    return res;
			}
			return load_subtree( new2 );

	 }

    }
    return 0;
}


int
register_mib_context(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen,
	     int priority,
	     int range_subid,
	     oid range_ubound,
	     struct snmp_session *ss,
	     const char *context,
	     int timeout,
	     int flags)
{
  struct subtree *subtree, *sub2;
  int res, i;
  struct register_parameters reg_parms;
  
  subtree = (struct subtree *) malloc(sizeof(struct subtree));
  if ( subtree == NULL )
    return MIB_REGISTRATION_FAILED;
  memset(subtree, 0, sizeof(struct subtree));

  DEBUGMSGTL(("register_mib", "registering \"%s\" at ", moduleName));
  DEBUGMSGOID(("register_mib", mibloc, mibloclen));
  DEBUGMSG(("register_mib","\n"));
    
	/*
	 * Create the new subtree node being registered
	 */
  memcpy(subtree->name, mibloc, mibloclen*sizeof(oid));
  subtree->namelen = (u_char) mibloclen;
  memcpy(subtree->start, mibloc, mibloclen*sizeof(oid));
  subtree->start_len = (u_char) mibloclen;
  memcpy(subtree->end, mibloc, mibloclen*sizeof(oid));
  subtree->end[ mibloclen-1 ]++;	/* XXX - or use 'variables' info ? */
  subtree->end_len = (u_char) mibloclen;
  memcpy(subtree->label, moduleName, strlen(moduleName)+1);
  if ( var ) {
    subtree->variables = (struct variable *) malloc(varsize*numvars);
    memcpy(subtree->variables, var, numvars*varsize);
    subtree->variables_len = numvars;
    subtree->variables_width = varsize;
  }
  subtree->priority = priority;
  subtree->timeout  = timeout;
  subtree->session = ss;
  res = load_subtree(subtree);

	/*
	 * If registering a range,
	 *   use the first subtree as a template
	 *   for the rest of the range
	 */
  if (( res == MIB_REGISTERED_OK ) && ( range_subid != 0 )) {
    for ( i = mibloc[range_subid-1] +1 ; i < (int)range_ubound ; i++ ) {
	sub2 = (struct subtree *) malloc(sizeof(struct subtree));
	if ( sub2 == NULL ) {
	    unregister_mib_context( mibloc, mibloclen, priority,
				  range_subid, range_ubound, context);
	    return MIB_REGISTRATION_FAILED;
	}
	memcpy( sub2, subtree, sizeof(struct subtree));
	sub2->start[range_subid-1] = i;
	sub2->end[  range_subid-1] = i;		/* XXX - ???? */
	res = load_subtree(sub2);
	if ( res != MIB_REGISTERED_OK ) {
	    unregister_mib_context( mibloc, mibloclen, priority,
				  range_subid, range_ubound, context);
	    return MIB_REGISTRATION_FAILED;
	}
    }
  } else if (res == MIB_DUPLICATE_REGISTRATION ||
	     res == MIB_REGISTRATION_FAILED) {
      free_subtree(subtree);
  }

  reg_parms.name = mibloc;
  reg_parms.namelen = mibloclen;
  reg_parms.priority = priority;
  reg_parms.range_subid  = range_subid;
  reg_parms.range_ubound = range_ubound;
  reg_parms.timeout = timeout;

  /*  Should this really be called if the registration hasn't actually 
      succeeded?  */

  snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_REGISTER_OID,
                      &reg_parms);

  return res;
}

int
register_mib_range(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen,
	     int priority,
	     int range_subid,
	     oid range_ubound,
	     struct snmp_session *ss)
{
  return register_mib_context( moduleName, var, varsize, numvars,
				mibloc, mibloclen, priority,
				range_subid, range_ubound, ss, "", -1, 0);
}

int
register_mib_priority(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen,
	     int priority)
{
  return register_mib_range( moduleName, var, varsize, numvars,
				mibloc, mibloclen, priority, 0, 0, NULL );
}

int
register_mib(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen)
{
  return register_mib_priority( moduleName, var, varsize, numvars,
				mibloc, mibloclen, DEFAULT_MIB_PRIORITY );
}


void
unload_subtree( struct subtree *sub, struct subtree *prev)
{
    struct subtree *ptr;

    if ( prev != NULL ) {	/* non-leading entries are easy */
	prev->children = sub->children;
	return;
    }
			/* otherwise, we need to amend our neighbours as well */

    if ( sub->children == NULL) {	/* just remove this node completely */
	for (ptr = sub->prev ; ptr ; ptr=ptr->children )
	    ptr->next = sub->next;
	for (ptr = sub->next ; ptr ; ptr=ptr->children )
	    ptr->prev = sub->prev;
	return;
    }
    else {
	for (ptr = sub->prev ; ptr ; ptr=ptr->children )
	    ptr->next = sub->children;
	for (ptr = sub->next ; ptr ; ptr=ptr->children )
	    ptr->prev = sub->children;
	return;
    }
}

int
unregister_mib_context( oid *name, size_t len, int priority,
	     		int range_subid, oid range_ubound, const char* context)
{
  struct subtree *list, *myptr;
  struct subtree *prev, *child;             /* loop through children */
  struct register_parameters reg_parms;

  list = find_subtree( name, len, subtrees );
  if ( list == NULL )
	return MIB_NO_SUCH_REGISTRATION;

  for ( child=list, prev=NULL;  child != NULL;
			 	prev=child, child=child->children ) {
      if (( snmp_oid_compare( child->name, child->namelen, name, len) == 0 )
	  && ( child->priority == priority ))
		break;	/* found it */
  }
  if ( child == NULL )
	return MIB_NO_SUCH_REGISTRATION;

  unload_subtree( child, prev );
  myptr = child;	/* remember this for later */

		/*
		 *  Now handle any occurances in the following subtrees,
		 *	as a result of splitting this range.  Due to the
		 *	nature of the way such splits work, the first
		 * 	subtree 'slice' that doesn't refer to the given
		 *	name marks the end of the original region.
		 *
		 *  This should also serve to register ranges.
		 */

  for ( list = myptr->next ; list != NULL ; list=list->next ) {
  	for ( child=list, prev=NULL;  child != NULL;
			 	      prev=child, child=child->children ) {
	    if (( snmp_oid_compare( child->name, child->namelen,
							name, len) == 0 )
		&& ( child->priority == priority )) {

		    unload_subtree( child, prev );
		    free_subtree( child );
		    break;
	    }
	}
	if ( child == NULL )	/* Didn't find the given name */
	    break;
  }
  free_subtree( myptr );
  
  reg_parms.name = name;
  reg_parms.namelen = len;
  reg_parms.priority = priority;
  reg_parms.range_subid  = range_subid;
  reg_parms.range_ubound = range_ubound;
  snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_UNREGISTER_OID,
                      &reg_parms);

  return MIB_UNREGISTERED_OK;
}

int
unregister_mib_range( oid *name, size_t len, int priority,
	     		int range_subid, oid range_ubound)
{
  return unregister_mib_context( name, len, priority, range_subid, range_ubound, "" );
}

int
unregister_mib_priority(oid *name, size_t len, int priority)
{
  return unregister_mib_range( name, len, priority, 0, 0 );
}

int
unregister_mib(oid *name,
	       size_t len)
{
  return unregister_mib_priority( name, len, DEFAULT_MIB_PRIORITY );
}

void
unregister_mibs_by_session (struct snmp_session *ss)
{
  struct subtree *list, *list2;
  struct subtree *child, *prev, *next_child;

  for( list = subtrees; list != NULL; list = list2) {
    list2 = list->next;
    for ( child=list, prev=NULL;  child != NULL; child=next_child ) {

      next_child = child->children;
      if (( (ss->flags & SNMP_FLAGS_SUBSESSION) && child->session == ss ) ||
          (!(ss->flags & SNMP_FLAGS_SUBSESSION) && child->session &&
                                      child->session->subsession == ss )) {
              unload_subtree( child, prev );
              free_subtree( child );
      }
      else
          prev = child;
    }
  }
}


struct subtree *
free_subtree(struct subtree *st)
{
  struct subtree *ret = NULL;
  if ((snmp_oid_compare(st->name, st->namelen, st->start, st->start_len) == 0)
       && (st->variables != NULL))
    free(st->variables);
  if (st->next != NULL)
    ret = st->next;
  free(st);
  return ret;
}

/* in_a_view: determines if a given snmp_pdu is allowed to see a
   given name/namelen OID pointer
   name         IN - name of var, OUT - name matched
   nameLen      IN -number of sub-ids in name, OUT - subid-is in matched name
   pi           IN - relevant auth info re PDU 
   cvp          IN - relevant auth info re mib module
*/

int
in_a_view(oid		  *name,      /* IN - name of var, OUT - name matched */
          size_t	  *namelen,   /* IN -number of sub-ids in name*/
          struct snmp_pdu *pdu,       /* IN - relevant auth info re PDU */
          int	           type)      /* IN - variable type being checked */
{

  struct view_parameters view_parms;
  view_parms.pdu = pdu;
  view_parms.name = name;
  if (namelen)
      view_parms.namelen = *namelen;
  else
      view_parms.namelen = 0;
  view_parms.errorcode = 0;

  if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW)
    return 0;		/* Enable bypassing of view-based access control */

  /* check for v1 and counter64s, since snmpv1 doesn't support it */
  if (pdu->version == SNMP_VERSION_1 && type == ASN_COUNTER64)
    return 5;
  switch (pdu->version) {
  case SNMP_VERSION_1:
  case SNMP_VERSION_2c:
  case SNMP_VERSION_3:
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_ACM_CHECK,
                        &view_parms);
    return view_parms.errorcode;
  }
  return 1;
}

/* in_a_view: determines if a given snmp_pdu is ever going to be allowed to do
   anynthing or if it's not going to ever be authenticated. */
int
check_access(struct snmp_pdu *pdu)      /* IN - pdu being checked */
{
  struct view_parameters view_parms;
  view_parms.pdu = pdu;
  view_parms.name = 0;
  view_parms.namelen = 0;
  view_parms.errorcode = 0;

  if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW)
    return 0;		/* Enable bypassing of view-based access control */

  switch (pdu->version) {
  case SNMP_VERSION_1:
  case SNMP_VERSION_2c:
  case SNMP_VERSION_3:
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                        SNMPD_CALLBACK_ACM_CHECK_INITIAL,
                        &view_parms);
    return view_parms.errorcode;
  }
  return 1;
}

/* lexicographical compare two object identifiers.
 * Returns -1 if name1 < name2,
 *          0 if name1 = name2, or name1 matches name2 for length of name2
 *          1 if name1 > name2
 *
 * Note: snmp_oid_compare checks len2 before last return.
 */
int
compare_tree(const oid *in_name1,
	     size_t len1, 
	     const oid *in_name2, 
	     size_t len2)
{
    register int len, res;
    register const oid * name1 = in_name1;
    register const oid * name2 = in_name2;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching OID */
    while(len-- > 0){
	res = *(name1++) - *(name2++);
	if (res < 0)
	    return -1;
	if (res > 0)
	    return 1;
    }
    /* both OIDs equal up to length of shorter OID */
    if (len1 < len2)
	return -1;

    /* name1 matches name2 for length of name2, or they are equal */
    return 0;
}

struct subtree *find_subtree_previous(oid *name,
			     size_t len,
			     struct subtree *subtree)
{
  struct subtree *myptr, *previous = NULL;

  if ( subtree )
	myptr = subtree;
  else
	myptr = subtrees;	/* look through everything */

  for( ; myptr != NULL; previous = myptr, myptr = myptr->next) {
    if (snmp_oid_compare(name, len, myptr->start, myptr->start_len) < 0)
      return previous;
  }
  return previous;
}

struct subtree *find_subtree_next(oid *name, 
				  size_t len,
				  struct subtree *subtree)
{
  struct subtree *myptr = NULL;

  myptr = find_subtree_previous(name, len, subtree);
  if ( myptr != NULL ) {
     myptr = myptr->next;
     while ( myptr && (myptr->variables == NULL || myptr->variables_len == 0) )
         myptr = myptr->next;
     return myptr;
  }
  else if (subtree && snmp_oid_compare(name, len, subtree->start, subtree->start_len) < 0)
     return subtree;
  else
     return NULL;
}

struct subtree *find_subtree(oid *name,
			     size_t len,
			     struct subtree *subtree)
{
  struct subtree *myptr;

  myptr = find_subtree_previous(name, len, subtree);
  if (myptr && snmp_oid_compare(name, len, myptr->end, myptr->end_len) < 0)
	return myptr;

  return NULL;
}

struct snmp_session *get_session_for_oid( oid *name, size_t len)
{
   struct subtree *myptr;

   myptr = find_subtree_previous(name, len, subtrees);
   while ( myptr && myptr->variables == NULL )
        myptr = myptr->next;

   if ( myptr == NULL )
        return NULL;
   else
        return myptr->session;
}



static struct subtree root_subtrees[] = {
   { { 0 }, 1 },	/* ccitt */
   { { 1 }, 1 },	/*  iso  */
   { { 2 }, 1 }		/* joint-ccitt-iso */
};


void setup_tree (void)
{
#ifdef USING_AGENTX_SUBAGENT_MODULE
  int role;

  role = ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE);
  ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, MASTER_AGENT);
#endif

  register_mib("", NULL, 0, 0,
	root_subtrees[0].name,  root_subtrees[0].namelen);
  register_mib("", NULL, 0, 0,
	root_subtrees[1].name,  root_subtrees[1].namelen);
  register_mib("", NULL, 0, 0,
	root_subtrees[2].name,  root_subtrees[2].namelen);

  /* Support for 'static' subtrees (subtrees_old) has now been dropped */

  /* No longer necessary to sort the mib tree - this is inherent in
     the construction of the subtree structure */

#ifdef USING_AGENTX_SUBAGENT_MODULE
  ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, role);
#endif
}


extern void dump_idx_registry( void );
void dump_registry( void )
{
    struct subtree *myptr, *myptr2;
    char start_oid[SPRINT_MAX_LEN];
    char end_oid[SPRINT_MAX_LEN];

    for( myptr = subtrees ; myptr != NULL; myptr = myptr->next) {
	sprint_objid(start_oid, myptr->start, myptr->start_len);
	sprint_objid(end_oid, myptr->end, myptr->end_len);
	printf("%c %s - %s %c\n",
		( myptr->variables ? ' ' : '(' ),
		  start_oid, end_oid,
		( myptr->variables ? ' ' : ')' ));
	for( myptr2 = myptr ; myptr2 != NULL; myptr2 = myptr2->children) {
	    if ( myptr2->label && myptr2->label[0] )
		printf("\t%s\n", myptr2->label);
	}
    }

    dump_idx_registry();
}


int external_readfd[NUM_EXTERNAL_FDS], external_readfdlen = 0;
int external_writefd[NUM_EXTERNAL_FDS], external_writefdlen = 0;
int external_exceptfd[NUM_EXTERNAL_FDS], external_exceptfdlen = 0;
void (* external_readfdfunc[NUM_EXTERNAL_FDS])(int, void *);
void (* external_writefdfunc[NUM_EXTERNAL_FDS])(int, void *);
void (* external_exceptfdfunc[NUM_EXTERNAL_FDS])(int, void *);
void *external_readfd_data[NUM_EXTERNAL_FDS];
void *external_writefd_data[NUM_EXTERNAL_FDS];
void *external_exceptfd_data[NUM_EXTERNAL_FDS];

int register_readfd(int fd, void (*func)(int, void *), void *data) {
    if (external_readfdlen < NUM_EXTERNAL_FDS) {
	external_readfd[external_readfdlen] = fd;
	external_readfdfunc[external_readfdlen] = func;
	external_readfd_data[external_readfdlen] = data;
	external_readfdlen++;
	DEBUGMSGTL(("register_readfd", "registered fd %d\n", fd));
	return FD_REGISTERED_OK;
    } else {
	snmp_log(LOG_CRIT, "register_readfd: too many file descriptors\n");
	return FD_REGISTRATION_FAILED;
    }
}

int register_writefd(int fd, void (*func)(int, void *), void *data) {
    if (external_writefdlen < NUM_EXTERNAL_FDS) {
	external_writefd[external_writefdlen] = fd;
	external_writefdfunc[external_writefdlen] = func;
	external_writefd_data[external_writefdlen] = data;
	external_writefdlen++;
	DEBUGMSGTL(("register_writefd", "registered fd %d\n", fd));
	return FD_REGISTERED_OK;
    } else {
	snmp_log(LOG_CRIT, "register_writefd: too many file descriptors\n");
	return FD_REGISTRATION_FAILED;
    }
}

int register_exceptfd(int fd, void (*func)(int, void *), void *data) {
    if (external_exceptfdlen < NUM_EXTERNAL_FDS) {
	external_exceptfd[external_exceptfdlen] = fd;
	external_exceptfdfunc[external_exceptfdlen] = func;
	external_exceptfd_data[external_exceptfdlen] = data;
	external_exceptfdlen++;
	DEBUGMSGTL(("register_exceptfd", "registered fd %d\n", fd));
	return FD_REGISTERED_OK;
    } else {
	snmp_log(LOG_CRIT, "register_exceptfd: too many file descriptors\n");
	return FD_REGISTRATION_FAILED;
    }
}

int unregister_readfd(int fd) {
    int i, j;

    for (i = 0; i < external_readfdlen; i++) {
	if (external_readfd[i] == fd) {
	    external_readfdlen--;
	    for (j = i; j < external_readfdlen; j++) {
		external_readfd[j] = external_readfd[j+1];
		external_readfd_data[j] = external_readfd_data[j+1];
	    }
	    DEBUGMSGTL(("unregister_readfd", "unregistered fd %d\n", fd));
	    return FD_UNREGISTERED_OK;
	}
    }
    return FD_NO_SUCH_REGISTRATION;
}

int unregister_writefd(int fd) {
    int i, j;

    for (i = 0; i < external_writefdlen; i++) {
	if (external_writefd[i] == fd) {
	    external_writefdlen--;
	    for (j = i; j < external_writefdlen; j++) {
		external_writefd[j] = external_writefd[j+1];
		external_writefd_data[j] = external_writefd_data[j+1];
	    }
	    DEBUGMSGTL(("unregister_writefd", "unregistered fd %d\n", fd));
	    return FD_UNREGISTERED_OK;
	}
    }
    return FD_NO_SUCH_REGISTRATION;
}

int unregister_exceptfd(int fd) {
    int i, j;

    for (i = 0; i < external_exceptfdlen; i++) {
	if (external_exceptfd[i] == fd) {
	    external_exceptfdlen--;
	    for (j = i; j < external_exceptfdlen; j++) {
		external_exceptfd[j] = external_exceptfd[j+1];
		external_exceptfd_data[j] = external_exceptfd_data[j+1];
	    }
	    DEBUGMSGTL(("unregister_exceptfd", "unregistered fd %d\n", fd));
	    return FD_UNREGISTERED_OK;
	}
    }
    return FD_NO_SUCH_REGISTRATION;
}

int external_signal_scheduled[NUM_EXTERNAL_SIGS];
void (* external_signal_handler[NUM_EXTERNAL_SIGS])(int);

#ifndef WIN32

/*
 * TODO: add agent_SIGXXX_handler functions and `case SIGXXX: ...' lines
 *       below for every single that might be handled by register_signal().
 */

RETSIGTYPE agent_SIGCHLD_handler(int sig)
{
  external_signal_scheduled[SIGCHLD]++;
#ifndef HAVE_SIGACTION
  /* signal() sucks. It *might* have SysV semantics, which means that
   * a signal handler is reset once it gets called. Ensure that it
   * remains active.
   */
  signal(SIGCHLD, agent_SIGCHLD_handler);
#endif
}

int register_signal(int sig, void (*func)(int))
{

    switch (sig) {
#if defined(SIGCHLD)
    case SIGCHLD:
#ifdef HAVE_SIGACTION
	{
		static struct sigaction act;
		act.sa_handler = agent_SIGCHLD_handler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGCHLD, &act, NULL);
	}
#else
	signal(SIGCHLD, (void *)agent_SIGCHLD_handler);
#endif
	break;
#endif
    default:
	snmp_log(LOG_CRIT,
		 "register_signal: signal %d cannot be handled\n", sig);
	return SIG_REGISTRATION_FAILED;
    }

    external_signal_handler[sig] = func;
    external_signal_scheduled[sig] = 0;
    
    DEBUGMSGTL(("register_signal", "registered signal %d\n", sig));
    return SIG_REGISTERED_OK;
}

int unregister_signal(int sig) {
    signal(sig, SIG_DFL);
    DEBUGMSGTL(("unregister_signal", "unregistered signal %d\n", sig));
    return SIG_UNREGISTERED_OK;
}

#endif /* !WIN32 */
