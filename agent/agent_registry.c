/*
 * agent_registry.c
 *
 * Maintain a registry of MIB subtrees, together
 *   with related information regarding mibmodule, sessions, etc
 */

#define IN_SNMP_VARS_C

#include <config.h>
#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#else
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>

#include "mibincl.h"
#include "default_store.h"
#include "ds_agent.h"
#include "callback.h"
#include "agent_callbacks.h"
#include "agent_registry.h"

#include "snmpd.h"
#include "mibgroup/struct.h"

#define DEFAULT_MIB_PRIORITY		16
#define UCD_REG_FLAG_SPLIT_REGISTRATION 0x1

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

    if ( new_sub == NULL )
	return 1;

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
	    load_subtree( new2 );
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
			load_subtree( new_sub );
			load_subtree( new2 );

	 }

    }
    return 0;
}


int
register_mib_priority(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen,
	     u_char priority)
{
  struct subtree *subtree;
  char c_oid[SPRINT_MAX_LEN];
  int res;
  struct register_parameters reg_parms;
  
  subtree = (struct subtree *) malloc(sizeof(struct subtree));
  if ( subtree == NULL )
    return -1;
  memset(subtree, 0, sizeof(struct subtree));

  sprint_objid(c_oid, mibloc, mibloclen);
  DEBUGMSGTL(("register_mib", "registering \"%s\" at %s\n",
              moduleName, c_oid));
    
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
  res = load_subtree(subtree);

  reg_parms.name = mibloc;
  reg_parms.namelen = mibloclen;
  snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_REGISTER_OID,
                      &reg_parms);

  return res;
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


int
unload_subtree( oid *name, size_t len, struct subtree *previous)
{
  struct subtree *list, *list_prev = NULL;      /* loop through children */
  struct subtree *prev, *prev_next;             /* loop through previous children */
#define LABELSIZE 256
  char label[LABELSIZE];

  list = previous->next;

  if ( snmp_oid_compare( list->name, list->namelen, name, len) != 0 )
        return -1;
  strcpy( label, list->label );         /* or save registration ID */
 
  while (1) {
    prev = previous;

    while ( list != NULL ) {
        if (!strcmp( list->label, label))
            break;                      /* or check registration ID */

        list_prev = list;
        list = list->children;
    }
    if ( list == NULL )
        break;                          /* break from infinite loop */

                        /* Identifier the successor to use instead of 'list' */
    if ( list->children ) {
        prev_next = list->children;
        list->children->next = list->next;
    }
    else
        prev_next = list->next;

    while (prev != NULL) {              /* Unlink 'list' from preceding entries */
        if ( prev->next == list )
            prev->next = prev_next;
        prev = prev->children;
    }

    if (list_prev)
        list_prev->children = list->children;
    list->children = NULL;
    list = free_subtree( list );        /* returns list->next */
    previous = previous->next;
  }
  return 0;
}

int
unregister_mib(oid *name,
	       size_t len)
{
  struct subtree *my_ptr;
  int res;
  struct register_parameters reg_parms;

  my_ptr = find_subtree( name, len, subtrees );
  if ( my_ptr == NULL )
     return -1;

  res = unload_subtree(name, len, subtrees);

  reg_parms.name = name;
  reg_parms.namelen = len;
  snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_UNREGISTER_OID,
                      &reg_parms);

  return res;
}


struct subtree *
free_subtree(struct subtree *st)
{
  struct subtree *ret = NULL;
  if (st->variables != NULL)
    free(st->variables);
  if (st->children != NULL)
    free_subtree(st->children);
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
  view_parms.namelen = *namelen;
  view_parms.errorcode = 1;

  if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW)
    return 1;		/* Enable bypassing of view-based access control */

  /* check for v1 and counter64s, since snmpv1 doesn't support it */
  if (pdu->version == SNMP_VERSION_1 && type == ASN_COUNTER64)
    return 0;
  switch (pdu->version) {
  case SNMP_VERSION_1:
  case SNMP_VERSION_2c:
  case SNMP_VERSION_3:
    snmp_call_callbacks(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_ACM_CHECK,
                        &view_parms);
    return view_parms.errorcode;
  }
  return 0;
}



int
compare_tree(oid *name1,
	     size_t len1, 
	     oid *name2, 
	     size_t len2)
{
    register int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
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
}
