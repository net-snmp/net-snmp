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

#include "m2m.h"
#include "snmp_vars_m2m.h"
#define SNMPV2                  1, 3, 6, 1, 6
#define PARTYMIB        SNMPV2, 3, 3
#define SNMPV2M2M       SNMPV2, 3, 3

#include "snmpd.h"
#include "mibgroup/struct.h"
#include "mibgroup/mib_module_includes.h"

#ifdef USING_AGENTX_SUBAGENT_MODULE
#include "agentx/subagent.h"
#endif


#define UCD_REG_FLAG_SPLIT_REGISTRATION 0x1

struct subtree *subtrees;

int tree_compare(const struct subtree *ap, const struct subtree *bp)
{
  return snmp_oid_compare(ap->name,ap->namelen,bp->name,bp->namelen);
}

int is_parent(oid *name1, int len1, oid *name2)
{
    register int len = len1;

    if ( name2 == NULL )
	return 0;	/* Null child - doesn't count */
	
		/*
		 * Is name1 a strict prefix of name2 ?
		 */
    while(len-- > 0){
	if (*name2++ != *name1++)
	    return 0;	/* No */
    }
    return 1;		/* Yes */
}



	/*
	 *  Merge overlapping registration entries,
	 *    such that each subtree list (linked via 'children')
	 *    relates to the same OID range
	 *  This is done by splitting the enclosing entry into three:
	 *    pre-match / match / post-match
	 *    (any of which may in fact be empty)
	 *
	 *  This is described in the AgentX protocol (RFC 2257 & successors)
	 *    but is a more generally useful approach anyway
	 */

void
merge_variables( struct subtree *first, struct subtree *second )
{
    int num_variables = 0;
    char *cp = (char *)first->variables;
    int i;

    if ( first->variables == NULL )
	return;

		/* Divide the 'variables' structure between the two trees */
    for ( i = 0 ; i < first->variables_len ; i++ ) {
	if ( snmp_oid_compare(((struct variable *)cp)->name,
			      ((struct variable *)cp)->namelen,
			      second->name    + first->namelen,
			      second->namelen - first->namelen) < 0 ) {
	    num_variables++;
	    cp += first->variables_width;
	}
	else
	    break;
    }

    second->variables      = (struct variable *)cp;
    second->variables_len -= num_variables;
     first->variables_len  = num_variables;

    if ( first->variables_len == 0 )
	 first->variables = NULL;
    if (second->variables_len == 0 )
	second->variables = NULL;
}

void
merge_trees( struct subtree *existing, struct subtree *new_tree )
{
    struct subtree temp;			/* temporary 'post' entry */
    struct subtree *post_ptr = &temp;		/* tail of 'post' list    */
    struct subtree *match_ptr = new_tree;	/* tail of 'match' list   */

    struct subtree *new_match, *new_post;


		/* Link in the new entry, and the 'post' placeholder */
    memset( &temp, 0, sizeof(struct subtree));
    temp.next        = existing->next;
    new_tree->next   = &temp;
    existing->next   = new_tree;

    memcpy( temp.name, new_tree->name, new_tree->namelen*sizeof(oid) );
    temp.namelen = new_tree->namelen;
    temp.name[ (new_tree->namelen)-1 ]++;

		/*
		 * Loop through the list of existing subtrees,
		 *  splitting them and linking the new match/post
		 *  subtrees into the relevant lists
		 */
    while ( existing ) {
	new_match = (struct subtree *)malloc( sizeof( struct subtree ));
	if ( new_match == NULL )
	    break;
	new_post = (struct subtree *)malloc( sizeof( struct subtree ));
	if ( new_post == NULL ) {
	    free( new_match );
	    break;
	}

		/* Set up the new entries ... */
	memcpy( new_match, existing, sizeof(*existing));
	memcpy( new_match->name, new_tree->name, new_tree->namelen*sizeof(oid));
	new_match->namelen = new_tree->namelen;
	new_match->flags |= UCD_REG_FLAG_SPLIT_REGISTRATION;
	merge_variables( existing, new_match );

	memcpy( new_post, existing, sizeof(*existing));
	memcpy( new_post->name, new_tree->name, new_tree->namelen*sizeof(oid) );
	new_post->namelen = new_tree->namelen;
	new_post->name[ (new_tree->namelen)-1 ]++;
	new_post->flags |= UCD_REG_FLAG_SPLIT_REGISTRATION;
	merge_variables( new_match, new_post );

		/* .... and link them in properly */
	post_ptr->children    = new_post;
	new_post->children    = NULL;
	new_post->next        = post_ptr->next;
	match_ptr->children   = new_match;
	new_match->children   = NULL;
	new_match->next       = post_ptr;
	existing->next        = match_ptr;

	existing     = existing->children;
	match_ptr    = match_ptr->children;
	post_ptr     = post_ptr ->children;
    }

		/* Finally, unlink the temporary 'post' entry */
    new_tree->next           = temp.children;
    new_tree->children->next = temp.children;
}


int
load_subtree (struct subtree *new_subtree)
{
    struct subtree *next_tree = subtrees;
    struct subtree *previous = NULL;

    new_subtree->flags &= ~(UCD_REG_FLAG_SPLIT_REGISTRATION);
    previous = find_subtree_previous(new_subtree->name, new_subtree->namelen, subtrees);
    if (previous) {
	if ((snmp_oid_compare(new_subtree->name, new_subtree->namelen, 
			      previous->name, previous->namelen) == 0)
	    && (strlen(previous->label) > 0 ))
			return -2;		/* Duplicate registration */
	next_tree = previous->next;
    }
    else
	next_tree = subtrees;


		/*
		 * Three possibilities:
		 *   a) the new registration is a subtree of an existing one
		 *   b) an existing registration is a subtree of the new one
		 *   a) the new registration does not overlap
		 */
    if ( previous && (previous->namelen < new_subtree->namelen)
		  && (is_parent(previous->name, previous->namelen, new_subtree->name))) {
	merge_trees( previous, new_subtree );
    }
    else if ( next_tree && (next_tree->namelen < new_subtree->namelen)
		  && (is_parent(new_subtree->name, new_subtree->namelen, next_tree->name))) {
	merge_trees( new_subtree, next_tree );
    }
    else {
	if (previous) {
	    while(previous) {
	        previous->next = new_subtree;
	        previous = previous->children;
	    }
	}
	else
	    subtrees = new_subtree;
	new_subtree->next = next_tree;
    }
    return 0;
}

int
register_mib(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen)
{
  struct subtree *subtree;
  char c_oid[SPRINT_MAX_LEN];
  int res;

  subtree = (struct subtree *) malloc(sizeof(struct subtree));
  if ( subtree == NULL )
    return -1;
  memset(subtree, 0, sizeof(struct subtree));

  sprint_objid(c_oid, mibloc, mibloclen);
  DEBUGMSGTL(("register_mib", "registering \"%s\" at %s\n",
              moduleName, c_oid));
    
  memcpy(subtree->name, mibloc, mibloclen*sizeof(oid));
  memcpy(subtree->label, moduleName, strlen(moduleName)+1);
  subtree->namelen = (u_char) mibloclen;
  subtree->variables = (struct variable *) malloc(varsize*numvars);
  memcpy(subtree->variables, var, numvars*varsize);
  subtree->variables_len = numvars;
  subtree->variables_width = varsize;
  res = load_subtree(subtree);

#ifdef USING_AGENTX_SUBAGENT_MODULE
  if ( agent_role == SUB_AGENT )
    agentx_register( agentx_session, mibloc, mibloclen );
#endif

  return res;
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

  my_ptr = find_subtree( name, len, subtrees );
  if ( my_ptr == NULL )
     return -1;

  res = unload_subtree(name, len, subtrees);
#ifdef USING_AGENTX_SUBAGENT_MODULE
  if ( agent_role == SUB_AGENT )
    agentx_unregister( agentx_session, name, len );
#endif

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

#ifdef USING_V2PARTY_VIEW_VARS_MODULE
extern int in_view (oid *, int, int);
#endif

int
in_a_view(oid		  *name,      /* IN - name of var, OUT - name matched */
          size_t	  *namelen,   /* IN -number of sub-ids in name*/
          struct snmp_pdu *pdu,       /* IN - relevant auth info re PDU */
          int	           type)      /* IN - variable type being checked */
{
  if (pdu->flags & UCD_MSG_FLAG_ALWAYS_IN_VIEW)
    return 1;		/* Enable bypassing of view-based access control */

  /* check for v1 and counter64s, since snmpv1 doesn't support it */
  if (pdu->version == SNMP_VERSION_1 && type == ASN_COUNTER64)
    return 0;
  switch (pdu->version) {
  case SNMP_VERSION_1:
  case SNMP_VERSION_2c:
  case SNMP_VERSION_3:
#ifdef USING_MIBII_VACM_VARS_MODULE
    return vacm_in_view(pdu, name, *namelen);
#else
    return 1;
#endif
  case SNMP_VERSION_2p:
#ifdef USING_V2PARTY_VIEW_VARS_MODULE
    return in_view(name, *namelen, 0 /* XXX: pi->cxp->contextViewIndex */);
#else
    return 1;
#endif
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
    if (snmp_oid_compare(name, len, myptr->name, myptr->namelen) < 0)
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
     while ( myptr && myptr->variables == NULL )
         myptr = myptr->next;
     return myptr;
  }
  else if ( snmp_oid_compare(name, len, subtree->name, subtree->namelen) < 0)
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
  if (snmp_oid_compare(name, len, myptr->name, myptr->namelen) == 0)
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

struct subtree subtrees_old[] = {
#include "mibgroup/mib_module_loads.h"
};

int subtree_old_size (void) {
  return (sizeof(subtrees_old)/ sizeof(struct subtree));
}

void setup_tree (void)
{
  extern struct subtree *subtrees,subtrees_old[];
  int i;
    
  if ( subtrees == NULL ) {
	subtrees =             &(root_subtrees[0]);
	subtrees->next =       &(root_subtrees[1]);
	subtrees->next->next = &(root_subtrees[2]);
  }

  /* Go through the 'static' subtrees (subtrees_old),
	and link them into the global subtree structure */

  for ( i=0 ; i < subtree_old_size(); i++ )
	load_subtree( &(subtrees_old[i]) );

  /* No longer necessary to sort the mib tree - this is inherent in
     the construction of the subtree structure */
}

