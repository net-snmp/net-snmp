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


static struct subtree*
insert_in_children_list(struct subtree *eldest,	/* The eldest child in the list of potential
						   siblings (or ancestors) */
			struct subtree *new_tree)	/* The new subtree to install */
{
    struct subtree *sibling = eldest;
    struct subtree *previous = NULL;

		/* Search for earlier subtrees (including ancestors) */

    while ( (sibling!=NULL) &&
	    tree_compare(sibling, new_tree) <0 ) {
	if ( is_parent(sibling->name, sibling->namelen, new_tree->name) ) {

		/* Found an ancestor of the new subtree, so recurse */
	    struct subtree *result;

	    result = insert_in_children_list( sibling->children, new_tree );
	    if ( result != NULL )
		sibling->children = result;	/* New eldest child */
	    return NULL;
	}
		/* Skip over earlier sibling (or 'uncle') subtrees */
	previous = sibling;
	sibling = sibling->next;
    }


		/* Run out of earlier subtrees */

    if (( sibling == NULL ) ||
	    tree_compare(sibling, new_tree) >0 ) {
	if (( sibling != NULL ) &&
	      is_parent(new_tree->name, new_tree->namelen, sibling->name) ) {
		/* The new subtree is the parent of existing subtrees,
			which need to be cut out of the current sibling list,
			and inserted as children of the new subtree */

	    struct subtree *prev_kid = sibling;
	    struct subtree *next_kid = sibling->next;

	    new_tree->children = sibling;
	
	    while (( next_kid != NULL ) &&
		     is_parent(new_tree->name, new_tree->namelen, next_kid->name) ) {
		prev_kid = next_kid;
		next_kid = next_kid->next;
	    }
	    prev_kid = NULL;
	    sibling = next_kid;		/* I.e. the next sibling of the new subtree */
	}
		
		/* Found the correct place to insert the new tree */
	new_tree->next = sibling;
	if ( previous != NULL ) {
	    previous->next = new_tree;
	    return NULL;
	}
	else {
	    return new_tree;	/* Tell the parent this is a new eldest child */
	}
    }

		/*
		   This point is only reached if the new subtree
			corresponds exactly to an existing subtree.
		   There are three possibilities:
			- Two module implementations are covering
			    exactly the same data  (Not A Good Idea)
			- The same module implemntation has been
			    loaded twice  (so it's safe to ignore it)
			- Two module implementations are cooperating
			    to cover different portions of the subtree.

		  This third is legitmate, so ought to be handled.
		  The probable implementation should move the 'mount_point'
		    sufficiently to differentiate the two, possibly splitting
		    one or both into a collection of smaller subtrees.

		  This idea will be quietly shelved for now, at least until
		    the simple case has been implemented, weighed in the
		    balance and found wanting.....
		*/
   return NULL;
}


void
register_mib(const char *moduleName,
	     struct variable *var,
	     size_t varsize,
	     size_t numvars,
	     oid *mibloc,
	     size_t mibloclen)
{
  struct subtree *subtree;
  char c_oid[SPRINT_MAX_LEN];

  subtree = (struct subtree *) malloc(sizeof(struct subtree));
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
  load_subtree(subtree);

  if ( agent_role == SUB_AGENT )
    agentx_register( agentx_session, mibloc, mibloclen );
}

/* unregister_mib(oid mibloc, int mibloclen)
 */
void
unregister_mib(oid *name,
	       size_t len)
{
  unregister_mib_tree(name, len, subtrees);
  if ( agent_role == SUB_AGENT )
    agentx_unregister( agentx_session, name, len );
}

struct subtree *
unregister_mib_tree(oid *name,
		    size_t len,
		    struct subtree *subtree)
{
  struct subtree *myptr = NULL;
  int ret;

  if ((ret = snmp_oid_compare(name, len, subtree->name, subtree->namelen)) == 0) {
    /* found it */
    return subtree;
  }

  if (ret > 0) {
    if (is_parent(subtree->name, subtree->namelen, name) &&
        subtree->children != NULL) {
      myptr = unregister_mib_tree(name, len, subtree->children);
      if (myptr != NULL) {
        /* found it, remove it as our child possibly adding the next child */
        myptr = free_subtree(myptr);
        subtree->children = myptr;
        return NULL;
      }
    }
    if (subtree->next != NULL) {
      myptr = unregister_mib_tree(name, len, subtree->next);
      if (myptr != NULL) {
        /* found it next, remove it as next and take the one after that. */
        myptr = free_subtree(myptr);
        subtree->next = myptr;
        return NULL;
      }
    }
  }
  return NULL;
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

struct subtree *find_subtree_next(oid *name, 
				  size_t len,
				  struct subtree *subtree)
{
  struct subtree *myptr = NULL;
  int ret;

  if ((ret = snmp_oid_compare(name, len, subtree->name, subtree->namelen)) == 0) {
    if (subtree->children != NULL)
      return subtree->children;
    if (subtree->next != NULL)
      return subtree->next;
    return NULL;
  }

  if (ret > 0) {
    if (is_parent(subtree->name, subtree->namelen, name) &&
        subtree->children != NULL) {
      myptr = find_subtree_next(name, len, subtree->children);
      if (myptr != NULL)
        return myptr;
      return subtree->next;
    }
    if (subtree->next != NULL)
      return find_subtree_next(name, len, subtree->next);
  }

  return NULL;
}

struct subtree *find_subtree(oid *name,
			     size_t len,
			     struct subtree *subtree)
{
  struct subtree *myptr;

  for(myptr = subtree; myptr != NULL; myptr = myptr->next) {
    if (snmp_oid_compare(name, len, myptr->name, myptr->namelen) == 0)
      return myptr;
  }
  return NULL;
}



void
load_subtree (struct subtree *new_subtree)
{
    insert_in_children_list( subtrees, new_subtree );
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

