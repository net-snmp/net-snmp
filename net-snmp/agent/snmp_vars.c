/*
 * snmp_vars.c - return a pointer to the named variable.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989, 1990 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/
/*
 * additions, fixes and enhancements for Linux by Erik Schoenfelder
 * (schoenfr@ibr.cs.tu-bs.de) 1994/1995.
 * Linux additions taken from CMU to UCD stack by Jennifer Bray of Origin
 * (jbray@origin-at.co.uk) 1997
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

#include <sys/socket.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#include "mibincl.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "m2m.h"
#include "snmp_vars_m2m.h"
#include "../snmplib/system.h"
#include "kernel.h"

/* #include "common_header.h" */
#include "mibgroup/struct.h"
#include "mibgroup/mib_module_includes.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "mib_module_config.h"
#if USING_MIBII_VACM_VARS_MODULE
#include "mibgroup/mibII/vacm_vars.h"
#endif

#include "snmpd.h"
#include "party.h"
#include "context.h"

#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b)) 
#endif

static int compare_tree __P((oid *, int, oid *, int));
extern struct subtree subtrees_old[];

static u_char *search_subtree_vars __P((struct subtree *, oid *, int *, u_char *, int *, u_short *, int, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)), struct packet_info *, int *));

struct subtree *find_subtree_next __P((oid *, int, struct subtree *));

static u_char	*search_subtree __P((struct subtree *, oid *, int *, u_char *, int *, u_short *, int, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)), struct packet_info *, int *));

static int in_a_view __P((oid *, int *, struct packet_info *, struct variable *));

int subtree_size;
int subtree_malloc_size;

/*
 *	Each variable name is placed in the variable table, without the
 * terminating substring that determines the instance of the variable.  When
 * a string is found that is lexicographicly preceded by the input string,
 * the function for that entry is called to find the method of access of the
 * instance of the named variable.  If that variable is not found, NULL is
 * returned, and the search through the table continues (it will probably
 * stop at the next entry).  If it is found, the function returns a character
 * pointer and a length or a function pointer.  The former is the address
 * of the operand, the latter is a write routine for the variable.
 *
 * u_char *
 * findVar(name, length, exact, var_len, write_method)
 * oid	    *name;	    IN/OUT - input name requested, output name found
 * int	    length;	    IN/OUT - number of sub-ids in the in and out oid's
 * int	    exact;	    IN - TRUE if an exact match was requested.
 * int	    len;	    OUT - length of variable or 0 if function returned.
 * int	    write_method;   OUT - pointer to function to set variable,
 *                                otherwise 0
 *
 *     The writeVar function is returned to handle row addition or complex
 * writes that require boundary checking or executing an action.
 * This routine will be called three times for each varbind in the packet.
 * The first time for each varbind, action is set to RESERVE1.  The type
 * and value should be checked during this pass.  If any other variables
 * in the MIB depend on this variable, this variable will be stored away
 * (but *not* committed!) in a place where it can be found by a call to
 * writeVar for a dependent variable, even in the same PDU.  During
 * the second pass, action is set to RESERVE2.  If this variable is dependent
 * on any other variables, it will check them now.  It must check to see
 * if any non-committed values have been stored for variables in the same
 * PDU that it depends on.  Sometimes resources will need to be reserved
 * in the first two passes to guarantee that the operation can proceed
 * during the third pass.  During the third pass, if there were no errors
 * in the first two passes, writeVar is called for every varbind with action
 * set to COMMIT.  It is now that the values should be written.  If there
 * were errors during the first two passes, writeVar is called in the third
 * pass once for each varbind, with the action set to FREE.  An opportunity
 * is thus provided to free those resources reserved in the first two passes.
 * 
 * writeVar(action, var_val, var_val_type, var_val_len, statP, name, name_len)
 * int	    action;	    IN - RESERVE1, RESERVE2, COMMIT, or FREE
 * u_char   *var_val;	    IN - input or output buffer space
 * u_char   var_val_type;   IN - type of input buffer
 * int	    var_val_len;    IN - input and output buffer len
 * u_char   *statP;	    IN - pointer to local statistic
 * oid      *name           IN - pointer to name requested
 * int      name_len        IN - number of sub-ids in the name
 */

long		long_return;
#ifndef ibm032
u_char		return_buf[258];  
#else
u_char		return_buf[256]; /* nee 64 */
#endif


void
init_agent __P((void))
{
#ifdef CAN_USE_NLIST
	init_kmem("/dev/kmem");
#endif

	setup_tree();

#include "mibgroup/mib_module_inits.h"

	init_agent_read_config();

#ifdef TESTING
	auto_nlist_print_tree(-2, 0);
#endif
}  /* end init_agent() */


#define CMUMIB 1, 3, 6, 1, 4, 1, 3
#define       CMUUNIXMIB  CMUMIB, 2, 2

#define SNMPV2 			1, 3, 6, 1, 6
#define SNMPV2M2M		SNMPV2, 3, 2

#define SNMPV2ALARMEVENTS	SNMPV2M2M, 1, 1, 3

#define RMONMIB 1, 3, 6, 1, 2, 1, 16

#define HOST                    RMONMIB, 4
#define HOSTCONTROL             HOST, 1, 1                      /* hostControlEntry */
#define HOSTTAB                 HOST, 2, 1                      /* hostEntry */
#define HOSTTIMETAB             HOST, 3, 1                      /* hostTimeEntry */
#define HOSTTOPN                RMONMIB, 5
#define HOSTTOPNCONTROL HOSTTOPN, 1, 1          /* hostTopNControlEntry */
#define HOSTTOPNTAB             HOSTTOPN, 2, 1          /* hostTopNEntry */
#define HOSTTIMETABADDRESS                                      1
#define HOSTTIMETABCREATIONORDER                        2
#define HOSTTIMETABINDEX                                        3
#define HOSTTIMETABINPKTS                                       4
#define HOSTTIMETABOUTPKTS                                      5
#define HOSTTIMETABINOCTETS                                     6
#define HOSTTIMETABOUTOCTETS                            7
#define HOSTTIMETABOUTERRORS                            8
#define HOSTTIMETABOUTBCASTPKTS                         9
#define HOSTTIMETABOUTMCASTPKTS                         10

#if 0
#define RMONMIB 1, 3, 6, 1, 2, 1, 16

#define ALARM                   RMONMIB, 3
#define ALARMTAB                ALARM, 1, 1                 /* alarmEntry */
#define EVENT                   RMONMIB, 9
#define EVENTTAB                EVENT, 1, 1                 /* eventEntry */
#endif

#define PARTYMIB 	SNMPV2, 3, 3

/* various OIDs that are needed throughout the agent */
#ifdef USING_V2PARTY_ALARM_MODULE
Export oid alarmVariableOid[] = {SNMPV2ALARMENTRY, ALARMTABVARIABLE};
Export int alarmVariableOidLen = sizeof(alarmVariableOid) / sizeof(oid);
Export oid alarmSampleTypeOid[] = {SNMPV2ALARMENTRY, ALARMTABSAMPLETYPE};
Export int alarmSampleTypeOidLen = sizeof(alarmSampleTypeOid) / sizeof(oid);
Export oid alarmValueOid[] = {SNMPV2ALARMENTRY, ALARMTABVALUE};
Export int alarmValueOidLen = sizeof(alarmValueOid) / sizeof(oid);
Export oid alarmFallingThreshOid[] = {SNMPV2ALARMENTRY, ALARMTABFALLINGTHRESH};
Export int alarmFallingThreshOidLen = sizeof(alarmFallingThreshOid)/sizeof(oid);
Export oid alarmRisingThreshOid[] = {SNMPV2ALARMENTRY, ALARMTABRISINGTHRESH};
Export int alarmRisingThreshOidLen = sizeof(alarmRisingThreshOid)/sizeof(oid);
#endif

Export oid nullOid[] = {0,0};
Export int nullOidLen = sizeof(nullOid)/sizeof(oid);
Export oid sysUpTimeOid[] = {1,3,6,1,2,1,1,3,0};
Export int sysUpTimeOidLen = sizeof(sysUpTimeOid)/sizeof(oid);
#ifdef USING_V2PARTY_EVENT_MODULE
Export oid eventIdOid[] = {SNMPV2EVENTENTRY, EVENTTABID};
Export int eventIdOidLen = sizeof(eventIdOid)/sizeof(oid);
Export oid trapRisingAlarmOid[] = {SNMPV2ALARMEVENTS, 1};
Export int trapRisingAlarmOidLen = sizeof(trapRisingAlarmOidLen)/sizeof(oid);
Export oid trapFallingAlarmOid[] = {SNMPV2ALARMEVENTS, 2};
Export int trapFallingAlarmOidLen = sizeof(trapFallingAlarmOidLen)/sizeof(oid);
Export oid trapObjUnavailAlarmOid[] = {SNMPV2ALARMEVENTS, 3};
Export int trapObjUnavailAlarmOidLen = sizeof(trapObjUnavailAlarmOidLen)/sizeof(oid);
#endif

struct subtree *subtrees;   /* this is now set up in
                                      read_config.c */

struct subtree subtrees_old[] = {
#include "mibgroup/mib_module_loads.h"
};

#ifdef USING_V2PARTY_VIEW_VARS_MODULE
extern int in_view __P((oid *, int, int));
#endif

int subtree_old_size __P((void)) {
  return (sizeof(subtrees_old)/ sizeof(struct subtree));
}

/* register_mib(char *moduleName, struct variable *, int varsize,
                int numvars, oid mibloc, int mibloclen)
 */
void
register_mib(moduleName, var, varsize, numvars, mibloc, mibloclen)
  char *moduleName;
  struct variable *var;
  int varsize;
  int numvars;
  oid *mibloc;
  int mibloclen;
{
  struct subtree *subtree;
  char c_oid[MAX_NAME_LEN];

  subtree = (struct subtree *) malloc(sizeof(struct subtree));
  memset(subtree, 0, sizeof(struct subtree));

  if (snmp_get_do_debugging()) {
    sprint_objid(c_oid, mibloc, mibloclen);
    DEBUGP ("registering \"%s\" at %s\n", moduleName, c_oid);
  }
    
  memcpy(subtree->name, mibloc, mibloclen*sizeof(oid));
  memcpy(subtree->label, moduleName, strlen(moduleName)+1);
  subtree->namelen = (u_char) mibloclen;
  subtree->variables = (struct variable *) malloc(varsize*numvars);
  memcpy(subtree->variables, var, numvars*varsize);
  subtree->variables_len = numvars;
  subtree->variables_width = varsize;
  load_subtree(subtree);
}

/* unregister_mib(oid mibloc, int mibloclen)
 */
void
unregister_mib(name, len)
  oid *name;
  int len;
{
  unregister_mib_tree(name, len, subtrees);
}

struct subtree *
unregister_mib_tree(name, len, subtree)
  oid *name;
  int len;
  struct subtree *subtree;
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
free_subtree(st)
  struct subtree *st;
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

/* in_a_view: determines if a given packet_info is allowed to see a
   given name/namelen OID pointer */

static int
in_a_view(name, namelen, pi, cvp)
  struct packet_info *pi;   /* IN - relevant auth info re PDU */
  struct variable	*cvp; /* IN - relevant auth info re mib module */
  oid		*name;	    /* IN - name of var, OUT - name matched */
  int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
{
  /* check for v1 and counter64s, since snmpv1 doesn't support it */
  if (pi->version == SNMP_VERSION_1 && cvp->type == ASN_COUNTER64)
    return 0;
  return (
#ifdef USING_V2PARTY_VIEW_VARS_MODULE
#define GOT_A_VIEW_CHECK
    /* check against the older v2party view support */
    (pi->version == SNMP_VERSION_2p &&
     in_view(name, *namelen, pi->cxp->contextViewIndex)) ||
#endif
#ifdef USING_MIBII_VACM_VARS_MODULE
#define GOT_A_VIEW_CHECK
    /* check against the snmpv3 VACM support */
    (vacm_in_view(pi, name, *namelen)) ||
#endif
#ifndef GOT_A_VIEW_CHECK
    /* no support at all for views?  Ick!
       Oh well, default to allowing access to everyone then. */
    1
#else
    0  /* needed for end of || clauses above */
#endif
    );
}


/*
 * getStatPtr - return a pointer to the named variable, as well as it's
 * type, length, and access control list.
 * Now uses 'search_subtree' (recursively) and 'search_subtree_vars'
 * to do most of the work
 *
 * If an exact match for the variable name exists, it is returned.  If not,
 * and exact is false, the next variable lexicographically after the
 * requested one is returned.
 *
 * If no appropriate variable can be found, NULL is returned.
 */
static  int 		found;

static u_char *
search_subtree_vars(tp, name, namelen, type, len, acl, exact, write_method, pi,
	   noSuchObject)
    struct subtree *tp;
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    int	       (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    struct packet_info *pi; /* IN - relevant auth info re PDU */
    int		*noSuchObject;
{
    register struct variable *vp;
    struct variable	compat_var, *cvp = &compat_var;
    register int	x;
    register u_char	*access = NULL;
    int			result;
    oid 		*suffix;
    int			suffixlen;

	    if ( tp->variables == NULL )
		return NULL;

	    result = compare_tree(name, *namelen, tp->name, (int)tp->namelen);
	    suffixlen = *namelen - tp->namelen;
	    suffix = name + tp->namelen;
	    /* the following is part of the setup for the compatability
	       structure below that has been moved out of the main loop.
	     */
	    memcpy(cvp->name, tp->name, tp->namelen * sizeof(oid));

	    for(x = 0, vp = tp->variables; x < tp->variables_len;
		vp =(struct variable *)((char *)vp +tp->variables_width), x++){
		/* if exact and ALWAYS
		   if next  and result >= 0 */
                /* and if vp->namelen != 0   -- Wes */
		if (vp->namelen && (exact || result >= 0)){
		    result = compare_tree(suffix, suffixlen, vp->name,
				     (int)vp->namelen);
		}
		/* if exact and result == 0
		   if next  and result <= 0 */
                /* or if vp->namelen == 0    -- Wes */
		if ((!exact && (result <= 0)) || (exact && (result == 0)) ||
                  vp->namelen == 0) {
		    /* builds an old (long) style variable structure to retain
		       compatability with var_* functions written previously.
		     */
                  if (vp->namelen)
                    memcpy((cvp->name + tp->namelen),
			  vp->name, vp->namelen * sizeof(oid));
		    cvp->namelen = tp->namelen + vp->namelen;
		    cvp->type = vp->type;
		    cvp->magic = vp->magic;
		    cvp->acl = vp->acl;
		    cvp->findVar = vp->findVar;
                    *write_method = NULL;
		    access = (*(vp->findVar))(cvp, name, namelen, exact,
						  len, write_method);
		    if (*write_method)
			*acl = cvp->acl;
                    /* check for permission to view this part of the OID tree */
		    if ((access != NULL || (*write_method != NULL && exact)) &&
                        !in_a_view(name, namelen, pi, cvp)) {
                        access = NULL;
			*write_method = NULL;
		    } else if (exact){
			found = TRUE;
		    }
		    /* this code is incorrect if there is
		       a view configuration that exludes a particular
		       instance of a variable.  It would return noSuchObject,
		       which would be an error */
		    if (access != NULL || (*write_method != NULL && exact))
			break;
		}
		/* if exact and result <= 0 */
		if (exact && (result  <= 0)){
	            *type = cvp->type;
		    *acl = cvp->acl;
		    if (found)
                      *noSuchObject = FALSE;
		    else
                      *noSuchObject = TRUE;
		    return NULL;
		}
	    }
	    if (access != NULL || (exact && *write_method != NULL)) {
	        *type = cvp->type;
		*acl = cvp->acl;
		return access;
	    }
	    return NULL;
}

static u_char *
search_subtree(sub_tp, name, namelen, type, len, acl, exact, write_method, pi,
	   noSuchObject)
    struct subtree *sub_tp;
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    int	       (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    struct packet_info *pi; /* IN - relevant auth info re PDU */
    int		*noSuchObject;
{
    struct subtree *tp;

    u_char *this_return, *child_return;
    oid     this_name[MAX_NAME_LEN];
    oid     child_name[MAX_NAME_LEN];
    int     this_namelen, child_namelen;
    u_char  this_type,    child_type;
    int     this_len,     child_len,    compare_len;
    u_short this_acl,     child_acl;
    int     this_NoObj,   child_NoObj;
    int     **this_write __P((int, u_char *, u_char, int, u_char *, oid *, int));
    int     **child_write __P((int, u_char *, u_char, int, u_char *, oid *, int));
 

    if ( sub_tp == NULL )
	return NULL;

    tp = sub_tp->children;

		/*
		 * Consider the simple cases first:
		 */
			/* No children, so use local info only */
    if ( tp == NULL )
	return( search_subtree_vars( sub_tp, name, namelen,
		type, len, acl, exact, write_method, pi, noSuchObject));

    while ( tp != NULL ) {
	compare_len = MIN( tp->namelen, *namelen );
	if ( snmp_oid_compare(tp->name, compare_len, name, compare_len) >= 0 )
	    break;
	tp = tp->next;
    }

			/* No relevant children, so as above */
    if ( tp == NULL )
	return( search_subtree_vars( sub_tp, name, namelen,
		type, len, acl, exact, write_method, pi, noSuchObject));

			/* No local info, so children or nothing */
    if ( sub_tp->variables == NULL ) {
	while ( tp != NULL ) {
	    child_return = search_subtree( tp, name, namelen,
			type, len, acl, exact, write_method, pi, noSuchObject);
	    if ( child_return != NULL || (exact && write_method != NULL))
		return child_return;
	    else
		tp = tp->next;
	}
	return NULL;	/* Nothing left */
    }


		/*
		 *   This leaves the situation where both
		 * the current node, and children could
		 * potentially answer the query.
		 *   We need to ask both, and compare answers.
		 */

			/* First set up copies of the name requested,
				so one query doesn't affect the other */
	memcpy(this_name, name, *namelen * sizeof(oid));
	this_namelen = *namelen;
	memcpy(child_name, name, *namelen * sizeof(oid));
	child_namelen = *namelen;

			/* Ask the current node */
	this_return = search_subtree_vars( sub_tp,
		this_name, &this_namelen,
		&this_type, &this_len, &this_acl, exact,
		write_method, pi, &this_NoObj);

			/* This answer is the best we'll get, so use it */
	if ( this_return != NULL &&
	     ( exact ||
	       snmp_oid_compare( this_name, this_namelen, tp->name, tp->namelen) < 0 )) {
		*namelen = this_namelen;
		memcpy(name, this_name, *namelen * sizeof(oid));
		*type = this_type;
		*len  = this_len;
		*acl  = this_acl;
	/*	*write_method = *this_write;	*/
		*noSuchObject = this_NoObj;
		return this_return;
	}

			/* Ask the children until we get an answer */
	child_return=NULL;
	while ( child_return == NULL) {
	    child_return = search_subtree( tp,
		child_name, &child_namelen,
		&child_type, &child_len, &child_acl, exact,
		write_method, pi, &child_NoObj);
	    tp = tp->next;

			/* Only one possibly relevant subtree */
	    if ( exact || tp == NULL  ||
			/* or 'this' answer is better than remaining children */
		( this_return != NULL && child_return == NULL &&
		  snmp_oid_compare( tp->name, tp->namelen, this_name, this_namelen) > 0 ))
			break;
	}

			/* If one answer is still NULL, use the other .. */
	if ( this_return == NULL && child_return == NULL ) {
		return NULL;
	}
	else if ( this_return == NULL ) {
		*namelen = child_namelen;
		memcpy(name, child_name, *namelen * sizeof(oid));
		*type = child_type;
		*len  = child_len;
		*acl  = child_acl;
	/*	*write_method = child_write;	*/
		*noSuchObject = child_NoObj;
		return child_return;
	}
	else if ( child_return == NULL ) {
		*namelen = this_namelen;
		memcpy(name, this_name, *namelen * sizeof(oid));
		*type = this_type;
		*len  = this_len;
		*acl  = this_acl;
	/*	*write_method = this_write;	*/
		*noSuchObject = this_NoObj;
		return this_return;
	}
			/* else use the minimum of the two (non-NULL) answers */
	else
	if ( snmp_oid_compare( this_name, this_namelen,
		      child_name, child_namelen) > 0 ) {
		*namelen = child_namelen;
		memcpy(name, child_name, *namelen * sizeof(oid));
		*type = child_type;
		*len  = child_len;
		*acl  = child_acl;
	/*	*write_method = child_write;	*/
		*noSuchObject = child_NoObj;
		return child_return;
	}
	else {
		*namelen = this_namelen;
		memcpy(name, this_name, *namelen * sizeof(oid));
		*type = this_type;
		*len  = this_len;
		*acl  = this_acl;
	/*	*write_method = this_write;	*/
		*noSuchObject = this_NoObj;
		return this_return;
	}
}

u_char	*
getStatPtr(name, namelen, type, len, acl, exact, write_method, pi,
	   noSuchObject)
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    int	       (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    struct packet_info *pi; /* IN - relevant auth info re PDU */
    int		*noSuchObject;
{
    register struct subtree	*tp;
    oid			save[MAX_NAME_LEN];
    int			savelen = 0;
    u_char              result_type;
    u_short             result_acl;
    u_char              *search_return=NULL;

    found = FALSE;

    if (!exact){
	memcpy(save, name, *namelen * sizeof(oid));
	savelen = *namelen;
    }
    *write_method = NULL;
    for (tp = subtrees; tp != NULL ; tp = tp->next ) {
	search_return = search_subtree( tp, name, namelen, &result_type,
		len, &result_acl, exact, write_method, pi, noSuchObject);
	if ( search_return != NULL || (*write_method != NULL && exact))
	    break;
    }
    if ( tp == NULL ) {
	if (!search_return && !exact){
	    memcpy(name, save, savelen * sizeof(oid));
	    *namelen = savelen;
	}
	if (found)
	    *noSuchObject = FALSE;
	else
	    *noSuchObject = TRUE;
        return NULL;
    }
    *type = result_type;
    *acl =  result_acl;
    return search_return;
}

/*
{
  *write_method = NULL;
  for(tp = first; tp < end; tp = next){
      if ((in matches tp) or (in < tp)){
	  inlen -= tp->length;
	  for(vp = tp->vp; vp < end; vp = next){
	      if ((in < vp) || (exact && (in == vp))){
		  cobble up compatable vp;
		  call findvar;
		  if (it returns nonzero)
		      break both loops;
	      }
	      if (exact && (in < vp)) ???
		  return NULL;
	  }
      }      
  }
}
*/

static int
compare_tree(name1, len1, name2, len2)
    register oid	    *name1, *name2;
    register int	    len1, len2;
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

struct subtree *find_subtree_next(name, len, subtree)
  oid *name;
  int len;
  struct subtree *subtree;
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

struct subtree *find_subtree(name, len, subtree)
  oid *name;
  int len;
  struct subtree *subtree;
{
  struct subtree *myptr;

  for(myptr = subtree; myptr != NULL; myptr = myptr->next) {
    if (snmp_oid_compare(name, len, myptr->name, myptr->namelen) == 0)
      return myptr;
  }
  return NULL;
}
