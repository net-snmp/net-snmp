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
#include "common_header.h"
#include "mibgroup/mib_module_includes.h"

#include "snmpd.h"
#include "party.h"
#include "context.h"

int compare_tree __P((oid *, int, oid *, int));
extern struct subtree subtrees_old[];

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
 
#ifndef linux
void
init_nlist(nl)
  struct nlist nl[];
{
  int ret;
#if HAVE_KVM_OPENFILES
  kvm_t *kernel;
  char kvm_errbuf[4096];

  if((kernel = kvm_openfiles(KERNEL_LOC, NULL, NULL, O_RDONLY, kvm_errbuf)) == NULL) {
      perror("kvm_openfiles");
      exit(1);
  }
  if ((ret = kvm_nlist(kernel, nl)) == -1) {
      perror("kvm_nlist");
      exit(1);
  }
  kvm_close(kernel);
#else
  if ((ret = nlist(KERNEL_LOC,nl)) == -1) {
    perror("nlist");
    exit(1);
  }
#endif
  for(ret = 0; nl[ret].n_name != NULL; ret++) {
      if (nl[ret].n_type == 0) {
#ifdef DODEBUG
	  DEBUGP1("nlist err:  %s not found\n",nl[ret].n_name);
      } else {
	  fprintf(stderr, "nlist: %s 0x%X\n", nl[ret].n_name,
		  (unsigned int)nl[ret].n_value);
#endif
      }
  }
}
#endif

void
init_snmp __P((void))
{
#ifndef linux
  init_kmem("/dev/kmem"); 
#endif

#include "mibgroup/mib_module_inits.h"
}

#ifndef linux
int KNLookup(nl, nl_which, buf, s)
    struct nlist nl[];
    int nl_which;
    char *buf;
    int s;
{   struct nlist *nlp = &nl[nl_which];

    if (nlp->n_value == 0) {
        fprintf (stderr, "Accessing non-nlisted variable: %s\n", nlp->n_name);
	nlp->n_value = -1;	/* only one error message ... */
	return 0;
    }
    if (nlp->n_value == -1)
        return 0;

    return klookup(nlp->n_value, buf, s);
}
#endif


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
#ifdef USING_ALARM_MODULE
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
#ifdef USING_EVENT_MODULE
Export oid eventIdOid[] = {SNMPV2EVENTENTRY, EVENTTABID};
Export int eventIdOidLen = sizeof(eventIdOid)/sizeof(oid);
Export oid trapRisingAlarmOid[] = {SNMPV2ALARMEVENTS, 1};
Export int trapRisingAlarmOidLen = sizeof(trapRisingAlarmOidLen)/sizeof(oid);
Export oid trapFallingAlarmOid[] = {SNMPV2ALARMEVENTS, 2};
Export int trapFallingAlarmOidLen = sizeof(trapFallingAlarmOidLen)/sizeof(oid);
Export oid trapObjUnavailAlarmOid[] = {SNMPV2ALARMEVENTS, 3};
Export int trapObjUnavailAlarmOidLen = sizeof(trapObjUnavailAlarmOidLen)/sizeof(oid);
#endif


struct subtree *subtrees;   /* this is now malloced in
                                      mibgroup/extensible.c */

struct subtree subtrees_old[] = {
#include "mibgroup/mib_module_loads.h"
};

#ifdef USING_VIEW_VARS_MODULE
extern int in_view __P((oid *, int, int));
#endif

int subtree_old_size() {
  return (sizeof(subtrees_old)/ sizeof(struct subtree));
}

/*
 * getStatPtr - return a pointer to the named variable, as well as it's
 * type, length, and access control list.
 *
 * If an exact match for the variable name exists, it is returned.  If not,
 * and exact is false, the next variable lexicographically after the
 * requested one is returned.
 *
 * If no appropriate variable can be found, NULL is returned.
 */
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
    register struct variable *vp;
    struct variable	compat_var, *cvp = &compat_var;
    register int	x;
    int			y;
    register u_char	*access = NULL;
    int			result, treeresult;
    oid 		*suffix;
    int			suffixlen;
    int 		found = FALSE;
    oid			save[MAX_NAME_LEN];
    int			savelen = 0;
#ifdef USING_PASS_MODULE
    extern int numrelocs, numpassthrus;
#endif

    if (!exact){
	bcopy(name, save, *namelen * sizeof(oid));
	savelen = *namelen;
    }
    *write_method = NULL;
    for (y = 0, tp = subtrees; y < (subtree_old_size()
#ifdef USING_PASS_MODULE
                                    + numrelocs + numpassthrus
#endif
      ); tp++, y++){
	treeresult = compare_tree(name, *namelen, tp->name, (int)tp->namelen);
	/* if exact and treeresult == 0
	   if next  and treeresult <= 0 */
	if (treeresult == 0 || (!exact && treeresult < 0)){
	    result = treeresult;
	    suffixlen = *namelen - tp->namelen;
	    suffix = name + tp->namelen;
	    /* the following is part of the setup for the compatability
	       structure below that has been moved out of the main loop.
	     */
	    bcopy((char *)tp->name, (char *)cvp->name,
		  tp->namelen * sizeof(oid));

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
                    bcopy((char *)vp->name, (char *)(cvp->name + tp->namelen),
			  vp->namelen * sizeof(oid));
		    cvp->namelen = tp->namelen + vp->namelen;
		    cvp->type = vp->type;
		    cvp->magic = vp->magic;
		    cvp->acl = vp->acl;
		    cvp->findVar = vp->findVar;
		    access = (*(vp->findVar))(cvp, name, namelen, exact,
						  len, write_method);
		    if (write_method)
			*acl = cvp->acl;
		    if (access &&
                        (
#ifdef USING_VIEW_VARS_MODULE
                          ((pi->version == SNMP_VERSION_2p) &&
                           !in_view(name, *namelen, pi->cxp->contextViewIndex)) ||
#endif
                         ((pi->version == SNMP_VERSION_1 ||
                           pi->version == SNMP_VERSION_2c) &&
                          (((cvp->acl & 0xAFFC) == SNMPV2ANY) ||
                            (cvp->acl & 0xAFFC) == SNMPV2AUTH)) ||
                          ((pi->version == SNMP_VERSION_2p) &&
                          ((cvp->acl & 0xAFFC) == SNMPV2AUTH) &&
                          (pi->srcp->partyAuthProtocol == NOAUTH ||
                           pi->dstp->partyAuthProtocol == NOAUTH)))) {
                      access = NULL;
			*write_method = NULL;
			/*
			  if (in_view(vp->name, vp->namelen,
			      pi->dstParty, pi->dstPartyLength)
			      found = TRUE;
			 */
		    } else if (exact){
			found = TRUE;
		    }
		    /* this code is incorrect if there is
		       a view configuration that exludes a particular
		       instance of a variable.  It would return noSuchObject,
		       which would be an error */
		    if (access != NULL)
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
	    if (access != NULL)
		break;
	}
    }
    if (y == (subtree_old_size()
#ifdef USING_PASS_MODULE
              + numrelocs + numpassthrus
#endif
      )) {
	if (!access && !exact){
	    bcopy(save, name, savelen * sizeof(oid));
	    *namelen = savelen;
	}
	if (found)
	    *noSuchObject = FALSE;
	else
	    *noSuchObject = TRUE;
        return NULL;
    }
    /* vp now points to the approprate struct */
    *type = cvp->type;
    *acl = cvp->acl;
    return access;
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

int
compare(name1, len1, name2, len2)
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
    if (len2 < len1)
	return 1;
    return 0;	/* both strings are equal */
}

int
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
