#include <config.h>

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

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_vars.h"

#include "view_vars.h"

#define OIDCMP(l1, l2, o1, o2) (((l1) == (l2)) \
				&& !bcmp((char *)(o1), (char *)(o2), \
					 (l1)*sizeof(oid)))

#define VIEWINDEX_MASK		0x01
#define VIEWSUBTREE_MASK	0x02
#define VIEWMASK_MASK		0x04
#define VIEWTYPE_MASK		0x08
#define VIEWSTORAGETYPE_MASK	0x10
#define VIEWSTATUS_MASK		0x20

#define VIEWCOMPLETE_MASK	0x3F /* all columns */

struct viewEntry *view_rowCreate __P((int, oid *, int));
void view_rowDelete __P((int, oid *, int));
int in_view __P((oid *, int, int));


struct viewEntry *
view_rowCreate(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    struct viewEntry *vp;

    if (viewSubtreeLen > 32)
	return NULL;
    vp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
    vp->viewBitMask = 0;
    vp->reserved->viewStatus = VIEWNONEXISTENT;

    vp->viewBitMask = vp->reserved->viewBitMask =
	VIEWINDEX_MASK | VIEWSUBTREE_MASK;
    /* Watch out for this becoming permanent by accident:
     * If during FREE stage below we discover row didn't exist before,
     * free row.
     */
    return vp;
}

void
view_rowDelete(viewIndex, viewSubtree, viewSubtreeLen)
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
{
    view_destroyEntry(viewIndex, viewSubtree, viewSubtreeLen);
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and vp is non-NULL, the instance exists, but not this
 * variable.
 * If statP is NULL and vp is NULL, then neither this instance nor the
 * variable exists.
 */
int
write_view(action, var_val, var_val_type, var_val_len, statP, name, length)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      length;
{
#if 0
    struct viewEntry *vp, *rp;
    int var, size, viewSubtreeLen;
    int viewIndex;
    oid *viewSubtree;
    long val;
    int bigsize = 1000;

/*
 * This routine handles requests for variables of the form:
 * .iso.org.dod.internet.snmpV2.snmpModules.partyMIB.partyMIBObjects
 * .snmpViews.viewTable.viewEntry.X.viewIndex.oidlen.oid,
 * or .1.3.6.1.6.3.3.2.4.1.1.X.viewIndex.oidlen.oid
 * where the oid suffix is variable length.
 * Therefore, the first index is name[12].  The length of the second
 * index starts at name[13], and the second index starts at name[14].
 */
    if (length < 14)
	return SNMP_ERR_NOCREATION;
    var = name[11];
    viewIndex = name[12];
    viewSubtreeLen = name[13];
    viewSubtree = name + 14;
    if (length != 14 + viewSubtreeLen)
	return SNMP_ERR_NOCREATION;
    /* XXX are these length checks necessary?  If not, take them out of
       here and party_vars.c */

    vp = view_getEntry(viewIndex, viewSubtree, viewSubtreeLen);
    if (vp)
	rp = vp->reserved;
    if (action == RESERVE1 && !vp){
	if ((vp = view_rowCreate(viewIndex,
				 viewSubtree, viewSubtreeLen)) == NULL)
	    return SNMP_ERR_RESOURCEUNAVAILABLE;
	rp = vp->reserved;
	/* create default vals here in reserve area */
	rp->viewType = VIEWINCLUDED;
	rp->viewMaskLen = 0;
	rp->viewBitMask = VIEWCOMPLETE_MASK;
    } else if (action == COMMIT){
	if (vp->viewStatus == VIEWNONEXISTENT){
	    /* commit the default vals */
	    /* This havpens at most once per entry because the status is set to
	       valid after the first pass.  After that, this commit code
	       does not get executed.  It is also important to note that this
	       gets executed before any of the commits below (and never after
	       them), so they overlay their data on top of these defaults.
	       This commit code should allow for the object specific code
	       to have overlayed data after the code above has executed.
	      */
	    vp->viewMaskLen = rp->viewMaskLen;
	    bcopy(rp->viewMask, vp->viewMask, rp->viewMaskLen);
	    vp->viewStatus = rp->viewStatus;
	    vp->viewBitMask = rp->viewBitMask;
	}
    } else if (action == FREE){
	if (vp && vp->viewStatus == VIEWNONEXISTENT){
	    view_rowDelete(viewParty, viewPartyLen,
			   viewSubtree, viewSubtreeLen);
	    vp = rp = NULL;
	}
	if (vp)	/* satisfy postcondition for bitMask */
	    rp->viewBitMask = vp->viewBitMask;
    }

/* XXX !!! check return values from the asn_parse_* routines */
    switch(var){
      case VIEWMASK:
        if (action == RESERVE1){
            if (var_val_type != ASN_OCTET_STR)
                return SNMP_ERR_WRONGTYPE;
            size = sizeof(rp->viewMask);
            asn_parse_string(var_val, &bigsize, &var_val_type,
                             rp->viewMask, &size);
            rp->viewMaskLen = size;
            if (size > 16)
                return SNMP_ERR_WRONGVALUE;
            rp->viewBitMask |= VIEWMASK_MASK;
        } else if (action == COMMIT){
            vp->viewMaskLen = rp->viewMaskLen;
            bcopy(rp->viewMask, vp->viewMask, vp->viewMaskLen);
        }
	break;
      case VIEWSTATUS:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 3)
		return SNMP_ERR_WRONGVALUE;
	    rp->viewStatus = val;
	    rp->viewBitMask |= VIEWSTATUS_MASK;
	} else if (action == RESERVE2){
	    if ((rp->viewType == VIEWINCLUDED
		 || rp->viewType == VIEWEXCLUDED)
		&& (rp->viewBitMask != VIEWCOMPLETE_MASK))
		return SNMP_ERR_INCONSISTENTVALUE;
	    /* tried to set incomplete row valid */
	} else if (action == COMMIT){
	    vp->viewStatus = rp->viewStatus;
	} else if (action == ACTION && vp->viewStatus == VIEWINVALID){
		view_rowDelete(vp->viewParty, vp->viewPartyLen,
			      vp->viewSubtree, vp->viewSubtreeLen);
	}
	break;
      case VIEWPARTY:
      case VIEWSUBTREE:
      default:
	    return SNMP_ERR_NOCREATION;
    }
    if (action == COMMIT)	/* make any new columns avpear */
	vp->viewBitMask = rp->viewBitMask;

#endif
    return TRUE;
}

u_char *
var_view(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid *name;      /* IN/OUT - input name requested, output name found */
    register int *length;    /* IN/OUT - length of input and output oid's */
    int          exact;      /* IN - TRUE if an exact match was requested. */
    int          *var_len;   /* OUT - length of variable or 0 if function returned. */
    int          (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    oid newname[MAX_NAME_LEN], lowname[MAX_NAME_LEN], *np;
    int newnamelen, lownamelen;
    struct viewEntry *vwp, *lowvwp = NULL;
    u_long mask;
    oid *viewSubtree;
    int viewIndex, viewSubtreeLen;
/*
 * This routine handles requests for variables of the form:
 * .iso.org.dod.internet.snmpV2.snmpModules.partyMIB.partyMIBObjects
 * .snmpViews.viewTable.viewEntry.X.viewIndex.oid,
 * or .1.3.6.1.6.3.3.2.4.1.1.X.viewIndex.oid
 * where the oid suffix is variable length.
 * Therefore, the first index is name[12], and the second index starts
 * at name[13].
 */
    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    if (exact){
        if (*length < 14 ||
	    bcmp((char *)name, (char *)vp->name, 12 * sizeof(oid)))
	    return NULL;
	viewIndex = name[12];
	viewSubtreeLen = *length - 13;
	viewSubtree = name + 13;
	if (*length != 13 + viewSubtreeLen)
	    return NULL;
    	*write_method = write_view;
        vwp = view_getEntry(viewIndex, viewSubtree, viewSubtreeLen);
	if (vwp == NULL)
	    return NULL;
	if (!(vwp->viewBitMask & mask))
	    return NULL;
    } else {
      /* find "next" control entry */
      view_scanInit();
      for(vwp = view_scanNext(); vwp; vwp = view_scanNext()){
	if (!(vwp->viewBitMask & mask))
	    continue;
	np = newname + 12;
	*np++ = vwp->viewIndex;
	bcopy((char *)vwp->viewSubtree, (char *)np,
	      vwp->viewSubtreeLen * sizeof(oid));
	newnamelen = 13 + vwp->viewSubtreeLen;
	if ((compare(newname, newnamelen, name, *length) > 0) &&
	    (!lowvwp || compare(newname, newnamelen,
			       lowname, lownamelen) < 0)){
	    /*
	     * if new one is greater than input and closer to input than
	     * previous lowest, save this one as the "next" one.
	     */
	    bcopy((char *)newname, (char *)lowname, newnamelen * sizeof(oid));
	    lownamelen = newnamelen;
	    lowvwp = vwp;
	}
      }
      if (lowvwp == NULL)
	  return NULL;
      vwp = lowvwp;
      bcopy((char *)lowname, (char *)name, lownamelen * sizeof(oid));
      *length = lownamelen;
    }

    *var_len = sizeof(long);
    long_return = 0;

    switch (vp->magic){
      case VIEWMASK:
	*var_len = vwp->viewMaskLen;
	return (u_char *)vwp->viewMask;
      case VIEWTYPE:
	return (u_char *)&vwp->viewType;
      case VIEWSTORAGETYPE:
	return (u_char *)&vwp->viewStorageType;
      case VIEWSTATUS:
	return (u_char *)&vwp->viewStatus;
      default:
            ERROR_MSG("");
    }
    return NULL;
}

int
in_view(name, namelen, viewIndex)
    oid *name;
    int namelen, viewIndex;
{
    struct viewEntry *vwp, *savedvwp = NULL;

    view_scanInit();
    for(vwp = view_scanNext(); vwp; vwp = view_scanNext()){
	if (vwp->viewIndex != viewIndex || vwp->viewStatus != VIEWACTIVE)
	    continue;
	if (vwp->viewSubtreeLen > namelen
	    || bcmp(vwp->viewSubtree, name, vwp->viewSubtreeLen * sizeof(oid)))
	    continue;
	/* no wildcards here yet */
	if (!savedvwp){
	    savedvwp = vwp;
	} else {
	    if (vwp->viewSubtreeLen > savedvwp->viewSubtreeLen)
		savedvwp = vwp;
/*
	    else if (vwp->viewSubtreeLen == savedvwp->viewSubtreeLen
		     && greater(vwp->viewSubtree, savedvwp->viewSubtree))
		savedvwp = vwp;
 */
		
	}
    }
    if (!savedvwp)
	return FALSE;
    if (savedvwp->viewType == VIEWINCLUDED)
	return TRUE;
    return FALSE;
}
