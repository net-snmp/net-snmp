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

#include "mibgroup/snmpv2_vars.h"

#include "acl.h"

#define OIDCMP(l1, l2, o1, o2) (((l1) == (l2)) \
				&& !bcmp((char *)(o1), (char *)(o2), \
					 (l1)*sizeof(oid)))

#define ACLTARGET_MASK		0x01
#define ACLSUBJECT_MASK	        0x02
#define ACLRESOURCES_MASK	0x04
#define ACLPRIVILEGES_MASK	0x08
#define ACLSTORAGETYPE_MASK	0x10
#define ACLSTATUS_MASK		0x20

#define ACLCOMPLETE_MASK	0x3F /* all columns */

struct aclEntry *acl_rowCreate __P((int, int, int));
void acl_rowDelete __P((int, int, int));

struct aclEntry *
acl_rowCreate(target, subject, resources)
    int target, subject, resources;
{
    struct aclEntry *ap;

    ap = acl_createEntry(target, subject, resources);
    ap->aclBitMask = 0;
    ap->reserved->aclStatus = ACLNONEXISTENT;

    ap->aclBitMask = ap->reserved->aclBitMask =
	ACLTARGET_MASK | ACLSUBJECT_MASK;
    /* Watch out for this becoming permanent by accident:
     * If during FREE stage below we discover row didn't exist before,
     * free row.
     */
    return ap;
}

void
acl_rowDelete(target, subject, resources)
    int target, subject, resources;
{
    acl_destroyEntry(target, subject, resources);
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and ap is non-NULL, the instance exists, but not this variable.
 * If statP is NULL and ap is NULL, then neither this instance nor the variable exists.
 */
int
write_acl(action, var_val, var_val_type, var_val_len, statP, name, length)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      length;
{
    struct aclEntry *ap, *rp;
    int var, targetlen, subjectlen;
    oid *target, *subject;
    long val;
    int bigsize = 1000;

/*
 * This routine handles requests for variables of the form:
 * .iso.org.dod.internet.snmpSecrets.partyAccess.aclTable.aclEntry.X.oidlen.oid.oidlen.oid
 * or .1.3.6.1.2.1.21.2.1.1.X.oidlen.oid.oidlen.oid, where the oid suffixes are
 * variable length.
 * Therefore, the length of the first index is name[11] and the index starts
 * at name[12].  The length of the second index starts at name[12 + name[11]],
 * and the second index starts at name[13 + name[1]].
 */
    if (length < 16)
	return SNMP_ERR_NOCREATION;
    var = name[10];
    targetlen = name[11];
    target = name + 12;
    if (length <= 12 + targetlen)
	return SNMP_ERR_NOCREATION;
    subjectlen = name[12 + targetlen];
    subject = name + 13 + targetlen;
    if (length != 13 + targetlen + subjectlen)
	return SNMP_ERR_NOCREATION;
    /* XXX are these length checks necessary?  If not, take them out of
       here and party_vars.c */

    ap = acl_getEntry(target, targetlen, subject, subjectlen);
    if (ap)
	rp = ap->reserved;
    if (action == RESERVE1 && !ap){
	if ((ap = acl_rowCreate(target, targetlen,
				subject, subjectlen)) == NULL)
	    return SNMP_ERR_RESOURCEUNAVAILABLE;
	rp = ap->reserved;
	/* create default vals here in reserve area */
	rp->aclPriveleges = ACLPRIVELEGESGET | ACLPRIVELEGESGETNEXT;
	rp->aclStatus = ACLACTIVE;
	rp->aclBitMask = ACLCOMPLETE_MASK;
    } else if (action == COMMIT){
	if (ap->aclStatus == ACLNONEXISTENT){
	    /* commit the default vals */
	    /* This haapens at most once per entry because the status is set to
	       valid after the first pass.  After that, this commit code
	       does not get executed.  It is also important to note that this
	       gets executed before any of the commits below (and never after
	       them), so they overlay their data on top of these defaults.
	       This commit code should allow for the object specific code
	       to have overlayed data after the code above has executed.
	      */
	    ap->aclPriveleges = rp->aclPriveleges;
	    ap->aclStatus = rp->aclStatus;
	    ap->aclBitMask = rp->aclBitMask;
	}
    } else if (action == FREE){
	if (ap && ap->aclStatus == ACLNONEXISTENT){
	    acl_rowDelete(target, targetlen, subject, subjectlen);
	    ap = rp = NULL;
	}
	if (ap)	/* satisfy postcondition for bitMask */
	    rp->aclBitMask = ap->aclBitMask;
    }

/* XXX !!! check return values from the asn_parse_* routines */
    switch(var){
      case ACLPRIVELEGES:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 0 || val > 31)
		return SNMP_ERR_WRONGVALUE;
	    rp->aclPriveleges = val;
	    rp->aclBitMask |= ACLPRIVILEGES_MASK;
	} else if (action == COMMIT){
	    ap->aclPriveleges = rp->aclPriveleges;
	}
	break;
      case ACLSTATUS:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 2)
		return SNMP_ERR_WRONGVALUE;
	    rp->aclStatus = val;
	    rp->aclBitMask |= ACLSTATUS_MASK;
	} else if (action == RESERVE2){
	    if ((rp->aclStatus == ACLACTIVE)
		&& (rp->aclBitMask != ACLCOMPLETE_MASK))
		return SNMP_ERR_INCONSISTENTVALUE;
	    /* tried to set incomplete row valid */
	} else if (action == COMMIT){
	    ap->aclStatus = rp->aclStatus;
	} else if (action == ACTION && ap->aclStatus == ACLDESTROY){
		acl_rowDelete(ap->aclTarget, ap->aclSubject, ap->aclResources);
	}
	break;
      case ACLTARGET:
      case ACLSUBJECT:
      default:
	    return SNMP_ERR_NOCREATION;
    }
    if (action == COMMIT)	/* make any new columns aapear */
	ap->aclBitMask = rp->aclBitMask;

    return SNMP_ERR_NOERROR;
}

u_char *
var_acl(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid *name;      /* IN/OUT - input name requested, output name found */
    register int *length;    /* IN/OUT - length of input and output oid's */
    int          exact;      /* IN - TRUE if an exact match was requested. */
    int          *var_len;   /* OUT - length of variable or 0 if function returned. */
    int          (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    oid newname[MAX_NAME_LEN], lowname[MAX_NAME_LEN], *np;
    int newnamelen, lownamelen;
    struct aclEntry *ap, *lowap = NULL;
    u_long mask;
    int target, subject, resources;

/*
 * This routine handles requests for variables of the form:
 *
 * .iso.org.dod.internet.snmpV2.snmpModules.partyMIB.partyMIBObjects
 * .snmpAccess.aclTable.aclEntry.X.tgt.sub.res
 * or .1.3.6.1.6.3.3.2.3.1.1.X.sub.tgt.res
 * Therefore, the target is at name[12], the subject is at name[13], and
 * the resources is at name[14].
 */

    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    if (exact){
        if (*length != 15 ||
	    bcmp((char *)name, (char *)vp->name, 12 * sizeof(oid)))
	    return NULL;
	target = name[12];
	subject = name[13];
	resources = name[14];
    	*write_method = write_acl;
        ap = acl_getEntry(target, subject, resources);
	if (ap == NULL)
	    return NULL;
	if (!(ap->aclBitMask & mask))
	    return NULL;
    } else {
      /* find "next" control entry */
      acl_scanInit();
      for(ap = acl_scanNext(); ap; ap = acl_scanNext()){
	if (!(ap->aclBitMask & mask))
	    continue;
	np = newname + 12;
	*np++ = ap->aclTarget;
	*np++ = ap->aclSubject;
	*np = ap->aclResources;
	newnamelen = 15;
	if ((compare(newname, newnamelen, name, *length) > 0) &&
	    (!lowap || compare(newname, newnamelen,
			       lowname, lownamelen) < 0)){
	    /*
	     * if new one is greater than input and closer to input than
	     * previous lowest, save this one as the "next" one.
	     */
	    bcopy((char *)newname, (char *)lowname, newnamelen * sizeof(oid));
	    lownamelen = newnamelen;
	    lowap = ap;
	}
      }
      if (lowap == NULL)
	  return NULL;
      ap = lowap;
      bcopy((char *)lowname, (char *)name, lownamelen * sizeof(oid));
      *length = lownamelen;
    }

    *var_len = sizeof(long);
    long_return = 0;

    switch (vp->magic){
      case ACLPRIVELEGES:
	return (u_char *)&ap->aclPriveleges;
      case ACLSTORAGETYPE:
	return (u_char *)&ap->aclStorageType;
      case ACLSTATUS:
	return (u_char *)&ap->aclStatus;
      default:
            ERROR("");
    }
    return NULL;
}

