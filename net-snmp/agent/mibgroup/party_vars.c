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
#include "system.h"

#include "acl.h"
#include "view.h"

#include "party_vars.h"

oid snmpUdpDomain[] = {1, 3, 6, 1, 6, 1, 1};
/* no others defined yet */

static oid noAuth[] = {1, 3, 6, 1, 6, 3, 3, 1, 1, 1};
static oid snmpv2MD5AuthProt[] = {1, 3, 6, 1, 6, 3, 3, 1, 1, 4};

static oid noPriv[] = {1, 3, 6, 1, 6, 3, 3, 1, 1, 2};
static oid dESPrivProt[] = {1, 3, 6, 1, 6, 3, 3, 1, 1, 3};

#define OIDCMP(l1, l2, o1, o2) (((l1) == (l2)) \
				&& !bcmp((char *)(o1), (char *)(o2), \
					 (l1)*sizeof(oid)))

#define PARTYIDENTITY_MASK		0x0001
#define PARTYINDEX_MASK			0x0002
#define PARTYTDOMAIN_MASK		0x0004
#define PARTYTADDRESS_MASK		0x0008
#define PARTYMAXMESSAGESIZE_MASK	0x0010
#define PARTYLOCAL_MASK			0x0020
#define PARTYAUTHPROTOCOL_MASK		0x0040
#define PARTYAUTHCLOCK_MASK		0x0080
#define PARTYAUTHPRIVATE_MASK		0x0100
#define PARTYAUTHPUBLIC_MASK		0x0200
#define PARTYAUTHLIFETIME_MASK		0x0400
#define PARTYPRIVPROTOCOL_MASK		0x0800
#define PARTYPRIVPRIVATE_MASK		0x1000
#define PARTYPRIVPUBLIC_MASK		0x2000
#define PARTYSTORAGETYPE_MASK		0x4000
#define PARTYSTATUS_MASK		0x8000

#define PARTYCOMPLETE_MASK		0xFFFF	/* all collumns */

struct partyEntry *
party_rowCreate(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    struct partyEntry *pp;

    if (partyIDLen > 32)
	return NULL;
    pp = party_createEntry(partyID, partyIDLen);
    pp->partyBitMask = 0;
    pp->partyStatus = pp->reserved->partyStatus = PARTYNONEXISTENT;

    pp->partyBitMask = pp->reserved->partyBitMask =
	PARTYINDEX_MASK | PARTYSTATUS_MASK;
    /* Watch out for this becoming permanent by accident:
     * If during FREE stage below we discover row didn't exist before,
     * free row.
     */
    return pp;
}

void
party_rowDelete(partyID, partyIDLen)
    oid *partyID;
    int partyIDLen;
{
    party_destroyEntry(partyID, partyIDLen);
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and pp is non-NULL, the instance exists, but not this
 * variable.
 * If statP is NULL and pp is NULL, then neither this instance nor the
 * variable exists.
 */
int
write_party(action, var_val, var_val_type, var_val_len, statP, name, length)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      length;
{
    struct partyEntry *pp, *rp;
    int var, indexlen, len;
    oid *index;
    long val;
    oid buf[32];
    int bigsize = 1000, size;
    struct aclEntry *ap;
    struct viewEntry *vp;
    u_long myaddr;
    
    if (length < 13)  /* maybe this should be 15 to guarantee oidlength >= 2 */
	return SNMP_ERR_NOCREATION;  
    var = name[11];
    indexlen = name[12];
    index = name + 13;
    if (length != 13 + indexlen)
	return SNMP_ERR_NOCREATION;

    pp = party_getEntry(index, indexlen);
    if (pp)
	rp = pp->reserved;
    if (action == RESERVE1 && !pp){
	if ((pp = party_rowCreate(index, indexlen)) == NULL)
	    return SNMP_ERR_RESOURCEUNAVAILABLE;
	rp = pp->reserved;
	/* create default vals here in reserve area
	 * partyIndex is automatically defval'd by party_createEntry().
         */
	rp->partyTDomain = DOMAINSNMPUDP;
	bzero((char *)rp->partyTAddress, 6);
	rp->partyTAddressLen = 6;
	rp->partyMaxMessageSize = 484;
	rp->partyLocal = 2; /* FALSE */
	rp->partyAuthProtocol = NOAUTH;
	rp->partyAuthClock = 0;
	rp->partyAuthPrivateLen = 0;
	rp->partyAuthPublicLen = 0;
	rp->partyAuthLifetime = 300;
	rp->partyPrivProtocol = NOPRIV;
	rp->partyPrivPrivateLen = 0;
	rp->partyPrivPublicLen = 0;
	rp->partyStorageType = 2; /* volatile */
	rp->partyStatus = PARTYACTIVE;
	rp->partyBitMask = PARTYCOMPLETE_MASK ^ PARTYLOCAL_MASK; /* XXX */
    } else if (action == COMMIT){
	if (pp->partyStatus == PARTYNONEXISTENT){
	    /* commit the default vals */
	    /* This happens at most once per entry because the status is set to
	       valid after the first pass.  After that, this commit code
	       does not get executed.  It is also important to note that this
	       gets executed before any of the commits below (and never after
	       them), so they overlay their data on top of these defaults.
	       This commit code should allow for the object specific code
	       to have overlayed data after the code above has executed.
	      */
	    pp->partyTDomain = rp->partyTDomain;
	    bcopy(rp->partyTAddress, pp->partyTAddress, rp->partyTAddressLen);
	    pp->partyTAddressLen = rp->partyTAddressLen;
	    pp->partyMaxMessageSize = rp->partyMaxMessageSize;
	    pp->partyLocal = rp->partyLocal;
	    pp->partyAuthProtocol = rp->partyAuthProtocol;
	    pp->partyAuthClock = rp->partyAuthClock;
	    gettimeofday(&pp->tv, (struct timezone *)0);
	    pp->tv.tv_sec -= pp->partyAuthClock;
	    pp->partyAuthPrivateLen = rp->partyAuthPrivateLen;
	    pp->partyAuthPublicLen = rp->partyAuthPublicLen;
	    pp->partyAuthLifetime = rp->partyAuthLifetime;
	    pp->partyPrivProtocol = rp->partyPrivProtocol;
	    pp->partyPrivPrivateLen = rp->partyPrivPrivateLen;
	    pp->partyPrivPublicLen = rp->partyPrivPublicLen;
	    pp->partyStorageType = rp->partyStorageType;
	    pp->partyStatus = rp->partyStatus;
	    pp->partyBitMask = rp->partyBitMask;
	    
	}
    } else if (action == FREE){
	if (pp && pp->partyStatus == PARTYNONEXISTENT){
	    party_rowDelete(index, indexlen);
	    pp = rp = NULL;
	}
	if (pp)	/* satisfy postcondition for bitMask */
	    rp->partyBitMask = pp->partyBitMask;
    }

/* XXX !!! check return values from the asn_parse_* routines */
    switch(var){
      case PARTYTDOMAIN:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(snmpUdpDomain)/sizeof(oid), buf,
		       snmpUdpDomain)){
		rp->partyTDomain = DOMAINSNMPUDP;
		rp->partyBitMask |= PARTYTDOMAIN_MASK;
	    } else {
		return SNMP_ERR_WRONGVALUE;
	    }
	} else if (action == COMMIT){
	    pp->partyTDomain = rp->partyTDomain;
	}
	break;
      case PARTYTADDRESS:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->partyTAddress);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->partyTAddress, &size);
	    rp->partyTAddressLen = size;
	    /* if other TDomains were possible, it would be necessary to
	       check the size in the reserve2 phase to see if it was
	       consistent with the TDomain.
	       Also: what if TAddr is changed to a local party: consider
	       implications for MaxMessageSize.
	     */
	    if (size != 6)
		return SNMP_ERR_WRONGLENGTH;
	    rp->partyBitMask |= PARTYTADDRESS_MASK;
	} else if (action == COMMIT){
	    pp->partyTAddressLen = rp->partyTAddressLen;
	    bcopy(rp->partyTAddress, pp->partyTAddress, pp->partyTAddressLen);
	}
	break;
      case PARTYMAXMESSAGESIZE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 484 || val > 65507)
		return SNMP_ERR_WRONGVALUE;
	    rp->partyMaxMessageSize = val;
	    rp->partyBitMask |= PARTYMAXMESSAGESIZE_MASK;
	} else if (action == RESERVE2){
	    myaddr = get_myaddr();
	    if ((rp->partyTDomain == DOMAINSNMPUDP)
		&& !bcmp((char *)&myaddr, rp->partyTAddress, 4)){
		/* party is local */
		/* 1500 should be constant in snmp_impl.h */
		if (rp->partyMaxMessageSize > 1500)
		    return SNMP_ERR_INCONSISTENTVALUE;
	    }
	} else if (action == COMMIT){
	    pp->partyMaxMessageSize = rp->partyMaxMessageSize;
	}
	break;
      case PARTYLOCAL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 2)
		return SNMP_ERR_WRONGVALUE;
	    rp->partyLocal = val;
	    rp->partyBitMask |= PARTYLOCAL_MASK;
	} else if (action == RESERVE2){
	    myaddr = get_myaddr();
	    if (val == 1 && (rp->partyTDomain == DOMAINSNMPUDP)
		&& bcmp((char *)&myaddr, rp->partyTAddress, 4)){
		/* this is an attempt to set this party local with a
		   remote IP address */
		    return SNMP_ERR_INCONSISTENTVALUE;
	    }
	} else if (action == COMMIT){
	    pp->partyLocal = rp->partyLocal;
	}
	break;
      case PARTYAUTHPROTOCOL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(noAuth)/sizeof(oid), buf, noAuth)){
		rp->partyAuthProtocol = NOAUTH;
	    } else if (OIDCMP(size, sizeof(snmpv2MD5AuthProt)/sizeof(oid), buf,
			      snmpv2MD5AuthProt)){
		rp->partyAuthProtocol = SNMPV2MD5AUTHPROT;
	    } else {
		/* no other currently defined */
		return SNMP_ERR_WRONGVALUE ;
	    }
	    rp->partyBitMask |= PARTYAUTHPROTOCOL_MASK;
	} else if (action == COMMIT){
	    pp->partyAuthProtocol = rp->partyAuthProtocol;
	}
	break;
      case PARTYAUTHCLOCK:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    rp->partyAuthClock = val;
	    rp->partyBitMask |= PARTYAUTHCLOCK_MASK;
	} else if (action == COMMIT){
	    pp->partyAuthClock = rp->partyAuthClock;
	    gettimeofday(&pp->tv, (struct timezone *)0);
	    pp->tv.tv_sec -= pp->partyAuthClock;
	}
	break;
      case PARTYAUTHPRIVATE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->partyAuthPrivate);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->partyAuthPrivate, &size);
	    rp->partyAuthPrivateLen = size;
	    if (size > 16)
		return SNMP_ERR_WRONGLENGTH;
	    rp->partyBitMask |= PARTYAUTHPRIVATE_MASK;
	} else if (action == COMMIT){
	    if (!(pp->partyBitMask & PARTYAUTHPRIVATE_MASK))
		pp->partyAuthPrivateLen = 0;
	    for(len = 0; (len < pp->partyAuthPrivateLen)
		&& (len < rp->partyAuthPrivateLen); len++){
		pp->partyAuthPrivate[len] ^=
		    rp->partyAuthPrivate[len];
	    }
	    while(len < rp->partyAuthPrivateLen)
		pp->partyAuthPrivate[len] =
		    rp->partyAuthPrivate[len];
	    pp->partyAuthPrivateLen = rp->partyAuthPrivateLen;
	}
	break;
      case PARTYAUTHPUBLIC:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->partyAuthPublic);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->partyAuthPublic, &size);
	    rp->partyAuthPublicLen = size;
	    if (size > 32)
		return SNMP_ERR_WRONGLENGTH;
	    rp->partyBitMask |= PARTYAUTHPUBLIC_MASK;
	} else if (action == COMMIT){
	    pp->partyAuthPublicLen = rp->partyAuthPublicLen;
	    bcopy((char *)rp->partyAuthPublic,
		  (char *)pp->partyAuthPublic, pp->partyAuthPublicLen);
	}
	break;
      case PARTYAUTHLIFETIME:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    /* what range should I check for ???
	    if (val < 1 || val > 3600)
		return SNMP_ERR_WRONGVALUE;
	    */
	    rp->partyAuthLifetime = val;
	    rp->partyBitMask |= PARTYAUTHLIFETIME_MASK;
	} else if (action == COMMIT){
	    pp->partyAuthLifetime = rp->partyAuthLifetime;
	}
	break;
      case PARTYPRIVPROTOCOL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(noPriv)/sizeof(oid), buf, noPriv)){
		rp->partyPrivProtocol = NOPRIV;
	    } else if (OIDCMP(size, sizeof(dESPrivProt)/sizeof(oid), buf,
			      dESPrivProt)){
		rp->partyPrivProtocol = DESPRIVPROT;
	    } else {
		/* no other currently defined */
		return SNMP_ERR_WRONGVALUE;
	    }
	    rp->partyBitMask |= PARTYPRIVPROTOCOL_MASK;
	} else if (action == COMMIT){
	    pp->partyPrivProtocol = rp->partyPrivProtocol;
	}
	break;
      case PARTYPRIVPRIVATE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->partyPrivPrivate);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->partyPrivPrivate, &size);
	    rp->partyPrivPrivateLen = size;
	    if (size > 16)
		return SNMP_ERR_WRONGLENGTH;
	    rp->partyBitMask |= PARTYPRIVPRIVATE_MASK;
	} else if (action == COMMIT){
	    if (!(pp->partyBitMask & PARTYPRIVPRIVATE_MASK))
		pp->partyPrivPrivateLen = 0;
	    for(len = 0; (len < pp->partyPrivPrivateLen)
		&& (len < rp->partyPrivPrivateLen); len++){
		pp->partyPrivPrivate[len] ^=
		    rp->partyPrivPrivate[len];
	    }
	    while(len < rp->partyPrivPrivateLen)
		pp->partyPrivPrivate[len] =
		    rp->partyPrivPrivate[len];
	    pp->partyPrivPrivateLen = rp->partyPrivPrivateLen;
	}
	break;
      case PARTYPRIVPUBLIC:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->partyPrivPublic);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->partyPrivPublic, &size);
	    rp->partyPrivPublicLen = size;
	    if (size > 32)
		return SNMP_ERR_WRONGLENGTH;
	    rp->partyBitMask |= PARTYPRIVPUBLIC_MASK;
	} else if (action == COMMIT){
	    bcopy((char *)rp->partyPrivPublic, (char *)pp->partyPrivPublic,
		  rp->partyPrivPublicLen);
	    pp->partyPrivPublicLen = rp->partyPrivPublicLen;
	}
	break;
      case PARTYSTORAGETYPE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 4)
		return SNMP_ERR_WRONGVALUE;
	    if (val != 2) /* above is as per MIB,
			     this is implementation specific */
		return SNMP_ERR_WRONGVALUE;
	    rp->partyStorageType = val;
	    rp->partyBitMask |= PARTYSTORAGETYPE_MASK;
	} else if (action == COMMIT){
	    pp->partyStorageType = rp->partyStorageType;
	}
	break;
      case PARTYSTATUS: /* read-write access */
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 6 || val == 3)
		return SNMP_ERR_WRONGVALUE;
	    rp->partyStatus = val;
	    rp->partyBitMask |= PARTYSTATUS_MASK;
	} else if (action == RESERVE2){
	    if (((rp->partyStatus == PARTYCREATEANDGO)
		|| (rp->partyStatus == PARTYCREATEANDWAIT))
		&& (pp->partyStatus != PARTYNONEXISTENT))
		return SNMP_ERR_INCONSISTENTVALUE;
	    if (((rp->partyStatus == PARTYACTIVE)
		|| (rp->partyStatus == PARTYNOTINSERVICE))
		&& (pp->partyStatus == PARTYNONEXISTENT))
		return SNMP_ERR_INCONSISTENTVALUE;
	    if (((rp->partyStatus == PARTYACTIVE)
		 || (rp->partyStatus == PARTYNOTINSERVICE))
		&& (rp->partyBitMask != PARTYCOMPLETE_MASK))
		return SNMP_ERR_INCONSISTENTVALUE;
	    /* tried to set incomplete row valid */
	} else if (action == COMMIT){
	    if (rp->partyStatus == PARTYCREATEANDGO)
		rp->partyStatus = PARTYACTIVE;
	    if (rp->partyStatus == PARTYCREATEANDWAIT)
		rp->partyStatus = PARTYNOTINSERVICE;
	    pp->partyStatus = rp->partyStatus;
	} else if (action == ACTION && pp->partyStatus == PARTYDESTROY){
	    /* delete all related acl entries */
#if 0
	    acl_scanInit();
	    ap = acl_scanNext();
	    do {
		for(; ap; ap = acl_scanNext()){
		    if ((ap->aclTargetLen == pp->partyIdentityLen
			 && !bcmp(ap->aclTarget, pp->partyIdentity,
				  ap->aclTargetLen * sizeof(oid)))
			|| (ap->aclSubjectLen == pp->partyIdentityLen
			    && !bcmp(ap->aclSubject, pp->partyIdentity,
				     ap->aclSubjectLen * sizeof(oid)))){
			acl_destroyEntry(ap->aclTarget, ap->aclTargetLen,
					 ap->aclSubject, ap->aclSubjectLen);
			acl_scanInit();
			ap = acl_scanNext();
			break;
			/* ap is still set, so we'll start over again */
		    }
		}
	    } while (ap);
	    /* delete all related view entries */
	    view_scanInit();
	    vp = view_scanNext();
	    do {
		for(; vp; vp = view_scanNext()){
		    if (vp->viewPartyLen == pp->partyIdentityLen
			&& !bcmp(vp->viewParty, pp->partyIdentity,
				 vp->viewPartyLen * sizeof(oid))){
			view_destroyEntry(vp->viewParty, vp->viewPartyLen,
					  vp->viewSubtree, vp->viewSubtreeLen);
			view_scanInit();
			vp = view_scanNext();
			break;
			/* vp is still set, so we'll start over again */
		    }
		}
	    } while (vp);
#endif		
		
	    /* then delete the party itself */
	    party_rowDelete(pp->partyIdentity, pp->partyIdentityLen);
	}
	/* if action and party created and it is local, open up new
	 * listening port, if appropriate.
	 */
	break;
      case PARTYIDENTITY:
      default:
	    return SNMP_ERR_NOCREATION;
    }
    if (action == COMMIT)	/* make any new collumns appear */
	pp->partyBitMask = rp->partyBitMask;

    return SNMP_ERR_NOERROR;
}

u_char *
var_party(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid *name;      /* IN/OUT - input name requested, output name found */
    register int *length;    /* IN/OUT - length of input and output oid's */
    int          exact;      /* IN - TRUE if an exact match was requested. */
    int          *var_len;   /* OUT - length of variable or 0 if function returned. */
    int          (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    oid newname[MAX_NAME_LEN], lowname[MAX_NAME_LEN];
    int newnamelen, lownamelen;
    struct partyEntry *pp, *lowpp = NULL;
    u_long mask;
    struct timeval now;
/*
 * This routine handles requests for variables of the form:

 * .iso.org.dod.internet.snmpV2.snmpModules.partyMIB.partyMIBObjects
 * .snmpParties.partyTable.partyEntry.X.oid
 * or .1.3.6.1.6.3.3.2.1.1.1.X.oid, where the oid suffix is
 * variable length
 * Therefore, the index starts at name[12].
 */

    mask = 1 << (vp->magic - 1);
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    if (exact){
        if (*length < 13 ||
	    bcmp((char *)name, (char *)vp->name, 11 * sizeof(oid)))
	    return NULL;
    	*write_method = write_party;
        pp = party_getEntry(name + 12, *length - 12);
	if (pp == NULL)
	    return NULL;
	if (!(pp->partyBitMask & mask))
	    return NULL;
    } else {
      /* find "next" control entry */
      party_scanInit();
      for(pp = party_scanNext(); pp; pp = party_scanNext()){
	if (!(pp->partyBitMask & mask))
	    continue;
	bcopy((char *)pp->partyIdentity, (char *)(newname + 12),
	      pp->partyIdentityLen * sizeof(oid));
	newnamelen = 12 + pp->partyIdentityLen;
	if ((compare(newname, newnamelen, name, *length) > 0) &&
	    (!lowpp || compare(newname, newnamelen,
			       lowname, lownamelen) < 0)){
	    /*
	     * if new one is greater than input and closer to input than
	     * previous lowest, save this one as the "next" one.
	     */
	    bcopy((char *)newname, (char *)lowname, newnamelen * sizeof(oid));
	    lownamelen = newnamelen;
	    lowpp = pp;
	}
      }
      if (lowpp == NULL)
	  return NULL;
      pp = lowpp;
      bcopy((char *)lowname, (char *)name, lownamelen * sizeof(oid));
      *length = lownamelen;
    }

    *var_len = sizeof(long);
    long_return = 0;

    switch (vp->magic){
      case PARTYINDEX:
	return (u_char *)&pp->partyIndex;
      case PARTYTDOMAIN:
	if (pp->partyTDomain == DOMAINSNMPUDP){
	    *var_len = sizeof(snmpUdpDomain);
	    return (u_char *)snmpUdpDomain;
	} else {
	    ERROR_MSG("");
	    return NULL;
	}
      case PARTYTADDRESS:
	*var_len = pp->partyTAddressLen;
	return (u_char *)pp->partyTAddress;
      case PARTYMAXMESSAGESIZE:
	return (u_char *)&pp->partyMaxMessageSize;
      case PARTYLOCAL:
	return (u_char *)&pp->partyLocal;
      case PARTYAUTHPROTOCOL:
	if (pp->partyAuthProtocol == SNMPV2MD5AUTHPROT){
	    *var_len = sizeof(snmpv2MD5AuthProt);
	    return (u_char *)snmpv2MD5AuthProt;
	} else if (pp->partyAuthProtocol == NOAUTH){ /* noAuth */
	    *var_len = sizeof(noAuth);
	    return (u_char *)noAuth;
	} else {
	    ERROR_MSG("");
	    return NULL;
	}
      case PARTYAUTHCLOCK:
	gettimeofday(&now, (struct timezone *)0);
	long_return = (u_long) now.tv_sec - pp->tv.tv_sec;
	return (u_char *)&long_return;
      case PARTYAUTHPRIVATE:
	*var_len = 0;  /* zero length return value */
	return (u_char *)pp->partyIdentity;  /* dummy pointer */
      case PARTYAUTHPUBLIC:
	*var_len = pp->partyAuthPublicLen;
	return (u_char *)pp->partyAuthPublic;
      case PARTYAUTHLIFETIME:
	return (u_char *)&pp->partyAuthLifetime;
      case PARTYPRIVPROTOCOL:
	if (pp->partyPrivProtocol == DESPRIVPROT){
	    *var_len = sizeof(dESPrivProt);
	    return (u_char *)dESPrivProt;
	} else if (pp->partyPrivProtocol == NOPRIV){ /* noPriv */
	    *var_len = sizeof(noPriv);
	    return (u_char *)noPriv;
	}
	/*NOTREACHED*/
      case PARTYPRIVPRIVATE:
	*var_len = 0;	/* zero length return value */
	return (u_char *)pp->partyIdentity;	/* dummy pointer */
      case PARTYPRIVPUBLIC:
	*var_len = pp->partyPrivPublicLen;
	return (u_char *)pp->partyPrivPublic;
      case PARTYCLONEFROM:
	*var_len = 8;
	bzero(return_buf, 8);
	return (u_char *)return_buf;
      case PARTYSTORAGETYPE:
	return (u_char *)&pp->partyStorageType;
      case PARTYSTATUS:
	if (pp->partyStatus == PARTYNOTINSERVICE
	    && pp->partyBitMask != PARTYCOMPLETE_MASK){
	    long_return = PARTYNOTREADY;
	    return (u_char *)&long_return;
	}
	return (u_char *)&pp->partyStatus;
      default:
            ERROR_MSG("");
    }
    return NULL;
}
