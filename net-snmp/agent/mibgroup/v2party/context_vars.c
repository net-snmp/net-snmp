#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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
#include <netinet/in.h>

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_vars.h"
#include "system.h"

#include "acl.h"
#include "view.h"

#include "context_vars.h"

static oid currentTime[] = {1, 3, 6, 1, 6, 3, 3, 1, 2, 1};
static oid restartTime[] = {1, 3, 6, 1, 6, 3, 3, 1, 2, 2};

#define OIDCMP(l1, l2, o1, o2) (((l1) == (l2)) \
				&& !memcmp((char *)(o1), (char *)(o2), \
					 (l1)*sizeof(oid)))

#define CONTEXTIDENTITY_MASK		0x0001
#define CONTEXTINDEX_MASK		0x0002
#define CONTEXTVIEWINDEX_MASK		0x0004
#define CONTEXTLOCALENTITY_MASK		0x0008
#define CONTEXTLOCALTIME_MASK		0x0010
#define CONTEXTDSTPARTYINDEX_MASK	0x0020
#define CONTEXTSRCPARTYINDEX_MASK	0x0040
#define CONTEXTPROXYCONTEXT_MASK	0x0080
#define CONTEXTSTORAGETYPE_MASK		0x0100
#define CONTEXTSTATUS_MASK		0x0200

#define CONTEXTCOMPLETE_MASK		0x03FF	/* all collumns */

struct contextEntry *
context_rowCreate(oid *contextID, int contextIDLen)
{
    struct contextEntry *cp;

    if (contextIDLen > 32)
	return NULL;
    cp = context_createEntry(contextID, contextIDLen);
    cp->contextBitMask = 0;
    cp->contextStatus = cp->reserved->contextStatus = SNMP_ROW_NONEXISTENT;

    cp->contextBitMask = cp->reserved->contextBitMask =
	CONTEXTINDEX_MASK | CONTEXTSTATUS_MASK;
    /* Watch out for this becoming permanent by accident:
     * If during FREE stage below we discover row didn't exist before,
     * free row.
     */
    return cp;
}

void
context_rowDelete(oid *contextID, int contextIDLen)
{
    context_destroyEntry(contextID, contextIDLen);
}

/*
 * If statP is non-NULL, the referenced object is at that location.
 * If statP is NULL and cp is non-NULL, the instance exists, but not this
 * variable.
 * If statP is NULL and cp is NULL, then neither this instance nor the
 * variable exists.
 */
int
write_context(int action,
	      u_char *var_val,
	      u_char var_val_type,
	      int var_val_len,
	      u_char *statP,
	      oid *name,
	      int length)
{
#if 0
    struct contextEntry *cp, *rp;
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

    cp = context_getEntry(index, indexlen);
    if (cp)
	rp = cp->reserved;
    if (action == RESERVE1 && !cp){
	if ((cp = context_rowCreate(index, indexlen)) == NULL)
	    return SNMP_ERR_RESOURCEUNAVAILABLE;
	rp = cp->reserved;
	/* create default vals here in reserve area
	 * contextIndex is automatically defval'd by context_createEntry().
         */
	rp->contextTDomain = DOMAINSNMPUDP;
	memset((char *)rp->contextTAddress, 0, 6);
	rp->contextTAddressLen = 6;
	rp->contextMaxMessageSize = 484;
	rp->contextLocal = 2; /* FALSE */
	rp->contextAuthProtocol = NOAUTH;
	rp->contextAuthClock = 0;
	rp->contextAuthPrivateLen = 0;
	rp->contextAuthPublicLen = 0;
	rp->contextAuthLifetime = 300;
	rp->contextPrivProtocol = NOPRIV;
	rp->contextPrivPrivateLen = 0;
	rp->contextPrivPublicLen = 0;
	rp->contextStorageType = 2; /* volatile */
	rp->contextStatus = SNMP_ROW_ACTIVE;
	rp->contextBitMask = CONTEXTCOMPLETE_MASK ^ CONTEXTLOCAL_MASK; /* XXX */
    } else if (action == COMMIT){
	if (cp->contextStatus == SNMP_ROW_NONEXISTENT){
	    /* commit the default vals */
	    /* This hacpens at most once per entry because the status is set to
	       valid after the first pass.  After that, this commit code
	       does not get executed.  It is also important to note that this
	       gets executed before any of the commits below (and never after
	       them), so they overlay their data on top of these defaults.
	       This commit code should allow for the object specific code
	       to have overlayed data after the code above has executed.
	      */
	    cp->contextTDomain = rp->contextTDomain;
	    memcpy(cp->contextTAddress, rp->contextTAddress, rp->contextTAddressLen);
	    cp->contextTAddressLen = rp->contextTAddressLen;
	    cp->contextMaxMessageSize = rp->contextMaxMessageSize;
	    cp->contextLocal = rp->contextLocal;
	    cp->contextAuthProtocol = rp->contextAuthProtocol;
	    cp->contextAuthClock = rp->contextAuthClock;
	    gettimeofday(&cp->tv, (struct timezone *)0);
	    cp->tv.tv_sec -= cp->contextAuthClock;
	    cp->contextAuthPrivateLen = rp->contextAuthPrivateLen;
	    cp->contextAuthPublicLen = rp->contextAuthPublicLen;
	    cp->contextAuthLifetime = rp->contextAuthLifetime;
	    cp->contextPrivProtocol = rp->contextPrivProtocol;
	    cp->contextPrivPrivateLen = rp->contextPrivPrivateLen;
	    cp->contextPrivPublicLen = rp->contextPrivPublicLen;
	    cp->contextStorageType = rp->contextStorageType;
	    cp->contextStatus = rp->contextStatus;
	    cp->contextBitMask = rp->contextBitMask;
	    
	}
    } else if (action == FREE){
	if (cp && cp->contextStatus == SNMP_ROW_NONEXISTENT){
	    context_rowDelete(index, indexlen);
	    cp = rp = NULL;
	}
	if (cp)	/* satisfy postcondition for bitMask */
	    rp->contextBitMask = cp->contextBitMask;
    }

/* XXX !!! check return values from the asn_parse_* routines */
    switch(var){
      case CONTEXTTDOMAIN:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(snmpUdpDomain)/sizeof(oid), buf,
		       snmpUdpDomain)){
		rp->contextTDomain = DOMAINSNMPUDP;
		rp->contextBitMask |= CONTEXTTDOMAIN_MASK;
	    } else {
		return SNMP_ERR_WRONGVALUE;
	    }
	} else if (action == COMMIT){
	    cp->contextTDomain = rp->contextTDomain;
	}
	break;
      case CONTEXTTADDRESS:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->contextTAddress);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->contextTAddress, &size);
	    rp->contextTAddressLen = size;
	    /* if other TDomains were possible, it would be necessary to
	       check the size in the reserve2 phase to see if it was
	       consistent with the TDomain.
	       Also: what if TAddr is changed to a local context: consider
	       implications for MaxMessageSize.
	     */
	    if (size != 6)
		return SNMP_ERR_WRONGLENGTH;
	    rp->contextBitMask |= CONTEXTTADDRESS_MASK;
	} else if (action == COMMIT){
	    cp->contextTAddressLen = rp->contextTAddressLen;
	    memcpy(cp->contextTAddress, rp->contextTAddress, cp->contextTAddressLen);
	}
	break;
      case CONTEXTMAXMESSAGESIZE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 484 || val > 65507)
		return SNMP_ERR_WRONGVALUE;
	    rp->contextMaxMessageSize = val;
	    rp->contextBitMask |= CONTEXTMAXMESSAGESIZE_MASK;
	} else if (action == RESERVE2){
	    myaddr = get_myaddr();
	    if ((rp->contextTDomain == DOMAINSNMPUDP)
		&& !memcmp((char *)&myaddr, rp->contextTAddress, 4)){
		/* context is local */
		/* 1500 should be constant in snmp_impl.h */
		if (rp->contextMaxMessageSize > 1500)
		    return SNMP_ERR_INCONSISTENTVALUE;
	    }
	} else if (action == COMMIT){
	    cp->contextMaxMessageSize = rp->contextMaxMessageSize;
	}
	break;
      case CONTEXTLOCAL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 2)
		return SNMP_ERR_WRONGVALUE;
	    rp->contextLocal = val;
	    rp->contextBitMask |= CONTEXTLOCAL_MASK;
	} else if (action == RESERVE2){
	    myaddr = get_myaddr();
	    if (val == 1 && (rp->contextTDomain == DOMAINSNMPUDP)
		&& memcmp((char *)&myaddr, rp->contextTAddress, 4)){
		/* this is an attempt to set this context local with a
		   remote IP address */
		    return SNMP_ERR_INCONSISTENTVALUE;
	    }
	} else if (action == COMMIT){
	    cp->contextLocal = rp->contextLocal;
	}
	break;
      case CONTEXTAUTHPROTOCOL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(noAuth)/sizeof(oid), buf, noAuth)){
		rp->contextAuthProtocol = NOAUTH;
	    } else if (OIDCMP(size, sizeof(snmpv2MD5AuthProt)/sizeof(oid), buf,
			      snmpv2MD5AuthProt)){
		rp->contextAuthProtocol = SNMPV2MD5AUTHPROT;
	    } else {
		/* no other currently defined */
		return SNMP_ERR_WRONGVALUE ;
	    }
	    rp->contextBitMask |= CONTEXTAUTHPROTOCOL_MASK;
	} else if (action == COMMIT){
	    cp->contextAuthProtocol = rp->contextAuthProtocol;
	}
	break;
      case CONTEXTAUTHCLOCK:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    rp->contextAuthClock = val;
	    rp->contextBitMask |= CONTEXTAUTHCLOCK_MASK;
	} else if (action == COMMIT){
	    cp->contextAuthClock = rp->contextAuthClock;
	    gettimeofday(&cp->tv, (struct timezone *)0);
	    cp->tv.tv_sec -= cp->contextAuthClock;
	}
	break;
      case CONTEXTAUTHPRIVATE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->contextAuthPrivate);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->contextAuthPrivate, &size);
	    rp->contextAuthPrivateLen = size;
	    if (size > 16)
		return SNMP_ERR_WRONGLENGTH;
	    rp->contextBitMask |= CONTEXTAUTHPRIVATE_MASK;
	} else if (action == COMMIT){
	    if (!(cp->contextBitMask & CONTEXTAUTHPRIVATE_MASK))
		cp->contextAuthPrivateLen = 0;
	    for(len = 0; (len < cp->contextAuthPrivateLen)
		&& (len < rp->contextAuthPrivateLen); len++){
		cp->contextAuthPrivate[len] ^=
		    rp->contextAuthPrivate[len];
	    }
	    while(len < rp->contextAuthPrivateLen)
		cp->contextAuthPrivate[len] =
		    rp->contextAuthPrivate[len];
	    cp->contextAuthPrivateLen = rp->contextAuthPrivateLen;
	}
	break;
      case CONTEXTAUTHPUBLIC:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->contextAuthPublic);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->contextAuthPublic, &size);
	    rp->contextAuthPublicLen = size;
	    if (size > 32)
		return SNMP_ERR_WRONGLENGTH;
	    rp->contextBitMask |= CONTEXTAUTHPUBLIC_MASK;
	} else if (action == COMMIT){
	    cp->contextAuthPublicLen = rp->contextAuthPublicLen;
	    memcpy(cp->contextAuthPublic, rp->contextAuthPublic,
		  cp->contextAuthPublicLen);
	}
	break;
      case CONTEXTAUTHLIFETIME:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    /* what range should I check for ???
	    if (val < 1 || val > 3600)
		return SNMP_ERR_WRONGVALUE;
	    */
	    rp->contextAuthLifetime = val;
	    rp->contextBitMask |= CONTEXTAUTHLIFETIME_MASK;
	} else if (action == COMMIT){
	    cp->contextAuthLifetime = rp->contextAuthLifetime;
	}
	break;
      case CONTEXTPRIVPROTOCOL:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OBJECT_ID)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(buf)/sizeof(oid);
	    asn_parse_objid(var_val, &bigsize, &var_val_type, buf, &size);
	    if (OIDCMP(size, sizeof(noPriv)/sizeof(oid), buf, noPriv)){
		rp->contextPrivProtocol = NOPRIV;
	    } else if (OIDCMP(size, sizeof(dESPrivProt)/sizeof(oid), buf,
			      dESPrivProt)){
		rp->contextPrivProtocol = DESPRIVPROT;
	    } else {
		/* no other currently defined */
		return SNMP_ERR_WRONGVALUE;
	    }
	    rp->contextBitMask |= CONTEXTPRIVPROTOCOL_MASK;
	} else if (action == COMMIT){
	    cp->contextPrivProtocol = rp->contextPrivProtocol;
	}
	break;
      case CONTEXTPRIVPRIVATE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->contextPrivPrivate);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->contextPrivPrivate, &size);
	    rp->contextPrivPrivateLen = size;
	    if (size > 16)
		return SNMP_ERR_WRONGLENGTH;
	    rp->contextBitMask |= CONTEXTPRIVPRIVATE_MASK;
	} else if (action == COMMIT){
	    if (!(cp->contextBitMask & CONTEXTPRIVPRIVATE_MASK))
		cp->contextPrivPrivateLen = 0;
	    for(len = 0; (len < cp->contextPrivPrivateLen)
		&& (len < rp->contextPrivPrivateLen); len++){
		cp->contextPrivPrivate[len] ^=
		    rp->contextPrivPrivate[len];
	    }
	    while(len < rp->contextPrivPrivateLen)
		cp->contextPrivPrivate[len] =
		    rp->contextPrivPrivate[len];
	    cp->contextPrivPrivateLen = rp->contextPrivPrivateLen;
	}
	break;
      case CONTEXTPRIVPUBLIC:
	if (action == RESERVE1){
	    if (var_val_type != ASN_OCTET_STR)
		return SNMP_ERR_WRONGTYPE;
	    size = sizeof(rp->contextPrivPublic);
	    asn_parse_string(var_val, &bigsize, &var_val_type,
			     rp->contextPrivPublic, &size);
	    rp->contextPrivPublicLen = size;
	    if (size > 32)
		return SNMP_ERR_WRONGLENGTH;
	    rp->contextBitMask |= CONTEXTPRIVPUBLIC_MASK;
	} else if (action == COMMIT){
	    memcpy(cp->contextPrivPublic,
		  rp->contextPrivPublic, rp->contextPrivPublicLen);
	    cp->contextPrivPublicLen = rp->contextPrivPublicLen;
	}
	break;
      case CONTEXTSTORAGETYPE:
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 4)
		return SNMP_ERR_WRONGVALUE;
	    if (val != 2) /* above is as per MIB,
			     this is implementation specific */
		return SNMP_ERR_WRONGVALUE;
	    rp->contextStorageType = val;
	    rp->contextBitMask |= CONTEXTSTORAGETYPE_MASK;
	} else if (action == COMMIT){
	    cp->contextStorageType = rp->contextStorageType;
	}
	break;
      case CONTEXTSTATUS: /* read-write access */
	if (action == RESERVE1){
	    if (var_val_type != ASN_INTEGER)
		return SNMP_ERR_WRONGTYPE;
	    asn_parse_int(var_val, &bigsize, &var_val_type, &val, sizeof(val));
	    if (val < 1 || val > 6 || val == 3)
		return SNMP_ERR_WRONGVALUE;
	    rp->contextStatus = val;
	    rp->contextBitMask |= CONTEXTSTATUS_MASK;
	} else if (action == RESERVE2){
	    if (((rp->contextStatus == SNMP_ROW_CREATEANDGO)
		|| (rp->contextStatus == SNMP_ROW_CREATEANDWAIT))
		&& (cp->contextStatus != SNMP_ROW_NONEXISTENT))
		return SNMP_ERR_INCONSISTENTVALUE;
	    if (((rp->contextStatus == SNMP_ROW_ACTIVE)
		|| (rp->contextStatus == SNMP_ROW_NOTINSERVICE))
		&& (cp->contextStatus == SNMP_ROW_NONEXISTENT))
		return SNMP_ERR_INCONSISTENTVALUE;
	    if (((rp->contextStatus == SNMP_ROW_ACTIVE)
		 || (rp->contextStatus == SNMP_ROW_NOTINSERVICE))
		&& (rp->contextBitMask != CONTEXTCOMPLETE_MASK))
		return SNMP_ERR_INCONSISTENTVALUE;
	    /* tried to set incomplete row valid */
	} else if (action == COMMIT){
	    if (rp->contextStatus == SNMP_ROW_CREATEANDGO)
		rp->contextStatus = SNMP_ROW_ACTIVE;
	    if (rp->contextStatus == SNMP_ROW_CREATEANDWAIT)
		rp->contextStatus = SNMP_ROW_NOTINSERVICE;
	    cp->contextStatus = rp->contextStatus;
	} else if (action == ACTION && cp->contextStatus == SNMP_ROW_DESTROY){
	    /* delete all related acl entries */
	    acl_scanInit();
	    ap = acl_scanNext();
	    do {
		for(; ap; ap = acl_scanNext()){
		    if ((ap->aclTargetLen == cp->contextIdentityLen
			 && !memcmp(ap->aclTarget, cp->contextIdentity,
				  ap->aclTargetLen * sizeof(oid)))
			|| (ap->aclSubjectLen == cp->contextIdentityLen
			    && !memcmp(ap->aclSubject, cp->contextIdentity,
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
		    if (vp->viewContextLen == cp->contextIdentityLen
			&& !memcmp(vp->viewContext, cp->contextIdentity,
				 vp->viewContextLen * sizeof(oid))){
			view_destroyEntry(vp->viewContext, vp->viewContextLen,
					  vp->viewSubtree, vp->viewSubtreeLen);
			view_scanInit();
			vp = view_scanNext();
			break;
			/* vp is still set, so we'll start over again */
		    }
		}
	    } while (vp);
		
	    /* then delete the context itself */
	    context_rowDelete(cp->contextIdentity, cp->contextIdentityLen);
	}
	/* if action and context created and it is local, open up new
	 * listening port, if acpropriate.
	 */
	break;
      case CONTEXTIDENTITY:
      default:
	    return SNMP_ERR_NOCREATION;
    }
    if (action == COMMIT)	/* make any new collumns acpear */
	cp->contextBitMask = rp->contextBitMask;

#endif
    return SNMP_ERR_NOERROR;
}

u_char *
var_context(struct variable *vp,
	    oid *name,
	    int *length,
	    int exact,
	    int *var_len,
	    WriteMethod **write_method)
{
    oid newname[MAX_OID_LEN], lowname[MAX_OID_LEN];
    int newnamelen, lownamelen=0;
    struct contextEntry *cp, *lowcp = NULL;
    u_long mask;
/*
 * This routine handles requests for variables of the form:

 * .iso.org.dod.internet.snmpV2.snmpModules.partyMIB.partyMIBObjects
 * .snmpContexts.contextTable.contextEntry.X.oid
 * or .1.3.6.1.6.3.3.2.2.1.1.X.oid, where the oid suffix is
 * variable length
 * Therefore, the index starts at name[12].
 */

    mask = 1 << (vp->magic - 1);
    memcpy(newname, vp->name, (int)vp->namelen * sizeof(oid));
    if (exact){
        if (*length < 13 ||
	    memcmp((char *)name, (char *)vp->name, 11 * sizeof(oid)))
	    return NULL;
    	*write_method = write_context;
        cp = context_getEntry(name + 12, *length - 12);
	if (cp == NULL)
	    return NULL;
	if (!(cp->contextBitMask & mask))
	    return NULL;
    } else {
      /* find "next" control entry */
      context_scanInit();
      for(cp = context_scanNext(); cp; cp = context_scanNext()){
	if (!(cp->contextBitMask & mask))
	    continue;
	memcpy((newname + 12),
	      cp->contextIdentity, cp->contextIdentityLen * sizeof(oid));
	newnamelen = 12 + cp->contextIdentityLen;
	if ((snmp_oid_compare(newname, newnamelen, name, *length) > 0) &&
	    (!lowcp || snmp_oid_compare(newname, newnamelen,
			       lowname, lownamelen) < 0)){
	    /*
	     * if new one is greater than input and closer to input than
	     * previous lowest, save this one as the "next" one.
	     */
	    memcpy(lowname, newname, newnamelen * sizeof(oid));
	    lownamelen = newnamelen;
	    lowcp = cp;
	}
      }
      if (lowcp == NULL)
	  return NULL;
      cp = lowcp;
      memcpy(name, lowname, lownamelen * sizeof(oid));
      *length = lownamelen;
    }

    *var_len = sizeof(long);
    long_return = 0;

    switch (vp->magic){
      case CONTEXTINDEX:
	return (u_char *)&cp->contextIndex;
      case CONTEXTLOCAL:
	return (u_char *)&cp->contextLocal;
      case CONTEXTVIEWINDEX:
	return (u_char *)&cp->contextViewIndex;
      case CONTEXTLOCALENTITY:
	*var_len = cp->contextLocalEntityLen;
	return (u_char *)cp->contextLocalEntity;
      case CONTEXTLOCALTIME:
	if (cp->contextLocalTime == CURRENTTIME){
	    *var_len = sizeof(currentTime);
	    return (u_char *)currentTime;
	} else if (cp->contextLocalTime == RESTARTTIME){
	    *var_len = sizeof(restartTime);
	    return (u_char *)restartTime;
	} else {
	    ERROR_MSG("");
	    return NULL;
	}
      case CONTEXTDSTPARTYINDEX:
	*var_len = 8;
	memset(return_buf, 0, 8);
	return (u_char *)return_buf;
      case CONTEXTSRCPARTYINDEX:
	*var_len = 8;
	memset(return_buf, 0, 8);
	return (u_char *)return_buf;
      case CONTEXTPROXYCONTEXT:
        *var_len = cp->contextProxyContextLen * sizeof(oid);
        return (u_char *)cp->contextProxyContext;
      case CONTEXTSTORAGETYPE:
	return (u_char *)&cp->contextStorageType;
      case CONTEXTSTATUS:
	if (cp->contextStatus == SNMP_ROW_NOTINSERVICE
	    && cp->contextBitMask != CONTEXTCOMPLETE_MASK){
	    long_return = SNMP_ROW_NOTREADY;
	    return (u_char *)&long_return;
	}
	return (u_char *)&cp->contextStatus;
      default:
            ERROR_MSG("");
    }
    return NULL;
}
