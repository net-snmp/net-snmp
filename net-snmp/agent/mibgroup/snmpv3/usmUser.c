/* 
 * usmUser.c
 */

#include <config.h>
#include <stdlib.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#ifdef HAVE_KMT_H
#	include <kmt.h>
#endif
#ifdef HAVE_KMT_ALGS_H
#	include <kmt_algs.h>
#endif

#include "mibincl.h"
#include "snmpusm.h"
#include "snmpv3.h"
#include "snmp-tc.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "util_funcs.h"
#include "keytools.h"
#include "tools.h"

#include "usmUser.h"
#include "transform_oids.h"

/* needed for the write_ functions to find the start of the index */
#define USM_MIB_LENGTH 12

static unsigned int usmUserSpinLock=0;

void
init_usmUser(void)
{
  snmpd_register_config_handler("usmUser",
                                usm_parse_config_usmUser, NULL);
}

void
shutdown_usmUser(void)
{
  /* save the user base */
  usm_save_users("usmUser", "snmpd");
}

/*******************************************************************-o-******
 * usm_generate_OID
 *
 * Parameters:
 *	*prefix		(I) OID prefix to the usmUser table entry.
 *	 prefixLen	(I)
 *	*uptr		(I) Pointer to a user in the user list.
 *	*length		(O) Length of generated index OID.
 *      
 * Returns:
 *	Pointer to the OID index for the user (uptr)  -OR-
 *	NULL on failure.
 *
 *
 * Generate the index OID for a given usmUser name.  'length' is set to
 * the length of the index OID.
 *
 * Index OID format is:
 *
 *    <...prefix>.<engineID_length>.<engineID>.<user_name_length>.<user_name>
 */
oid *
usm_generate_OID(oid *prefix, int prefixLen, struct usmUser *uptr,
                       int *length)
{
  oid *indexOid;
  int i;

  *length = 2 + uptr->engineIDLen + strlen(uptr->name) + prefixLen;
  indexOid = (oid *) malloc(*length * sizeof(oid));
  if (indexOid) {
    memmove(indexOid, prefix, prefixLen * sizeof (oid));

    indexOid[prefixLen] = uptr->engineIDLen;
    for(i = 0; i < uptr->engineIDLen; i++)
      indexOid[prefixLen+1+i] = (oid) uptr->engineID[i];

    indexOid[prefixLen + uptr->engineIDLen + 1] = strlen(uptr->name);
    for(i = 0; i < strlen(uptr->name); i++)
      indexOid[prefixLen + uptr->engineIDLen + 2 + i] = (oid) uptr->name[i];
  }
  return indexOid;

}  /* end usm_generate_OID() */

/* usm_parse_oid(): parses an index to the usmTable to break it down into
   a engineID component and a name component.  The results are stored in:

   **engineID:   a newly malloced string.
   *engineIDLen: The length of the malloced engineID string above.
   **name:       a newly malloced string.
   *nameLen:     The length of the malloced name string above.

   returns 1 if an error is encountered, or 0 if successful.
*/
int 
usm_parse_oid(oid *oidIndex, int oidLen,
              unsigned char **engineID, int *engineIDLen,
              unsigned char **name, int *nameLen)
{
  int nameL;
  int engineIDL;
  int i;

  /* first check the validity of the oid */
  if (oidLen <= 0 || oidIndex < 0) {
    DEBUGP("parse_oid: null oid or zero length oid passed in\n");
    return 1;
  }
  engineIDL = *oidIndex;		/* initial engineID length */
  if (oidLen < engineIDL + 2) {
    DEBUGP("parse_oid: invalid oid length: less than the engineIDLen\n");
    return 1;
  }
  nameL = oidIndex[engineIDL+1];	/* the initial name length */
  if (oidLen != engineIDL + nameL + 2) {
    DEBUGP("parse_oid: invalid oid length: length is not exact\n");
    return 1;
  }

  /* its valid, malloc the space and store the results */
  if (engineID == NULL || name == NULL) {
    DEBUGP("parse_oid: null storage pointer passed in.\n");
    return 1;
  }

  *engineID = (unsigned char *) malloc(engineIDL*sizeof(unsigned char));
  if (*engineID == NULL) {
    DEBUGP("parse_oid: malloc of the engineID failed\n");
    return 1;
  }
  *engineIDLen = engineIDL;

  *name = (unsigned char *) malloc((nameL+1)*sizeof(unsigned char));
  if (*name == NULL) {
    DEBUGP("parse_oid: malloc of the name failed\n");
    return 1;
  }
  *nameLen = nameL;
  
  for(i = 0; i < engineIDL; i++)
    engineID[0][i] = oidIndex[i+1];

  for(i = 0; i < nameL; i++)
    name[0][i] = oidIndex[i+2+engineIDL];
  name[0][nameL] = 0;

  return 0;

}  /* end usm_parse_oid() */

/*******************************************************************-o-******
 * usm_parse_user
 *
 * Parameters:
 *	*name		Complete OID indexing a given usmUser entry.
 *	 name_length
 *      
 * Returns:
 *	Pointer to a usmUser  -OR-
 *	NULL if name does not convert to a usmUser.
 * 
 * Convert an (full) OID and return a pointer to a matching user in the
 * user list if one exists.
 */
struct usmUser *
usm_parse_user(oid *name, int name_len)
{
  struct usmUser *uptr;

  unsigned char *newName, *engineID;
  int nameLen, engineIDLen;
  
  /* get the name and engineID out of the incoming oid */
  if (usm_parse_oid(&(name[USM_MIB_LENGTH]), name_len-USM_MIB_LENGTH,
                    &engineID, &engineIDLen, &newName, &nameLen))
    return NULL;

  /* Now see if a user exists with these index values */
  uptr = usm_get_user(engineID, engineIDLen, newName);
  free(engineID);
  free(newName);

  return uptr;

}  /* end usm_parse_user() */

/*******************************************************************-o-******
 * var_usmUser
 *
 * Parameters:
 *	  *vp	   (I)     Variable-binding associated with this action.
 *	  *name	   (I/O)   Input name requested, output name found.
 *	  *length  (I/O)   Length of input and output oid's.
 *	   exact   (I)     TRUE if an exact match was requested.
 *	  *var_len (O)     Length of variable or 0 if function returned.
 *	(**write_method)   Hook to name a write method (UNUSED).
 *      
 * Returns:
 *	Pointer to (char *) containing related data of length 'length'
 *	  (May be NULL.)
 *
 *
 * Call-back function passed to the agent in order to return information
 * for the USM MIB tree.
 *
 *
 * If this invocation is not for USMUSERSPINLOCK, lookup user name
 * in the usmUser list.
 *
 * If the name does not match any user and the request
 * is for an exact match, -or- if the usmUser list is empty, create a 
 * new list entry.
 *
 * Finally, service the given USMUSER* var-bind.  A NULL user generally
 * results in a NULL return value.
 */
unsigned char *
var_usmUser(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{
  struct usmUser *uptr=NULL, *nptr, *pptr;
  int i, rtest, result;
  oid *indexOid;
  int len;

  /* variables we may use later */
  static long long_ret;
  static unsigned char string[SNMP_MAXBUF];
  static oid objid[2];                      /* for .0.0 */

  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (vp->magic != USMUSERSPINLOCK) {
#define MAX_NEWNAME_LEN 128
    oid newname[MAX_NEWNAME_LEN];
    len = (*length < vp->namelen) ? *length : vp->namelen;
    rtest = compare(name, len, vp->name, len);
    if (rtest > 0 ||
/*      (rtest == 0 && !exact && (int) vp->namelen+1 < (int) *length) || */
        (exact == 1 && rtest != 0)) {
      if (var_len)
	*var_len = 0;
      return 0;
    }
    memset((char *) newname,(0),MAX_NEWNAME_LEN*sizeof(oid));
    if (((int) *length) <= (int) vp->namelen || rtest == -1) {
      /* oid is not within our range yet */
      /* need to fail if not exact */
      uptr = usm_get_userList();

    } else {
      for(nptr = usm_get_userList(), pptr = NULL, uptr = NULL; nptr != NULL;
          pptr = nptr, nptr = nptr->next) {
        indexOid = usm_generate_OID(vp->name, vp->namelen, nptr, &len);
        result = compare(name, *length, indexOid, len);
        DEBUGP("usmUser: Checking user: %s - ", nptr->name);
        for(i = 0; i < nptr->engineIDLen; i++)
          DEBUGP(" %x",nptr->engineID[i]);
        DEBUGP(" - %d \n  -> OID: ", result);
        DEBUGPOID(indexOid, len);
        DEBUGP("\n");
        if (exact) {
          if (result == 0) {
            free(indexOid);
            uptr = nptr;
            continue;
          }
        } else {
          if (result == 0) {
            /* found an exact match.  Need the next one for !exact */
            free(indexOid);
            uptr = nptr->next;
            continue;
          } else if (result == 1) {
            free(indexOid);
            uptr = nptr;
            continue;
          }
        }
        free(indexOid);
      }
    }  /* endif -- name <= vp->name */

    /* if uptr is NULL and exact we need to continue for creates */
    if (uptr == NULL && !exact)
      return(NULL);

    if (uptr) {
      indexOid = usm_generate_OID(vp->name, vp->namelen, uptr, &len);
      *length = len;
      memmove(name, indexOid, len*sizeof(oid));
      DEBUGP("usmUser: Found user: %s - ", uptr->name);
      for(i = 0; i < uptr->engineIDLen; i++)
        DEBUGP(" %x",uptr->engineID[i]);
      DEBUGP("\n  -> OID: ");
      DEBUGPOID(indexOid, len);
      DEBUGP("\n");
    } else {
      indexOid = NULL;
    }
  } else {
    if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;
  }  /* endif -- vp->magic != USMUSERSPINLOCK */

  switch(vp->magic) {
    case USMUSERSPINLOCK:
      *write_method = write_usmUserSpinLock;
      long_ret = usmUserSpinLock;
      return (unsigned char *) &long_ret;

    case USMUSERSECURITYNAME:
      if (uptr) {
        *var_len = strlen(uptr->secName);
        return (unsigned char *) uptr->secName;
      }
      return NULL;

    case USMUSERCLONEFROM:
      *write_method = write_usmUserCloneFrom;
      if (uptr) {
        objid[0] = 0; /* "When this object is read, the ZeroDotZero OID */
        objid[1] = 0; /*  is returned." */
        *var_len = sizeof(oid)*2;
        return (unsigned char *) objid;
      }
      return NULL;

    case USMUSERAUTHPROTOCOL:
      *write_method = write_usmUserAuthProtocol;
      if (uptr) {
        *var_len = uptr->authProtocolLen*sizeof(oid);
        return (unsigned char *) uptr->authProtocol;
      }
      return NULL;

    case USMUSERAUTHKEYCHANGE:
    case USMUSEROWNAUTHKEYCHANGE:
      /* we treat these the same, and let the calling module
         distinguish between them */
      *write_method = write_usmUserAuthKeyChange;
      if (uptr) {
        *string = 0; /* always return a NULL string */
        *var_len = strlen(string);
        return (unsigned char *) string;
      }
      return NULL;

    case USMUSERPRIVPROTOCOL:
      *write_method = write_usmUserPrivProtocol;
      if (uptr) {
        *var_len = uptr->privProtocolLen*sizeof(oid);
        return (unsigned char *) uptr->privProtocol;
      }
      return NULL;

    case USMUSERPRIVKEYCHANGE:
    case USMUSEROWNPRIVKEYCHANGE:
      /* we treat these the same, and let the calling module
         distinguish between them */
      *write_method = write_usmUserPrivKeyChange;
      if (uptr) {
        *string = 0; /* always return a NULL string */
        *var_len = strlen(string);
        return (unsigned char *) string;
      }
      return NULL;

    case USMUSERPUBLIC:
      *write_method = write_usmUserPublic;
      if (uptr) {
        if (uptr->userPublicString) {
          *var_len = strlen(uptr->userPublicString);
          return uptr->userPublicString;
        }
        *string = 0;
        *var_len = strlen(string); /* return an empty string if the public
                                      string hasn't been defined yet */
        return (unsigned char *) string;
      }
      return NULL;

    case USMUSERSTORAGETYPE:
      *write_method = write_usmUserStorageType;
      if (uptr) {
        long_ret = uptr->userStorageType;
        return (unsigned char *) &long_ret;
      }
      return NULL;

    case USMUSERSTATUS:
      *write_method = write_usmUserStatus;
      if (uptr) {
        long_ret = uptr->userStatus;
        return (unsigned char *) &long_ret;
      }
      return NULL;

    default:
      ERROR_MSG("");
  }
  return 0;

}  /* end var_usmUser() */

/* write_usmUserSpinLock(): called when a set is performed on the
   usmUserSpinLock object */
int
write_usmUserSpinLock(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static long long_ret;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;

  if (var_val_type != ASN_INTEGER){
      DEBUGP("write to usmUserSpinLock not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGP("write to usmUserSpinLock: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  size = sizeof(long_ret);
  asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);
  if (long_ret != usmUserSpinLock)
    return SNMP_ERR_INCONSISTENTVALUE;
  if (action == COMMIT) {
    if (usmUserSpinLock == 2147483647)
      usmUserSpinLock = 0;
    else
      usmUserSpinLock++;
  }
  return SNMP_ERR_NOERROR;
}  /* end write_usmUserSpinLock() */

/*******************************************************************-o-******
 * write_usmUserCloneFrom
 *
 * Parameters:
 *	 action
 *	*var_val
 *	 var_val_type
 *	 var_val_len
 *	*statP		(UNUSED)
 *	*name		OID of user to clone from.
 *	 name_len
 *      
 * Returns:
 *	SNMP_ERR_NOERROR		On success  -OR-  If user exists
 *					  and has already been cloned.
 *	SNMP_ERR_GENERR			Local function call failures.
 *	SNMP_ERR_INCONSISTENTNAME	'name' does not exist in user list
 *					  -OR-  user to clone from != RS_ACTIVE.
 *	SNMP_ERR_WRONGLENGTH		OID length > than local buffer size.
 *	SNMP_ERR_WRONGTYPE		ASN_OBJECT_ID is wrong.
 *
 *
 * XXX:  should handle action=UNDO's.
 */
int
write_usmUserCloneFrom(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static oid objid[USM_LENGTH_OID_MAX], *oidptr;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  struct usmUser *uptr, *cloneFrom;
  
  if (var_val_type != ASN_OBJECT_ID){
      DEBUGP("write to usmUserCloneFrom not ASN_OBJECT_ID\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(objid)){
      DEBUGP("write to usmUserCloneFrom: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
    /* parse the clonefrom objid */
    size = sizeof(objid);
    if(!asn_parse_objid(var_val, &bigsize, &var_val_type, objid, &size))
      return SNMP_ERR_GENERR;

    if ((uptr = usm_parse_user(name, name_len)) == NULL) 
      /* We don't allow creations here */
      return SNMP_ERR_INCONSISTENTNAME;

    /* have the user already been cloned?  If so, second cloning is
       not allowed, but does not generate an error */
    if (uptr->cloneFrom)
      return SNMP_ERR_NOERROR;

    /* does the cloneFrom user exist? */
    if ((cloneFrom = usm_parse_user(objid, size)) == NULL)
      /* We don't allow creations here */
      return SNMP_ERR_INCONSISTENTNAME;

    /* is it active */
    if (cloneFrom->userStatus != RS_ACTIVE)
      return SNMP_ERR_INCONSISTENTNAME;

    /* set the cloneFrom OID */
    if ((oidptr = snmp_duplicate_objid(objid, size/sizeof(oid))) == NULL)
      return SNMP_ERR_GENERR;

    /* do the actual cloning */

    if (uptr->cloneFrom)
      free(uptr->cloneFrom);
    uptr->cloneFrom = oidptr;

    usm_cloneFrom_user(cloneFrom, uptr);
    
  }  /* endif: action == COMMIT */

  return SNMP_ERR_NOERROR;


}  /* end write_usmUserCloneFrom() */

/*******************************************************************-o-******
 * write_usmUserAuthProtocol
 *
 * Parameters:
 *	 action
 *	*var_val	OID of auth transform to set.
 *	 var_val_type
 *	 var_val_len
 *	*statP
 *	*name		OID of user upon which to perform set operation.
 *	 name_len
 *      
 * Returns:
 *	SNMP_ERR_NOERROR		On success.
 *	SNMP_ERR_GENERR
 *	SNMP_ERR_INCONSISTENTVALUE
 *	SNMP_ERR_NOSUCHNAME
 *	SNMP_ERR_WRONGLENGTH
 *	SNMP_ERR_WRONGTYPE
 */
int
write_usmUserAuthProtocol(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static oid objid[USM_LENGTH_OID_MAX];
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  static oid *optr;
  struct usmUser *uptr;

  if (var_val_type != ASN_OBJECT_ID){
      DEBUGP("write to usmUserAuthProtocol not ASN_OBJECT_ID\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(objid)){
      DEBUGP("write to usmUserAuthProtocol: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      size = sizeof(objid);
      asn_parse_objid(var_val, &bigsize, &var_val_type, objid, &size);

      /* don't allow creations here */
      if ((uptr = usm_parse_user(name, name_len)) == NULL)
        return SNMP_ERR_NOSUCHNAME;

      /* check the objid for validity */
      /* only allow sets to perform a change to usmNoAuthProtocol */
      if (compare(objid, size, usmNoAuthProtocol,
                  sizeof(usmNoAuthProtocol)/sizeof(oid)) != 0)
        return SNMP_ERR_INCONSISTENTVALUE;
      
      /* if the priv protocol is not usmNoPrivProtocol, we can't change */
      if (compare(uptr->privProtocol, uptr->privProtocolLen, usmNoPrivProtocol,
                  sizeof(usmNoPrivProtocol)/sizeof(oid)) != 0)
        return SNMP_ERR_INCONSISTENTVALUE;

      /* finally, we can do it */
      optr = uptr->authProtocol;
      if ((uptr->authProtocol = snmp_duplicate_objid(objid, size))
          == NULL) {
        uptr->authProtocol = optr;
        return SNMP_ERR_GENERR;
      }
      free(optr);
      uptr->authProtocolLen = size;
  }
  return SNMP_ERR_NOERROR;
}  /* end write_usmUserAuthProtocol() */

/*******************************************************************-o-******
 * write_usmUserAuthKeyChange
 *
 * Parameters:
 *	 action		
 *	*var_val	Octet string representing new KeyChange value.
 *	 var_val_type
 *	 var_val_len
 *	*statP		(UNUSED)
 *	*name		OID of user upon which to perform set operation.
 *	 name_len
 *      
 * Returns:
 *	SNMP_ERR_NOERR		Success.
 *	SNMP_ERR_WRONGTYPE	
 *	SNMP_ERR_WRONGLENGTH	
 *	SNMP_ERR_NOSUCHNAME	
 *	SNMP_ERR_GENERR
 *
 * Note: This function handles both the usmUserAuthKeyChange and
 *       usmUserOwnAuthKeyChange objects.  We are not passed the name
 *       of the user requseting the keychange, so we leave this to the
 *       calling module to verify when and if we should be called.  To
 *       change this would require a change in the mib module API to
 *       pass in the securityName requesting the change.
 *
 * XXX:  should handle action=UNDO's.
 */
int
write_usmUserAuthKeyChange(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  static unsigned char   string[SNMP_MAXBUF_SMALL];
  int                    size, bigsize = SNMP_MAXBUF_SMALL;
  struct usmUser        *uptr;
  unsigned char          buf[SNMP_MAXBUF_SMALL];
  int                    buflen = SNMP_MAXBUF_SMALL;

  char                  *fnAuthKey    = "write_usmUserAuthKeyChange",
                        *fnOwnAuthKey = "write_usmUserOwnAuthKeyChange",
                        *fname;
  
  if (name[USM_MIB_LENGTH-1] == 6)
    fname = fnAuthKey;
  else
    fname = fnOwnAuthKey;
  
  if (var_val_type != ASN_OCTET_STR) {
    DEBUGP("write to %s not ASN_OCTET_STR\n", fname);
    return SNMP_ERR_WRONGTYPE;
  }

  if (var_val_len > sizeof(string)) {
    DEBUGP("write to %s: bad length\n", fname);
    return SNMP_ERR_WRONGLENGTH;
  }

  if (action == COMMIT) {
    /* parse the incoming string (key) out of the data */
    size = sizeof(string);
    asn_parse_string(var_val, &bigsize, &var_val_type, string, &size);

    /* don't allow creations here */
    if ((uptr = usm_parse_user(name, name_len)) == NULL) {
      return SNMP_ERR_NOSUCHNAME;
    }

    /* Change the key. */
    DEBUGP("%s: changing auth key for user %s\n", fname, uptr->secName);

    if (decode_keychange(uptr->authProtocol, uptr->authProtocolLen,
                         uptr->authKey, uptr->authKeyLen,
                         string, size,
                         buf, &buflen) != SNMPERR_SUCCESS) {
      DEBUGP("%s: ... failed\n", fname);
        return SNMP_ERR_GENERR;
    }
    DEBUGP("%s: ... succeeded\n", fname);
    SNMP_FREE(uptr->authKey);
    memdup(&uptr->authKey, buf, buflen);
    uptr->authKeyLen = buflen;
  }

  return SNMP_ERR_NOERROR;
} /* end write_usmUserAuthKeyChange() */

int
write_usmUserPrivProtocol(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static oid objid[USM_LENGTH_OID_MAX];
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  static oid *optr;
  struct usmUser *uptr;

  if (var_val_type != ASN_OBJECT_ID){
      DEBUGP("write to usmUserPrivProtocol not ASN_OBJECT_ID\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(objid)){
      DEBUGP("write to usmUserPrivProtocol: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      size = sizeof(objid);
      asn_parse_objid(var_val, &bigsize, &var_val_type, objid, &size);

      /* don't allow creations here */
      if ((uptr = usm_parse_user(name, name_len)) == NULL)
        return SNMP_ERR_NOSUCHNAME;

      /* check the objid for validity */
      /* only allow sets to perform a change to usmNoPrivProtocol */
      if (compare(objid, size, usmNoPrivProtocol,
                  sizeof(usmNoPrivProtocol)/sizeof(oid)) != 0)
        return SNMP_ERR_INCONSISTENTVALUE;
      
      /* finally, we can do it */
      optr = uptr->privProtocol;
      if ((uptr->privProtocol = snmp_duplicate_objid(objid, size))
          == NULL) {
        uptr->privProtocol = optr;
        return SNMP_ERR_GENERR;
      }
      free(optr);
      uptr->privProtocolLen = size;
  }
  return SNMP_ERR_NOERROR;
}  /* end write_usmUserPrivProtocol() */

/*
 * Note: This function handles both the usmUserPrivKeyChange and
 *       usmUserOwnPrivKeyChange objects.  We are not passed the name
 *       of the user requseting the keychange, so we leave this to the
 *       calling module to verify when and if we should be called.  To
 *       change this would require a change in the mib module API to
 *       pass in the securityName requesting the change.
 *
 */
int
write_usmUserPrivKeyChange(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  static unsigned char   string[SNMP_MAXBUF_SMALL];
  int                    size, bigsize = SNMP_MAXBUF_SMALL;
  struct usmUser        *uptr;
  unsigned char          buf[SNMP_MAXBUF_SMALL];
  int                    buflen = SNMP_MAXBUF_SMALL;

  char                  *fnPrivKey    = "write_usmUserPrivKeyChange",
                        *fnOwnPrivKey = "write_usmUserOwnPrivKeyChange",
                        *fname;
  
  if (name[USM_MIB_LENGTH-1] == 9)
    fname = fnPrivKey;
  else
    fname = fnOwnPrivKey;
  
  if (var_val_type != ASN_OCTET_STR) {
    DEBUGP("write to %s not ASN_OCTET_STR\n", fname);
    return SNMP_ERR_WRONGTYPE;
  }

  if (var_val_len > sizeof(string)) {
    DEBUGP("write to %s: bad length\n", fname);
    return SNMP_ERR_WRONGLENGTH;
  }

  if (action == COMMIT) {
    /* parse the incoming string (key) out of the data */
    size = sizeof(string);
    asn_parse_string(var_val, &bigsize, &var_val_type, string, &size);

    /* don't allow creations here */
    if ((uptr = usm_parse_user(name, name_len)) == NULL) {
      return SNMP_ERR_NOSUCHNAME;
    }

    /* Change the key. */
    DEBUGP("%s: changing priv key for user %s\n", fname, uptr->secName);

    if (decode_keychange(uptr->authProtocol, uptr->authProtocolLen,
                         uptr->privKey, uptr->privKeyLen,
                         string, size,
                         buf, &buflen) != SNMPERR_SUCCESS) {
      DEBUGP("%s: ... failed\n", fname);
        return SNMP_ERR_GENERR;
    }
    DEBUGP("%s: ... succeeded\n", fname);
    SNMP_FREE(uptr->privKey);
    memdup(&uptr->privKey, buf, buflen);
    uptr->privKeyLen = buflen;
  }

  return SNMP_ERR_NOERROR;
}  /* end write_usmUserPrivKeyChange() */

int
write_usmUserPublic(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static unsigned char string[SNMP_MAXBUF];
  int size, bigsize=SNMP_MAXBUF_MEDIUM;

  struct usmUser *uptr;

  if (var_val_type != ASN_OCTET_STR){
      DEBUGP("write to usmUserPublic not ASN_OCTET_STR\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGP("write to usmUserPublic: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
    /* don't allow creations here */
    if ((uptr = usm_parse_user(name, name_len)) == NULL) {
      return SNMP_ERR_NOSUCHNAME;
    }
    if (uptr->userPublicString)
      free(uptr->userPublicString);
    uptr->userPublicString = (char *) malloc(sizeof(char)*var_val_len+1);
    if (uptr->userPublicString == NULL) {
      return SNMP_ERR_GENERR;
    }
    size = var_val_len;
    asn_parse_string(var_val, &bigsize, &var_val_type,
                     uptr->userPublicString, &size);
    uptr->userPublicString[var_val_len] = 0;
    DEBUGP("setting public string: %d - %s\n", var_val_len,
           uptr->userPublicString);
  }
  return SNMP_ERR_NOERROR;
}  /* end write_usmUserPublic() */

int
write_usmUserStorageType(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static long long_ret;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  struct usmUser *uptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGP("write to usmUserStorageType not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGP("write to usmUserStorageType: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((uptr = usm_parse_user(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      size = sizeof(long_ret);
      asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);
      if ((long_ret == ST_VOLATILE || long_ret == ST_NONVOLATILE) &&
          (uptr->userStorageType == ST_VOLATILE ||
           uptr->userStorageType == ST_NONVOLATILE))
        uptr->userStorageType = long_ret;
      else
        return SNMP_ERR_INCONSISTENTVALUE;
  }
  return SNMP_ERR_NOERROR;
}  /* end write_usmUserStorageType() */

/*******************************************************************-o-******
 * write_usmUserStatus
 *
 * Parameters:
 *	 action
 *	*var_val
 *	 var_val_type
 *	 var_val_len
 *	*statP
 *	*name
 *	 name_len
 *      
 * Returns:
 *	SNMP_ERR_NOERROR		On success.
 *	SNMP_ERR_GENERR	
 *	SNMP_ERR_INCONSISTENTNAME
 *	SNMP_ERR_INCONSISTENTVALUE
 *	SNMP_ERR_WRONGLENGTH
 *	SNMP_ERR_WRONGTYPE
 */
int
write_usmUserStatus(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
  /* variables we may use later */
  static long long_ret;
  int size, bigsize=SNMP_MAXBUF_MEDIUM;
  unsigned char *engineID;
  int engineIDLen;
  unsigned char *newName;
  int nameLen;
  struct usmUser *uptr;

  if (var_val_type != ASN_INTEGER){
      DEBUGP("write to usmUserStatus not ASN_INTEGER\n");
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGP("write to usmUserStatus: bad length\n");
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
    size = sizeof(long_ret);
    asn_parse_int(var_val, &bigsize, &var_val_type, &long_ret, size);

    /* ditch illegal values now */
    /* notReady can not be used, but the return error code is not mentioned */
    if (long_ret == RS_NOTREADY || long_ret < 1 || long_ret > 6)
      return SNMP_ERR_INCONSISTENTVALUE;
    
    /* see if we can parse the oid for engineID/name first */
    if (usm_parse_oid(&(name[USM_MIB_LENGTH]), name_len-USM_MIB_LENGTH,
                      &engineID, &engineIDLen, &newName, &nameLen))
      return SNMP_ERR_INCONSISTENTNAME;

    /* Now see if a user already exists with these index values */
    uptr = usm_get_user(engineID, engineIDLen, newName);


    if (uptr) {			/* If so, we set the appropriate value... */
      free(engineID);
      free(newName);
      if (long_ret == RS_CREATEANDGO || long_ret == RS_CREATEANDWAIT) {
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        usm_remove_user(uptr);
        usm_free_user(uptr);
      } else {
        uptr->userStatus = long_ret;
      }

    } else {			/* ...else we create a new user */
      /* check for a valid status column set */
      if (long_ret == RS_ACTIVE || long_ret == RS_NOTINSERVICE) {
        free(engineID);
        free(newName);
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        /* destroying a non-existent row is actually legal */
        free(engineID);
        free(newName);
        return SNMP_ERR_NOERROR;
      }

      /* generate a new user */
      if ((uptr = usm_create_user()) == NULL) {
        free(engineID);
        free(newName);
        return SNMP_ERR_GENERR;
      }

      /* copy in the engineID */
      uptr->engineID =
        (unsigned char *) malloc(sizeof(unsigned char)*engineIDLen);
      if (uptr->engineID == NULL) {
        free(engineID);
        free(newName);
        free(uptr);
        return SNMP_ERR_GENERR;
      }
      uptr->engineIDLen = engineIDLen;
      memcpy(uptr->engineID, engineID, engineIDLen*sizeof(unsigned char));
      free(engineID);

      /* copy in the name and secname */
      uptr->name = (unsigned char *) malloc(strlen(newName));
      if ((uptr->name = strdup(newName)) == NULL) {
        free(newName);
        usm_free_user(uptr);
        return SNMP_ERR_GENERR;
      }
      free(newName);
      if ((uptr->secName = strdup(uptr->name)) == NULL) {
        usm_free_user(uptr);
        return SNMP_ERR_GENERR;
      }

      /* set the status of the row based on the request */
      if (long_ret == RS_CREATEANDGO)
        uptr->userStatus = RS_ACTIVE;
      else if (long_ret == RS_CREATEANDWAIT)
        uptr->userStatus = RS_NOTINSERVICE;

      /* finally, add it to our list of users */
      usm_add_user(uptr);

    }  /* endif -- uptr */
  }  /* endif -- action==COMMIT */

  return SNMP_ERR_NOERROR;

}  /* end write_usmUserStatus() */

