/*
 * snmpv3.c
 */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_STDLIB_H
#       include <stdlib.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "system.h"
#include "asn1.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "read_config.h"
#include "lcd_time.h"
#include "scapi.h"
#include "tools.h"
#include "lcd_time.h"
#include "snmp_debug.h"
#include "snmp_logging.h"
#include "callback.h"
#include "default_store.h"

#include "transform_oids.h"

static u_long		 engineBoots	   = 1;
static unsigned char	*engineID	   = NULL;
static size_t		 engineIDLength	   = 0;
static unsigned char	*oldEngineID	   = NULL;
static size_t		 oldEngineIDLength = 0;
static struct timeval	 snmpv3starttime;

/* 
 * Set up default snmpv3 parameter value storage.
 */
static oid	*defaultAuthType	= NULL;
static size_t	 defaultAuthTypeLen	= 0;
static oid	*defaultPrivType	= NULL;
static size_t	 defaultPrivTypeLen	= 0;

void
snmpv3_authtype_conf(char *word, char *cptr)
{
  if (strcmp(cptr,"MD5") == 0)
    defaultAuthType = usmHMACMD5AuthProtocol;
  else if (strcmp(cptr,"SHA") == 0)
    defaultAuthType = usmHMACMD5AuthProtocol;
  else
    config_perror("unknown authentication type");
  defaultAuthTypeLen = USM_LENGTH_OID_TRANSFORM;
  DEBUGMSGTL(("snmpv3","set default authentication type: %s\n", cptr));
}

oid *
get_default_authtype(size_t *len)
{
  if (len)
    *len = defaultAuthTypeLen;
  return defaultAuthType;
}

void
snmpv3_privtype_conf(char *word, char *cptr)
{
  if (strcmp(cptr,"DES") == 0)
    defaultPrivType = usmDESPrivProtocol;
  else
    config_perror("unknown privacy type");
  defaultPrivTypeLen = USM_LENGTH_OID_TRANSFORM;
  DEBUGMSGTL(("snmpv3","set default privacy type: %s\n", cptr));
}

oid *
get_default_privtype(size_t *len)
{
  if (len)
    *len = defaultPrivTypeLen;
  return defaultPrivType;
}

/*******************************************************************-o-******
 * snmpv3_secLevel_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *
 * Line syntax:
 *	defSecurityLevel "noAuthNoPriv" | "authNoPriv" | "authPriv"
 */
void
snmpv3_secLevel_conf(char *word, char *cptr)
{
  char buf[1024];
  
  if (strcmp(cptr,"noAuthNoPriv") == 0 || strcmp(cptr, "1") == 0)
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SECLEVEL, SNMP_SEC_LEVEL_NOAUTH);
  else if (strcmp(cptr,"authNoPriv") == 0 || strcmp(cptr, "2") == 0)
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SECLEVEL, SNMP_SEC_LEVEL_AUTHNOPRIV);
  else if (strcmp(cptr,"authPriv") == 0 || strcmp(cptr, "3") == 0)
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SECLEVEL, SNMP_SEC_LEVEL_AUTHPRIV);
  else {
    sprintf(buf,"unknown security level: cptr");
    config_perror(buf);
  }
  DEBUGMSGTL(("snmpv3","default secLevel set to: %s = %d\n", cptr,
              ds_get_int(DS_LIBRARY_ID, DS_LIB_SECLEVEL)));
}

/*******************************************************************-o-******
 * setup_engineID
 *
 * Parameters:
 *	**eidp
 *	 *text	Printable (?) text to be plugged into the snmpEngineID.
 *
 * Return:
 *	Length of allocated engineID string in bytes,  -OR-
 *	-1 on error.
 *
 *
 * Create an snmpEngineID using text and the local IP address.  If eidp
 * is defined, use it to return a pointer to the newly allocated data.
 * Otherwise, use the result to define engineID defined in this module.
 *
 * Line syntax:
 *	engineID <text> | NULL
 *
 * XXX	What if a node has multiple interfaces?
 * XXX	What if multiple engines all choose the same address?
 *      (answer:  You're screwed, because you might need a kul database
 *       which is dependant on the current engineID.  Enumeration and other
 *       tricks won't work). 
 */
int
setup_engineID(u_char **eidp, const char *text)
{
  int		  enterpriseid	= htonl(ENTERPRISE_NUMBER),
		  localsetup	= (eidp) ? 0 : 1;
			/* Use local engineID if *eidp == NULL.  */
#ifdef HAVE_GETHOSTNAME
  u_char	  buf[SNMP_MAXBUF_SMALL];
  struct hostent *hent;
#endif
  u_char     *bufp = NULL;
  size_t	  len;
 

  /*
   * Determine length of the engineID string.
   */
  if (text) {
    len = 5+strlen(text)+1;	/* 5 leading bytes+text+null char. */

  } else {
    len = 5 + 4;		/* 5 leading bytes + four byte IPv4 address */
#ifdef HAVE_GETHOSTNAME
    gethostname((char *)buf, sizeof(buf));
    hent = gethostbyname((char *)buf);
#ifdef AF_INET6
    if (hent && hent->h_addrtype == AF_INET6)
      len += 12;		/* 16 bytes total for IPv6 address. */
#endif
#endif /* HAVE_GETHOSTNAME */
  }  /* endif -- text (1) */


  /*
   * Allocate memory and store enterprise ID.
   */
  if ((bufp = (u_char *) malloc(len)) == NULL) {
    snmp_log_perror("setup_engineID malloc");
    return -1;
  }

  memcpy(bufp, &enterpriseid, sizeof(enterpriseid)); /* XXX Must be 4 bytes! */
  bufp[0] |= 0x80;
  

  /*
   * Store the given text  -OR-   the first found IP address.
   */
  if (text) {
    bufp[4] = 4;
    sprintf((char *)bufp+5,text);

  } else {
    bufp[4] = 1;
#ifdef HAVE_GETHOSTNAME
    gethostname((char *)buf, sizeof(buf));
    hent = gethostbyname((char *)buf);

    if (hent && hent->h_addrtype == AF_INET) {
      memcpy(bufp+5, hent->h_addr_list[0], hent->h_length);

#ifdef AF_INET6
    } else if (hent && hent->h_addrtype == AF_INET6) {
      bufp[4] = 2;
      memcpy(bufp+5, hent->h_addr_list[0], hent->h_length);
#endif

    } else {		/* Unknown address type.  Default to 127.0.0.1. */

      bufp[5] = 127;
      bufp[6] = 0;
      bufp[7] = 0;
      bufp[8] = 1;
    }
#else /* HAVE_GETHOSTNAME */
    /* Unknown address type.  Default to 127.0.0.1. */
    
    bufp[5] = 127;
    bufp[6] = 0;
    bufp[7] = 0;
    bufp[8] = 1;
#endif /* HAVE_GETHOSTNAME */
    
  }  /* endif -- text (2) */


  /*
   * Pass the string back to the calling environment, or use it for
   * our local engineID.
   */
  if (localsetup) {
	SNMP_FREE(engineID);
	engineID	= bufp;
	engineIDLength	= len;

  } else {
	*eidp = bufp;
  }


  return len;

}  /* end setup_engineID() */

/*******************************************************************-o-******
 * engineBoots_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *
 * Line syntax:
 *	engineBoots <num_boots>
 */
void
engineBoots_conf(char *word, char *cptr)
{
  engineBoots = atoi(cptr)+1;
  DEBUGMSGTL(("snmpv3","engineBoots: %d\n",engineBoots));
}



/*******************************************************************-o-******
 * engineID_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *
 * This function reads a string from the configuration file and uses that
 * string to initialize the engineID.  It's assumed to be human readable.
 */
void
engineID_conf(char *word, char *cptr)
{
  setup_engineID(NULL, cptr);
  DEBUGMSGTL(("snmpv3","initialized engineID with: %s\n",cptr));
}

void
version_conf(char *word, char *cptr)
{
  if (strcmp(cptr,"1") == 0) {
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION, SNMP_VERSION_1);
  } else if (strcmp(cptr,"2c") == 0) {
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION, SNMP_VERSION_2c);
  } else if (strcmp(cptr,"3") == 0) {
    ds_set_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION, SNMP_VERSION_3);
  } else {
    config_perror("unknown version specification");
    return;
  }
  DEBUGMSGTL(("snmpv3","set default version to %d\n",
              ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION)));
}

/* engineID_old_conf(char *, char *):

   Reads a octet string encoded engineID into the oldEngineID and
   oldEngineIDLen pointers.
*/
void
oldengineID_conf(char *word, char *cptr)
{
  read_config_read_octet_string(cptr, &oldEngineID, &oldEngineIDLength);
}


/*******************************************************************-o-******
 * init_snmpv3
 *
 * Parameters:
 *	*type	Label for the config file "type" used by calling entity.
 *      
 * Set time and engineID.
 * Set parsing functions for config file tokens.
 * Initialize SNMP Crypto API (SCAPI).
 */
void
init_snmpv3(const char *type) {
  gettimeofday(&snmpv3starttime, NULL);
  if (type && !strcmp(type,"snmpapp")) {
     setup_engineID(NULL,"__snmpapp__");
  } else {
     setup_engineID(NULL, NULL);
  }

  /* initialize submodules */
  init_usm();

  /* we need to be called back later */
  snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_POST_READ_CONFIG,
                         init_snmpv3_post_config, NULL);
  /* we need to be called back later */
  snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
                         snmpv3_store, (void *)type);


#if		!defined(USE_INTERNAL_MD5)
  /* doesn't belong here at all */
  sc_init();
#endif		/* !USE_INTERNAL_MD5 */

  /* register all our configuration handlers (ack, there's a lot) */

  /* handle engineID setup before everything else which may depend on it */
  register_premib_handler(type,"engineID", engineID_conf, NULL, "string");
  register_premib_handler(type,"oldEngineID", oldengineID_conf, NULL,
                          "len hexEngineId");
  register_config_handler(type,"engineBoots", engineBoots_conf, NULL, "num");

  /* default store config entries */
  ds_register_config(ASN_OCTET_STR, "snmp", "defSecurityName", DS_LIBRARY_ID,
                     DS_LIB_SECNAME);
  ds_register_config(ASN_OCTET_STR, "snmp", "defContext", DS_LIBRARY_ID,
                     DS_LIB_CONTEXT);
  ds_register_config(ASN_OCTET_STR, "snmp", "defPassphrase", DS_LIBRARY_ID,
                     DS_LIB_PASSPHRASE);
  ds_register_config(ASN_OCTET_STR, "snmp", "defAuthPassphrase", DS_LIBRARY_ID,
                     DS_LIB_AUTHPASSPHRASE);
  ds_register_config(ASN_OCTET_STR, "snmp", "defPrivPassphrase", DS_LIBRARY_ID,
                     DS_LIB_PRIVPASSPHRASE);
  register_config_handler("snmp","defVersion", version_conf, NULL, "num");

  register_config_handler("snmp","defAuthType", snmpv3_authtype_conf, NULL,
                          "MD5|SHA");
  register_config_handler("snmp","defPrivType", snmpv3_privtype_conf, NULL,
                          "DES (currently the only possible value)");
  register_config_handler("snmp","defSecurityLevel", snmpv3_secLevel_conf,
                          NULL, "noAuthNoPriv|authNoPriv|authPriv");
  register_config_handler(type,"userSetAuthPass", usm_set_password, NULL,
                          "secname engineIDLen engineID pass");
  register_config_handler(type,"userSetPrivPass", usm_set_password, NULL,
                          "secname engineIDLen engineID pass");
  register_config_handler(type,"userSetAuthKey", usm_set_password, NULL,
                          "secname engineIDLen engineID KuLen Ku");
  register_config_handler(type,"userSetPrivKey", usm_set_password, NULL,
                          "secname engineIDLen engineID KuLen Ku");
  register_config_handler(type,"userSetAuthLocalKey", usm_set_password, NULL,
                          "secname engineIDLen engineID KulLen Kul");
  register_config_handler(type,"userSetPrivLocalKey", usm_set_password, NULL,
                          "secname engineIDLen engineID KulLen Kul");
}

/*
 * initializations for SNMPv3 to be called after the configuration files
 * have been read.
 */

int
init_snmpv3_post_config(int majorid, int minorid, void *serverarg,
                        void *clientarg) {

  size_t engineIDLen;
  u_char *c_engineID;

  c_engineID = snmpv3_generate_engineID(&engineIDLen);

  /* if our engineID has changed at all, the boots record must be set to 1 */
  if (engineIDLen != oldEngineIDLength ||
      oldEngineID == NULL || c_engineID == NULL ||
      memcmp(oldEngineID, c_engineID, engineIDLen) != 0) {
    engineBoots = 1;
  }

  /* set our local engineTime in the LCD timing cache */
  set_enginetime(c_engineID, engineIDLen, 
                 snmpv3_local_snmpEngineBoots(), 
                 snmpv3_local_snmpEngineTime(),
                 TRUE);

  free(c_engineID);
  return SNMPERR_SUCCESS;
}

/*******************************************************************-o-******
 * store_snmpv3
 *
 * Parameters:
 *	*type
 */
int
snmpv3_store(int majorID, int minorID, void *serverarg, void *clientarg) {
  char line[SNMP_MAXBUF_SMALL];
  u_char c_engineID[SNMP_MAXBUF_SMALL];
  size_t  engineIDLen;
  const char *type = (const char *) clientarg;

  if (type == NULL)  /* should never happen, since the arg is ours */
    type = "unknown";

  sprintf(line, "engineBoots %ld", engineBoots);
  read_config_store(type, line);

  engineIDLen = snmpv3_get_engineID(c_engineID, SNMP_MAXBUF_SMALL);

  if (engineIDLen) {
    /* store the engineID used for this run */
    sprintf(line, "oldEngineID ");
    read_config_save_octet_string(line+strlen(line), c_engineID,
                                  engineIDLen);
    read_config_store(type, line);
  }
  return SNMPERR_SUCCESS;
}  /* snmpv3_store() */

u_long
snmpv3_local_snmpEngineBoots(void)
{
  return engineBoots;
}


/*******************************************************************-o-******
 * snmpv3_get_engineID
 *
 * Parameters:
 *	*buf
 *	 buflen
 *      
 * Returns:
 *	Length of engineID	On Success
 *	SNMPERR_GENERR		Otherwise.
 *
 *
 * Store engineID in buf; return the length.
 *
 */
int
snmpv3_get_engineID(u_char *buf, size_t buflen)
{
  /*
   * Sanity check.
   */
  if ( !buf || (buflen < engineIDLength) ) {
    return SNMPERR_GENERR;
  }

  memcpy(buf,engineID,engineIDLength);
  return engineIDLength;

}  /* end snmpv3_get_engineID() */

/*******************************************************************-o-******
 * snmpv3_clone_engineID
 *
 * Parameters:
 *	**dest
 *       *dest_len
 *       src
 *	 srclen
 *      
 * Returns:
 *	Length of engineID	On Success
 *	0		        Otherwise.
 *
 *
 * Clones engineID, creates memory
 *
 */
int
snmpv3_clone_engineID(u_char **dest, size_t* destlen, u_char*src, size_t srclen)
{
  if ( !dest || !destlen ) return 0;

  *dest = NULL; *destlen = 0;

  if (srclen && src) {
    *dest = (u_char*)malloc((unsigned)srclen * sizeof(u_char));
    if (*dest == NULL) return 0;
    memmove(*dest, src, srclen * sizeof(u_char));
    *destlen = srclen;
  }
  return *destlen;
}  /* end snmpv3_clone_engineID() */


/*******************************************************************-o-******
 * snmpv3_generate_engineID
 *
 * Parameters:
 *	*length
 *      
 * Returns:
 *	Pointer to copy of engineID	On Success.
 *	NULL				If malloc() or snmpv3_get_engineID()
 *						fail.
 *
 * Generates a malloced copy of our engineID.
 *
 * 'length' is set to the length of engineID  -OR-  < 0 on failure.
 */
u_char *
snmpv3_generate_engineID(size_t *length)
{
  u_char *newID;
  newID = (u_char *) malloc(engineIDLength);

  if (newID) {
    *length = snmpv3_get_engineID(newID, engineIDLength);
  }

  if (*length < 0) {
    SNMP_FREE(newID);
    newID = NULL;
  }

  return newID;

}  /* end snmpv3_generate_engineID() */

/* snmpv3_local_snmpEngineTime(): return the number of seconds since the
   snmpv3 engine last incremented engine_boots */
u_long
snmpv3_local_snmpEngineTime(void)
{
  struct timeval now;

  gettimeofday(&now, NULL);
  return calculate_time_diff(&now, &snmpv3starttime)/100;
}

#ifdef SNMP_TESTING_CODE
/* snmpv3_set_engineBootsAndTime(): this function does not exist.  Go away. */
/*   It certainly should never be used, unless in a testing scenero,
     which is why it was created */
void
snmpv3_set_engineBootsAndTime(int boots, int ttime) {
  engineBoots = boots;
  gettimeofday(&snmpv3starttime, NULL);
  snmpv3starttime.tv_sec -= ttime;
}
#endif
