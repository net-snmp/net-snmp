/*
 * snmpv3.c
 */

#include <config.h>

#include <stdio.h>
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
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#if HAVE_STDLIB_H
#       include <stdlib.h>
#endif


#include "system.h"
#include "asn1.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "read_config.h"
#include "scapi.h"
#include "tools.h"
#include "debug.h"

#include "transform_oids.h"

static int		 engineBoots	   = 1;
static unsigned char	*engineID	   = NULL;
static int		 engineIDLength	   = 0;
static unsigned char	*oldEngineID	   = NULL;
static int		 oldEngineIDLength = 0;
static struct timeval	 snmpv3starttime;

/* 
 * Set up default snmpv3 parameter value storage.
 */
static char	*defaultSecName		= NULL;
static char	*defaultContext		= NULL;
static char	*defaultPassphrase	= NULL;
static char	*defaultAuthPassphrase	= NULL;
static char	*defaultPrivPassphrase	= NULL;
static oid	*defaultAuthType	= NULL;
static int	 defaultAuthTypeLen	= 0;
static oid	*defaultPrivType	= NULL;
static int	 defaultPrivTypeLen	= 0;
int		defaultSecurityLevel	= 0;


/*******************************************************************-o-******
 * snmpv3_secName_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *
 * Line syntax:
 *	defSecurityName <name>
 */
void
snmpv3_secName_conf(char *word, char *cptr)
{
  if (defaultSecName)
    free(defaultSecName);
  defaultSecName = strdup(cptr);
  DEBUGP("default security name set to: %s\n",defaultSecName);
}

char *
get_default_secName(void)
{
  return defaultSecName;
}


void
snmpv3_passphrase_conf(char *word, char *cptr)
{
  char **pass;
  if (strcmp(word, "defAuthPassphrase"))
    pass = &defaultAuthPassphrase;
  else if (strcmp(word, "defPrivPassphrase"))
    pass = &defaultPrivPassphrase;
  else
    pass = &defaultPassphrase;
  if (*pass)
    free(*pass);
  *pass = strdup(cptr);
  DEBUGP("set %s\n",word);
}

char *
get_default_authpass(void)
{
  if (defaultAuthPassphrase)
    return defaultAuthPassphrase;
  return defaultPassphrase;
}

char *
get_default_privpass(void)
{
  if (defaultPrivPassphrase)
    return defaultPrivPassphrase;
  return defaultPassphrase;
}

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
  DEBUGP("set default authentication type: %s\n", cptr);
}

oid *
get_default_authtype(int *len)
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
  DEBUGP("set default privacy type: %s\n", cptr);
}

oid *
get_default_privtype(int *len)
{
  if (len)
    *len = defaultPrivTypeLen;
  return defaultPrivType;
}



/*******************************************************************-o-******
 * snmpv3_context_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *	
 * Line syntax:
 *	defContext <context>
 */
void
snmpv3_context_conf(char *word, char *cptr)
{
  if (defaultContext)
    free(defaultContext);
  defaultContext = strdup(cptr);
  DEBUGP("default context set to: %s\n",defaultContext);
}

char *
get_default_context(void)
{
  return defaultContext;
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
    defaultSecurityLevel = SNMP_SEC_LEVEL_NOAUTH;
  else if (strcmp(cptr,"authNoPriv") == 0 || strcmp(cptr, "2") == 0)
    defaultSecurityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
  else if (strcmp(cptr,"authPriv") == 0 || strcmp(cptr, "3") == 0)
    defaultSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
  else {
    sprintf(buf,"unknown security level: cptr");
    config_perror(buf);
  }
  DEBUGP("default secLevel set to: %s = %d\n", cptr, defaultSecurityLevel);
}

int
get_default_secLevel(void)
{
  return defaultSecurityLevel;
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
setup_engineID(u_char **eidp, char *text)
{
  int		  enterpriseid	= htonl(ENTERPRISE_NUMBER),
		  len,
		  localsetup	= (eidp) ? 0 : 1;
			/* Use local engineID if *eidp == NULL.  */
  char		  buf[SNMP_MAXBUF_SMALL],
		 *bufp = NULL;
  struct hostent *hent;
 
EM(-1);

  /*
   * Determine length of the engineID string.
   */
  if (text) {
    len = 5+strlen(text)+1;	/* 5 leading bytes+text+null char. */

  } else {
    len = 5 + 4;		/* 5 leading bytes + four byte IPv4 address */
    gethostname(buf, SNMP_MAXBUF_SMALL);
    hent = gethostbyname(buf);
#ifdef AF_INET6
    if (hent && hent->h_addrtype == AF_INET6)
      len += 12;		/* 16 bytes total for IPv6 address. */
#endif
  }  /* endif -- text (1) */


  /*
   * Allocate memory and store enterprise ID.
   */
  if ((bufp = (char *) malloc(len)) == NULL) {
    perror("malloc");
    return -1;
  }

  memcpy(bufp, &enterpriseid, sizeof(enterpriseid)); /* XXX Must be 4 bytes! */
  bufp[0] |= 0x80;
  

  /*
   * Store the given text  -OR-   the first found IP address.
   */
  if (text) {
    bufp[4] = 4;
    sprintf(bufp+5,text);

  } else {
    bufp[4] = 1;
    gethostname(buf, SNMP_MAXBUF_SMALL);
    hent = gethostbyname(buf);

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
  DEBUGP("engineBoots: %d\n",engineBoots);
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
  DEBUGP("initialized engineID with: %s\n",cptr);
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
init_snmpv3(char *type) {
  gettimeofday(&snmpv3starttime, NULL);
  setup_engineID(NULL, NULL);
  /* handle engineID setup before everything else which may depend on it */
  register_premib_handler(type,"engineID", engineID_conf, NULL);
  register_premib_handler(type,"oldEngineID", oldengineID_conf, NULL);
  register_config_handler(type,"engineBoots", engineBoots_conf, NULL);
  register_config_handler("snmp","defSecurityName", snmpv3_secName_conf, NULL);
  register_config_handler("snmp","defContext", snmpv3_context_conf, NULL);
  register_config_handler("snmp","defAuthType", snmpv3_authtype_conf, NULL);
  register_config_handler("snmp","defPrivType", snmpv3_privtype_conf, NULL);
  register_config_handler("snmp","defPassphrase", snmpv3_passphrase_conf, NULL);
  register_config_handler("snmp","defAuthPassphrase",
                          snmpv3_passphrase_conf, NULL);
  register_config_handler("snmp","defPrivPassphrase",
                          snmpv3_passphrase_conf, NULL);
  register_config_handler("snmp","defSecurityLevel", snmpv3_secLevel_conf,
                          NULL);
  register_config_handler(type,"userSetAuthPass", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivPass", usm_set_password, NULL);
  register_config_handler(type,"userSetAuthKey", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivKey", usm_set_password, NULL);
  register_config_handler(type,"userSetAuthLocalKey", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivLocalKey", usm_set_password, NULL);
#if		!defined(USE_INTERNAL_MD5)
	sc_init();
#endif		/* !USE_INTERNAL_MD5 */
}

/*
 * initializations for SNMPv3 to be called after the configuration files
 * have been read.
 */

void
init_snmpv3_post_config(void) {

  int engineIDLen;
  u_char *engineID;
  u_char line[SNMP_MAXBUF_SMALL];

  engineID = snmpv3_generate_engineID(&engineIDLen);

  /* if our engineID has changed at all, the boots record must be set to 1 */
  if (engineIDLen != oldEngineIDLength ||
      oldEngineID == NULL || engineID == NULL ||
      memcmp(oldEngineID, engineID, engineIDLen) != 0) {
    engineBoots = 1;
  }

  /* set our local engineTime in the LCD timing cache */
  set_enginetime(engineID, engineIDLen, 
                 snmpv3_local_snmpEngineBoots(), 
                 snmpv3_local_snmpEngineTime(),
                 TRUE);

  free(engineID);
}

/*******************************************************************-o-******
 * shutdown_snmpv3
 *
 * Parameters:
 *	*type
 */
void
shutdown_snmpv3(char *type)
{
  char line[SNMP_MAXBUF_SMALL];
  char buf[SNMP_MAXBUF_SMALL];
  char engineID[SNMP_MAXBUF_SMALL];
  int  engineIDLen;

  sprintf(line, "engineBoots %d", engineBoots);
  read_config_store(type, line);

  engineIDLen = snmpv3_get_engineID(engineID, SNMP_MAXBUF_SMALL);

  if (engineIDLen) {
    /* store the engineID used for this run */
    sprintf(line, "oldEngineID ");
    read_config_save_octet_string(line+strlen(line), engineID,
                                  engineIDLen);
    read_config_store(type, line);
  }
        
#if		!defined(USE_INTERNAL_MD5) 
  sc_shutdown();
#endif		/* !USE_INTERNAL_MD5 */

}  /* shutdown_snmpv3() */

int
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
snmpv3_get_engineID(char *buf, int buflen)
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
snmpv3_generate_engineID(int *length)
{
  char *newID;
  newID = (char *) malloc(engineIDLength);

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
int
snmpv3_local_snmpEngineTime(void)
{
  struct timeval now;

  gettimeofday(&now, NULL);
  return calculate_time_diff(&now, &snmpv3starttime)/100;
}

/* snmpv3_set_engineBootsAndTime(): this function does not exist.  Go away. */
/*   It certainly should never be used, unless in a testing scenero,
     which is why it was created */
int
snmpv3_set_engineBootsAndTime(int boots, int ttime) {
  static struct timeval	 oldsnmpv3starttime;
 
  engineBoots = boots;
  gettimeofday(&snmpv3starttime, NULL);
  snmpv3starttime.tv_sec -= ttime;
}
