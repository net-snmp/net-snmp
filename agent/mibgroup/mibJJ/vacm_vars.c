/*
 * SNMPv3 View-based Access Control Model
 */

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <ctype.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#include "snmp-tc.h"
#include "mibincl.h"
#include "read_config.h"
#include "agent_read_config.h"
#include "system.h"
#include "vacm.h"
#include "callback.h"
#include "agent_registry.h"
#include "agent_callbacks.h"
#include "vacm_vars.h"
#include "util_funcs.h"
#ifdef USING_MIBII_SYSORTABLE_MODULE
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
#include "sysORTable.h"
#endif
static unsigned int vacmViewSpinLock=0;

void
init_vacm_vars (void) 
{

#ifdef USING_MIBII_SYSORTABLE_MODULE
  static oid reg[] = {SNMP_OID_SNMPMODULES,16,2,2,1};
#endif
  
#define PRIVRW	(SNMPV2ANY | 0x5000)

  struct variable2 vacm_sec2group[] = {
    {SECURITYGROUP, ASN_OCTET_STR, RWRITE, var_vacm_sec2group, 1, {3}},
    {SECURITYSTORAGE, ASN_INTEGER, RWRITE, var_vacm_sec2group, 1, {4}},
    {SECURITYSTATUS, ASN_INTEGER, RWRITE, var_vacm_sec2group, 1, {5}},
  };

  struct variable2 vacm_access[] = {
    {ACCESSMATCH, ASN_INTEGER, RWRITE, var_vacm_access, 1, {4}},
    {ACCESSREAD, ASN_OCTET_STR, RWRITE, var_vacm_access, 1, {5}},
    {ACCESSWRITE, ASN_OCTET_STR, RWRITE, var_vacm_access, 1, {6}},
    {ACCESSNOTIFY, ASN_OCTET_STR, RWRITE, var_vacm_access, 1, {7}},
    {ACCESSSTORAGE, ASN_INTEGER, RWRITE, var_vacm_access, 1, {8}},
    {ACCESSSTATUS, ASN_INTEGER, RWRITE, var_vacm_access, 1, {9}},
  };

  struct variable4 vacm_view[] = {
	{VACMVIEWSPINLOCK, ASN_INTEGER, RWRITE, var_vacm_view, 1, {1}},
    {VIEWMASK, ASN_OCTET_STR, RWRITE, var_vacm_view, 3, {2,1,3}},
    {VIEWTYPE, ASN_INTEGER, RWRITE, var_vacm_view, 3, {2,1,4}},
    {VIEWSTORAGE, ASN_INTEGER, RWRITE, var_vacm_view, 3, {2,1,5}},
    {VIEWSTATUS, ASN_INTEGER, RWRITE, var_vacm_view, 3, {2,1,6}},
  };

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid vacm_sec2group_oid[] = { OID_VACMGROUPENTRY };
  oid vacm_access_oid[] = { OID_VACMACCESSENTRY};
  oid vacm_view_oid[] = { OID_VACMMIBVIEWS };

  /* we need to be called back later */
  snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_STORE_DATA,
                         store_vacm, NULL);

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/vacm:sec2group", vacm_sec2group, variable2, \
               vacm_sec2group_oid);
  REGISTER_MIB("mibII/vacm:access", vacm_access, variable2, vacm_access_oid);
  REGISTER_MIB("mibII/vacm:view", vacm_view, variable4, vacm_view_oid);

  snmpd_register_config_handler("com2sec", vacm_parse_security,
                                vacm_free_security,"name source community");
  snmpd_register_config_handler("group", vacm_parse_group, vacm_free_group,
                                "name v1|v2c|usm security");
  snmpd_register_config_handler("access", vacm_parse_access, vacm_free_access,
                            "name context model level prefx read write notify");
  snmpd_register_config_handler("view", vacm_parse_view, vacm_free_view,
                                "name type subtree [mask]");
  snmpd_register_config_handler("rwcommunity", vacm_parse_simple,
                                NULL,"community [default|hostname|network/bits] [oid]");
  snmpd_register_config_handler("rocommunity", vacm_parse_simple,
                                NULL,"community [default|hostname|network/bits] [oid]");
  snmpd_register_config_handler("rwuser", vacm_parse_simple,
                                NULL,"user [noauth|auth|priv] [oid]");
  snmpd_register_config_handler("rouser", vacm_parse_simple,
                                NULL,"user [noauth|auth|priv] [oid]");
  snmpd_register_config_handler("vacmView", vacm_parse_config_view, NULL,
                                "internal use only");
  snmpd_register_config_handler("vacmGroup", vacm_parse_config_group, NULL,
                                "internal use only");
  snmpd_register_config_handler("vacmAccess", vacm_parse_config_access, NULL,
                                "internal use only");                                
					  

#ifdef USING_MIBII_SYSORTABLE_MODULE
  register_sysORTable(reg,10,"View-based Access Control Model for SNMP.");
#endif

  /* register ourselves to handle access control */
  snmp_register_callback(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_ACM_CHECK,
                         vacm_in_view_callback, NULL);
  snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                         SNMPD_CALLBACK_ACM_CHECK_INITIAL,
                         vacm_in_view_callback, NULL);
}

static struct vacm_securityEntry *securityFirst =0, *securityLast =0;

#define EXAMPLE_NETWORK		"NETWORK"
#define EXAMPLE_COMMUNITY	"COMMUNITY"

void vacm_parse_security (const char *token, 
			  char *param)
{
    char *name, *source, *community;
    const char *mask;
    char *cp;
    struct vacm_securityEntry *sp, se;
    int maskLength, maskBit;
    struct sockaddr_in *srcIp, *srcMask;
    char null[] = "";

    memset (&se, 0 , sizeof se);
    name = strtok(param, "\t\n ");
    if (!name) {
	config_perror("missing NAME parameter");
	return;
    }
    source = strtok(NULL, "\t\n ");
    if (!source) {
	config_perror("missing SOURCE parameter");
	return;
    }
    if ( !strncmp( source, EXAMPLE_NETWORK, strlen(EXAMPLE_NETWORK)) ) {
	config_perror("Example config NETWORK not properly configured");
	return;		/* or exit(1); */
    }
    community = strtok(NULL, "\t\n ");
    if (!community) {
	config_perror("missing COMMUNITY parameter");
	return;
    }
    if ( !strncmp( community, EXAMPLE_COMMUNITY, strlen(EXAMPLE_COMMUNITY)) ) {
	config_perror("Example config COMMUNITY not properly configured");
	return;		/* or exit(1); */
    }
    srcIp   = (struct sockaddr_in*)&(se.sourceIp);
    srcMask = (struct sockaddr_in*)&(se.sourceMask);
    cp = strchr(source, '/');
    if (cp == NULL) cp = null;
    else *cp++ = 0;
    mask = cp;
    if (strcmp("default", source) == 0 || strcmp("0.0.0.0", source) == 0) {
	memset(&(srcIp->sin_addr), 0, sizeof(struct in_addr));
	mask = "0.0.0.0";
    }
    else if ((srcIp->sin_addr.s_addr = inet_addr (source)) == (unsigned) -1) {
	struct hostent *hp = gethostbyname(source);
	if (hp != NULL) {
	    memcpy(&(srcIp->sin_addr), hp->h_addr, 4);
	}
	else {
	    config_perror ("bad source address");
	    return;
	}
    }
    if (*mask == 0) memset (&(srcMask->sin_addr), 0xff, sizeof(struct in_addr));
    else {
	if (strchr(mask, '.')) {
	    if ((srcMask->sin_addr.s_addr = inet_addr(mask)) == (unsigned)-1) {
		config_perror("bad mask");
		return;
	    }
	}
	else {
	    maskLength = atoi(mask);
	    if (maskLength <= 0 || maskLength > 32) {
		config_perror("bad mask length");
		return;
	    }
	    maskBit = 0x80000000L;
	    srcMask->sin_addr.s_addr = 0;
	    while (maskLength--) {
		srcMask->sin_addr.s_addr |= maskBit;
		maskBit >>= 1;
	    }
	    srcMask->sin_addr.s_addr = htonl(srcMask->sin_addr.s_addr);
	}
    }
    if ((srcIp->sin_addr.s_addr & ~srcMask->sin_addr.s_addr) != 0) {
	config_perror("source/mask mismatch");
	return;
    }
    if (strlen(name)+1 > sizeof(se.securityName)) {
    	config_perror("security name too long");
	return;
    }
    if (strlen(community)+1 > sizeof(se.community)) {
    	config_perror("community name too long");
	return;
    }
    strcpy(se.securityName, name);
    strcpy(se.community, community);
    sp = (struct vacm_securityEntry *)malloc (sizeof *sp);
    if (sp == NULL) {
    	config_perror("memory error");
	return;
    }
    *sp = se;
    if (securityFirst != NULL) {
	securityLast->next = sp;
	securityLast = sp;
    }
    else {
	securityFirst = securityLast = sp;
    }
}

void vacm_free_security (void)
{
    struct vacm_securityEntry *sp;
    while ((sp = securityFirst)) {
	securityFirst = sp->next;
	free(sp);
    }
}

void vacm_parse_group (const char *token, 
		       char *param)
{
    char *group, *model, *security;
    int imodel;
    struct vacm_groupEntry *gp = NULL;

    group = strtok (param, " \t\n");
    model = strtok (NULL, " \t\n");
    security = strtok (NULL, " \t\n");

    if (group == NULL || *group == 0) {
	config_perror("missing GROUP parameter");
	return;
    }
    if (model == NULL || *model == 0) {
	config_perror("missing MODEL parameter");
	return;
    }
    if (security == NULL || *security == 0) {
	config_perror("missing SECURITY parameter");
	return;
    }
    if (strcasecmp(model, "v1") == 0) imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0) imodel = SNMP_SEC_MODEL_SNMPv2c;
    else if (strcasecmp(model, "usm") == 0) imodel = SNMP_SEC_MODEL_USM;
    else if (strcasecmp(model, "any") == 0) {
	config_perror("bad security model \"any\" should be: v1, v2c or usm - installing anyway");
	imodel = SNMP_SEC_MODEL_ANY;
    }
    else {
	config_perror("bad security model, should be: v1, v2c or usm");
	return;
    }
    if (strlen(security)+1 > sizeof(gp->groupName)) {
    	config_perror("security name too long");
	return;
    }
    gp = vacm_createGroupEntry(imodel, security);
    if (!gp) {
	config_perror("failed to create group entry");
	return;
    }
    strcpy (gp->groupName, group);
    gp->storageType = SNMP_STORAGE_PERMANENT;
    gp->status = SNMP_ROW_ACTIVE;
    free (gp->reserved);
    gp->reserved = NULL;
}

void vacm_free_group (void)
{
    vacm_destroyAllGroupEntries();
}

void vacm_parse_access (const char *token, char *param)
{
    char *name, *context, *model, *level, *prefix, *readView, *writeView, *notify;
    int imodel, ilevel, iprefix;
    struct vacm_accessEntry *ap;

    name = strtok(param, " \t\n");
    if (!name) {
	config_perror("missing NAME parameter");
	return;
    }
    context = strtok(NULL, " \t\n");
    if (!context) {
	config_perror("missing CONTEXT parameter");
	return;
    }
    model = strtok(NULL, " \t\n");
    if (!model) {
	config_perror("missing MODEL parameter");
	return;
    }
    level = strtok(NULL, " \t\n");
    if (!level) {
	config_perror("missing LEVEL parameter");
	return;
    }
    prefix = strtok(NULL, " \t\n");
    if (!prefix) {
	config_perror("missing PREFIX parameter");
	return;
    }
    readView = strtok(NULL, " \t\n");
    if (!readView) {
	config_perror("missing readView parameter");
	return;
    }
    writeView = strtok(NULL, " \t\n");
    if (!writeView) {
	config_perror("missing writeView parameter");
	return;
    }
    notify = strtok(NULL, " \t\n");
    if (!notify) {
	config_perror("missing notifyView parameter");
	return;
    }
    if (strcmp(context, "\"\"") == 0) *context = 0;
    if (strcasecmp(model, "any") == 0) imodel = SNMP_SEC_MODEL_ANY;
    else if (strcasecmp(model, "v1") == 0) imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0) imodel = SNMP_SEC_MODEL_SNMPv2c;
    else if (strcasecmp(model, "usm") == 0) imodel = SNMP_SEC_MODEL_USM;
    else {
	config_perror("bad security model (any, v1, v2c, usm)");
	return;
    }
    if (strcasecmp(level, "noauth") == 0) ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "noauthnopriv") == 0) ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "auth") == 0) ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "authnopriv") == 0) ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "priv") == 0) ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else if (strcasecmp(level, "authpriv") == 0) ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else {
	config_perror("bad security level (noauthnopriv, authnopriv, authpriv)");
	return;
    }
    if (strcmp(prefix,"exact") == 0) iprefix = 1;
    else if (strcmp(prefix,"prefix") == 0) iprefix = 2;
    else if (strcmp(prefix,"0") == 0) {
	config_perror("bad prefix match parameter \"0\", should be: exact or prefix - installing anyway");
	iprefix = 1;
    }
    else {
	config_perror("bad prefix match parameter, should be: exact or prefix");
	return;
    }
    if (strlen(readView)+1 > sizeof(ap->readView)) {
    	config_perror("readView too long");
	return;
    }
    if (strlen(writeView)+1 > sizeof(ap->writeView)) {
    	config_perror("writeView too long");
	return;
    }
    if (strlen(notify)+1 > sizeof(ap->notifyView)) {
    	config_perror("notifyView too long");
	return;
    }
    ap = vacm_createAccessEntry (name, context, imodel, ilevel);
    if (!ap) {
	config_perror("failed to create access entry");
	return;
    }
    strcpy(ap->readView, readView);
    strcpy(ap->writeView, writeView);
    strcpy(ap->notifyView, notify);
    ap->contextMatch = iprefix;
    ap->storageType = SNMP_STORAGE_PERMANENT;
    ap->status = SNMP_ROW_ACTIVE;
    free (ap->reserved);
    ap->reserved = NULL;
}

void vacm_free_access (void)
{
    vacm_destroyAllAccessEntries();
}

void vacm_parse_view (const char *token, 
		      char *param)
{
    char *name, *type, *subtree, *mask;
    int inclexcl;
    struct vacm_viewEntry *vp;
    oid suboid[MAX_OID_LEN];
    size_t suboid_len = 0;
    u_char viewMask[sizeof (vp->viewMask)];
    int i;

    name = strtok (param, " \t\n");
    if (!name) {
	config_perror("missing NAME parameter");
	return;
    }
    type = strtok (NULL, " \n\t");
    if (!type) {
	config_perror("missing TYPE parameter");
	return;
    }
    subtree = strtok(NULL, " \t\n");
    if (!subtree) {
	config_perror("missing SUBTREE parameter");
	return;
    }
    mask = strtok(NULL, " \t\n");

    if (strcmp(type, "included") == 0) inclexcl = SNMP_VIEW_INCLUDED;
    else if (strcmp(type, "excluded") == 0) inclexcl = SNMP_VIEW_EXCLUDED;
    else {
	config_perror("TYPE must be included/excluded?");
	return;
    }
    suboid_len = MAX_OID_LEN;
    if (!read_objid(subtree, suboid, &suboid_len)) {
	config_perror("bad SUBTREE object id");
	return;
    }
    if (mask) {
	int val;
	i = 0;
	for (mask = strtok(mask, ".:"); mask; mask = strtok(NULL, ".:")) {
	    if (i >= sizeof(viewMask)) {
		config_perror("MASK too long");
		return;
	    }
	    if (sscanf(mask, "%x", &val) == 0) {
		config_perror("invalid MASK");
		return;
	    }
	    viewMask[i] = val;
	    i++;
	}
    }
    else {
	for (i = 0; i < sizeof(viewMask); i++)
	    viewMask[i] = 0xff;
    }
    vp = vacm_createViewEntry(name, suboid, suboid_len);
    if (!vp) {
	config_perror("failed to create view entry");
	return;
    }
    memcpy(vp->viewMask, viewMask, sizeof(viewMask));
    vp->viewType = inclexcl;
    vp->viewStorageType = SNMP_STORAGE_PERMANENT;
    vp->viewStatus = SNMP_ROW_ACTIVE;
    free (vp->reserved);
    vp->reserved = NULL;
}

void vacm_free_view (void)
{
    vacm_destroyAllViewEntries();
}

void vacm_parse_simple(const char *token, char *confline) {
  char line[SPRINT_MAX_LEN];
  char community[COMMUNITY_MAX_LEN];
  char theoid[SPRINT_MAX_LEN];
  char viewname[SPRINT_MAX_LEN];
  char addressname[SPRINT_MAX_LEN];
  const char *rw = "none";
  const char *model = "any";
  char *cp;
  static int num = 0;
  char secname[SPRINT_MAX_LEN];
  char authtype[SPRINT_MAX_LEN];

  /* community name or user name */
  cp = copy_word(confline, community);

  if (strcmp(token,"rouser") == 0 || strcmp(token,"rwuser") == 0) {
    /* authentication type */
    if (cp && *cp)
      cp = copy_word(cp, authtype);
    else
      strcpy(authtype, "auth");
    DEBUGMSGTL((token, "setting auth type: \"%s\"\n",authtype));
    model = "usm";
  } else {
    /* source address */
    if (cp && *cp) {
      cp = copy_word(cp, addressname);
    } else {
      strcpy(addressname, "default");
    }
    /* authtype has to be noauth */
    strcpy(authtype, "noauth");
  }

  /* oid they can touch */
  if (cp && *cp) {
    cp = copy_word(cp, theoid);
  } else {
    strcpy(theoid, ".1");
  }

  if (strcmp(token,"rwcommunity") == 0 || strcmp(token,"rwuser") == 0)
    rw = viewname;

  if (strcmp(token,"rwcommunity") == 0 || strcmp(token,"rocommunity") == 0) {
    /* com2sec mapping */
    /* com2sec anonymousSecNameNUM    ADDRESS  COMMUNITY */
    sprintf(secname, "anonymousSecName%03d", num);
    sprintf(line,"%s %s %s", secname, addressname, community);
    DEBUGMSGTL((token,"passing: %s %s\n", "com2sec", line));
    vacm_parse_security("com2sec",line);

    /* sec->group mapping */
    /* group   anonymousGroupNameNUM  any      anonymousSecNameNUM */
    sprintf(line,"anonymousGroupName%03d v1 %s", num, secname);
    DEBUGMSGTL((token,"passing: %s %s\n", "group", line));
    vacm_parse_group("group",line);
    sprintf(line,"anonymousGroupName%03d v2c %s", num, secname);
    DEBUGMSGTL((token,"passing: %s %s\n", "group", line));
    vacm_parse_group("group",line);
  } else {
    strcpy(secname, community);

    /* sec->group mapping */
    /* group   anonymousGroupNameNUM  any      anonymousSecNameNUM */
    sprintf(line,"anonymousGroupName%03d usm %s", num, secname);
    DEBUGMSGTL((token,"passing: %s %s\n", "group", line));
    vacm_parse_group("group",line);
  }


  /* view definition */
  /* view    anonymousViewNUM       included OID */
  sprintf(viewname,"anonymousView%03d",num);
  sprintf(line,"%s included %s", viewname, theoid);
  DEBUGMSGTL((token,"passing: %s %s\n", "view", line));
  vacm_parse_view("view",line);

  /* map everything together */
  /* access  anonymousGroupNameNUM  "" MODEL AUTHTYPE exact anonymousViewNUM [none/anonymousViewNUM] [none/anonymousViewNUM] */
  sprintf(line, "anonymousGroupName%03d  \"\" %s %s exact %s %s %s", num,
          model, authtype, viewname, rw, rw);
  DEBUGMSGTL((token,"passing: %s %s\n", "access", line));
  vacm_parse_access("access",line);
  num++;
}

int
vacm_in_view_callback(int majorID, int minorID, void *serverarg,
                      void *clientarg) {
  struct view_parameters *view_parms = (struct view_parameters *) serverarg;
  int retval;
  
  if (view_parms == NULL)
    return 1;
  retval = vacm_in_view(view_parms->pdu, view_parms->name,
                        view_parms->namelen);
  if (retval != 0)
    view_parms->errorcode = retval;
  return retval;
}


/*******************************************************************-o-******
 * vacm_in_view
 *
 * Parameters:
 *	*pdu
 *	*name
 *	 namelen
 *      
 * Returns:
 *	0	On success.
 *	1	Missing security name.
 *	2	Missing group
 *	3	Missing access
 *	4	Missing view
 *	5	Not in view
 *
 * Debug output listed as follows:
 *	<securityName> <groupName> <viewName> <viewType>
 */
int vacm_in_view (struct snmp_pdu *pdu,
		  oid *name,
		  size_t namelen)
{
    struct vacm_securityEntry *sp = securityFirst;
    struct vacm_accessEntry *ap;
    struct vacm_groupEntry *gp;
    struct vacm_viewEntry *vp;
    struct sockaddr_in *pduIp = (struct sockaddr_in*)&(pdu->address);
    struct sockaddr_in *srcIp, *srcMask;
    char *vn;
    char *sn;

    if (pdu->version == SNMP_VERSION_1 || pdu->version == SNMP_VERSION_2c) {
	if (snmp_get_do_debugging()) {
            char *buf;
            if (pdu->community) {
                buf = malloc(1+ pdu->community_len);
                memcpy(buf, pdu->community, pdu->community_len);
                buf[pdu->community_len] = '\0';
            } else {
                DEBUGMSGTL(("mibII/vacm_vars", "NULL community"));
                buf = strdup("NULL");
            }
            
	    DEBUGMSGTL(("mibII/vacm_vars", "vacm_in_view: ver=%d, source=%.8x, community=%s\n", pdu->version, pduIp->sin_addr.s_addr, buf));
	    free (buf);
	}

	/* allow running without snmpd.conf */
	if (sp == NULL) {
	    DEBUGMSGTL(("mibII/vacm_vars", "vacm_in_view: accepted with no com2sec entries\n"));
	    switch (pdu->command) {
	    case SNMP_MSG_GET:
	    case SNMP_MSG_GETNEXT:
	    case SNMP_MSG_GETBULK:
		return 0;
	    default:
		return 1;
	    }
	}
	while (sp) {
	    srcIp   = (struct sockaddr_in *)&(sp->sourceIp);
	    srcMask = (struct sockaddr_in *)&(sp->sourceMask);
	    if ((pduIp->sin_addr.s_addr & srcMask->sin_addr.s_addr)
		    == srcIp->sin_addr.s_addr
                && strlen(sp->community) == pdu->community_len
		&& !strncmp(sp->community, (char *)pdu->community, pdu->community_len))
		break;
	    sp = sp->next;
	}
	if (sp == NULL) return 1;
	sn = sp->securityName;
    } else if (pdu->securityModel == SNMP_SEC_MODEL_USM) {
      DEBUGMSG (("mibII/vacm_vars",
                 "vacm_in_view: ver=%d, model=%d, secName=%s\n",
                 pdu->version, pdu->securityModel, pdu->securityName));
      sn = pdu->securityName;
    } else {
	sn = NULL;
    }

    if (sn == NULL) return 1;
    DEBUGMSGTL(("mibII/vacm_vars", "vacm_in_view: sn=%s", sn));

    gp = vacm_getGroupEntry(pdu->securityModel, sn);
    if (gp == NULL) { DEBUGMSG(("mibII/vacm_vars", "\n")); return 2; }
    DEBUGMSG (("mibII/vacm_vars", ", gn=%s", gp->groupName));

    ap = vacm_getAccessEntry(gp->groupName, "", pdu->securityModel,
                             pdu->securityLevel);
    if (ap == NULL) { DEBUGMSG(("mibII/vacm_vars", "\n")); return 3; }

    if (name == 0) { /* only check the setup of the vacm for the request */
        DEBUGMSG(("mibII/vacm_vars", ", Done checking setup\n"));
        return 0;
    }

    switch (pdu->command) {
      case SNMP_MSG_GET:
      case SNMP_MSG_GETNEXT:
      case SNMP_MSG_GETBULK:
	vn = ap->readView;
	break;
      case SNMP_MSG_SET:
	vn = ap->writeView;
	break;
      case SNMP_MSG_TRAP:
      case SNMP_MSG_TRAP2:
      case SNMP_MSG_INFORM:
	vn = ap->notifyView;
	break;
      default:
        snmp_log(LOG_ERR, "bad msg type in vacm_in_view: %d\n", pdu->command);
	vn = ap->readView;
    }
    DEBUGMSG (("mibII/vacm_vars", ", vn=%s", vn));

    vp = vacm_getViewEntry (vn, name, namelen);
    if (vp == NULL) { DEBUGMSG(("mibII/vacm_vars", "\n")); return 4; }
    DEBUGMSG(("mibII/vacm_vars", ", vt=%d\n", vp->viewType));

    if (vp->viewType == SNMP_VIEW_EXCLUDED) return 5;

    return 0;

}  /* end vacm_in_view() */


u_char *var_vacm_sec2group(struct variable *vp,
			   oid *name,
			   size_t *length,
			   int exact,
			   size_t *var_len,
			   WriteMethod **write_method)
{
    struct vacm_groupEntry *gp;
    oid *groupSubtree;
    int groupSubtreeLen;
    int secmodel;
    char secname[32], *cp;

    *write_method = NULL;
    if (memcmp(name, vp->name, sizeof(oid)*vp->namelen) != 0) {
	memcpy(name, vp->name, sizeof(oid)*vp->namelen);
	*length = vp->namelen;
    }
    if (exact) {
	if (*length < 13) return NULL;

	secmodel = name[11];
	groupSubtree = name+13;
	groupSubtreeLen = *length - 13;
	cp = secname;
	while (groupSubtreeLen-- > 0) {
            if (*groupSubtree > 255)
              return 0; /* illegal value */
	    *cp++ = (char) *groupSubtree++;
	}
	*cp = 0;

	gp = vacm_getGroupEntry(secmodel, secname);
    }
    else {
	secmodel = *length > 11 ? name[11] : 0;
	groupSubtree = name+12;
	groupSubtreeLen = *length - 12;
	cp = secname;
	while (groupSubtreeLen-- > 0) {
            if (*groupSubtree > 255)
              return 0; /* illegal value */
	    *cp++ = (char) *groupSubtree++;
	}
	*cp = 0;
	vacm_scanGroupInit();
	while ((gp = vacm_scanGroupNext()) != NULL) {
	    if (gp->securityModel > secmodel ||
		(gp->securityModel == secmodel && strcmp(gp->securityName, secname) > 0))
		break;
	}
	if (gp) {
	    name[11] = gp->securityModel;
	    *length = 12;
	    cp = gp->securityName;
	    while (*cp) {
		name[(*length)++] = *cp++;
	    }
	}
    }

    if (!gp && !exact) return NULL;

    *var_len =sizeof(long_return);
    switch (vp->magic) {
    case SECURITYMODEL:
	  if(gp)
	  {
	long_return = gp->securityModel;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case SECURITYNAME:
	  if(gp)
	  {
	*var_len = gp->securityName[0];
	return (u_char *)&gp->securityName[1];
	  }
	  return NULL;
    case SECURITYGROUP:
	  *write_method = write_vacmGroupName;
	  if(gp)
	  {
	*var_len = strlen(gp->groupName);
	return (u_char *)gp->groupName;
	  }
	  return NULL;
    case SECURITYSTORAGE:
	  *write_method = write_vacmSecurityToGroupStorageType;
	  if(gp)
	  {
	long_return = gp->storageType;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case SECURITYSTATUS:
	  *write_method = write_vacmSecurityToGroupStatus;
	  if(gp)
	  {
	long_return = gp->status;
	return (u_char *)&long_return;
    }
    return NULL;
    }
    return NULL;
}

u_char *var_vacm_access(struct variable *vp,
			oid *name,
			size_t *length,
			int exact,
			size_t *var_len,
			WriteMethod **write_method)
{
    struct vacm_accessEntry *gp;
    int secmodel;
    int seclevel;
    char groupName[32];
    char contextPrefix[32];
    oid *op;
    int len;
    char *cp;
    int cmp;

    *write_method = NULL;
    
    if (memcmp(name, vp->name, sizeof(oid)*vp->namelen) != 0) {
	memcpy(name, vp->name, sizeof(oid)*vp->namelen);
	*length = vp->namelen;
    }
	if (exact) 
	{
	if (*length < 15) return NULL;

	op = name+11;
	len = *op++;
	cp = groupName;
	while (len-- > 0) {
            if (*op > 255)
              return 0; /* illegal value */
	    *cp++ = (char) *op++;
	}
	*cp = 0;
	len = *op++;
	cp = contextPrefix;
	while (len-- > 0) {
            if (*op > 255)
              return 0; /* illegal value */
	    *cp++ = (char) *op++;
	}
	*cp = 0;
	secmodel = *op++;
	seclevel = *op++;
	if (op != name + *length) {
	    return NULL;
	}

	gp = vacm_getAccessEntry(groupName, contextPrefix, secmodel, seclevel);
    }
    else {
	secmodel = seclevel = 0;
	groupName[0] = 0;
	contextPrefix[0] = 0;
	op = name+11;
	if (op >= name + *length) {
	}
	else {
	    len = *op;
	    cp = groupName;
	    while (len-- >= 0) {
                if (*op > 255)
                  return 0; /* illegal value */
		*cp++ = (char) *op++;
	    }
	    *cp = 0;
	}
	if (op >= name + *length) {
	}
	else {
	    len = *op;
	    cp = contextPrefix;
	    while (len-- >= 0) {
                if (*op > 255)
                  return 0; /* illegal value */
		*cp++ = (char) *op++;
	    }
	    *cp = 0;
	}
	if (op >= name + *length) {
	}
	else {
	    secmodel = *op++;
	}
	if (op >= name + *length) {
	}
	else {
	    seclevel = *op++;
	}
	vacm_scanAccessInit();
	while ((gp = vacm_scanAccessNext()) != NULL) {
	    cmp = strcmp(gp->groupName, groupName);
	    if (cmp > 0) break;
	    if (cmp < 0) continue;
	    cmp = strcmp(gp->contextPrefix, contextPrefix);
	    if (cmp > 0) break;
	    if (cmp < 0) continue;
	    if (gp->securityModel > secmodel) break;
	    if (gp->securityModel < secmodel) continue;
	    if (gp->securityLevel > seclevel) break;
	}
	if (gp) {
	    *length = 11;
	    cp = gp->groupName;
	    do {
		name[(*length)++] = *cp++;
	    } while (*cp);
	    cp = gp->contextPrefix;
	    do {
		name[(*length)++] = *cp++;
	    } while (*cp);
	    name[(*length)++] = gp->securityModel;
	    name[(*length)++] = gp->securityLevel;
	}
    }

    if (!gp  && !exact) return NULL;
	
	

    *var_len =sizeof(long_return);
    switch (vp->magic) {
    case ACCESSMATCH:
	  *write_method = write_vacmAccessContextMatch;
	  if(gp)
	  {
	long_return = gp->contextMatch;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case ACCESSLEVEL:
	  if(gp)
	  {
	long_return = gp->securityLevel;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case ACCESSMODEL:
	  if(gp)
	  {
	long_return = gp->securityModel;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case ACCESSPREFIX:
	  if(gp)
	  {
	*var_len = *gp->contextPrefix;
	return (u_char *)&gp->contextPrefix[1];
	  }
	  return NULL;
    case ACCESSREAD:
	  *write_method = write_vacmAccessReadViewName;
	  if(gp)
	  {
	*var_len = strlen(gp->readView);
	return (u_char *)gp->readView;
	  }
	  return NULL;
    case ACCESSWRITE:
	  *write_method = write_vacmAccessWriteViewName;
	  if(gp)
	  {
	*var_len = strlen(gp->writeView);
	return (u_char *)gp->writeView;
	  }
	  return NULL;
    case ACCESSNOTIFY:
	  *write_method = write_vacmAccessNotifyViewName;
	  if(gp)
	  {
	*var_len = strlen(gp->notifyView);
	return (u_char *)gp->notifyView;
	  }
	  return NULL;
    case ACCESSSTORAGE:
	  *write_method = write_vacmAccessStorageType;
	  if(gp)
	  {
	long_return = gp->storageType;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case ACCESSSTATUS:
	  *write_method = write_vacmAccessStatus;
	  if(gp)
	  {
	long_return = gp->status;
	return (u_char *)&long_return;
    }
    return NULL;
    }
    return NULL;
}

u_char *var_vacm_view(struct variable *vp,
		      oid *name,
		      size_t *length,
		      int exact,
		      size_t *var_len,
		      WriteMethod **write_method)
{
    struct vacm_viewEntry *gp=NULL;
    char viewName[32];
    oid subtree[MAX_OID_LEN];
    size_t subtreeLen = 0;
    oid *op, *op1;
    int len;
    char *cp;
    int cmp,cmp2;

    *write_method = NULL;
    *var_len =sizeof(long_return);
    if(vp->magic != VACMVIEWSPINLOCK)
    {

    if (memcmp(name, vp->name, sizeof(oid)*vp->namelen) != 0) {
	memcpy(name, vp->name, sizeof(oid)*vp->namelen);
	*length = vp->namelen;
    }
    if (exact) {
	if (*length < 15) return NULL;

	op = name+12;
	len = *op++;
	cp = viewName;
	while (len-- > 0) {
            if (*op > 255)
              return 0; 
	    *cp++ = (char) *op++;
	}
	*cp = 0;
	len = *length - (op - name);
	op1 = subtree;
	while (len-- > 0) {
	    *op1++ = *op++;
	    subtreeLen++;
	}
	if (op != name + *length) {
	    return NULL;
	}

	gp = vacm_getViewEntry(viewName, subtree, subtreeLen);
	if(gp)
	  if(gp->viewSubtreeLen!=subtreeLen)
		  gp=NULL;
    }
    else {
	viewName[0] = 0;
	op = name+12;
	if (op >= name + *length) {
	}
	else {
	    len = *op;
	    cp = viewName;
	    while (len-- >= 0) {
                if (*op > 255)
                  return 0; 
		*cp++ = (char) *op++;
	    }
	    *cp = 0;
	}
	if (op >= name + *length) {
	}
	else {
	    len = *length - (op - name);
	    op1 = subtree;
	    while (len-- >= 0) {
		*op1++ = *op++;
		subtreeLen++;
	    }
	    subtreeLen--;
	}
	vacm_scanViewInit();
	while ((gp = vacm_scanViewNext()) != NULL) {
	    cmp = strcmp(gp->viewName, viewName);
	    cmp2= memcmp(gp->viewSubtree,subtree,sizeof(oid)*subtreeLen);
		if (cmp==0 && cmp2>0) break;
	    if (cmp > 0) break;
	    if (cmp < 0) continue;
	}
	if (gp) {
	    *length = 12;
	    cp = gp->viewName;
	    do {
		name[(*length)++] = *cp++;
	    } while (*cp);
	    op1 = gp->viewSubtree;
	    len = gp->viewSubtreeLen;
	    while (len-- > 0){
		name[(*length)++] = *op1++;
	    } 
	}
    }

    if (!gp && !exact) return NULL;
	
	} else {
	  if(header_generic(vp,name,length,exact,var_len,write_method))
		return NULL;
	} /*endif -- vp->magic != VACMVIEWSPINLOCK */

    switch (vp->magic) {
    case VACMVIEWSPINLOCK:
      *write_method = write_vacmViewSpinLock;
      long_return = vacmViewSpinLock;
      return (unsigned char *) &long_return;
    case VIEWNAME:
	  if(gp)
	  {
	*var_len = gp->viewName[0];
	return (u_char *)&gp->viewName[1];
	  }
	  return NULL;
    case VIEWSUBTREE:
	  if(gp)
	  {
	*var_len = gp->viewSubtreeLen*sizeof(oid);
	return (u_char *)gp->viewSubtree;
	  }
	  return NULL;
    case VIEWMASK:
	  *write_method=write_vacmViewMask;
	  if(gp)
	  {
	*var_len = (gp->viewSubtreeLen + 7) / 8;
	return (u_char *)gp->viewMask;
	  }
	  return NULL;
    case VIEWTYPE:
	  *write_method=write_vacmViewType;
	  if(gp)
	  {
	long_return = gp->viewType;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case VIEWSTORAGE:
	  *write_method=write_vacmViewStorageType; 
	  if(gp)
	  {
	long_return = gp->viewStorageType;
	return (u_char *)&long_return;
	  }
	  return NULL;
    case VIEWSTATUS:
	  *write_method=write_vacmViewStatus;
	  if(gp)
	  {
	long_return = gp->viewStatus;
	return (u_char *)&long_return;
    }
    return NULL;
    }
    return NULL;
}

oid *
sec2group_generate_OID(oid *prefix, size_t prefixLen, struct vacm_groupEntry *geptr,
                       size_t *length)
{
  oid *indexOid;
  int i,securityNameLen;

  securityNameLen=strlen(geptr->securityName);
  
  *length = 2 + securityNameLen + prefixLen;
  indexOid = (oid *) malloc(*length * sizeof(oid));
  if (indexOid) {
    memmove(indexOid, prefix, prefixLen * sizeof (oid));
    
    indexOid[prefixLen] = geptr->securityModel;

    indexOid[prefixLen+1]= securityNameLen;
    for(i = 0; i < securityNameLen; i++)
      indexOid[prefixLen+2+i] = (oid) geptr->securityName[i];

  }
  return indexOid;

}

int 
sec2group_parse_oid(oid *oidIndex, size_t oidLen,
              int *model, unsigned char **name, size_t *nameLen)
{
  int nameL;
  int i;

  /* first check the validity of the oid */
  if ((oidLen <= 0) || (!oidIndex)) {
    return 1;
  }
  nameL = oidIndex[1];	/* the initial name length */
  if ((int)oidLen != nameL + 2) {
    return 1;
  }

  /* its valid, malloc the space and store the results */
  if (name == NULL) {
    return 1;
  }

  *name = (unsigned char *) malloc(nameL+1);
  if (*name == NULL) {
    return 1;
  }
  
  *model = oidIndex[0];
  *nameLen = nameL;
  

  for(i = 0; i < nameL; i++) {
    if (oidIndex[i+2] > 255) {
      free(*name);
      return 1;
    }
    name[0][i] = (unsigned char) oidIndex[i+2];
  }
  name[0][nameL] = 0;
  
  return 0;

} 

struct vacm_groupEntry *
sec2group_parse_groupEntry(oid *name, size_t name_len)
{
  struct vacm_groupEntry *geptr;

  char *newName;
  int model;
  size_t nameLen;
  
  /* get the name and engineID out of the incoming oid */
  if (sec2group_parse_oid(&name[SEC2GROUP_MIB_LENGTH], name_len-SEC2GROUP_MIB_LENGTH,
                     &model, (u_char **)&newName, &nameLen))
    return NULL;

  /* Now see if a user exists with these index values */
  geptr = vacm_getGroupEntry(model, newName);
  free(newName);

  return geptr;

}  /* end vacm_parse_groupEntry() */

int
write_vacmGroupName(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
    /* variables we may use later */
  static unsigned char string[SNMP_MAXBUF];

  struct vacm_groupEntry *geptr;

  if (var_val_type != ASN_OCTET_STR){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmGroupName not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmGroupName: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT) {
    /* don't allow creations here */
    if ((geptr = sec2group_parse_groupEntry(name, name_len)) == NULL) {
      return SNMP_ERR_NOSUCHNAME;
    }
    memcpy(geptr->groupName, var_val, var_val_len);
    geptr->groupName[var_val_len] = 0;
  }
  
  return SNMP_ERR_NOERROR;
}

int
write_vacmSecurityToGroupStorageType(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  struct vacm_groupEntry *geptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((geptr = sec2group_parse_groupEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      long_ret = *((long *) var_val);
      if ((long_ret == ST_VOLATILE || long_ret == ST_NONVOLATILE) &&
          (geptr->storageType == ST_VOLATILE ||
           geptr->storageType == ST_NONVOLATILE))
        geptr->storageType = long_ret;
      else
        return SNMP_ERR_INCONSISTENTVALUE;
  }
  return SNMP_ERR_NOERROR;
}


int
write_vacmSecurityToGroupStatus(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{

  /* variables we may use later */
  static long long_ret;
  int model;
  char *newName;
  size_t nameLen;
  struct vacm_groupEntry *geptr;

  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStatus not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStatus: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
    long_ret = *((long *) var_val);

    /* ditch illegal values now */
    /* notReady can not be used, but the return error code is not mentioned */
    if (long_ret == RS_NOTREADY || long_ret < 1 || long_ret > 6)
      return SNMP_ERR_INCONSISTENTVALUE;
    
    /* see if we can parse the oid for model/name first */
    if (sec2group_parse_oid(&name[SEC2GROUP_MIB_LENGTH], name_len-SEC2GROUP_MIB_LENGTH,
                      &model, (u_char **)&newName, &nameLen))
      return SNMP_ERR_INCONSISTENTNAME;

    /* Now see if a group already exists with these index values */
    geptr = vacm_getGroupEntry(model, newName);


    if (geptr) {			/* If so, we set the appropriate value... */
      if (long_ret == RS_CREATEANDGO || long_ret == RS_CREATEANDWAIT) {
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        vacm_destroyGroupEntry(model,newName);        
      } else {
        geptr->status = long_ret;
      }
      free(newName);
    } else {			/* ...else we create a new group entry */
      /* check for a valid status column set */
      if (long_ret == RS_ACTIVE || long_ret == RS_NOTINSERVICE) {
        free(newName);
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        /* destroying a non-existent row is actually legal */
        free(newName);
        return SNMP_ERR_NOERROR;
      }

      /* generate a new group entry */
      if ((geptr = vacm_createGroupEntry(model,newName)) == NULL) {
        free(newName);
        return SNMP_ERR_GENERR;
      }

	  /*set default storage type*/
	  geptr->storageType = ST_NONVOLATILE;

      /* set the status of the row based on the request */
      if (long_ret == RS_CREATEANDGO)
        geptr->status = RS_ACTIVE;
      else if (long_ret == RS_CREATEANDWAIT)
        geptr->status = RS_NOTINSERVICE;

    }  /* endif -- uptr */
  }  /* endif -- action==COMMIT */

  return SNMP_ERR_NOERROR;
}

oid *
access_generate_OID(oid *prefix, size_t prefixLen, struct vacm_accessEntry *aptr,
                       size_t *length)
{
  oid *indexOid;
  int i,groupNameLen,contextPrefixLen;

  groupNameLen=strlen(aptr->groupName);
  contextPrefixLen=strlen(aptr->contextPrefix);

  *length = 4 + groupNameLen + contextPrefixLen + prefixLen;
  indexOid = (oid *) malloc(*length * sizeof(oid));
  if (indexOid) {
    memmove(indexOid, prefix, prefixLen * sizeof (oid));
  
  indexOid[prefixLen]=groupNameLen;    
  for(i = 0; i < groupNameLen; i++)
      indexOid[groupNameLen+1+i] = (oid) aptr->groupName[i];
      
  indexOid[prefixLen+groupNameLen+1]=contextPrefixLen;    
  for(i = 0; i < contextPrefixLen; i++)
      indexOid[prefixLen+groupNameLen+2+i] = (oid) aptr->contextPrefix[i];

  indexOid[prefixLen+groupNameLen+contextPrefixLen+3] = aptr->securityModel;
  indexOid[prefixLen+groupNameLen+contextPrefixLen+4] = aptr->securityLevel;

  }
  return indexOid;

}

int 
access_parse_oid(oid *oidIndex, size_t oidLen,
			  unsigned char **groupName, size_t *groupNameLen,
              unsigned char **contextPrefix, size_t *contextPrefixLen,
              int *model, int *level)
{
  int groupNameL,contextPrefixL;
  int i;

  /* first check the validity of the oid */
  if ((oidLen <= 0) || (!oidIndex)) {
    return 1;
  }
  groupNameL=oidIndex[0];
  contextPrefixL = oidIndex[groupNameL+1];	/* the initial name length */
  if ((int)oidLen != groupNameL+contextPrefixL + 4) {
    return 1;
  }

  /* its valid, malloc the space and store the results */
  if (contextPrefix == NULL || groupName == NULL) {
    return 1;
  }

  *groupName = (unsigned char *) malloc(groupNameL+1);
  if (*groupName == NULL) {
    return 1;
  }
  
  *contextPrefix = (unsigned char *) malloc(contextPrefixL+1);
  if (*contextPrefix == NULL) {
	  free(*groupName);
    return 1;
  }
    
  *contextPrefixLen = contextPrefixL;
  *groupNameLen = groupNameL;

  for(i = 0; i < groupNameL; i++) {
    if (oidIndex[i+1] > 255) {
      free(*groupName);
      free(*contextPrefix);
      return 1;
    }
    groupName[0][i] = (unsigned char) oidIndex[i+1];
  }
  groupName[0][groupNameL] = 0;
  

  for(i = 0; i < contextPrefixL; i++) {
    if (oidIndex[i+groupNameL+2] > 255) {
	  free(*groupName);
      free(*contextPrefix);
      return 1;
    }
    contextPrefix[0][i] = (unsigned char) oidIndex[i+groupNameL+2];
  }
  contextPrefix[0][contextPrefixL] = 0;
  
  *model = oidIndex[groupNameL+contextPrefixL+2];
  *level = oidIndex[groupNameL+contextPrefixL+3];
 
  return 0;

} 

struct vacm_accessEntry *
access_parse_accessEntry(oid *name, size_t name_len)
{
  struct vacm_accessEntry *aptr;

  char *newGroupName;
  char *newContextPrefix;
  int model,level;
  size_t groupNameLen,contextPrefixLen;
  
  /* get the name and engineID out of the incoming oid */
  if (access_parse_oid(&name[ACCESS_MIB_LENGTH], name_len-ACCESS_MIB_LENGTH,
					  (u_char **)&newGroupName, &groupNameLen,
					  (u_char **)&newContextPrefix, &contextPrefixLen,
					  &model, &level))
    return NULL;

  /* Now see if a user exists with these index values */
  aptr = vacm_getAccessEntry(newGroupName, newContextPrefix, model, level);
  free(newContextPrefix);
  free(newGroupName);
  
  return aptr;

}  /* end vacm_parse_accessEntry() */

int
write_vacmAccessStatus(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{

  /* variables we may use later */
  static long long_ret;
  int model,level;
  char *newGroupName,*newContextPrefix;
  size_t groupNameLen,contextPrefixLen;
  struct vacm_accessEntry *aptr;

  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStatus not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStatus: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
    long_ret = *((long *) var_val);

    /* ditch illegal values now */
    /* notReady can not be used, but the return error code is not mentioned */
    if (long_ret == RS_NOTREADY || long_ret < 1 || long_ret > 6)
      return SNMP_ERR_INCONSISTENTVALUE;
    
    /* see if we can parse the oid for model/name first */
    if (access_parse_oid(&name[ACCESS_MIB_LENGTH], name_len-ACCESS_MIB_LENGTH,
                      (u_char **)&newGroupName, &groupNameLen,
                      (u_char **)&newContextPrefix, &contextPrefixLen,
                      &model,&level))
      return SNMP_ERR_INCONSISTENTNAME;

    /* Now see if a group already exists with these index values */
    aptr = vacm_getAccessEntry(newGroupName,newContextPrefix,model,level);


    if (aptr) {			/* If so, we set the appropriate value... */
      if (long_ret == RS_CREATEANDGO || long_ret == RS_CREATEANDWAIT) {
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        vacm_destroyAccessEntry(newGroupName,newContextPrefix,model,level);
      } else {
        aptr->status = long_ret;
      }
      free(newGroupName);
      free(newContextPrefix);
    } else {			/* ...else we create a new group entry */
      /* check for a valid status column set */
      if (long_ret == RS_ACTIVE || long_ret == RS_NOTINSERVICE) {
        free(newGroupName);
        free(newContextPrefix);
        return SNMP_ERR_INCONSISTENTVALUE;
      }
      if (long_ret == RS_DESTROY) {
        /* destroying a non-existent row is actually legal */
        free(newGroupName);
        free(newContextPrefix);
        return SNMP_ERR_NOERROR;
      }

      /* generate a new group entry */
      if ((aptr = vacm_createAccessEntry(newGroupName,newContextPrefix,model,level)) == NULL) {
        free(newGroupName);
        free(newContextPrefix);
        return SNMP_ERR_GENERR;
      }

	  /*set default storage type*/
	  /*This version only supports volatile storage*/
	  aptr->storageType = ST_NONVOLATILE;

      /* set the status of the row based on the request */
      if (long_ret == RS_CREATEANDGO)
        aptr->status = RS_ACTIVE;
      else if (long_ret == RS_CREATEANDWAIT)
        aptr->status = RS_NOTINSERVICE;

    }  /* endif -- uptr */
  }  /* endif -- action==COMMIT */

  return SNMP_ERR_NOERROR;
}

int
write_vacmAccessStorageType(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  struct vacm_accessEntry *aptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((aptr = access_parse_accessEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      long_ret = *((long *) var_val);
/*      if ((long_ret == ST_VOLATILE || long_ret == ST_NONVOLATILE) &&
          (aptr->storageType == ST_VOLATILE ||
           aptr->storageType == ST_NONVOLATILE)) */
	  /*This version only supports volatile storage*/ 
	  if (long_ret == ST_VOLATILE &&
          aptr->storageType == ST_VOLATILE)           
        aptr->storageType = long_ret;
      else
        return SNMP_ERR_INCONSISTENTVALUE;
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmAccessContextMatch(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  struct vacm_accessEntry *aptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessContextMatch not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessContextMatch: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((aptr = access_parse_accessEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      long_ret = *((long *) var_val);
      if (long_ret == CM_EXACT || long_ret == CM_PREFIX)
        aptr->contextMatch = long_ret;
      else
        return SNMP_ERR_INCONSISTENTVALUE;
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmAccessReadViewName(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static unsigned char string[VACMSTRINGLEN];
  struct vacm_accessEntry *aptr;
  
  if (var_val_type != ASN_OCTET_STR){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessReadViewName not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessReadViewName: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((aptr = access_parse_accessEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      
      memcpy(aptr->readView, var_val, var_val_len);
	  aptr->readView[var_val_len] = 0;
           
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmAccessWriteViewName(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static unsigned char string[VACMSTRINGLEN];
  struct vacm_accessEntry *aptr;
  
  if (var_val_type != ASN_OCTET_STR){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessWriteViewName not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessWriteViewName: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((aptr = access_parse_accessEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      
      memcpy(aptr->writeView, var_val, var_val_len);
	  aptr->writeView[var_val_len] = 0;
   
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmAccessNotifyViewName(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static unsigned char string[VACMSTRINGLEN];
  struct vacm_accessEntry *aptr;
  
  if (var_val_type != ASN_OCTET_STR){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessNotifyViewName not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmAccessNotifyViewName: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((aptr = access_parse_accessEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      
      memcpy(aptr->notifyView, var_val, var_val_len);
	  aptr->notifyView[var_val_len] = 0;
      
  }
  return SNMP_ERR_NOERROR;
}

int 
view_parse_oid(oid *oidIndex, size_t oidLen,
			  unsigned char **viewName, size_t *viewNameLen,
              oid **subtree, size_t *subtreeLen)
{
  int viewNameL,subtreeL;
  int i;

  /* first check the validity of the oid */
  if ((oidLen <= 0) || (!oidIndex)) {
    return 1;
  }
  viewNameL=oidIndex[0];
  subtreeL = oidLen-viewNameL-1;	/* the initial name length */
 
  /* its valid, malloc the space and store the results */
  if (viewName == NULL || subtree == NULL) {
    return 1;
  }

  
  *viewName = (unsigned char *) malloc(viewNameL+1);

  if (*viewName == NULL) {
    return 1;
  }
  
  *subtree = (oid *) malloc(sizeof(oid)*subtreeL);        
  if (*subtree == NULL) {
	  free(*viewName);
    return 1;
  }
    
  *subtreeLen = subtreeL;
  *viewNameLen = viewNameL;

  for(i = 0; i < viewNameL; i++) {
    if (oidIndex[i+1] > 255) {
      free(*viewName);
      free(*subtree);
      return 1;
    }
    viewName[0][i] = (unsigned char) oidIndex[i+1];
  }
  viewName[0][viewNameL] = 0;
  
  
  for(i = 0; i < subtreeL; i++) {  
    if (oidIndex[i+viewNameL+1] > 255) {
	  free(*viewName);
      free(*subtree);
      return 1;
    }
    subtree[0][i] = (oid) oidIndex[i+viewNameL+1];
  }

  return 0;

} 

oid *
view_generate_OID(oid *prefix, size_t prefixLen, struct vacm_viewEntry *vptr,
                       size_t *length)
{
  oid *indexOid;
  int i,viewNameLen,viewSubtreeLen;

  viewNameLen=strlen(vptr->viewName);
  viewSubtreeLen=vptr->viewSubtreeLen;

  *length = 2 + viewNameLen + viewSubtreeLen + prefixLen;
  indexOid = (oid *) malloc(*length * sizeof(oid));
  if (indexOid) {
    memmove(indexOid, prefix, prefixLen * sizeof (oid));
  
  indexOid[prefixLen]=viewNameLen;    
  for(i = 0; i < viewNameLen; i++)
      indexOid[viewNameLen+1+i] = (oid) vptr->viewName[i];
      
  indexOid[prefixLen+viewNameLen+1]=viewSubtreeLen;    
  for(i = 0; i < viewSubtreeLen; i++)
      indexOid[prefixLen+viewNameLen+2+i] = (oid) vptr->viewSubtree[i];

  }
  return indexOid;

}

struct vacm_viewEntry *
view_parse_viewEntry(oid *name, size_t name_len)
{
  struct vacm_viewEntry *vptr;

  char *newViewName;
  oid *newViewSubtree;
  size_t viewNameLen,viewSubtreeLen;
  
  if (view_parse_oid(&name[VIEW_MIB_LENGTH], name_len-VIEW_MIB_LENGTH,
					  (u_char **)&newViewName, &viewNameLen,
					  (oid **)&newViewSubtree, &viewSubtreeLen))
    return NULL;

  vptr = vacm_getViewEntry(newViewName, newViewSubtree, viewSubtreeLen);
  free(newViewName);
  free(newViewSubtree);
  
  return vptr;

}  /* end vacm_parse_viewEntry() */

int
write_vacmViewStatus(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{

  /* variables we may use later */
  static long long_ret;
  char *newViewName;
  oid *newViewSubtree;
  size_t viewNameLen,viewSubtreeLen;
  struct vacm_viewEntry *vptr;

  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewStatus not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewStatus: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
    long_ret = *((long *) var_val);

    /* ditch illegal values now */
    /* notReady can not be used, but the return error code is not mentioned */
    if (long_ret == RS_NOTREADY || long_ret < 1 || long_ret > 6)
      return SNMP_ERR_INCONSISTENTVALUE;
    
    /* see if we can parse the oid for model/name first */
    if (view_parse_oid(&name[VIEW_MIB_LENGTH], name_len-VIEW_MIB_LENGTH,
                      (u_char **)&newViewName, &viewNameLen,
                      (oid **)&newViewSubtree, &viewSubtreeLen))      
      return SNMP_ERR_INCONSISTENTNAME;		
	
	
    /* Now see if a group already exists with these index values */
    vptr = vacm_getViewEntry(newViewName, newViewSubtree, viewSubtreeLen);
    
    if (vptr)
	  {			/* If so, we set the appropriate value... */
		if (long_ret == RS_CREATEANDGO || long_ret == RS_CREATEANDWAIT) 
		{
		  return SNMP_ERR_INCONSISTENTVALUE;
		}
		if (long_ret == RS_DESTROY) 
		{
		  vacm_destroyViewEntry(newViewName, newViewSubtree, viewSubtreeLen);        
		} 
		else 
		{
		  vptr->viewStatus = long_ret;
		}
	  } 
	  else 
	  {			/* ...else we create a new group entry */
		/* check for a valid status column set */
		if (long_ret == RS_ACTIVE || long_ret == RS_NOTINSERVICE) {
          free(newViewName);
          free(newViewSubtree);
          return SNMP_ERR_INCONSISTENTVALUE;
		}
		
		if (long_ret == RS_DESTROY) {
		  /* destroying a non-existent row is actually legal */
		  free(newViewName);
          free(newViewSubtree);        
          return SNMP_ERR_NOERROR;
        }

	    /* generate a new group entry */
        if ((vptr = vacm_createViewEntry(newViewName,newViewSubtree,viewSubtreeLen)) == NULL) {
		  free(newViewName);
          free(newViewSubtree);
		  return SNMP_ERR_GENERR;
		}
		
		/*set default storage type*/
		vptr->viewStorageType = ST_NONVOLATILE;
		
		/* set the status of the row based on the request */
		if (long_ret == RS_CREATEANDGO)
		  vptr->viewStatus = RS_ACTIVE;
		else if (long_ret == RS_CREATEANDWAIT)
		  vptr->viewStatus = RS_NOTINSERVICE;

	  }  /* endif -- uptr */
	free(newViewName);
	free(newViewSubtree);
    }  /* endif -- action==COMMIT */

  return SNMP_ERR_NOERROR;
}

int
write_vacmViewStorageType(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  struct vacm_viewEntry *vptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmSecurityToGroupStorageType: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((vptr = view_parse_viewEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      long_ret = *((long *) var_val);
      
      if ((long_ret == ST_VOLATILE || long_ret == ST_NONVOLATILE) &&
          (vptr->viewStorageType == ST_VOLATILE ||
           vptr->viewStorageType == ST_NONVOLATILE))
		vptr->viewStorageType = long_ret;
      else
        return SNMP_ERR_INCONSISTENTVALUE;
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmViewMask(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static unsigned char string[VACMSTRINGLEN];
  struct vacm_viewEntry *vptr;
  
  if (var_val_type != ASN_OCTET_STR){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewTreeFamilyMask not ASN_OCTET_STR\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(string)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewTreeFamilyMask: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((vptr = view_parse_viewEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      
      memcpy(vptr->viewMask, var_val, var_val_len);
      vptr->viewMaskLen = var_val_len;   
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmViewType(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;
  struct vacm_viewEntry *vptr;
  
  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewTreeFamilyType not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewTreeFamilyType: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  if (action == COMMIT){
      /* don't allow creations here */
      if ((vptr = view_parse_viewEntry(name, name_len)) == NULL) {
        return SNMP_ERR_NOSUCHNAME;
      }
      
      long_ret=*((long *) var_val);
	  vptr->viewType=long_ret;
  }
  return SNMP_ERR_NOERROR;
}

int
write_vacmViewSpinLock(
   int      action,
   u_char   *var_val,
   u_char   var_val_type,
   size_t   var_val_len,
   u_char   *statP,
   oid      *name,
   size_t   name_len)
{
  /* variables we may use later */
  static long long_ret;

  if (var_val_type != ASN_INTEGER){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewSpinLock not ASN_INTEGER\n"));
      return SNMP_ERR_WRONGTYPE;
  }
  if (var_val_len > sizeof(long_ret)){
      DEBUGMSGTL(("mibII/vacm_vars","write to vacmViewSpinLock: bad length\n"));
      return SNMP_ERR_WRONGLENGTH;
  }
  long_ret = *((long *) var_val);
  if (long_ret != (long)vacmViewSpinLock)
    return SNMP_ERR_INCONSISTENTVALUE;
  if (action == COMMIT) {
    if (vacmViewSpinLock == 2147483647)
      vacmViewSpinLock = 0;
    else
      vacmViewSpinLock++;
  }
  return SNMP_ERR_NOERROR;
}  /* end write_vacmViewSpinLock() */
