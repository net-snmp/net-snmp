/*
 * SNMPv3 View-based Access Control Model
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <net-snmp/net-snmp-config.h>

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

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/agent_callbacks.h>
#include "vacm_conf.h"
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

void
init_vacm_conf(void)
{
    snmpd_register_config_handler("group", vacm_parse_group,
                                  vacm_free_group,
                                  "name v1|v2c|usm|... security");
    snmpd_register_config_handler("access", vacm_parse_access,
                                  vacm_free_access,
                                  "name context model level prefx read write notify");
    snmpd_register_config_handler("view", vacm_parse_view, vacm_free_view,
                                  "name type subtree [mask]");
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
    snmpd_register_config_handler("rwcommunity", vacm_parse_simple, NULL,
                                  "community [default|hostname|network/bits [oid]]");
    snmpd_register_config_handler("rocommunity", vacm_parse_simple, NULL,
                                  "community [default|hostname|network/bits [oid]]");
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
    snmpd_register_config_handler("rwcommunity6", vacm_parse_simple, NULL,
                                  "community [default|hostname|network/bits [oid]]");
    snmpd_register_config_handler("rocommunity6", vacm_parse_simple, NULL,
                                  "community [default|hostname|network/bits [oid]]");
#endif
#endif /* support for community based SNMP */
    snmpd_register_config_handler("rwuser", vacm_parse_simple, NULL,
                                  "user [noauth|auth|priv [oid]]");
    snmpd_register_config_handler("rouser", vacm_parse_simple, NULL,
                                  "user [noauth|auth|priv [oid]]");
    snmpd_register_config_handler("vacmView", vacm_parse_config_view, NULL,
                                  NULL);
    snmpd_register_config_handler("vacmGroup", vacm_parse_config_group,
                                  NULL, NULL);
    snmpd_register_config_handler("vacmAccess", vacm_parse_config_access,
                                  NULL, NULL);


    /*
     * register ourselves to handle access control 
     */
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_ACM_CHECK, vacm_in_view_callback,
                           NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_ACM_CHECK_INITIAL,
                           vacm_in_view_callback, NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_ACM_CHECK_SUBTREE,
                           vacm_in_view_callback, NULL);
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_READ_CONFIG,
                           vacm_warn_if_not_configured, NULL);
}



void
vacm_parse_group(const char *token, char *param)
{
    char           *group, *model, *security;
    int             imodel;
    struct vacm_groupEntry *gp = NULL;
    char           *st;

    group = strtok_r(param, " \t\n", &st);
    model = strtok_r(NULL, " \t\n", &st);
    security = strtok_r(NULL, " \t\n", &st);

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
    if (strcasecmp(model, "v1") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv2c;
    else if (strcasecmp(model, "any") == 0) {
        config_perror
            ("bad security model \"any\" should be: v1, v2c, usm or a registered security plugin name - installing anyway");
        imodel = SNMP_SEC_MODEL_ANY;
    } else {
        if ((imodel = se_find_value_in_slist("snmp_secmods", model)) ==
            SE_DNE) {
            config_perror
                ("bad security model, should be: v1, v2c or usm or a registered security plugin name");
            return;
        }
    }
    if (strlen(security) + 1 > sizeof(gp->groupName)) {
        config_perror("security name too long");
        return;
    }
    gp = vacm_createGroupEntry(imodel, security);
    if (!gp) {
        config_perror("failed to create group entry");
        return;
    }
    strncpy(gp->groupName, group, sizeof(gp->groupName));
    gp->groupName[ sizeof(gp->groupName)-1 ] = 0;
    gp->storageType = SNMP_STORAGE_PERMANENT;
    gp->status = SNMP_ROW_ACTIVE;
    free(gp->reserved);
    gp->reserved = NULL;
}

void
vacm_free_group(void)
{
    vacm_destroyAllGroupEntries();
}

void
vacm_parse_access(const char *token, char *param)
{
    char           *name, *context, *model, *level, *prefix, *readView,
        *writeView, *notify;
    int             imodel, ilevel, iprefix;
    struct vacm_accessEntry *ap;
    char   *st;

    name = strtok_r(param, " \t\n", &st);
    if (!name) {
        config_perror("missing NAME parameter");
        return;
    }
    context = strtok_r(NULL, " \t\n", &st);
    if (!context) {
        config_perror("missing CONTEXT parameter");
        return;
    }
    model = strtok_r(NULL, " \t\n", &st);
    if (!model) {
        config_perror("missing MODEL parameter");
        return;
    }
    level = strtok_r(NULL, " \t\n", &st);
    if (!level) {
        config_perror("missing LEVEL parameter");
        return;
    }
    prefix = strtok_r(NULL, " \t\n", &st);
    if (!prefix) {
        config_perror("missing PREFIX parameter");
        return;
    }
    readView = strtok_r(NULL, " \t\n", &st);
    if (!readView) {
        config_perror("missing readView parameter");
        return;
    }
    writeView = strtok_r(NULL, " \t\n", &st);
    if (!writeView) {
        config_perror("missing writeView parameter");
        return;
    }
    notify = strtok_r(NULL, " \t\n", &st);
    if (!notify) {
        config_perror("missing notifyView parameter");
        return;
    }
    if (strcmp(context, "\"\"") == 0)
        *context = 0;
    if (strcasecmp(model, "any") == 0)
        imodel = SNMP_SEC_MODEL_ANY;
    else if (strcasecmp(model, "v1") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv2c;
    else {
        if ((imodel = se_find_value_in_slist("snmp_secmods", model)) ==
            SE_DNE) {
            config_perror
                ("bad security model, should be: v1, v2c or usm or a registered security plugin name");
            return;
        }
    }
    if (strcasecmp(level, "noauth") == 0)
        ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "noauthnopriv") == 0)
        ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "auth") == 0)
        ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "authnopriv") == 0)
        ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "priv") == 0)
        ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else if (strcasecmp(level, "authpriv") == 0)
        ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else {
        config_perror
            ("bad security level (noauthnopriv, authnopriv, authpriv)");
        return;
    }
    if (strcmp(prefix, "exact") == 0)
        iprefix = 1;
    else if (strcmp(prefix, "prefix") == 0)
        iprefix = 2;
    else if (strcmp(prefix, "0") == 0) {
        config_perror
            ("bad prefix match parameter \"0\", should be: exact or prefix - installing anyway");
        iprefix = 1;
    } else {
        config_perror
            ("bad prefix match parameter, should be: exact or prefix");
        return;
    }
    if (strlen(readView) + 1 > sizeof(ap->readView)) {
        config_perror("readView too long");
        return;
    }
    if (strlen(writeView) + 1 > sizeof(ap->writeView)) {
        config_perror("writeView too long");
        return;
    }
    if (strlen(notify) + 1 > sizeof(ap->notifyView)) {
        config_perror("notifyView too long");
        return;
    }
    ap = vacm_createAccessEntry(name, context, imodel, ilevel);
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
    free(ap->reserved);
    ap->reserved = NULL;
}

void
vacm_free_access(void)
{
    vacm_destroyAllAccessEntries();
}

void
vacm_parse_view(const char *token, char *param)
{
    char           *name, *type, *subtree, *mask;
    int             inclexcl;
    struct vacm_viewEntry *vp;
    oid             suboid[MAX_OID_LEN];
    size_t          suboid_len = 0;
    u_char          viewMask[sizeof(vp->viewMask)];
    int             i;
    char            *st;

    name = strtok_r(param, " \t\n", &st);
    if (!name) {
        config_perror("missing NAME parameter");
        return;
    }
    type = strtok_r(NULL, " \n\t", &st);
    if (!type) {
        config_perror("missing TYPE parameter");
        return;
    }
    subtree = strtok_r(NULL, " \t\n", &st);
    if (!subtree) {
        config_perror("missing SUBTREE parameter");
        return;
    }
    mask = strtok_r(NULL, "\0", &st);

    if (strcmp(type, "included") == 0)
        inclexcl = SNMP_VIEW_INCLUDED;
    else if (strcmp(type, "excluded") == 0)
        inclexcl = SNMP_VIEW_EXCLUDED;
    else {
        config_perror("TYPE must be included/excluded?");
        return;
    }
    suboid_len = strlen(subtree)-1;
    if (subtree[suboid_len] == '.')
        subtree[suboid_len] = '\0';   /* stamp on a trailing . */
    suboid_len = MAX_OID_LEN;
    if (!snmp_parse_oid(subtree, suboid, &suboid_len)) {
        config_perror("bad SUBTREE object id");
        return;
    }
    if (mask) {
        int             val;
        i = 0;
        for (mask = strtok_r(mask, " .:", &st); mask; mask = strtok_r(NULL, " .:", &st)) {
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
    } else {
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
    free(vp->reserved);
    vp->reserved = NULL;
}

void
vacm_free_view(void)
{
    vacm_destroyAllViewEntries();
}

void
vacm_parse_simple(const char *token, char *confline)
{
    char            line[SPRINT_MAX_LEN];
    char            community[COMMUNITY_MAX_LEN];
    char            theoid[SPRINT_MAX_LEN];
    char            viewname[SPRINT_MAX_LEN];
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
    char            addressname[SPRINT_MAX_LEN];
#endif
    const char     *rw = "none";
    char            model[SPRINT_MAX_LEN];
    char           *cp;
    static int      num = 0;
    char            secname[SPRINT_MAX_LEN];
    char            authtype[SPRINT_MAX_LEN];

    /*
     * init 
     */
    strcpy(model, "any");

    /*
     * community name or user name 
     */
    cp = copy_nword(confline, community, sizeof(community));

    if (strcmp(token, "rouser") == 0 || strcmp(token, "rwuser") == 0) {
        /*
         * maybe security model type 
         */
        if (strcmp(community, "-s") == 0) {
            /*
             * -s model ... 
             */
            if (cp)
                cp = copy_nword(cp, model, sizeof(authtype));
            if (!cp) {
                config_perror("illegal line");
                return;
            }
            if (cp)
                cp = copy_nword(cp, community, sizeof(community));
        } else {
            strcpy(model, "usm");
        }
        /*
         * authentication type 
         */
        if (cp && *cp)
            cp = copy_nword(cp, authtype, sizeof(authtype));
        else
            strcpy(authtype, "auth");
        DEBUGMSGTL((token, "setting auth type: \"%s\"\n", authtype));
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
    } else {
        /*
         * source address 
         */
        if (cp && *cp) {
            cp = copy_nword(cp, addressname, sizeof(addressname));
        } else {
            strcpy(addressname, "default");
        }
        /*
         * authtype has to be noauth 
         */
        strcpy(authtype, "noauth");
#endif /* support for community based SNMP */
    }

    /*
     * oid they can touch 
     */
    if (cp && *cp) {
        cp = copy_nword(cp, theoid, sizeof(theoid));
    } else {
        strcpy(theoid, ".1");
    }

    if (
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
        strcmp(token, "rwcommunity") == 0 ||
#endif /* support for community based SNMP */
        strcmp(token, "rwuser") == 0)
        rw = viewname;

#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
    if (strcmp(token, "rwcommunity6") == 0)
        rw = viewname;
#endif

    if (strcmp(token, "rwcommunity") == 0
        || strcmp(token, "rocommunity") == 0) {
        /*
         * com2sec mapping 
         */
        /*
         * com2sec anonymousSecNameNUM    ADDRESS  COMMUNITY 
         */
        sprintf(secname, "comm%.27s", community);
        sprintf(viewname,"viewComm%.23s",community);
        snprintf(line, sizeof(line), "%s %s '%s'",
                 secname, addressname, community);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "com2sec", line));
        netsnmp_udp_parse_security("com2sec", line);

#ifdef SNMP_TRANSPORT_UNIX_DOMAIN
        snprintf(line, sizeof(line), "%s %s '%s'",
                 secname, addressname, community);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "com2secunix", line));
        netsnmp_unix_parse_security("com2secunix", line);
#endif
        /*
         * sec->group mapping 
         */
        /*
         * group   anonymousGroupNameNUM  any      anonymousSecNameNUM 
         */
        snprintf(line, sizeof(line),
                 "grp%.28s v1 %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "group", line));
        vacm_parse_group("group", line);
        snprintf(line, sizeof(line),
                 "grp%.28s v2c %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "group", line));
        vacm_parse_group("group", line);
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
    } else if (strcmp(token, "rwcommunity6") == 0
               || strcmp(token, "rocommunity6") == 0) {
        /*
         * com2sec6 mapping 
         */
        /*
         * com2sec6 anonymousSecNameNUM    ADDRESS  COMMUNITY 
         */
        sprintf(secname, "comm%.27s", community);
        sprintf(viewname,"viewComm%.23s",community);
        snprintf(line, sizeof(line), "%s %s '%s'",
                 secname, addressname, community);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "com2sec6", line));
        netsnmp_udp6_parse_security("com2sec6", line);

        /*
         * sec->group mapping 
         */
        /*
         * group   anonymousGroupNameNUM  any      anonymousSecNameNUM 
         */
        snprintf(line, sizeof(line),
                 "grp%.28s v1 %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "group", line));
        vacm_parse_group("group", line);
        snprintf(line, sizeof(line),
                 "grp%.28s v2c %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "group", line));
        vacm_parse_group("group", line);
#endif
    } else
#endif /* support for community based SNMP */
    {
        sprintf(viewname,"viewUSM%.24s",community);
        strncpy(secname, community, sizeof(secname));
        secname[ sizeof(secname)-1 ] = 0;

        /*
         * sec->group mapping 
         */
        /*
         * group   anonymousGroupNameNUM  any      anonymousSecNameNUM 
         */
        snprintf(line, sizeof(line),
                 "grp%.28s %s %s", secname, model, secname);
        line[ sizeof(line)-1 ] = 0;
        DEBUGMSGTL((token, "passing: %s %s\n", "group", line));
        vacm_parse_group("group", line);
    }

    /*
     * view definition 
     */
    /*
     * view    anonymousViewNUM       included OID 
     */
    snprintf(line, sizeof(line), "%s included %s", viewname, theoid);
    line[ sizeof(line)-1 ] = 0;
    DEBUGMSGTL((token, "passing: %s %s\n", "view", line));
    vacm_parse_view("view", line);

    /*
     * map everything together 
     */
    /*
     * access  anonymousGroupNameNUM  "" MODEL AUTHTYPE prefix anonymousViewNUM [none/anonymousViewNUM] [none/anonymousViewNUM] 
     */
    snprintf(line, sizeof(line),
            "grp%.28s  \"\" %s %s prefix %s %s %s",
            secname, model, authtype, viewname, rw, rw);
    line[ sizeof(line)-1 ] = 0;
    DEBUGMSGTL((token, "passing: %s %s\n", "access", line));
    vacm_parse_access("access", line);
    num++;
}

int
vacm_warn_if_not_configured(int majorID, int minorID, void *serverarg,
                            void *clientarg)
{
    const char * name = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID, 
                                        NETSNMP_DS_LIB_APPTYPE);
    if (NULL==name)
        name = "snmpd";
    
    if (!vacm_is_configured()) {
        snmp_log(LOG_WARNING,
                 "Warning: no access control information configured.\n  It's "
                 "unlikely this agent can serve any useful purpose in this "
                 "state.\n  Run \"snmpconf -g basic_setup\" to help you "
                 "configure the %s.conf file for this agent.\n", name );
    }
    return SNMP_ERR_NOERROR;
}

int
vacm_in_view_callback(int majorID, int minorID, void *serverarg,
                      void *clientarg)
{
    struct view_parameters *view_parms =
        (struct view_parameters *) serverarg;
    int             retval;

    if (view_parms == NULL)
        return 1;
    retval = vacm_in_view(view_parms->pdu, view_parms->name,
                          view_parms->namelen, view_parms->check_subtree);
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
 *       check_subtree
 *      
 * Returns:
 *	0	On success.
 *	1	Missing security name.
 *	2	Missing group
 *	3	Missing access
 *	4	Missing view
 *	5	Not in view
 *      6       No Such Context
 *      7       When testing an entire subtree, UNKNOWN (ie, the entire
 *              subtree has both allowed and disallowed portions)
 *
 * Debug output listed as follows:
 *	<securityName> <groupName> <viewName> <viewType>
 */
int
vacm_in_view(netsnmp_pdu *pdu, oid * name, size_t namelen,
             int check_subtree)
{
    struct vacm_accessEntry *ap;
    struct vacm_groupEntry *gp;
    struct vacm_viewEntry *vp;
    char            vacm_default_context[1] = "";
    char           *contextName = vacm_default_context;
    char           *vn;
    char           *sn = NULL;
    /*
     * len defined by the vacmContextName object 
     */
#define CONTEXTNAMEINDEXLEN 32
    char            contextNameIndex[CONTEXTNAMEINDEXLEN + 1];

#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
    if (pdu->version == SNMP_VERSION_1 || pdu->version == SNMP_VERSION_2c) {
        if (snmp_get_do_debugging()) {
            char           *buf;
            if (pdu->community) {
                buf = (char *) malloc(1 + pdu->community_len);
                memcpy(buf, pdu->community, pdu->community_len);
                buf[pdu->community_len] = '\0';
            } else {
                DEBUGMSGTL(("mibII/vacm_vars", "NULL community"));
                buf = strdup("NULL");
            }

            DEBUGMSGTL(("mibII/vacm_vars",
                        "vacm_in_view: ver=%d, community=%s\n",
                        pdu->version, buf));
            free(buf);
        }

        /*
         * Okay, if this PDU was received from a UDP or a TCP transport then
         * ask the transport abstraction layer to map its source address and
         * community string to a security name for us.  
         */

        if (pdu->tDomain == netsnmpUDPDomain
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
            || pdu->tDomain == netsnmp_snmpTCPDomain
#endif
            ) {
            if (!netsnmp_udp_getSecName(pdu->transport_data,
                                        pdu->transport_data_length,
                                        (char *) pdu->community,
                                        pdu->community_len, &sn,
                                        &contextName)) {
                /*
                 * There are no com2sec entries.  
                 */
                sn = NULL;
            }
            /* force the community -> context name mapping here */
            SNMP_FREE(pdu->contextName);
            pdu->contextName = strdup(contextName);
            pdu->contextNameLen = strlen(contextName);
#ifdef SNMP_TRANSPORT_UDPIPV6_DOMAIN
        } else if (pdu->tDomain == netsnmp_UDPIPv6Domain
#ifdef SNMP_TRANSPORT_TCPIPV6_DOMAIN
                   || pdu->tDomain == netsnmp_TCPIPv6Domain
#endif
            ) {
            if (!netsnmp_udp6_getSecName(pdu->transport_data,
                                         pdu->transport_data_length,
                                         (char *) pdu->community,
                                         pdu->community_len, &sn,
                                         &contextName)) {
                /*
                 * There are no com2sec entries.  
                 */
                sn = NULL;
            }
            /* force the community -> context name mapping here */
            SNMP_FREE(pdu->contextName);
            pdu->contextName = strdup(contextName);
            pdu->contextNameLen = strlen(contextName);
#endif
#ifdef SNMP_TRANSPORT_UNIX_DOMAIN
        } else if (pdu->tDomain == netsnmp_UnixDomain){
            if (!netsnmp_unix_getSecName(pdu->transport_data,
                                         pdu->transport_data_length,
                                         (char *) pdu->community,
                                         pdu->community_len, &sn,
                                         &contextName)) {
					sn = NULL;
            }
            /* force the community -> context name mapping here */
            SNMP_FREE(pdu->contextName);
            pdu->contextName = strdup(contextName);
            pdu->contextNameLen = strlen(contextName);
#endif	
        } else {
            /*
             * Map other <community, transport-address> pairs to security names
             * here.  For now just let non-IPv4 transport always succeed.
             * 
             * WHAAAATTTT.  No, we don't let non-IPv4 transports
             * succeed!  You must fix this to make it usable, sorry.
             * From a security standpoint this is insane. -- Wes
             */
            /** @todo alternate com2sec mappings for non v4 transports.
                Should be implemented via registration */
            sn = NULL;
        }

    } else
#endif /* support for community based SNMP */
      if (find_sec_mod(pdu->securityModel)) {
        /*
         * any legal defined v3 security model 
         */
        DEBUGMSG(("mibII/vacm_vars",
                  "vacm_in_view: ver=%d, model=%d, secName=%s\n",
                  pdu->version, pdu->securityModel, pdu->securityName));
        sn = pdu->securityName;
        contextName = pdu->contextName;
    } else {
        sn = NULL;
    }

    if (sn == NULL) {
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
        snmp_increment_statistic(STAT_SNMPINBADCOMMUNITYNAMES);
#endif
        DEBUGMSGTL(("mibII/vacm_vars",
                    "vacm_in_view: No security name found\n"));
        return 1;
    }

    if (pdu->contextNameLen > CONTEXTNAMEINDEXLEN) {
        DEBUGMSGTL(("mibII/vacm_vars",
                    "vacm_in_view: bad ctxt length %d\n",
                    pdu->contextNameLen));
        return 6;
    }
    /*
     * NULL termination of the pdu field is ugly here.  Do in PDU parsing? 
     */
    if (pdu->contextName)
        strncpy(contextNameIndex, pdu->contextName, pdu->contextNameLen);
    else
        contextNameIndex[0] = '\0';

    contextNameIndex[pdu->contextNameLen] = '\0';
    if (!netsnmp_subtree_find_first(contextNameIndex)) {
        /*
         * rfc2575 section 3.2, step 1
         * no such context here; return no such context error 
         */
        DEBUGMSGTL(("mibII/vacm_vars", "vacm_in_view: no such ctxt \"%s\"\n",
                    contextNameIndex));
        return 6;
    }

    DEBUGMSGTL(("mibII/vacm_vars", "vacm_in_view: sn=%s", sn));

    gp = vacm_getGroupEntry(pdu->securityModel, sn);
    if (gp == NULL) {
        DEBUGMSG(("mibII/vacm_vars", "\n"));
        return 2;
    }
    DEBUGMSG(("mibII/vacm_vars", ", gn=%s", gp->groupName));

    ap = vacm_getAccessEntry(gp->groupName, contextNameIndex,
                             pdu->securityModel, pdu->securityLevel);
    if (ap == NULL) {
        DEBUGMSG(("mibII/vacm_vars", "\n"));
        return 3;
    }

    if (name == 0) {            /* only check the setup of the vacm for the request */
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
        snmp_log(LOG_ERR, "bad msg type in vacm_in_view: %d\n",
                 pdu->command);
        vn = ap->readView;
    }
    DEBUGMSG(("mibII/vacm_vars", ", vn=%s", vn));

    if (check_subtree) {
        DEBUGMSG(("mibII/vacm_vars", "\n"));
        return vacm_checkSubtree(vn, name, namelen);
    }

    vp = vacm_getViewEntry(vn, name, namelen, VACM_MODE_FIND);

    if (vp == NULL) {
        DEBUGMSG(("mibII/vacm_vars", "\n"));
        return 4;
    }
    DEBUGMSG(("mibII/vacm_vars", ", vt=%d\n", vp->viewType));

    if (vp->viewType == SNMP_VIEW_EXCLUDED) {
#if !defined(DISABLE_SNMPV1) || !defined(DISABLE_SNMPV2C)
        if (pdu->version == SNMP_VERSION_1
            || pdu->version == SNMP_VERSION_2c) {
            snmp_increment_statistic(STAT_SNMPINBADCOMMUNITYUSES);
        }
#endif
        return 5;
    }

    return 0;

}                               /* end vacm_in_view() */


