#include <config.h>

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"

#include "snmp.h"
#include "tools.h"
#include "snmpTargetAddrEntry.h"
#include "snmpTargetParamsEntry.h"
#include "target.h"
#include "snmp-tc.h"

#define MAX_TAGS 128

struct snmp_session *
get_target_sessions(char *taglist, TargetFilterFunction *filterfunct,
                    void *filterArg) {
    struct snmp_session *ret = NULL, thissess;
    struct targetAddrTable_struct *targaddrs;
    char buf[SPRINT_MAX_LEN], smbuf[64];
    char tags[MAX_TAGS][SPRINT_MAX_LEN], *cp;
    int numtags = 0, i;
    oid udpdomain[] = { 1,3,6,1,6,1,1 };
    int udpdomainlen = sizeof(udpdomain)/sizeof(oid);
    static struct targetParamTable_struct *param;
    
    DEBUGMSGTL(("target_sessions","looking for: %s\n", taglist));
    for(cp = taglist; cp && numtags < MAX_TAGS;) {
        cp = copy_word(cp, tags[numtags]);
        DEBUGMSGTL(("target_sessions"," for: %d=%s\n", numtags,
                    tags[numtags]));
        numtags++;
    }
    
    for(targaddrs = get_addrTable(); targaddrs; targaddrs = targaddrs->next) {

        /* legal row? */
        if (targaddrs->tDomain == NULL ||
            targaddrs->tAddress == NULL ||
            targaddrs->rowStatus != SNMP_ROW_ACTIVE) {
            DEBUGMSGTL(("target_sessions",
                         "  which is not ready yet\n"));
            continue;
        }


        if (snmp_oid_compare(udpdomain, udpdomainlen,
                             targaddrs->tDomain,
                             targaddrs->tDomainLen) != 0) {
            snmp_log(LOG_ERR,
                     "unsupported domain for target address table entry %s\n",
                     targaddrs->name);
        }

        /* check tag list to see if we match */
        if (targaddrs->tagList) {
            /* loop through tag list looking for requested tags */
            for(cp = targaddrs->tagList; cp; ) {
                cp = copy_word(cp, buf);
                for(i = 0; i < numtags; i++) {
                    if (strcmp(buf,tags[i]) == 0) {
                        /* found a valid target table entry */
                        DEBUGMSGTL(("target_sessions","found one: %s\n",
                                     tags[i]));

                        if (targaddrs->params) {
                            param = get_paramEntry(targaddrs->params);
                            if (!param || param->rowStatus != SNMP_ROW_ACTIVE) {
                                /* parameter entry must exist and be active */
                                continue;
                            }
                        } else {
                            /* parameter entry must be specified */
                            continue;
                        }

                        /* last chance for caller to opt-out.  Call
                           filtering function */
                        if (filterfunct &&
                            (*(filterfunct))(targaddrs, param, filterArg)) {
                            continue;
                        }

                        if (targaddrs->storageType != ST_READONLY &&
                            targaddrs->sess &&
                            param->updateTime >=
                            targaddrs->sessionCreationTime) {
                            /* parameters have changed, nuke the old session */
                            snmp_close(targaddrs->sess);
                            targaddrs->sess = NULL;
                        }

                        /* target session already exists? */
                        if (targaddrs->sess == NULL) {

                            /* create an appropriate snmp session and add
                           it to our return list */
                            sprintf(smbuf, "%d.%d.%d.%d",
                                    (int) targaddrs->tAddress[0],
                                    (int) targaddrs->tAddress[1],
                                    (int) targaddrs->tAddress[2],
                                    (int) targaddrs->tAddress[3]);
                            memset(&thissess,0,sizeof(thissess));
                            thissess.peername = strdup(smbuf);
                            DEBUGMSGTL(("target_sessions","  to: %s:%d (%d*256+%d)\n",
                                        smbuf,
                                        (((unsigned int)
                                          targaddrs->tAddress[4])*256 +
                                         (unsigned int) targaddrs->tAddress[5]),
                                        targaddrs->tAddress[4],
                                        targaddrs->tAddress[5]));
                            thissess.remote_port =
                                ((unsigned int) targaddrs->tAddress[4])*256 +
                                (unsigned int) targaddrs->tAddress[5];
                            thissess.timeout = (targaddrs->timeout)*1000;
                            DEBUGMSGTL(("target_sessions","timeout: %d -> %d\n",
                                        targaddrs->timeout, thissess.timeout));
                            thissess.retries = targaddrs->retryCount;

                            if (param->mpModel == SNMP_VERSION_3 &&
                                param->secModel != 3) {
                                snmp_log(LOG_ERR,
                                         "unsupported model/secmodel combo for target %s\n",
                                         targaddrs->name);
                                /* XXX: memleak */
                                continue;
                            }
                            thissess.version = param->mpModel;
                            if (param->mpModel == SNMP_VERSION_3) {
                                thissess.securityName =
                                    strdup(param->secName);
                                thissess.securityNameLen =
                                    strlen(thissess.securityName);
                                thissess.securityLevel = param->secLevel;
                            } else {
                                thissess.community =
                                    (u_char *)strdup(param->secName);
                                thissess.community_len =
                                    strlen((char *)thissess.community);
                            }
                            
                            targaddrs->sess = snmp_open(&thissess);
                            targaddrs->sessionCreationTime = time(NULL);
                        }
                        if (targaddrs->sess) {
                            if (ret)
                                targaddrs->sess->next = ret;
                            ret = targaddrs->sess;
                        } else {
                            snmp_sess_perror("target session", &thissess);
                        }
                    }
                }
            }
        }
    }
    return ret;
}

