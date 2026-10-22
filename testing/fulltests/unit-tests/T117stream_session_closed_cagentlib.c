/* HEADER Target and proxy sessions closed by the peer */

#include "target/snmpTargetAddrEntry_data.h"
#include "target/snmpTargetParamsEntry_data.h"
#include "target/target.h"
#include "ucd-snmp/proxy.h"

static oid      tcp_domain[] = { 1, 3, 6, 1, 2, 1, 100, 1, 5 };
static oid      proxy_oid[] = { 1, 3, 6, 1, 3, 117 };
static char     tags[] = "t117";
char            proxy_line[128];
u_char          taddr[6];
struct targetAddrTable_struct *addr;
struct targetParamTable_struct *param;
netsnmp_transport *listener;
netsnmp_session *s1, *s2;
netsnmp_subtree *subtree;
netsnmp_mib_handler *handler;
struct simple_proxy *sp;
netsnmp_agent_request_info reqinfo;
netsnmp_request_info requests[2];
netsnmp_variable_list *vb = NULL;
struct sockaddr_in sin;
socklen_t       sinlen = sizeof(sin);
int             cfd1 = -1, cfd2 = -1, i, numfds, block;
fd_set          fdset;
struct timeval  timeout;

init_agent("snmpd");
init_snmp("snmpd");

memset(&sin, 0, sizeof(sin));
listener = netsnmp_tdomain_transport("tcp:127.0.0.1:0", 1, "tcp");
OK(listener != NULL &&
   getsockname(listener->sock, (struct sockaddr *)&sin, &sinlen) == 0,
   "listening on a loopback TCP port");
memcpy(taddr, &sin.sin_addr, 4);
memcpy(taddr + 4, &sin.sin_port, 2);
snprintf(proxy_line, sizeof(proxy_line),
         "-v2c -c public tcp:127.0.0.1:%d .1.3.6.1.3.117",
         ntohs(sin.sin_port));

param = snmpTargetParamTable_create();
param->paramNameData = strdup(tags);
param->paramNameLen = strlen(tags);
param->mpModel = SNMP_VERSION_2c;
param->secModel = SNMP_SEC_MODEL_SNMPv2c;
param->secLevel = SNMP_SEC_LEVEL_NOAUTH;
param->secNameData = strdup("public");
param->secNameLen = 6;
param->rowStatus = SNMP_ROW_ACTIVE;
snmpTargetParamTable_add(param);

addr = snmpTargetAddrTable_create();
addr->nameData = strdup(tags);
addr->nameLen = strlen(tags);
memcpy(addr->tDomain, tcp_domain, sizeof(tcp_domain));
addr->tDomainLen = OID_LENGTH(tcp_domain);
addr->tAddress = netsnmp_memdup(taddr, sizeof(taddr));
addr->tAddressLen = sizeof(taddr);
free(addr->tagListData);
addr->tagListData = strdup(tags);
addr->tagListLen = strlen(tags);
addr->paramsData = strdup(tags);
addr->paramsLen = strlen(tags);
addr->rowStatus = SNMP_ROW_ACTIVE;
snmpTargetAddrTable_add(addr);

s1 = get_target_sessions(tags, NULL, NULL);
OK(s1 != NULL && s1 == addr->sess, "get_target_sessions opens a session");
if (listener)
    cfd1 = listener->f_accept(listener);

proxy_parse_config("proxy", proxy_line);
if (listener)
    cfd2 = listener->f_accept(listener);
subtree = netsnmp_subtree_find(proxy_oid, OID_LENGTH(proxy_oid), NULL, "");
handler = subtree ?
    netsnmp_find_handler_by_name(subtree->reginfo, "proxy") : NULL;
sp = handler ? handler->myvoid : NULL;
OK(cfd1 >= 0 && cfd2 >= 0 && sp && sp->sess, "proxy session opened");

if (cfd1 >= 0)
    close(cfd1);
if (cfd2 >= 0)
    close(cfd2);
for (i = 0; i < 20; i++) {
    numfds = 0;
    block = 0;
    FD_ZERO(&fdset);
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    snmp_select_info(&numfds, &fdset, &timeout, &block);
    if (addr->sess == NULL && sp && sp->sess == NULL)
        break;
    if (select(numfds, &fdset, NULL, NULL, &timeout) > 0)
        snmp_read(&fdset);
}

OK(addr->sess == NULL, "target forgets the session closed by its peer");
s2 = get_target_sessions(tags, NULL, NULL);
OK(s2 != NULL && s2 == addr->sess &&
   snmp_sess_transport(snmp_sess_pointer(s2)) != NULL,
   "next get_target_sessions opens a new session");

OK(sp && sp->sess == NULL, "proxy forgets the session closed by its peer");
memset(&reqinfo, 0, sizeof(reqinfo));
memset(requests, 0, sizeof(requests));
reqinfo.mode = MODE_GET;
snmp_varlist_add_variable(&vb, proxy_oid, OID_LENGTH(proxy_oid), ASN_NULL,
                          NULL, 0);
snmp_varlist_add_variable(&vb, proxy_oid, OID_LENGTH(proxy_oid), ASN_NULL,
                          NULL, 0);
requests[0].requestvb = vb;
requests[0].next = &requests[1];
requests[1].requestvb = vb ? vb->next_variable : NULL;
requests[1].prev = &requests[0];
if (handler)
    proxy_handler(handler, subtree->reginfo, &reqinfo, requests);
OK(requests[0].status == SNMP_ERR_GENERR &&
   requests[0].delegated == 0 && requests[1].delegated == 0,
   "proxy_handler fails the requests without a session");

snmp_free_varbind(vb);
if (listener) {
    listener->f_close(listener);
    netsnmp_transport_free(listener);
}
snmp_shutdown("snmpd");
shutdown_agent();
