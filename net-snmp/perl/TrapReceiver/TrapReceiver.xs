/* -*- c -*- */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "perl_snmptrapd.h"

#include "const-c.inc"

typedef struct trapd_cb_data_s {
   SV *perl_cb;
} trapd_cb_data;

typedef struct netsnmp_oid_s {
    unsigned int        *name;
    unsigned int         len;
    unsigned int         namebuf[ MAX_OID_LEN ];
} netsnmp_oid;

int   perl_trapd_handler( netsnmp_pdu           *pdu,
                          netsnmp_transport     *transport,
                          netsnmp_trapd_handler *handler)
{
    trapd_cb_data *cb_data;
    SV *pcallback;
    netsnmp_variable_list *vb;
    netsnmp_oid *o;
    SV *arg;
    SV *rarg;
    SV **tmparray;
    int i, c = 0;
    u_char *outbuf;
    size_t ob_len = 0, oo_len = 0;
    AV *varbinds;
    HV *pduinfo;

    if (!pdu || !handler)
        return 0;

    /* nuke v1 PDUs */
    if (pdu->command == SNMP_MSG_TRAP)
        pdu = convert_v1pdu_to_v2(pdu);

    cb_data = handler->handler_data;
    if (!cb_data || !cb_data->perl_cb)
        return 0;

    pcallback = cb_data->perl_cb;

  {
    dSP;
    ENTER;
    SAVETMPS;

    /* get PDU related info */
    pduinfo = newHV();
#define STOREPDU(n, v) hv_store(pduinfo, n, strlen(n), v, 0)
#define STOREPDUi(n, v) STOREPDU(n, newSViv(v))
#define STOREPDUs(n, v) STOREPDU(n, newSVpv(v, 0))
    STOREPDUi("version", pdu->version);
    STOREPDUs("notificationtype", ((pdu->command == SNMP_MSG_INFORM) ? "INFORM":"TRAP"));
    STOREPDUi("requestid", pdu->reqid);
    STOREPDUi("messageid", pdu->msgid);
    STOREPDUi("transactionid", pdu->transid);
    STOREPDUi("errorstatus", pdu->errstat);
    STOREPDUi("errorindex", pdu->errindex);
    if (pdu->version == 3) {
        STOREPDUi("securitymodel", pdu->securityModel);
        STOREPDUi("securitylevel", pdu->securityLevel);
        STOREPDU("contextName", newSVpv(pdu->contextName, pdu->contextNameLen));
        STOREPDU("contextEngineID", newSVpv(pdu->contextEngineID, pdu->contextEngineIDLen));
        STOREPDU("securityEngineID", newSVpv(pdu->securityEngineID, pdu->securityEngineIDLen));
        STOREPDU("securityName", newSVpv(pdu->securityName, pdu->securityNameLen));
    } else {
        STOREPDU("community", newSVpv(pdu->community, pdu->community_len));
    }

    if (transport && transport->f_fmtaddr) {
        char *tstr = transport->f_fmtaddr(transport, pdu->transport_data,
                                          pdu->transport_data_length);
        STOREPDUs("receivedfrom", tstr);
        free(tstr);
    }

    /* get VARBIND related info */
    i = count_varbinds(pdu->variables);
    tmparray = malloc(sizeof(*tmparray) * i);

    varbinds = newAV();
    for(vb = pdu->variables; vb; vb = vb->next_variable) {

        PUSHMARK(sp);
        /* get the oid */ o = SNMP_MALLOC_TYPEDEF(netsnmp_oid);
        o->name = o->namebuf;
        o->len = vb->name_length;
        memcpy(o->name, vb->name, vb->name_length * sizeof(oid));

        rarg = newSViv((int) 0);
        arg = newSVrv(rarg, "netsnmp_oidPtr");
        sv_setiv(arg, (int) o);
        XPUSHs(rarg);

        PUTBACK;
        i = perl_call_pv("NetSNMP::OID::newwithptr", G_SCALAR);
        SPAGAIN;

        if (i != 1) {
            snmp_log(LOG_ERR, "unhandled OID error.\n");
            /* ack XXX */
        }
        tmparray[c++] = POPs;
        /* get the value */
    }

    PUSHMARK(sp);
    for(vb = pdu->variables, i = 0; vb; vb = vb->next_variable, i++) {
        /* push the oid */
        AV *vba;
        vba = newAV();


        /* get the value */
        outbuf = NULL;
        ob_len = 0;
        oo_len = 0;
	sprint_realloc_by_type(&outbuf, &ob_len, &oo_len, 1,
                               vb, 0, 0, 0);

        av_push(vba,tmparray[i]);
        av_push(vba,sv_2mortal(newSVpv(outbuf, oo_len)));
        av_push(vba,sv_2mortal(newSViv(vb->type)));
        av_push(varbinds, newRV((SV*)vba));
    }

    /* store the collected information on the stack */
    XPUSHs(newRV((SV*)pduinfo));
    XPUSHs(newRV((SV*)varbinds));

    /* actually call the callback function */
    PUTBACK;
    if (SvTYPE(pcallback) == SVt_PVCV) {
        perl_call_sv(pcallback, G_DISCARD);
        /* XXX: it discards the results, which isn't right */
    } else if (SvROK(pcallback) && SvTYPE(SvRV(pcallback)) == SVt_PVCV) {
        /* reference to code */
        perl_call_sv(SvRV(pcallback), G_DISCARD);
    } else {
        snmp_log(LOG_ERR, " tried to call a perl function but failed to understand its type: (ref = %x, svrok: %d, SVTYPE: %d)\n", pcallback, SvROK(pcallback), SvTYPE(pcallback));
    }

    free(tmparray);

    SPAGAIN;
    PUTBACK;
    FREETMPS;
    LEAVE;
  }
    return NETSNMPTRAPD_HANDLER_OK;
}

MODULE = NetSNMP::TrapReceiver		PACKAGE = NetSNMP::TrapReceiver		

INCLUDE: const-xs.inc

MODULE = NetSNMP::TrapReceiver PACKAGE = NetSNMP::TrapReceiver PREFIX=trapd_
int
trapd_register(regoid, perlcallback)
	char *regoid;
        SV   *perlcallback;
    PREINIT:
	oid myoid[MAX_OID_LEN];
	size_t myoid_len = MAX_OID_LEN;
        trapd_cb_data *cb_data;
        int gotit=1;
        netsnmp_trapd_handler *handler = NULL;
    CODE:
        {
            if (!regoid || !perlcallback) {
                RETVAL = 0;
                return;
            }
            if (strcmp(regoid,"all") == 0) {
                handler = 
                    netsnmp_add_global_traphandler(NETSNMPTRAPD_POST_HANDLER,
                                                   perl_trapd_handler);
            } else if (strcmp(regoid,"default") == 0) {
                handler = 
                    netsnmp_add_default_traphandler(perl_trapd_handler);
            } else if (!snmp_parse_oid(regoid, myoid, &myoid_len)) {
                snmp_log(LOG_ERR,
                         "Failed to parse oid for perl registration: %s %d\n",
                         regoid);
                RETVAL = 0;
                return;
            } else {
                handler = 
                    netsnmp_add_traphandler(perl_trapd_handler,
                                            myoid, myoid_len);
            }
        
            if (handler) {
                cb_data = SNMP_MALLOC_TYPEDEF(trapd_cb_data);
                cb_data->perl_cb = newSVsv(perlcallback);
                handler->handler_data = cb_data;
                RETVAL = 1;
            } else {
                RETVAL = 0;
            }
        }
    OUTPUT:
        RETVAL
