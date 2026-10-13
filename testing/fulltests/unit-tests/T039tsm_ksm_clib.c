/* HEADER Testing TSM and KSM security models (snmptsm.c / snmpksm.c) */
    int run_t039(void);
    int rc = run_t039();
    if (__did_plan == 0) {
        PLAN(__test_counter);
    }
    return rc;
}

#include <net-snmp/library/snmp_secmod.h>
#include <net-snmp/library/snmptsm.h>
#ifdef NETSNMP_TRANSPORT_TLSTCP_DOMAIN
#include <net-snmp/library/snmpTLSTCPDomain.h>
#endif

int
run_t039(void)
{
    struct snmp_secmod_def *sptr;
    netsnmp_session session;
    int rc;

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    init_snmp("T039tsm_ksm");

    sptr = find_sec_mod(SNMP_SEC_MODEL_TSM);
    if (sptr != NULL) {
        /* 1. Test tsm_rgenerate_out_msg (encode_reverse) */
        {
            struct snmp_secmod_outgoing_params oparms;
            netsnmp_pdu out_pdu;
            u_char msg_buf[256];
            u_char *whole_msg = msg_buf;
            size_t whole_msg_len = sizeof(msg_buf);
            size_t offset = 0;
            u_char global_data[] = { ASN_SEQUENCE | ASN_CONSTRUCTOR, 2, 2, 0 };
            u_char scoped_pdu[] = { ASN_SEQUENCE | ASN_CONSTRUCTOR, 2, 4, 0 };
            char long_secname[NETSNMP_TM_MAX_SECNAME + 16];
            char non_nul_secname[8] = { 'a', 'b', 'c', 'd', 'e', ':', ':', 0 };
            char prefixed_secname[] = "tls::alice";

            snmp_sess_init(&session);
            session.peername = (char *)"tls:localhost";
            memset(&out_pdu, 0, sizeof(out_pdu));
            memset(msg_buf, 0, sizeof(msg_buf));
            memset(&oparms, 0, sizeof(oparms));
            oparms.msgProcModel = SNMP_VERSION_3;
            oparms.maxMsgSize = sizeof(msg_buf);
            oparms.globalData = global_data;
            oparms.globalDataLen = sizeof(global_data);
            oparms.secModel = SNMP_SEC_MODEL_TSM;
            oparms.secLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            oparms.scopedPdu = scoped_pdu;
            oparms.scopedPduLen = sizeof(scoped_pdu);
            oparms.pdu = &out_pdu;
            oparms.session = &session;
            oparms.secParamsLen = &offset;
            oparms.wholeMsg = &whole_msg;
            oparms.wholeMsgLen = &whole_msg_len;
            oparms.wholeMsgOffset = &offset;

            /* 1a. Oversized secNameLen >= sizeof(tmStateRef->securityName) */
            memset(long_secname, 'x', sizeof(long_secname) - 1);
            long_secname[sizeof(long_secname) - 1] = '\0';
            oparms.secName = long_secname;
            oparms.secNameLen = sizeof(long_secname) - 1;
            rc = sptr->encode_reverse(&oparms);
            OK(rc == SNMPERR_GENERR,
               "tsm_rgenerate_out_msg rejects secNameLen >= sizeof(securityName)");

            /* 1b. use_prefix=1 with non-NUL-terminated secName without ':' inside secNameLen */
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                                   NETSNMP_DS_LIB_TSM_USE_PREFIX, 1);
            oparms.secName = non_nul_secname;
            oparms.secNameLen = 5; /* ':' is at index 5, outside secNameLen */
            offset = 0;
            rc = sptr->encode_reverse(&oparms);
            OK(rc == SNMPERR_GENERR,
               "tsm_rgenerate_out_msg uses memchr bounded by secNameLen for ':' lookup");

            /* 1c. use_prefix=1 with valid "tls:alice" */
            oparms.secStateRef = NULL;
            oparms.secName = prefixed_secname;
            oparms.secNameLen = strlen(prefixed_secname);
            offset = 0;
            rc = sptr->encode_reverse(&oparms);
            OK(rc == SNMPERR_SUCCESS && out_pdu.transport_data != NULL,
               "tsm_rgenerate_out_msg strips prefix and populates transport_data");
            SNMP_FREE(out_pdu.transport_data);
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                                   NETSNMP_DS_LIB_TSM_USE_PREFIX, 0);
        }

        /* 2. Test tsm_process_in_msg (decode) */
        {
            struct snmp_secmod_incoming_params iparms;
            netsnmp_pdu pdu;
            netsnmp_tmStateReference *tm_ref;
            void *sec_state_ref = NULL;
            u_char whole_pkt[] = {
                ASN_OCTET_STR, 0,
                ASN_SEQUENCE | ASN_CONSTRUCTOR, 2, 4, 0
            };
            u_char *scoped_pdu_out = NULL;
            size_t scoped_pdu_len = sizeof(whole_pkt);
            char sec_name[64];
            size_t sec_name_len;
            u_char sec_engine_id[32];
            size_t sec_engine_id_len = sizeof(sec_engine_id);
            size_t max_size_resp = 1400;

            snmp_sess_init(&session);
            memset(&pdu, 0, sizeof(pdu));
            pdu.flags = UCD_MSG_FLAG_TUNNELED;
            memset(&iparms, 0, sizeof(iparms));
            iparms.msgProcModel = SNMP_VERSION_3;
            iparms.maxMsgSize = 1500;
            iparms.secParams = whole_pkt;
            iparms.secModel = SNMP_SEC_MODEL_TSM;
            iparms.secLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            iparms.wholeMsg = whole_pkt;
            iparms.wholeMsgLen = sizeof(whole_pkt);
            iparms.secEngineID = sec_engine_id;
            iparms.secEngineIDLen = &sec_engine_id_len;
            iparms.secName = sec_name;
            iparms.secNameLen = &sec_name_len;
            iparms.scopedPdu = &scoped_pdu_out;
            iparms.scopedPduLen = &scoped_pdu_len;
            iparms.maxSizeResponse = &max_size_resp;
            iparms.secStateRef = &sec_state_ref;
            iparms.pdu = &pdu;
            iparms.sess = &session;

            /* 2a. NULL transport_data -> returns error */
            pdu.transport_data = NULL;
            pdu.transport_data_length = 0;
            sec_name_len = sizeof(sec_name);
            sec_engine_id_len = sizeof(sec_engine_id);
            scoped_pdu_len = sizeof(whole_pkt);
            rc = sptr->decode(&iparms);
            OK(rc != SNMPERR_SUCCESS,
               "tsm_process_in_msg rejects NULL transport_data");

            /* 2b. *secNameLen == 0 with allocated transport_data -> frees transport_data without leak */
            tm_ref = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);
            strcpy(tm_ref->securityName, "bob");
            tm_ref->securityNameLen = 3;
            tm_ref->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            pdu.transport_data = tm_ref;
            pdu.transport_data_length = sizeof(*tm_ref);
            sec_name_len = 0;
            sec_engine_id_len = sizeof(sec_engine_id);
            scoped_pdu_len = sizeof(whole_pkt);
            rc = sptr->decode(&iparms);
            OK(rc == SNMPERR_GENERR && pdu.transport_data == NULL,
               "tsm_process_in_msg frees transport_data when *secNameLen == 0");

            /* 2c. Valid transport_data with use_prefix=0 -> succeeds and sets secStateRef */
            tm_ref = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);
            memcpy(tm_ref->transportDomain, netsnmpUDPDomain,
                   netsnmpUDPDomain_len * sizeof(oid));
            tm_ref->transportDomainLen = netsnmpUDPDomain_len;
            strcpy(tm_ref->securityName, "bob");
            tm_ref->securityNameLen = 3;
            tm_ref->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            pdu.transport_data = tm_ref;
            pdu.transport_data_length = sizeof(*tm_ref);
            sec_state_ref = NULL;
            sec_name_len = sizeof(sec_name);
            sec_engine_id_len = sizeof(sec_engine_id);
            scoped_pdu_len = sizeof(whole_pkt);
            rc = sptr->decode(&iparms);
            OK(rc == SNMPERR_SUCCESS && strcmp(sec_name, "bob") == 0 &&
               pdu.transport_data == NULL && sec_state_ref != NULL,
               "tsm_process_in_msg succeeds with use_prefix=0 and transfers tmStateRef");
            if (sec_state_ref && sptr->pdu_free_state_ref) {
                sptr->pdu_free_state_ref(sec_state_ref);
                sec_state_ref = NULL;
            }

            /* 2d. Valid transport_data with use_prefix=1 and unknown domain -> frees tmStateRef on error */
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                                   NETSNMP_DS_LIB_TSM_USE_PREFIX, 1);
            tm_ref = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);
            memcpy(tm_ref->transportDomain, netsnmpUDPDomain,
                   netsnmpUDPDomain_len * sizeof(oid));
            tm_ref->transportDomainLen = netsnmpUDPDomain_len;
            strcpy(tm_ref->securityName, "bob");
            tm_ref->securityNameLen = 3;
            tm_ref->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
            pdu.transport_data = tm_ref;
            pdu.transport_data_length = sizeof(*tm_ref);
            sec_name_len = sizeof(sec_name);
            sec_engine_id_len = sizeof(sec_engine_id);
            scoped_pdu_len = sizeof(whole_pkt);
            rc = sptr->decode(&iparms);
            OK(rc == SNMPERR_GENERR && pdu.transport_data == NULL &&
               sec_state_ref == NULL,
               "tsm_process_in_msg frees tmStateRef when prefix lookup fails");
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                                   NETSNMP_DS_LIB_TSM_USE_PREFIX, 0);
        }
    } else {
        OK(1, "skipped: TSM security model not enabled");
    }

    snmp_shutdown("T039tsm_ksm");
