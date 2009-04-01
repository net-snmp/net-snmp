/*
 * snmptsmsm.c
 *
 * This code implements a security model that assumes the local user
 * that executed the agent is the user who's attributes called
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/library/snmptsm.h>

#include <unistd.h>

static int      tsm_session_init(netsnmp_session *);
static void     tsm_free_state_ref(void *);
static int      tsm_clone_pdu(netsnmp_pdu *, netsnmp_pdu *);
static void     tsm_free_pdu(netsnmp_pdu *pdu);

u_int next_sess_id = 1;

/** Initialize the TSM security module */
void
init_tsm(void)
{
    struct snmp_secmod_def *def;
    int ret;

    def = SNMP_MALLOC_STRUCT(snmp_secmod_def);

    if (!def) {
        snmp_log(LOG_ERR,
                 "Unable to malloc snmp_secmod struct, not registering TSM\n");
        return;
    }

    def->encode_reverse = tsm_rgenerate_out_msg;
    def->decode = tsm_process_in_msg;
    def->session_open = tsm_session_init;
    def->pdu_free_state_ref = tsm_free_state_ref;
    def->pdu_clone = tsm_clone_pdu;
    def->pdu_free = tsm_free_pdu;
    def->probe_engineid = snmpv3_probe_contextEngineID_rfc5343;

    DEBUGMSGTL(("tsm","registering ourselves\n"));
    ret = register_sec_mod(NETSNMP_TSM_SECURITY_MODEL, "tsm", def);
    DEBUGMSGTL(("tsm"," returned %d\n", ret));

    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "tsmUseTransportPrefix",
			       NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_TSM_USE_PREFIX);
}

/*
 * Initialize specific session information (right now, just set up things to
 * not do an engineID probe)
 */

static int
tsm_session_init(netsnmp_session * sess)
{
    DEBUGMSGTL(("tsm",
                "TSM: Reached our session initialization callback\n"));

    sess->flags |= SNMP_FLAGS_DONT_PROBE;

    /* XXX: likely needed for something: */
    /*
    tsmsession = sess->securityInfo =
    if (!tsmsession)
        return SNMPERR_GENERR;
    */

    return SNMPERR_SUCCESS;
}

/** Free our state information (this is only done on the agent side) */
static void
tsm_free_state_ref(void *ptr)
{
    netsnmp_tsmSecurityReference *tsmRef;

    if (NULL == ptr)
        return;

    tsmRef = (netsnmp_tsmSecurityReference *) ptr;
    /* the tmStateRef is always taken care of by the normal PDU, since this
       is just a reference to that one */
    /* DON'T DO: SNMP_FREE(tsmRef->tmStateRef); */
    /* SNMP_FREE(tsmRef);  ? */
}

static void
tsm_free_pdu(netsnmp_pdu *pdu)
{
    /* free the security reference */
    if (pdu->securityStateRef) {
        tsm_free_state_ref(pdu->securityStateRef);
        pdu->securityStateRef = NULL;
    }
}

/** This is called when a PDU is cloned (to increase reference counts) */
static int
tsm_clone_pdu(netsnmp_pdu *pdu, netsnmp_pdu *pdu2)
{
    netsnmp_tsmSecurityReference *oldref, *newref;

    oldref = pdu->securityStateRef;
    if (!oldref)
        return SNMPERR_SUCCESS;

    newref = SNMP_MALLOC_TYPEDEF(netsnmp_tsmSecurityReference);
    fprintf(stderr, "cloned as pdu=%p, ref=%p (oldref=%p)\n",
            pdu2, newref, pdu2->securityStateRef);
    if (!newref)
        return SNMPERR_GENERR;
    
    memcpy(newref, oldref, sizeof(*oldref));

    pdu2->securityStateRef = newref;

    /* the tm state reference is just a link to the one in the pdu,
       which was already copied by snmp_clone_pdu before handing it to
       us. */

    memdup(&newref->tmStateRef, oldref->tmStateRef,
           sizeof(*oldref->tmStateRef));
    return SNMPERR_SUCCESS;
}

/* asn.1 easing definitions */
#define TSMBUILD_OR_ERR(fun, args, msg, desc)       \
    DEBUGDUMPHEADER("send", desc); \
    rc = fun args;            \
    DEBUGINDENTLESS();        \
    if (rc == 0) { \
        DEBUGMSGTL(("tsm",msg)); \
        retval = SNMPERR_TOO_LONG; \
        goto outerr; \
    }

/****************************************************************************
 *
 * tsm_generate_out_msg
 *
 * Parameters:
 *	(See list below...)
 *
 * Returns:
 *	SNMPERR_SUCCESS                        On success.
 *	... and others
 *
 *
 * Generate an outgoing message.
 *
 ****************************************************************************/

int
tsm_rgenerate_out_msg(struct snmp_secmod_outgoing_params *parms)
{
    u_char         **wholeMsg = parms->wholeMsg;
    size_t	   *offset = parms->wholeMsgOffset;
    int rc;
    
    size_t         *wholeMsgLen = parms->wholeMsgLen;
    netsnmp_tsmSecurityReference *tsmSecRef;
    netsnmp_tmStateReference *tmStateRef;
    
    DEBUGMSGTL(("tsm", "Starting TSM processing\n"));

    /* if we have this, this message is in response to something that
       came in earlier */
    tsmSecRef = parms->secStateRef;
    
    if (tsmSecRef) {
        /* section 4.2, step 1 */
        if (tsmSecRef->tmStateRef)
            tmStateRef = tsmSecRef->tmStateRef;
        else
            tmStateRef = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);
        if (NULL == tmStateRef) {
            snmp_log(LOG_ERR, "failed to allocate a tmStateReference\n");
            return SNMPERR_GENERR;
        }
        tmStateRef->sameSecurity = NETSNMP_TM_USE_SAME_SECURITY;
        tmStateRef->requestedSecurityLevel = tsmSecRef->securityLevel;

        /* XXX: this may be freed automatically later by the library? */
        SNMP_FREE(parms->secStateRef);
    } else {
        /* section 4.2, step 2 */
        tmStateRef = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);
        if (tmStateRef == NULL) {
            return SNMPERR_GENERR;
        }
        
        tmStateRef->requestedSecurityLevel = parms->secLevel;
        tmStateRef->sameSecurity = NETSNMP_TM_SAME_SECURITY_NOT_REQUIRED;

        if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                   NETSNMP_DS_LIB_TSM_USE_PREFIX)) {
            /* XXX: probably shouldn't be a hard-coded list of
               supported transports */
            const char *prefix;
            if (strncmp("ssh:",parms->session->peername,4) == 0)
                prefix = "ssh:";
            else if (strncmp("dtls:",parms->session->peername,4) == 0)
                prefix = "dtls:";
            else
                return SNMPERR_GENERR;

            /* a: - lookup the prefix */
            /*    - if DNE, snmpTsmUnknownPrefixes++ and bail */
            if (!prefix) {
                /* snmpTsmUnknownPrefixes++ */
                return SNMPERR_GENERR;
            }

            /*    - If secName doesn't have the prefix (or any):
                  snmpTsmInvalidPrefixes++ and bail */
            if (strchr(parms->secName, ':') == 0 ||
                strlen(prefix)+1 >= parms->secNameLen ||
                strncmp(parms->secName, prefix, strlen(prefix)) != 0 ||
                parms->secName[strlen(prefix)] != ':') {

                /* snmpTsmInvalidPrefixes++ */
                return SNMPERR_GENERR;
            }

            /*    - Strip the prefix and trailing : */
            /* set tmSecurityName to securityName minus stripped part */
            memcpy(tmStateRef->securityName,
                   parms->secName + strlen(prefix) + 1,
                   parms->secNameLen - strlen(prefix) - 1);
            tmStateRef->securityNameLen = parms->secNameLen - strlen(prefix) -1;
        } else {
            /* set tmSecurityName to securityName */
            memcpy(tmStateRef->securityName, parms->secName,
                   parms->secNameLen);
            tmStateRef->securityNameLen = parms->secNameLen;
        }
    }
    tmStateRef->securityName[tmStateRef->securityNameLen] = '\0';

    /* Section 4.2, Step 3:
     * - Set securityParameters to a zero-length OCTET STRING ('0400')
     * 
     * We define here what the security message section will look like:
     * 04 00 -- null string
     */
    DEBUGDUMPHEADER("send", "tsm security parameters");
    rc = asn_realloc_rbuild_header(wholeMsg, wholeMsgLen, offset, 1,
                                     (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                             | ASN_OCTET_STR), 0);
    DEBUGINDENTLESS();
    if (rc == 0) {
        DEBUGMSGTL(("tsm", "building msgSecurityParameters failed.\n"));
        return SNMPERR_TOO_LONG;
    }
    
    /* Section 4.2, Step 4:
     * Combine the message parts into a wholeMsg and calculate wholeMsgLen
     */

    /*
     * Copy in the msgGlobalData and msgVersion.  
     */
    while ((*wholeMsgLen - *offset) < parms->globalDataLen) {
        if (!asn_realloc(wholeMsg, wholeMsgLen)) {
            DEBUGMSGTL(("tsm", "building global data failed.\n"));
            return SNMPERR_TOO_LONG;
        }
    }

    *offset += parms->globalDataLen;
    memcpy(*wholeMsg + *wholeMsgLen - *offset,
           parms->globalData, parms->globalDataLen);

    /*
     * Total packet sequence.  
     */
    rc = asn_realloc_rbuild_sequence(wholeMsg, wholeMsgLen, offset, 1,
                                     (u_char) (ASN_SEQUENCE |
                                               ASN_CONSTRUCTOR), *offset);
    if (rc == 0) {
        DEBUGMSGTL(("tsm", "building master packet sequence failed.\n"));
        return SNMPERR_TOO_LONG;
    }

    /* Section 4.2 Step 5:  return everything */

    if (parms->pdu->transport_data &&
        parms->pdu->transport_data != tmStateRef) {
        snmp_log(LOG_ERR, "tsm: needed to free transport data\n");
        SNMP_FREE(parms->pdu->transport_data);
    }

    /* put the transport state reference into the PDU for the transport */
    if (SNMPERR_SUCCESS !=
        memdup(&parms->pdu->transport_data, tmStateRef, sizeof(*tmStateRef))) {
        snmp_log(LOG_ERR, "tsm: malloc failure\n");
    }
    parms->pdu->transport_data_length = sizeof(*tmStateRef);

    DEBUGMSGTL(("tsm", "TSM processing completed.\n"));
    return SNMPERR_SUCCESS;
}

/****************************************************************************
 *
 * tsm_process_in_msg
 *
 * Parameters:
 *	(See list below...)
 *
 * Returns:
 *	TSM_ERR_NO_ERROR                        On success.
 *	TSM_ERR_GENERIC_ERROR
 *	TSM_ERR_UNSUPPORTED_SECURITY_LEVEL
 *
 *
 * Processes an incoming message.
 *
 ****************************************************************************/

int
tsm_process_in_msg(struct snmp_secmod_incoming_params *parms)
{
    u_char type_value;
    size_t remaining;
    u_char *data_ptr;
    netsnmp_tmStateReference *tmStateRef;
    netsnmp_tsmSecurityReference *tsmSecRef;
    u_char          ourEngineID[SNMP_MAX_ENG_SIZE];
    static size_t   ourEngineID_len = sizeof(ourEngineID);
    
    /* Section 5.2, step 1 */
    ourEngineID_len =
        snmpv3_get_engineID((u_char*)ourEngineID, ourEngineID_len);
    if (ourEngineID_len == 0 || ourEngineID_len > *parms->secEngineIDLen)
        return SNMPERR_GENERR;
    memcpy(parms->secEngineID, ourEngineID, *parms->secEngineIDLen);

    /* Section 5.2, step 2 */
    if (!parms->pdu->transport_data ||
        sizeof(netsnmp_tmStateReference) !=
        parms->pdu->transport_data_length) {
        /* if we're not coming in over a proper transport; bail! */
        DEBUGMSGTL(("tsm","improper transport data\n"));
        return -1;
    }
    tmStateRef = (netsnmp_tmStateReference *) parms->pdu->transport_data;
    parms->pdu->transport_data = NULL;

    if (tmStateRef == NULL ||
        /* not needed: tmStateRef->transportDomain == NULL || */
        /* not needed: tmStateRef->transportAddress == NULL || */
        tmStateRef->securityName[0] == '\0'
        /* || seclevel is not valid */
        ) {
        /* XXX: snmpTsmInvalidCaches++ */
        return SNMPERR_GENERR;
    }

    /* Section 5.2, step 3 */
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_LIB_TSM_USE_PREFIX)) {
        /* Section 5.2, step 3a */
        const char *prefix;
        prefix = "ssh:"; /* XXX */

        if (prefix == NULL) {
            /* XXX: snmpTsmUnknownPrefixes++ */
            return SNMPERR_GENERR;
        }

        if (strlen(prefix) < 1 || strlen(prefix) > 4) {
            /* XXX: snmpTsmInvalidPrefixes++ */
            return SNMPERR_GENERR;
        }
        
        snprintf(parms->secName, *parms->secNameLen,
                 "%s:%s", prefix, tmStateRef->securityName);
    } else {
        strncpy(parms->secName, tmStateRef->securityName, *parms->secNameLen);
    }
    *parms->secNameLen = strlen(parms->secName);
    DEBUGMSGTL(("tsm", "user: %s/%d\n", parms->secName, *parms->secNameLen));

    /* Section 5.2 Step 4 */
    if (parms->secLevel > tmStateRef->transportSecurityLevel) {
        /* XXX: snmpTsmInadequateSecurityLevels++ */
        return SNMPERR_UNSUPPORTED_SEC_LEVEL;
    }

    /* Section 5.2 Step 5 */

    if (NULL == *parms->secStateRef) {
        tsmSecRef = SNMP_MALLOC_TYPEDEF(netsnmp_tsmSecurityReference);
    } else {
        tsmSecRef = *parms->secStateRef;
    }

    if (!tsmSecRef)
        return SNMPERR_GENERR;

    *parms->secStateRef = tsmSecRef;
    tsmSecRef->tmStateRef = tmStateRef;

    /* If this did not come through a tunneled connection, this
       security model is inappropriate (and would be a HUGE security
       hole to assume otherwise).  This is functionally a double check
       since the pdu wouldn't have transport data otherwise.  But this
       is safer though is functionally an extra step beyond the TSM
       RFC. */
    DEBUGMSGTL(("tsm","checking how we got here\n"));
    if (!(parms->pdu->flags & UCD_MSG_FLAG_TUNNELED)) {
        DEBUGMSGTL(("tsm","  pdu not tunneled\n"));
        if (!(parms->sess->flags & NETSNMP_TRANSPORT_FLAG_TUNNELED)) {
            DEBUGMSGTL(("tsm","  session not tunneled\n"));
            return SNMPERR_USM_AUTHENTICATIONFAILURE;
        }
        DEBUGMSGTL(("tsm","  but session is tunneled\n"));
    } else {
        DEBUGMSGTL(("tsm","  tunneled\n"));
    }

    /* Section 5.2, Step 6 */
    /*
     * Eat the first octet header.
     */
    remaining = parms->wholeMsgLen - (parms->secParams - parms->wholeMsg);
    if ((data_ptr = asn_parse_sequence(parms->secParams, &remaining,
                                        &type_value,
                                        (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                         ASN_OCTET_STR),
                                        "usm first octet")) == NULL) {
        /*
         * RETURN parse error 
         */
        return SNMPERR_GENERR;
    }
    
    *parms->scopedPdu = data_ptr;
    *parms->scopedPduLen = parms->wholeMsgLen - (data_ptr - parms->wholeMsg);

    /* Section 5.2, Step 7 */
    *parms->maxSizeResponse = parms->maxMsgSize; /* XXX */

    tsmSecRef->securityLevel = parms->secLevel;

    return SNMPERR_SUCCESS;
}
