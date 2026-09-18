/*
 * Copyright (c) 2026, Net-snmp authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/snmp_secmod.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/snmptsm.h>
#include <net-snmp/library/vacm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }

    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                          NETSNMP_DS_LIB_PERSISTENT_DIR, "/tmp");

    init_snmp("snmp_sec_models_fuzzer");

    /* 1. Configure USM users with different Auth/Priv protocol combinations */
    char user_md5_des[] = "fuzzMD5 MD5 authpassword1234 DES privpassword1234";
    char user_sha_aes[] = "fuzzSHA SHA authpassword1234 AES privpassword1234";
    char user_noauth[] = "fuzzNoAuth";

    usm_parse_create_usmUser("createUser", user_md5_des);
    usm_parse_create_usmUser("createUser", user_sha_aes);
    usm_parse_create_usmUser("createUser", user_noauth);

    /* 3. Configure VACM groups, access rules, and views */
    struct vacm_groupEntry *ge;
    ge = vacm_createGroupEntry(SNMP_SEC_MODEL_USM, "fuzzMD5");
    if (ge) {
        ge->status = RS_ACTIVE;
        ge->storageType = ST_NONVOLATILE;
        strlcpy(ge->groupName, "fuzzGroup", sizeof(ge->groupName));
    }
    ge = vacm_createGroupEntry(SNMP_SEC_MODEL_USM, "fuzzSHA");
    if (ge) {
        ge->status = RS_ACTIVE;
        ge->storageType = ST_NONVOLATILE;
        strlcpy(ge->groupName, "fuzzGroup", sizeof(ge->groupName));
    }
    ge = vacm_createGroupEntry(SNMP_SEC_MODEL_USM, "fuzzNoAuth");
    if (ge) {
        ge->status = RS_ACTIVE;
        ge->storageType = ST_NONVOLATILE;
        strlcpy(ge->groupName, "fuzzGroup", sizeof(ge->groupName));
    }

    struct vacm_accessEntry *ae;
    ae = vacm_createAccessEntry("fuzzGroup", "", SNMP_SEC_MODEL_USM,
                                SNMP_SEC_LEVEL_NOAUTH);
    if (ae) {
        ae->status = RS_ACTIVE;
        ae->storageType = ST_NONVOLATILE;
        ae->contextMatch = CONTEXT_MATCH_EXACT;
        strlcpy((char *)ae->views[VACM_VIEW_READ], "fullView",
                sizeof(ae->views[VACM_VIEW_READ]));
        strlcpy((char *)ae->views[VACM_VIEW_WRITE], "fullView",
                sizeof(ae->views[VACM_VIEW_WRITE]));
        strlcpy((char *)ae->views[VACM_VIEW_NOTIFY], "fullView",
                sizeof(ae->views[VACM_VIEW_NOTIFY]));
    }

    oid fullViewOid[] = { 1, 3, 6, 1 };
    struct vacm_viewEntry *ve;
    ve = vacm_createViewEntry("fullView", fullViewOid, OID_LENGTH(fullViewOid));
    if (ve) {
        ve->viewStatus = RS_ACTIVE;
        ve->viewStorageType = ST_NONVOLATILE;
        ve->viewType = SNMP_VIEW_INCLUDED;
        ve->viewMask[0] = 0xff;
        ve->viewMaskLen = 1;
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    netsnmp_session session;
    netsnmp_pdu *pdu;
    u_char *pkt;

    if (size == 0)
        return 0;

    memset(&session, 0, sizeof(session));
    session.version = SNMP_VERSION_3;

    pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    if (!pdu)
        return 0;

    pkt = netsnmp_memdup(data, size);
    if (!pkt) {
        snmp_free_pdu(pdu);
        return 0;
    }

    /* 1. Test full SNMP message parsing with active security models */
    snmp_parse(NULL, &session, pdu, pkt, size);

    /* 2. Test scoped PDU parsing directly */
    size_t scoped_bytes = size;
    netsnmp_pdu *scoped_pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    if (scoped_pdu) {
        snmpv3_scopedPDU_parse(scoped_pdu, pkt, &scoped_bytes);
        snmp_free_pdu(scoped_pdu);
    }

    /* 3. Test VACM view lookups and subtree verification */
    if (pdu->variables && pdu->variables->name && pdu->variables->name_length > 0) {
        vacm_checkSubtree("fullView", pdu->variables->name,
                          pdu->variables->name_length);
        vacm_getViewEntry("fullView", pdu->variables->name,
                          pdu->variables->name_length, VACM_MODE_FIND);
        vacm_getViewEntry("fullView", pdu->variables->name,
                          pdu->variables->name_length, VACM_MODE_IGNORE_MASK);
        vacm_getViewEntry("fullView", pdu->variables->name,
                          pdu->variables->name_length, VACM_MODE_CHECK_SUBTREE);
        vacm_getAccessEntry("fuzzGroup",
                            pdu->contextName ? pdu->contextName : "",
                            pdu->securityModel, pdu->securityLevel);
    }

    free(pkt);
    snmp_free_pdu(pdu);
    netsnmp_cleanup_session(&session);

    return 0;
}
