/*
 * Copyright (c) 2025, Net-snmp authors
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
#include "../../apps/snmptrapd_handlers.h"
#include "ada_fuzz_header.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        /*
         * Turn on all debugging, to help understand what
         * bits of the parser are running.
         */
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    oid snmpTrapOid[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
    netsnmp_variable_list var2 = {
        .name = snmpTrapOid,
        .name_length = sizeof(snmpTrapOid) / sizeof(snmpTrapOid[0])
    };
    netsnmp_variable_list var1 = { .next_variable = &var2 };
    netsnmp_transport transport = { };
    netsnmp_session sess = { };
    netsnmp_pdu *pdu;
    int op;

    af_gb_init();
    var2.val_len = af_get_short(&data, &size);
    var2.val.objid = af_gb_get_random_data(&data, &size, var2.val_len);
    if (!var2.val.objid)
        goto cleanup;
    op = NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE;
    pdu = af_gb_get_random_data(&data, &size, sizeof(*pdu));
    if (!pdu)
        goto cleanup;
    pdu->enterprise_length = af_get_short(&data, &size);
    pdu->enterprise = af_gb_get_random_data(&data, &size,
                                            pdu->enterprise_length *
                                            sizeof(pdu->enterprise[0]));
    if (!pdu->enterprise)
        goto cleanup;
    pdu->community = NULL;
    pdu->community_len = 0;
    pdu->contextEngineID = NULL;
    pdu->contextEngineIDLen = 0;
    pdu->securityEngineID = NULL;
    pdu->securityEngineIDLen = 0;
    pdu->contextName = NULL;
    pdu->contextNameLen = 0;
    pdu->securityName = NULL;
    pdu->securityNameLen = 0;
    pdu->transport_data = NULL;
    pdu->transport_data_length = 0;
    pdu->variables = &var1;
    snmp_input(op, &sess, 0/*ignored*/, pdu, &transport);

cleanup:
    af_gb_cleanup();

    return 0;
}
