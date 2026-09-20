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
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/agent_registry.h>
#include <protocol.h>
#include <master.h>
#include <master_admin.h>
#include "../../agent/snmpd.h"
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int
fuzzer_transport_send(netsnmp_transport *t, const void *buf, int size,
                      void **opaque, int *opaque_len)
{
    return size;
}

static int
fuzzer_transport_close(netsnmp_transport *t)
{
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char path[PATH_MAX];
    char mibdirs[PATH_MAX];
    char *dir;

    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }

    strlcpy(path, (*argv)[0], sizeof(path));
    dir = dirname(path);
    snprintf(mibdirs, sizeof(mibdirs), "%s/../../mibs", dir);
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS,
                          mibdirs);
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_ROLE, MASTER_AGENT);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                          NETSNMP_DS_LIB_PERSISTENT_DIR, "/tmp");

    init_agent("agentx_master_fuzzer");
    init_snmp("agentx_master_fuzzer");

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    netsnmp_session sess, *session = NULL;
    netsnmp_transport *t = NULL;
    size_t offset = 0;

    if (size == 0)
        return 0;

    snmp_sess_init(&sess);
    sess.version = AGENTX_VERSION_1;
    sess.flags |= SNMP_FLAGS_STREAM_SOCKET;
    sess.callback = handle_master_agentx_packet;

    t = netsnmp_transport_alloc();
    if (!t)
        return 0;

    t->f_send = fuzzer_transport_send;
    t->f_close = fuzzer_transport_close;
    t->msgMaxSize = 65535;

    session = snmp_add_full(&sess, t, NULL, agentx_parse, NULL, NULL,
                            agentx_realloc_build, agentx_check_packet, NULL);
    if (!session)
        return 0;

    handle_master_agentx_packet(NETSNMP_CALLBACK_OP_CONNECT, session, 0,
                                NULL, NULL);

    while (offset < size) {
        size_t remaining = size - offset;
        int pkt_len = agentx_check_packet(NETSNMP_REMOVE_CONST(u_char *, data + offset),
                                          remaining);
        if (pkt_len <= 0 || (size_t)pkt_len > remaining) {
            pkt_len = remaining;
        }

        netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
        if (!pdu)
            break;

        pdu->version = AGENTX_VERSION_1;
        if (agentx_parse(session, pdu,
                         NETSNMP_REMOVE_CONST(u_char *, data + offset),
                         pkt_len) == SNMP_ERR_NOERROR) {
            handle_master_agentx_packet(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
                                        session, pdu->reqid, pdu, NULL);
        }

        snmp_free_pdu(pdu);
        offset += pkt_len;
    }

    handle_master_agentx_packet(NETSNMP_CALLBACK_OP_DISCONNECT, session, 0,
                                NULL, NULL);
    snmp_close(session);

    return 0;
}
