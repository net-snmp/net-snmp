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

static netsnmp_session *add_session(netsnmp_transport *t)
{
    netsnmp_session session;

    snmp_sess_init(&session);
    session.peername = SNMP_DEFAULT_PEERNAME;
    session.version = SNMP_DEFAULT_VERSION;
    session.community_len = SNMP_DEFAULT_COMMUNITY_LEN;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.callback = snmp_input;
    session.callback_magic = t;
    session.authenticator = NULL;
    session.isAuthoritative = SNMP_SESS_UNKNOWNAUTH;

    return snmp_add(&session, t, NULL, NULL);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("sess_process_packet");
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    netsnmp_transport *transport = NULL;
    netsnmp_session *session = NULL;
    const unsigned short pkt_len = size;
    const void *const pkt = data;
    int skt = -1;
    int ret = 1;

    if (pkt_len == 0)
        goto cleanup;

    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIBDIRS, "mibs");
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PERSISTENT_DIR,
                          "/tmp");

    init_snmp("snmptrapd");

    transport = netsnmp_transport_open_server("trap_fuzzer", "127.0.0.1:7365");
    if (!transport) {
        fprintf(stderr, "Error: failed to open Net-SNMP transport.\n");
        goto cleanup;
    }
    session = add_session(transport);
    if (!session) {
        fprintf(stderr, "Error: failed to add Net-SNMP session.\n");
        goto cleanup;
    }

    skt = socket(AF_INET, SOCK_DGRAM, 0);
    if (skt < 0) {
        perror("socket()");
        goto shutdown;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(7365),
        .sin_addr = { htonl(INADDR_LOOPBACK) }
    };
    if (connect(skt, &addr, sizeof(addr)) < 0) {
        perror("connect()");
        goto shutdown;
    }
    if (send(skt, pkt, pkt_len, 0) < 0) {
        perror("send()");
        goto shutdown;
    }
    {
        fd_set readfds,writefds,exceptfds;
        int numfds = 0, block = 0;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        timerclear(&timeout);
        timeout.tv_sec = 5;
        snmp_select_info(&numfds, &readfds, &timeout, &block);
        if (select(numfds, &readfds, &writefds, &exceptfds, &timeout) > 0)
            snmp_read(&readfds);
    }
    ret = 0;

shutdown:
    snmp_shutdown("snmptrapd");

cleanup:
    if (skt >= 0)
        close(skt);
    if (session)
        snmp_close(session);

    return ret;
}
