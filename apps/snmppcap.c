/*
 * Copyright (c) 2015, Arista Networks, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap/pcap.h>

typedef struct mystuff {
    int pktnum;
    netsnmp_session *pss;
} mystuff_t;

void
handle_pcap(u_char *user, const struct pcap_pkthdr *h,
                                         const u_char *bytes)
{
    size_t len;
    u_char *buf;
    int skip;
    netsnmp_pdu pdu;
    mystuff_t *mystuff = (mystuff_t *)user;
    int retval;
    netsnmp_variable_list *vars;

    /*
     * If it's not a full packet, then we can't parse it.
     */
    if ( h->caplen < h->len ) {
        printf( "Skipping packet; we only have %d of %d bytes\n", h->caplen, h->len );
        return;
    }

    /*
     * For now, no error checking and almost no parsing.
     * Assume that we have all Ethernet/IPv4/UDP/SNMP.
     */
    skip = 14 /* Ethernet */ + 20 /* IPv4 */ + 8 /* UDP */;
    buf = bytes + skip;
    len = h->len - skip;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,NETSNMP_DS_LIB_DUMP_PACKET)) {
        snmp_log(LOG_DEBUG, "\nReceived %d byte packet\n",
                 len);
        xdump(buf, len, "");
    }
    /* snmp_pdu_parse( &pdu, buf, &len ); */
    /* can we get away with NULL? */
    memset( &pdu, '\0', sizeof( pdu ) );
    retval = snmp_parse( NULL, mystuff->pss, &pdu, buf, len );
    printf( "packet %d retval %d (%s)\n", mystuff->pktnum++, retval, retval ? snmp_api_errstring( retval ) : "Success" );
    for (vars = pdu.variables; vars; vars = vars->next_variable) {
       printf( "   " );
       print_variable(vars->name, vars->name_length, vars );
    }
}

void
usage(void)
{
    fprintf(stderr, "USAGE: snmppcap ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr, " FILE\n\n");
    snmp_parse_args_descriptions(stderr);
}

int main(int argc, char **argv)
{
    netsnmp_session session, *ss;
    int arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *fname;
    pcap_t *p;
    mystuff_t mystuff;

    /*
     * snmp_parse_args usage here is totally overkill, but trying to
     * parse -D
     */
    switch (arg = snmp_parse_args(argc, argv, &session, "", NULL)) {
    case NETSNMP_PARSE_ARGS_ERROR:
        exit(1);
    case NETSNMP_PARSE_ARGS_SUCCESS_EXIT:
        exit(0);
    case NETSNMP_PARSE_ARGS_ERROR_USAGE:
        usage();
        exit(1);
    default:
        break;
    }
    if (arg != argc) {
        fprintf(stderr, "Specify exactly one file name\n");
        usage();
        exit(1);
    }
    fname = argv[ arg-1 ];
    p = pcap_open_offline( fname, errbuf );
    if ( p == NULL ) {
        fprintf(stderr, "%s: %s\n", fname, errbuf );
        return 1;
    }
    if ( pcap_datalink( p ) != DLT_EN10MB) {
        fprintf(stderr, "Only Ethernet pcaps currently supported\n");
        return 2;
    }
    /* todo: add the option of a filter here */
    mystuff.pktnum = 1;
    mystuff.pss = &session;
    /*XXX*/
    session.securityModel = SNMP_SEC_MODEL_USM;
    printf("flags %x securityModel %d version %d securityNameLen %d securityEngineIDLen %d\n",
          session.flags, session.securityModel, session.version,
          session.securityNameLen, session.securityEngineIDLen);
    create_user_from_session(&session);
    pcap_loop(p, -1, handle_pcap, &mystuff);
    return 0;
}
