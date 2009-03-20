/* Copyright 2009 SPARTA, Inc. All rights reserved
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/*
 * This is merely a wrapper around stdin/out for sshd to call.  It
 * simply passes traffic to the running snmpd through a unix domain
 * socket after first passing any needed SSH Domain information.
 */

#include <net-snmp/net-snmp-config.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#ifndef MAXPATHLEN
#warn no system max path length detected
#define MAXPATHLEN 2048
#endif

#define DEFAULT_SOCK_PATH "/var/net-snmp/sshdomainsocket"

#define SSHTOSNMP_VERSION_NUMBER 1



/*
 * Extra debugging output for, um, debugging.
 */

#define DEBUGGING 0

#ifdef DEBUGGING
#define DEBUG(x) deb(x)
#include <stdio.h>
FILE *debf = NULL;
void
deb(const char *string) {
    if (NULL == debf) {
        debf = fopen("/tmp/sshtosnmp.log", "a");
    }
    if (NULL != debf) {
        fprintf(debf, "%s\n", string);
        fflush(debf);
    }
}
#else  /* !DEBUGGING */
#define DEBUG(x)
#endif /* DEBUGGING code */

int
main(int argc, char **argv) {

    int sock;
    struct sockaddr_un addr;
    u_char buf[4096];
    u_short name_len;
    int rc = 0, pktsize = 0;

    fd_set read_set;

    DEBUG("starting up");

    /* Open a connection to the UNIX domain socket or fail */

    addr.sun_family = AF_UNIX;
    if (argc > 1) {
        strcpy(addr.sun_path, argv[1]);
    } else {
        strcpy(addr.sun_path, DEFAULT_SOCK_PATH);
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    DEBUG("created socket");
    if (sock <= 0) {
        exit(1);
    }
    if (connect(sock, (struct sockaddr *) &addr,
                sizeof(struct sockaddr_un)) != 0) {
        DEBUG("FAIL CONNECT");
        exit(1);
    }

    DEBUG("opened socket");

    /*
     * we are running as the user that ssh authenticated us as, and this
     * is the name that the agent needs for processing as a SNMPv3
     * security name.  So this is the only thing needed to pass to the
     * agent.
     */

    /* In case of future changes, we'll pass a version number first */

    buf[0] = SSHTOSNMP_VERSION_NUMBER;

    /* now send the user name, prefixed by a 16-bit length */

    name_len = strlen(getenv("USER"));
    if (name_len > sizeof(buf)-2) {
        exit(1);
    }
    buf[1] = (name_len & 0xff00) >> 8;
    buf[2] = (name_len & 0xff);

    /* XXX: should do this via getpwuid(getuid()) */
    memcpy(&buf[3], getenv("USER"), name_len);

    sendto(sock, buf, name_len+3, 0, NULL, 0);
    DEBUG("sent name");
    
    /* now we just send and receive from both the socket and stdin/stdout */

    while(1) {
        /* read from stdin and the socket */
        FD_SET(sock, &read_set);
        FD_SET(STDIN_FILENO, &read_set);

        /* blocking without a timeout be fine fine */
        select(sock+1, &read_set, NULL, NULL, NULL);

        if (FD_ISSET(STDIN_FILENO, &read_set)) {
            /* read from stdin to get stuff from sshd to send to the agent */
            DEBUG("data from stdin");
            rc = read(STDIN_FILENO, buf, sizeof(buf));

            if (rc <= 0) {
                /* end-of-file */
#ifndef HAVE_CLOSESOCKET
                rc = close(sock);
#else
                rc = closesocket(sock);
#endif
                exit(0);
            }
            DEBUG("read from stdin");

            /* send it up the pipe */
            pktsize = rc;
            rc = -1;
            while (rc < 0) {
                DEBUG("sending to socket");
                rc = sendto(sock, buf, pktsize, 0, NULL, 0);
                DEBUG("back from sendto");
                if (rc < 0)
                    DEBUG("sentto failed");
                if (rc < 0 && errno != EINTR) {
                    break;
                }
            }
            if (rc > 0)
                DEBUG("sent to socket");
            else
                DEBUG("failed to send to socket!!");
        }

        if (FD_ISSET(sock, &read_set)) {
            /* read from the socket and send to to stdout which goes to sshd */
            DEBUG("data on unix socket");

            rc = -1;
            while (rc < 0) {
                rc = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
                if (rc < 0 && errno != EINTR) {
                    close(sock);
                    exit(0);
                }
            }
            DEBUG("read from socket");

            pktsize = rc;
            rc = write(STDOUT_FILENO, buf, pktsize);
            /* XXX: check that counts match */
            if (rc > 0) {
                DEBUG("wrote to stdout");
            } else {
                DEBUG("failed to write to stdout");
            }
        }
    }
}
