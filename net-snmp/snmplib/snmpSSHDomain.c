#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif
#include <pwd.h>

#ifndef MAXPATHLEN
#warn no system max path length detected
#define MAXPATHLEN 2048
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/tools.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpUDPDomain.h>
#include <net-snmp/library/snmpTCPDomain.h>
#include <net-snmp/library/snmpSSHDomain.h>

#define MAX_NAME_LENGTH 127

#define DEFAULT_SOCK_PATH "/var/net-snmp/sshdomainsocket"

typedef struct netsnmp_ssh_addr_pair_s {
    struct sockaddr_in remote_addr;
    struct in_addr local_addr;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    char username[MAX_NAME_LENGTH+1];
    struct sockaddr_un unix_socket_end;
    char socket_path[MAXPATHLEN];
} netsnmp_ssh_addr_pair;

oid netsnmp_snmpSSHDomain[] = { TRANSPORT_DOMAIN_SSH_IP };
static netsnmp_tdomain sshDomain;

const char *keyfile1="/home/hardaker/.ssh/id_rsa.pub";
const char *keyfile2="/home/hardaker/.ssh/id_rsa";
const char *username="hardaker";

#define SNMPSSHDOMAIN_USE_EXTERNAL_PIPE 1

/*
 * Not static since it is needed here as well as in snmpUDPDomain, but not
 * public either
 */
int
netsnmp_sockaddr_in2(struct sockaddr_in *addr,
                     const char *inpeername, const char *default_target);

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.  
 */

static char *
netsnmp_ssh_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    netsnmp_ssh_addr_pair *addr_pair = NULL;

    if (data != NULL && len == sizeof(netsnmp_ssh_addr_pair)) {
	addr_pair = (netsnmp_ssh_addr_pair *) data;
    } else if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_ssh_addr_pair *) t->data;
    }

    if (addr_pair == NULL) {
        return strdup("SSH: unknown");
    } else {
        struct sockaddr_in *to = NULL;
	char tmp[64];
        to = (struct sockaddr_in *) &(addr_pair->remote_addr);
        if (to == NULL) {
            return strdup("SSH: unknown");
        }

        sprintf(tmp, "SSH: [%s]:%hd",
                inet_ntoa(to->sin_addr), ntohs(to->sin_port));
        return strdup(tmp);
    }
}



/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

static int
netsnmp_ssh_recv(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_tmStateReference *tmStateRef = NULL;
    netsnmp_ssh_addr_pair *addr_pair = NULL;
    int iamclient = 0;

    DEBUGMSGTL(("ssh", "at the top of ssh_recv\n"));
    DEBUGMSGTL(("ssh", "t=%p\n", t));
    if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_ssh_addr_pair *) t->data;
    }

    DEBUGMSGTL(("ssh", "addr_pair=%p\n", addr_pair));
    if (t != NULL && addr_pair && addr_pair->channel) {
        DEBUGMSGTL(("ssh", "t=%p, addr_pair=%p, channel=%p\n",
                    t, addr_pair, addr_pair->channel));
        iamclient = 1;
	while (rc < 0) {
	    rc = libssh2_channel_read(addr_pair->channel, buf, size);
	    if (rc < 0) {  /* XXX: from tcp; ssh equiv?:  && errno != EINTR */
		DEBUGMSGTL(("ssh", "recv fd %d err %d (\"%s\")\n",
			    t->sock, errno, strerror(errno)));
		break;
	    }
	    DEBUGMSGTL(("ssh", "recv fd %d got %d bytes\n",
			t->sock, rc));
	}
    } else if (t != NULL) {

#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE

        socklen_t       tolen = sizeof(struct sockaddr_un);

        if (t != NULL && t->sock >= 0) {
            struct sockaddr *to;
            to = (struct sockaddr *) SNMP_MALLOC_STRUCT(sockaddr_un);
            if (NULL == to) {
                *opaque = NULL;
                *olength = 0;
                return -1;
            }

            if(getsockname(t->sock, to, &tolen) != 0){
                free(to);
                *opaque = NULL;
                *olength = 0;
                return -1;
            };

            while (rc < 0) {
                rc = recvfrom(t->sock, buf, size, 0, NULL, NULL);
                if (rc < 0 && errno != EINTR) {
                    DEBUGMSGTL(("ssh", "recv fd %d err %d (\"%s\")\n",
                                t->sock, errno, strerror(errno)));
                    return rc;
                }
                *opaque = (void*)to;
                *olength = sizeof(struct sockaddr_un);
            }
            DEBUGMSGTL(("ssh", "recv fd %d got %d bytes\n",
                        t->sock, rc));

            if (addr_pair->username[0] == '\0') {
                u_short name_len = 0;
                u_char *charbuf  = buf;

                if (rc < 3) {
                    /* unsupported connection version */
                    snmp_log(LOG_ERR, "unsported sshtosnmp starting size\n");
                    return -1;
                }
                
                /* we haven't received the starting info */
                if ((u_char) charbuf[0] != 1) {
                    /* unsupported connection version */
                    snmp_log(LOG_ERR, "received unsported sshtosnmp version\n");
                    return -1;
                }

                name_len = (((u_char) charbuf[1]) * 0xff) + ((u_char) charbuf[2]);

                if (name_len > MAX_NAME_LENGTH) {
                    /* unsupported connection version */
                    snmp_log(LOG_ERR, "received sshtosnmp username length which is too long\n");
                    return -1;
                }

                if (rc < 3+name_len) {
                    /* unsupported connection version */
                    snmp_log(LOG_ERR, "unsported sshtosnmp starting size (name field not big enough)\n");
                    return -1;
                }                    

                memcpy(addr_pair->username, &charbuf[3], name_len);
                addr_pair->username[name_len] = '\0';
                DEBUGMSGTL(("ssh", "Setting user name to %d -> %s\n",
                            name_len, addr_pair->username));
                if (rc == 3+name_len) {
                    /* the only packet we received was the starting one */
                    /* XXX: no good signaling mechanism here */
                    t->flags |= NETSNMP_TRANSPORT_FLAG_EMPTY_PKT;
                    return 0;
                }

                rc -= 3+name_len;
                memmove(charbuf, &charbuf[3+name_len], rc);
            }
        }
        

#else /* we're called directly by sshd and use stdin/out */

        struct passwd *user_pw;

        iamclient = 0;
        /* we're on the server side and should read from stdin */
        while (rc < 0) {
            rc = read(STDIN_FILENO, buf, size);
            if (rc < 0 && errno != EINTR) {
                DEBUGMSGTL(("ssh",
                            " read on stdin failed: %d (\"%s\")\n",
                            errno, strerror(errno)));
                break;
            }
            if (rc == 0) {
                /* 0 input is probably bad since we selected on it */
                DEBUGMSGTL(("ssh", "got a 0 read on stdin\n"));
                return -1;
            }
            DEBUGMSGTL(("ssh", "read on stdin got %d bytes\n", rc));
        }

/* XXX: need to check the username, but addr_pair doesn't exist! */
        /*
        DEBUGMSGTL(("ssh", "current username=%s\n", c));
        if (addr_pair->username[0] == '\0') {
            if ((user_pw = getpwuid(getuid())) == NULL) {
                snmp_log(LOG_ERR, "No user found for uid %d\n", getuid());
                return -1;
            }
            if (strlen(user_pw->pw_name) > sizeof(addr_pair->username)-1) {
                snmp_log(LOG_ERR, "User name '%s' too long for snmp\n",
                         user_pw->pw_name);
                return -1;
            }
            strncpy(addr_pair->username, user_pw->pw_name,
                    sizeof(addr_pair->username));
            addr_pair->username[sizeof(addr_pair->username)-1] = '\0';
        }
        */

#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */
    }

    /* create a tmStateRef cache */
    tmStateRef = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);

    /* secshell document says were always authpriv, even if NULL algorithms */
    /* ugh! */
    /* XXX: disallow NULL in our implementations */
    tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

    /* XXX: figure out how to get the specified local secname from the session */
    if (iamclient && 0) {
        /* XXX: we're on the client; we should have named the
           connection ourselves...  pull this from session somehow? */
        strncpy(tmStateRef->securityName, addr_pair->username,
                sizeof(tmStateRef->securityName)-1);
    } else {
#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE
        strncpy(tmStateRef->securityName, addr_pair->username,
                sizeof(tmStateRef->securityName)-1);
#else /* we're called directly by sshd and use stdin/out */
        /* we're on the server... */
        /* XXX: this doesn't copy properly and can get pointer
           reference issues */
        if (strlen(getenv("USER")) > 127) {
            /* ruh roh */
            /* XXX: clean up */
            return -1;
            exit;
        }

        /* XXX: detect and throw out overflow secname sizes rather
           than truncating. */
        strncpy(tmStateRef->securityName, getenv("USER"),
                sizeof(tmStateRef->securityName)-1);
#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */
    }
    tmStateRef->securityName[sizeof(tmStateRef->securityName)-1] = '\0';
    tmStateRef->securityNameLen = strlen(tmStateRef->securityName);
    *opaque = tmStateRef;
    *olength = sizeof(netsnmp_tmStateReference);

    return rc;
}



static int
netsnmp_ssh_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;

    netsnmp_ssh_addr_pair *addr_pair = NULL;
    netsnmp_tmStateReference *tmStateRef = NULL;

    if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_ssh_addr_pair *) t->data;
    }

    if (opaque != NULL && *opaque != NULL &&
        *olength == sizeof(netsnmp_tmStateReference)) {
        tmStateRef = (netsnmp_tmStateReference *) *opaque;
    }

    if (!tmStateRef) {
        /* this is now an error according to my memory in the recent draft */
        snmp_log(LOG_ERR, "netsnmp_ssh_send wasn't passed a valid tmStateReference\n");
        return -1;
    }

    if (NULL != t && NULL != addr_pair && NULL != addr_pair->channel) {
        if (addr_pair->username[0] == '\0') {
            strncpy(addr_pair->username, tmStateRef->securityName,
                    sizeof(addr_pair->username)-1);
            addr_pair->username[sizeof(addr_pair->username)-1] = '\0';
        } else if (strcmp(addr_pair->username, tmStateRef->securityName) != 0 ||
                   strlen(addr_pair->username) != tmStateRef->securityNameLen) {
            /* error!  they must always match */
            snmp_log(LOG_ERR, "netsnmp_ssh_send was passed a tmStateReference with a securityName not equal to previous messages\n");
            return -1;
        }
	while (rc < 0) {
	    rc = libssh2_channel_write(addr_pair->channel, buf, size);
	    if (rc < 0) { /* XXX:  && errno != EINTR */
		break;
	    }
	}
    } else if (t != NULL) {
#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE

	while (rc < 0) {
            rc = sendto(t->sock, buf, size, 0, NULL, 0);
            
            if (rc < 0 && errno != EINTR) {
                break;
            }
        }

#else /* we're called directly by sshd and use stdin/out */
        /* on the server; send to stdout */
	while (rc < 0) {
	    rc = write(STDOUT_FILENO, buf, size);
            fflush(stdout);
	    if (rc < 0 && errno != EINTR) { /* XXX:  && errno != EINTR */
		break;
	    }
	}
#endif
    }

    return rc;
}



static int
netsnmp_ssh_close(netsnmp_transport *t)
{
    int rc = -1;
    netsnmp_ssh_addr_pair *addr_pair = NULL;

    if (t != NULL && t->data != NULL) {
	addr_pair = (netsnmp_ssh_addr_pair *) t->data;
    }

    if (t != NULL && addr_pair && t->sock >= 0) {
        DEBUGMSGTL(("ssh", "close fd %d\n", t->sock));

        if (addr_pair->channel) {
            libssh2_channel_close(addr_pair->channel);
            libssh2_channel_free(addr_pair->channel);
            addr_pair->channel = NULL;
        }

        if (addr_pair->session) {
            libssh2_session_disconnect(addr_pair->session, "Normal Shutdown");
            libssh2_session_free(addr_pair->session);
            addr_pair->session = NULL;
        }

#ifndef HAVE_CLOSESOCKET
        rc = close(t->sock);
#else
        rc = closesocket(t->sock);
#endif
        t->sock = -1;

#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE

        close(t->sock);
        
        if (!addr_pair->session && !addr_pair->channel) {
            /* unix socket based connection */
            close(t->sock);

            /* XXX: make configurable */
            unlink(addr_pair->socket_path);
        }

#else /* we're called directly by sshd and use stdin/out */

        /* on the server: close stdin/out */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */

    } else {

#ifndef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE
        /* on the server: close stdin/out */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */

    }
    return rc;
}



static int
netsnmp_ssh_accept(netsnmp_transport *t)
{
#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE

    /* much of this is duplicated from snmpUnixDomain.c */

    netsnmp_ssh_addr_pair *addr_pair;    
    int                    newsock   = -1;
    struct sockaddr       *farend    = NULL;
    socklen_t              farendlen = sizeof(struct sockaddr_un);


    if (t != NULL && t->sock >= 0) {
        addr_pair = SNMP_MALLOC_TYPEDEF(netsnmp_ssh_addr_pair);

        if (addr_pair == NULL) {
            /*
             * Indicate that the acceptance of this socket failed.
             */
            DEBUGMSGTL(("ssh", "accept: malloc failed\n"));
            return -1;
        }

        farend = (struct sockaddr *) &addr_pair->unix_socket_end;

        newsock = accept(t->sock, farend, &farendlen);

        if (newsock < 0) {
            DEBUGMSGTL(("ssh","accept failed rc %d errno %d \"%s\"\n",
                        newsock, errno, strerror(errno)));
            free(addr_pair);
            return newsock;
        }

        if (t->data != NULL) {
            free(t->data);
        }

        DEBUGMSGTL(("ssh", "accept succeeded (farend %p len %d)\n",
                    farend, farendlen));
        t->data = addr_pair;
        t->data_length = sizeof(netsnmp_ssh_addr_pair);
        netsnmp_sock_buffer_set(newsock, SO_SNDBUF, 1, 0);
        netsnmp_sock_buffer_set(newsock, SO_RCVBUF, 1, 0);
        return newsock;
    } else {
        return -1;
    }

#else /* we're called directly by sshd and use stdin/out */
    /* we don't need to do anything; server side uses stdin/out */
    /* XXX: check that we're an ssh connection */
    
    return STDIN_FILENO; /* return stdin */
#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */

}



/*
 * Open a SSH-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is 
 * the remote address to send things to.  
 */

netsnmp_transport *
netsnmp_ssh_transport(struct sockaddr_in *addr, int local)
{
    netsnmp_transport *t = NULL;
    netsnmp_ssh_addr_pair *addr_pair = NULL;
    int rc = 0;
    int i, auth_pw = 0;
    const char *fingerprint;
    char *userauthlist;
    struct sockaddr_un *unaddr;


    if (addr == NULL || addr->sin_family != AF_INET) {
        return NULL;
    }

    t = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    if (t == NULL) {
        return NULL;
    }
    memset(t, 0, sizeof(netsnmp_transport));

    t->domain = netsnmp_snmpSSHDomain;
    t->domain_length =
        sizeof(netsnmp_snmpSSHDomain) / sizeof(netsnmp_snmpSSHDomain[0]);

    t->flags = NETSNMP_TRANSPORT_FLAG_STREAM | NETSNMP_TRANSPORT_FLAG_TUNNELED;

    addr_pair = SNMP_MALLOC_TYPEDEF(netsnmp_ssh_addr_pair);
    if (addr_pair == NULL) {
        netsnmp_transport_free(t);
        return NULL;
    }
    t->data = addr_pair;
    t->data_length = sizeof(netsnmp_ssh_addr_pair);

    if (local) {
#ifdef SNMPSSHDOMAIN_USE_EXTERNAL_PIPE

        /* XXX: set t->local and t->local_length */


        t->flags |= NETSNMP_TRANSPORT_FLAG_LISTEN;

        unaddr = &addr_pair->unix_socket_end;

        /* open a unix domain socket */
        /* XXX: get data from the transport def for it's location */
        unaddr->sun_family = AF_UNIX;
        strcpy(unaddr->sun_path, DEFAULT_SOCK_PATH);
        strcpy(addr_pair->socket_path, DEFAULT_SOCK_PATH);

        t->sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (t->sock < 0) {
            netsnmp_transport_free(t);
            return NULL;
        }

        unlink(unaddr->sun_path);
        rc = bind(t->sock, (struct sockaddr *) unaddr, SUN_LEN(unaddr));
        if (rc != 0) {
            DEBUGMSGTL(("netsnmp_ssh_transport",
                        "couldn't bind \"%s\", errno %d (%s)\n",
                        unaddr->sun_path, errno, strerror(errno)));
            netsnmp_ssh_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }


        rc = listen(t->sock, NETSNMP_STREAM_QUEUE_LEN);
        if (rc != 0) {
            DEBUGMSGTL(("netsnmp_ssh_transport",
                        "couldn't listen to \"%s\", errno %d (%s)\n",
                        unaddr->sun_path, errno, strerror(errno)));
            netsnmp_ssh_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }
        

#else /* we're called directly by sshd and use stdin/out */
        /* for ssh on the server side we've been launched so bind to
           stdin/out */

        /* nothing to do */

        /* XXX: verify we're inside ssh */
        t->sock = STDIN_FILENO;
#endif /* ! SNMPSSHDOMAIN_USE_EXTERNAL_PIPE */

    } else {
        /* XXX: need an ipv6 friendly one too (sigh) */

        /* XXX: not ideal when structs don't actually match size wise */
        memcpy(&(addr_pair->remote_addr), addr, sizeof(struct sockaddr_in));

        t->sock = socket(PF_INET, SOCK_STREAM, 0);
        if (t->sock < 0) {
            netsnmp_transport_free(t);
            return NULL;
        }

        t->remote = (u_char *)malloc(6);
        if (t->remote == NULL) {
            netsnmp_ssh_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }
        memcpy(t->remote, (u_char *) & (addr->sin_addr.s_addr), 4);
        t->remote[4] = (htons(addr->sin_port) & 0xff00) >> 8;
        t->remote[5] = (htons(addr->sin_port) & 0x00ff) >> 0;
        t->remote_length = 6;

        /*
         * This is a client-type session, so attempt to connect to the far
         * end.  We don't go non-blocking here because it's not obvious what
         * you'd then do if you tried to do snmp_sends before the connection
         * had completed.  So this can block.
         */

        rc = connect(t->sock, (struct sockaddr *)addr,
		     sizeof(struct sockaddr));

        if (rc < 0) {
            netsnmp_ssh_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }

        /*
         * Allow user to override the send and receive buffers. Default is
         * to use os default.  Don't worry too much about errors --
         * just plough on regardless.  
         */
        netsnmp_sock_buffer_set(t->sock, SO_SNDBUF, local, 0);
        netsnmp_sock_buffer_set(t->sock, SO_RCVBUF, local, 0);

        /* open the SSH session and channel */
        addr_pair->session = libssh2_session_init();
        if (libssh2_session_startup(addr_pair->session, t->sock)) {
          shutdown:
            snmp_log(LOG_ERR, "Failed to establish an SSH session\n");
            netsnmp_ssh_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }

        /* At this point we havn't authenticated, The first thing to
           do is check the hostkey's fingerprint against our known
           hosts Your app may have it hard coded, may go to a file,
           may present it to the user, that's your call
         */
        fingerprint =
            libssh2_hostkey_hash(addr_pair->session, LIBSSH2_HOSTKEY_HASH_MD5);
        DEBUGMSGTL(("ssh", "Fingerprint: "));
        for(i = 0; i < 16; i++) {
            DEBUGMSG(("ssh", "%02x",
                      (unsigned char)fingerprint[i]));
        }
        DEBUGMSG(("ssh", "\n"));

        /* check what authentication methods are available */
        userauthlist =
            libssh2_userauth_list(addr_pair->session,
                                  username, strlen(username));
        DEBUGMSG(("ssh", "Authentication methods: %s\n", userauthlist));

        /* XXX: allow other types */
        /* XXX: 4 seems magic to me... */
        if (strstr(userauthlist, "publickey") != NULL) {
            auth_pw |= 4;
        }

        /* XXX: hard coded paths and users */
        if (auth_pw & 4) {
            /* public key */
            if (libssh2_userauth_publickey_fromfile(addr_pair->session,
                                                    username,
                                                    keyfile1, keyfile2,
                                                    NULL)) {
                snmp_log(LOG_ERR,"Authentication by public key failed!\n");
                goto shutdown;
            } else {
                DEBUGMSG(("ssh",
                          "\tAuthentication by public key succeeded.\n"));
            }
        } else {
            snmp_log(LOG_ERR,"Authentication by public key failed!\n");
            goto shutdown;
        }

        /* we've now authenticated both sides; contining onward ... */

        /* Request a channel */
        if (!(addr_pair->channel =
              libssh2_channel_open_session(addr_pair->session))) {
            snmp_log(LOG_ERR, "Unable to open a session\n");
            goto shutdown;
        }

        /* Request a terminal with 'vanilla' terminal emulation
         * See /etc/termcap for more options
         */
        /* XXX: needed?  doubt it */
/*         if (libssh2_channel_request_pty(addr_pair->channel, "vanilla")) { */
/*             snmp_log(LOG_ERR, "Failed requesting pty\n"); */
/*             goto shutdown; */
/*         } */
        if (libssh2_channel_subsystem(addr_pair->channel, "snmp")) {
            snmp_log(LOG_ERR, "Failed to request the ssh 'snmp' subsystem\n");
            goto shutdown;
        }
    }

    DEBUGMSG(("ssh","Opened connection.\n"));
    /*
     * Message size is not limited by this transport (hence msgMaxSize
     * is equal to the maximum legal size of an SNMP message).  
     */

    t->msgMaxSize = 0x7fffffff;
    t->f_recv     = netsnmp_ssh_recv;
    t->f_send     = netsnmp_ssh_send;
    t->f_close    = netsnmp_ssh_close;
    t->f_accept   = netsnmp_ssh_accept;
    t->f_fmtaddr  = netsnmp_ssh_fmtaddr;

    return t;
}



netsnmp_transport *
netsnmp_ssh_create_tstring(const char *str, int local,
			   const char *default_target)
{
    struct sockaddr_in addr;

    if (netsnmp_sockaddr_in2(&addr, str, default_target)) {
        return netsnmp_ssh_transport(&addr, local);
    } else {
        return NULL;
    }
}



netsnmp_transport *
netsnmp_ssh_create_ostring(const u_char * o, size_t o_len, int local)
{
    struct sockaddr_in addr;

    if (o_len == 6) {
        unsigned short porttmp = (o[4] << 8) + o[5];
        addr.sin_family = AF_INET;
        memcpy((u_char *) & (addr.sin_addr.s_addr), o, 4);
        addr.sin_port = htons(porttmp);
        return netsnmp_ssh_transport(&addr, local);
    }
    return NULL;
}



void
netsnmp_ssh_ctor(void)
{
    sshDomain.name = netsnmp_snmpSSHDomain;
    sshDomain.name_length = sizeof(netsnmp_snmpSSHDomain) / sizeof(oid);
    sshDomain.prefix = (const char **)calloc(2, sizeof(char *));
    sshDomain.prefix[0] = "ssh";

    sshDomain.f_create_from_tstring_new = netsnmp_ssh_create_tstring;
    sshDomain.f_create_from_ostring = netsnmp_ssh_create_ostring;

    DEBUGMSGTL(("ssh", "registering the ssh domain\n"));
    netsnmp_tdomain_register(&sshDomain);
}
