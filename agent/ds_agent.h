#ifndef DS_AGENT_H
#define DS_AGENT_H
/* defines agent's default store registrations */

/* booleans */
#define DS_AGENT_VERBOSE        0            /* 1 if verbose output desired */
#define DS_AGENT_ROLE           1            /* 0 if master, 1 if client */
#define DS_AGENT_NO_ROOT_ACCESS 2            /* 1 if we can't get root access */

/* strings */
#define DS_AGENT_PROGNAME 0        /* argv[0] */
#define DS_AGENT_X_SOCKET 1        /* AF_UNIX or ip:port socket addr */

/* integers */
#define DS_AGENT_FLAGS    0       /* session.flags */

#endif
