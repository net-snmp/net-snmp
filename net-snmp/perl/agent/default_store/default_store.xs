#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <net-snmp/agent/ds_agent.h>

static int
not_here(char *s)
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant_DS_AGENT_P(char *name, int len, int arg)
{
    switch (name[10 + 0]) {
    case 'O':
	if (strEQ(name + 10, "ORTS")) {	/* DS_AGENT_P removed */
#ifdef DS_AGENT_PORTS
	    return DS_AGENT_PORTS;
#else
	    goto not_there;
#endif
	}
    case 'R':
	if (strEQ(name + 10, "ROGNAME")) {	/* DS_AGENT_P removed */
#ifdef DS_AGENT_PROGNAME
	    return DS_AGENT_PROGNAME;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant_DS_AGENT_A(char *name, int len, int arg)
{
    if (10 + 6 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[10 + 6]) {
    case 'M':
	if (strEQ(name + 10, "GENTX_MASTER")) {	/* DS_AGENT_A removed */
#ifdef DS_AGENT_AGENTX_MASTER
	    return DS_AGENT_AGENTX_MASTER;
#else
	    goto not_there;
#endif
	}
    case 'P':
	if (strEQ(name + 10, "GENTX_PING_INTERVAL")) {	/* DS_AGENT_A removed */
#ifdef DS_AGENT_AGENTX_PING_INTERVAL
	    return DS_AGENT_AGENTX_PING_INTERVAL;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

static double
constant(char *name, int len, int arg)
{
    errno = 0;
    if (0 + 9 >= len ) {
	errno = EINVAL;
	return 0;
    }
    switch (name[0 + 9]) {
    case 'A':
	if (!strnEQ(name + 0,"DS_AGENT_", 9))
	    break;
	return constant_DS_AGENT_A(name, len, arg);
    case 'F':
	if (strEQ(name + 0, "DS_AGENT_FLAGS")) {	/*  removed */
#ifdef DS_AGENT_FLAGS
	    return DS_AGENT_FLAGS;
#else
	    goto not_there;
#endif
	}
    case 'G':
	if (strEQ(name + 0, "DS_AGENT_GROUPID")) {	/*  removed */
#ifdef DS_AGENT_GROUPID
	    return DS_AGENT_GROUPID;
#else
	    goto not_there;
#endif
	}
    case 'H':
	if (strEQ(name + 0, "DS_AGENT_H")) {	/*  removed */
#ifdef DS_AGENT_H
	    return DS_AGENT_H;
#else
	    goto not_there;
#endif
	}
    case 'I':
	if (strEQ(name + 0, "DS_AGENT_INTERNAL_SECNAME")) {	/*  removed */
#ifdef DS_AGENT_INTERNAL_SECNAME
	    return DS_AGENT_INTERNAL_SECNAME;
#else
	    goto not_there;
#endif
	}
    case 'N':
	if (strEQ(name + 0, "DS_AGENT_NO_ROOT_ACCESS")) {	/*  removed */
#ifdef DS_AGENT_NO_ROOT_ACCESS
	    return DS_AGENT_NO_ROOT_ACCESS;
#else
	    goto not_there;
#endif
	}
    case 'P':
	if (!strnEQ(name + 0,"DS_AGENT_", 9))
	    break;
	return constant_DS_AGENT_P(name, len, arg);
    case 'R':
	if (strEQ(name + 0, "DS_AGENT_ROLE")) {	/*  removed */
#ifdef DS_AGENT_ROLE
	    return DS_AGENT_ROLE;
#else
	    goto not_there;
#endif
	}
    case 'U':
	if (strEQ(name + 0, "DS_AGENT_USERID")) {	/*  removed */
#ifdef DS_AGENT_USERID
	    return DS_AGENT_USERID;
#else
	    goto not_there;
#endif
	}
    case 'V':
	if (strEQ(name + 0, "DS_AGENT_VERBOSE")) {	/*  removed */
#ifdef DS_AGENT_VERBOSE
	    return DS_AGENT_VERBOSE;
#else
	    goto not_there;
#endif
	}
    case 'X':
	if (strEQ(name + 0, "DS_AGENT_X_SOCKET")) {	/*  removed */
#ifdef DS_AGENT_X_SOCKET
	    return DS_AGENT_X_SOCKET;
#else
	    goto not_there;
#endif
	}
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = NetSNMP::agent::default_store	PACKAGE = NetSNMP::agent::default_store


double
constant(sv,arg)
    PREINIT:
	STRLEN		len;
    INPUT:
	SV *		sv
	char *		s = SvPV(sv, len);
	int		arg
    CODE:
	RETVAL = constant(s,len,arg);
    OUTPUT:
	RETVAL

