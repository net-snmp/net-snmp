#! /bin/sh -f

#
# Variables:  (* = exported)
#  *SNMP_TMPDIR:  	  place to put files used in testing.
#   SNMP_TESTDIR: 	  where the test scripts are kept.
#  *SNMP_PERSISTENT_FILE: where to store the agent's persistent information
#                         (XXX: this should be specific to just the agent)

#
# Only allow ourselves to be eval'ed once
#
if [ "x$TESTCONF_SH_EVALED" != "xyes" ]; then
    TESTCONF_SH_EVALED=yes

#
# Set up an NL suppressing echo command
#
case "`echo 'x\c'`" in
  'x\c')
    ECHO() { echo -n $*; }
    ;;
  x)
    ECHO() { echo $*\\c; }
    ;;
  *)
    echo "I don't understand your echo command ..."
    exit 1
    ;;
esac
#
# how verbose should we be (0 or 1)
#
if [ "x$SNMP_VERBOSE" = "x" ]; then
    SNMP_VERBOSE=0
    export SNMP_VERBOSE
fi

if [ "x$MIBDIRS" = "x" ]; then
    MIBDIRS=../../mibs:../../../mibs:
    export MIBDIRS
fi

# Set up the path to the programs we want to use.
if [ "x$SNMP_PATH" != "xyes" ]; then
    PATH=../agent:../apps:../../agent:../../apps:$PATH
    export PATH
    SNMP_PATH=yes
    export SNMP_PATH
fi
    

# Set up temporary directory
if [ "x$SNMP_TMPDIR" = "x" -a "x$SNMP_HEADERONLY" != "xyes" ]; then
    SNMP_TMPDIR="/tmp/snmp-test-$$"
    export SNMP_TMPDIR
    if [ -d $SNMP_TMPDIR ]; then
	echo "$0: ERROR: $SNMP_TMPDIR already existed."
	exit 1;
    fi
    mkdir $SNMP_TMPDIR
fi

if [ "x$SNMP_SAVE_TMPDIR" = "x" ]; then
    SNMP_SAVE_TMPDIR="no"
    export SNMP_SAVE_TMPDIR
fi

SNMP_TESTDIR="$SNMP_BASEDIR/tests"
SNMP_CONFIG_FILE="$SNMP_TMPDIR/snmpd.conf"
SNMP_SNMPD_PID_FILE="$SNMP_TMPDIR/snmpd.pid"
SNMP_SNMPD_LOG_FILE="$SNMP_TMPDIR/snmpd.log"
SNMP_SNMPD_PORT="-p 8765"
SNMP_PERSISTENT_FILE="$SNMP_TMPDIR/persistent-store.conf"
export SNMP_PERSISTENT_FILE

if [ "x$SNMP_FLAGS" = "x" ]; then
    SNMP_FLAGS="-d"
    export SNMP_FLAGS
fi

SNMP_FLAGS="$SNMP_FLAGS $SNMP_SNMPD_PORT"

# Make sure the agent doesn't parse any config file but what we give it.  
# this is mainly to protect against a broken agent that doesn't
# properly handle combinations of -c and -C.  (since I've broke it before).
SNMPCONFPATH="$SNMP_TMPDIR/does-not-exist"
export SNMPCONFPATH

fi # Only allow ourselves to be eval'ed once
