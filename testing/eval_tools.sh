#
# eval_tools.sh
#
# Output functions for script tests.  Source this from other test scripts
# to establish a standardized repertory of test functions.
#
#
# Except where noted, all functions return:
#	0	On success,	(Bourne Shell's ``true'')
#	non-0	Otherwise.
#
# Input arguments to each function are documented with each function.
#
#
# XXX  Suggestions:
#	DEBUG ON|OFF
#	dump CAPTURE output to stdout as well as to junkoutputfile.
#

#
# Only allow ourselves to be eval'ed once
#
if [ "x$EVAL_TOOLS_SH_EVALED" != "xyes" ]; then
    EVAL_TOOLS_SH_EVALED=yes
    . TESTCONF.sh

#
# Variables used in global environment of calling script.
#
failcount=0
junkoutputfile="$SNMP_TMPDIR/output-`basename $0`$$"
seperator="-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

#
# HEADER: returns a single line when SNMP_HEADERONLY mode and exits.
#
HEADER() {
    if [ "x$SNMP_HEADERONLY" != "x" ]; then
        echo test $*
	exit 0;
    else
	ECHO "testing $*...  "
	headerStr="testing $*"
    fi
}


#------------------------------------ -o-
#
OUTPUT() {	# <any_arguments>
	cat <<GRONK


$*


GRONK
}


#------------------------------------ -o-
#
SUCCESS() {	# <any_arguments>
	[ "$failcount" -ne 0 ] && return
	cat <<GROINK

SUCCESS: $*

GROINK
}



#------------------------------------ -o-
#
FAILED() {	# <return_value>, <any_arguments>
	[ "$1" -eq 0 ] && return
	shift

	failcount=`expr $failcount + 1`
	cat <<GRONIK

FAILED: $*

GRONIK
}

#------------------------------------ -o-
#
SKIPIFNOT() {
	grep "define $1" $SNMP_UPDIR/config.h $SNMP_UPDIR/mib_module_config.h > /dev/null
	if [ $? != 0 ]; then
	    REMOVETESTDATA
	    echo "SKIPPED"
	    exit 0;
	fi
}
	

#------------------------------------ -o-
#
VERIFY() {	# <path_to_file(s)>
	local	missingfiles=

	for f in $*; do
		[ -e "$f" ] && continue
		echo "FAILED: Cannot find file \"$f\"."
		missingfiles=true
	done

	[ "$missingfiles" = true ] && exit 1000
}


#------------------------------------ -o-
#
STARTTEST() {	
	[ ! -e "$junkoutputfile" ] && {
		touch $junkoutputfile
		return
	}
	echo "FAILED: Output file already exists: \"$junkoutputfile\"."
	exit 1000
}


#------------------------------------ -o-
#
STOPTEST() {
	rm -f "$junkoutputfile"
}


#------------------------------------ -o-
#
REMOVETESTDATA() {
#	ECHO "removing $SNMP_TMPDIR  "
	rm -rf $SNMP_TMPDIR
}


#------------------------------------ -o-
#
CAPTURE() {	# <command_with_arguments_to_execute>
    echo $* >> $SNMP_TMPDIR/invoked

	if [ $SNMP_VERBOSE -gt 0 ]; then
		cat <<KNORG

EXECUTING: $*

KNORG

	fi
	( $* 2>&1 ) > $junkoutputfile 2>&1

	if [ $SNMP_VERBOSE -gt 1 ]; then
		echo "Command Output: "
		echo "MIBDIR $MIBDIRS $MIBS"
		echo "$seperator"
		cat $junkoutputfile | sed 's/^/  /'
		echo "$seperator"
	fi
}

#------------------------------------ -o-
# Delay to let processes settle
DELAY() {
    if [ $SNMP_SLEEP -ne 0 ] ; then
	sleep $SNMP_SLEEP
    fi
}

#
# Checks the output result against what we expect.
#   Sets return_value to 0 or 1.
#
EXPECTRESULT() {
    if [ $snmp_last_test_result = $1 ]; then
	return_value=0
    else
	return_value=1
    fi
}

#------------------------------------ -o-
# Returns: Count of matched lines.
#
CHECK() {	# <pattern_to_match>
    if [ $SNMP_VERBOSE -gt 0 ]; then
	echo -n "checking output for \"$*\"..."
    fi

    rval=`grep -c "$*" "$junkoutputfile" 2>/dev/null`

    if [ $SNMP_VERBOSE -gt 0 ]; then
	echo "$rval matches found"
    fi

    snmp_last_test_result=$rval
    EXPECTRESULT 1  # default
    return $rval
}


CHECKTRAPD() {
    oldjunkoutpufile=$junkoutputfile
    junkoutputfile=$SNMP_SNMPTRAPD_LOG_FILE
    CHECK $*
    junkoutputfile=$oldjunkoutputfile
}

#------------------------------------ -o-
# Returns: Count of matched lines.
#
CHECKEXACT() {	# <pattern_to_match_exactly>
	rval=`grep -wc "$*" "$junkoutputfile" 2>/dev/null`
	snmp_last_test_result=$rval
	EXPECTRESULT 1  # default
	return $rval
}

CONFIGAGENT() {
    if [ "x$SNMP_CONFIG_FILE" = "x" ]; then
	echo "$0: failed because var: SNMP_CONFIG_FILE wasn't set"
	exit 1;
    fi
    echo $* >> $SNMP_CONFIG_FILE
}

CONFIGTRAPD() {
    if [ "x$SNMPTRAPD_CONFIG_FILE" = "x" ]; then
	echo "$0: failed because var: SNMPTRAPD_CONFIG_FILE wasn't set"
	exit 1;
    fi
    echo $* >> $SNMPTRAPD_CONFIG_FILE
}

#
# common to STARTAGENT and STARTTRAPD
# log command to "invoked" file
# delay after command to allow for settle
#
STARTPROG() {
    if [ $SNMP_VERBOSE -gt 1 ]; then
	echo "$CFG_FILE contains: "
	if [ -f $CFG_FILE ]; then
	    cat $CFG_FILE
	else
	    echo "[no config file]"
	fi
    fi
    if test -f $CFG_FILE; then
	COMMAND="$COMMAND -C -c $CFG_FILE"
    fi
    if [ $SNMP_VERBOSE -gt 0 ]; then
	echo "running: $COMMAND"
    fi
    echo $COMMAND >> $SNMP_TMPDIR/invoked
    $COMMAND > $LOG_FILE.stdout 2>&1

    DELAY
}

#------------------------------------ -o-
STARTAGENT() {
    COMMAND="snmpd $SNMP_FLAGS -r -P $SNMP_SNMPD_PID_FILE -l $SNMP_SNMPD_LOG_FILE $AGENT_FLAGS"
    CFG_FILE=$SNMP_CONFIG_FILE
    LOG_FILE=$SNMP_SNMPD_LOG_FILE

    STARTPROG
}

#------------------------------------ -o-
STARTTRAPD() {
    COMMAND="snmptrapd -d $SNMP_SNMPTRAPD_PORT -u $SNMP_SNMPTRAPD_PID_FILE -o $SNMP_SNMPTRAPD_LOG_FILE"
    CFG_FILE=$SNMPTRAPD_CONFIG_FILE
    LOG_FILE=$SNMP_SNMPTRAPD_LOG_FILE

    STARTPROG
}


## used by STOPAGENT and STOPTRAPD
# delay before kill to allow previous action to finish
#    this is especially important for interaction between
#    master agent and sub agent.
STOPPROG() {
    if [ -f $1 ]; then
	COMMAND="kill -TERM `cat $1`"
	echo $COMMAND >> $SNMP_TMPDIR/invoked

	DELAY
	$COMMAND > /dev/null 2>&1
    fi
}

#------------------------------------ -o-
#
STOPAGENT() {
    STOPPROG $SNMP_SNMPD_PID_FILE
    if [ $SNMP_VERBOSE -gt 1 ]; then
	echo "Agent Output:"
	echo "$seperator [stdout]"
	cat $SNMP_SNMPD_LOG_FILE.stdout
	echo "$seperator [logfile]"
	cat $SNMP_SNMPD_LOG_FILE
	echo "$seperator"
    fi
}

#------------------------------------ -o-
#
STOPTRAPD() {
    STOPPROG $SNMP_SNMPTRAPD_PID_FILE
    if [ $SNMP_VERBOSE -gt 1 ]; then
	echo "snmptrapd Output:"
	echo "$seperator [stdout]"
	cat $SNMP_SNMPTRAPD_LOG_FILE.stdout
	echo "$seperator [logfile]"
	cat $SNMP_SNMPTRAPD_LOG_FILE
	echo "$seperator"
    fi
}

#------------------------------------ -o-
#
FINISHED() {
    for pfile in $SNMP_TMPDIR/*pid* ; do
	pid=`cat $pfile`
	ps -e | egrep "^[ ]*$pid" > /dev/null 2>&1
	if [ $? = 0 ] ; then
	    SNMP_SAVE_TMPDIR=yes
	    COMMAND="kill -9 $pid"
	    echo $COMMAND "($pfile)" >> $SNMP_TMPDIR/invoked
	    $COMMAND > /dev/null 2>&1
	    return_value=1
	fi
    done
    if [ "x$return_value" != "x0" ]; then
	if [ -s core ] ; then
	    # XX hope that only one prog cores !
	    cp core $SNMP_TMPDIR/core.$$
	    rm -f core
	fi
	echo "FAIL"
	echo "$headerStr...FAIL" >> $SNMP_TMPDIR/invoked
	exit $return_value
    fi

    echo "ok"
    echo "$headerStr...ok" >> $SNMP_TMPDIR/invoked

    if [ "x$SNMP_SAVE_TMPDIR" != "xyes" ]; then
	REMOVETESTDATA
    fi
    exit $return_value
}

#------------------------------------ -o-
#
VERBOSE_OUT() {
    if [ $SNMP_VERBOSE > $1 ]; then
	shift
	echo "$*"
    fi
}

fi # Only allow ourselves to be eval'ed once
