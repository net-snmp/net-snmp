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
# Variables used in global environment of calling script.
#
failcount=0
junkoutputfile="output-`basename $0`$$"




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
	rm -rf "$junkoutputfile"
}


#------------------------------------ -o- 
#
CAPTURE() {	# <command_with_arguments_to_execute>
	cat <<KNORG

EXECUTING: $*

KNORG
	( $* 2>&1 ) >$junkoutputfile
}


#------------------------------------ -o- 
# Returns: Count of matched lines.
#
CHECK() {	# <pattern_to_match>
	rval=`grep -c $* "$junkoutputfile" 2>/dev/null`
	return $rval
}


#------------------------------------ -o- 
# Returns: Count of matched lines.
#
CHECKEXACT() {	# <pattern_to_match_exactly>
	rval=`grep -wc $* "$junkoutputfile" 2>/dev/null`
	return $rval
}

