#!/bin/sh
#
# T.sh
#
# Number of SUCCESSes:	FIX
#
# FIX  Short description.
#


. ./eval_tools.sh

#VERIFY <a_list_of_paths_to_files_to_verify_for_existence>

STARTTEST


#------------------------------------ -o- 
# Declarations.
#
DATAFILE_PREFIX=
DATAFILE_SUFFIXES=




#------------------------------------ -o- 
# Test.
#
OUTPUT "Example header for this test."


CAPTURE "<executable_with_arguments:_stores_stdout/stderr_for_use_later>"
FAILED $? "<diagnostic_label>"

CHECKEXACT "<string_to_look_for_an_exact_match_of_in_the_CAPTUREd_file_output>"
[ $? -eq 1 ]
FAILED $? "<diagnostic_label>"


SUCCESS "Example closing statement for this test."




#------------------------------------ -o- 
# Cleanup, exit.
#
STOPTEST

exit $failcount

