#!/bin/sh
#
# eval_onescript.sh SCRIPT
#
# Evaluates one test program, and helps it out by doing a bit of setup
# for it.  It does this by sourcing some configuration files for it
# first, and if it exited without calling FINISHED, call it.
#
# Not intended to be a tool for the common user!  Called by RUNTESTS
# directly instead.
#

. TESTCONF.sh

. eval_tools.sh

. ./$1

# We shouldn't get here...
# If we do, it means they didn't exit properly.
# So we will.
STOPAGENT      # Just in case.
FINISHED
