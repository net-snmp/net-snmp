#!/usr/bin/env bash

scriptdir="$(dirname "$0")"
export NOAUTODEPS=1
export SNMP_VERBOSE=1
if [ -z "$OSTYPE" ]; then
    case "$(uname)" in
        Linux)  OSTYPE=linux;;
        Darwin) OSTYPE=darwin;;
        *)      OSTYPE="UNKNOWN:$(uname)";;
    esac
    export OSTYPE
fi
case "$OSTYPE" in
    msys)
	;;
esac
"${scriptdir}"/net-snmp-configure master || exit $?
make -s                                  || exit $?
case "$MODE" in
    disable-set|mini*|read-only)
        exit 0;;
esac
[ -n "$APPVEYOR" ]			 && exit 0
"${scriptdir}"/net-snmp-run-tests        || exit $?
