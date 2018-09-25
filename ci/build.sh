#!/bin/bash

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
	export CFLAGS="-I/c/mingw/msys/1.0/include"
	export CPPFLAGS="$CFLAGS"
	export LDFLAGS="-L/c/mingw/msys/1.0/lib"
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
