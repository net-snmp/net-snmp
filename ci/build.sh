#!/usr/bin/env bash

scriptdir="$(dirname "$0")"
export NOAUTODEPS=1
export SNMP_VERBOSE=1
case $(uname) in
    MINGW64*|MSYS*)
	pacman --noconfirm -y
	pacman --noconfirm --sync openssl-devel
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
