#!/usr/bin/env bash

scriptdir="$(dirname "$0")"
export NOAUTODEPS=1
export SNMP_VERBOSE=1
case $(uname) in
    MINGW64*|MSYS*)
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-ada
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-fortran
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-libgfortran
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-objc
	pacman --noconfirm --sync --refresh
	pacman --noconfirm --sync --needed diffutils
	pacman --noconfirm --sync --needed make
	pacman --noconfirm --sync --needed mingw-w64-x86_64-libmariadbclient
	pacman --noconfirm --sync --needed mingw-w64-x86_64-gcc
	pacman --noconfirm --sync --needed mingw-w64-x86_64-openssl
	;;
esac
case "${BUILD}" in
    MSYS2)
	;;
    MinGW64)
	export PATH="/mingw64/bin:$PATH"
	;;
    *)
	;;
esac
echo "compiler path: $(type -p gcc)"
"${scriptdir}"/net-snmp-configure master || exit $?
make -s                                  || exit $?
case "$MODE" in
    disable-set|mini*|read-only)
        exit 0;;
esac
[ -n "$APPVEYOR" ]			 && exit 0
"${scriptdir}"/net-snmp-run-tests        || exit $?
