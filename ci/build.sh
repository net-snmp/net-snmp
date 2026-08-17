#!/usr/bin/env bash

scriptdir="$(dirname "$0")"

case "$MODE" in
    Android)
	NDK=$PWD/android-ndk-r27d/toolchains/llvm/prebuilt/linux-x86_64/bin
	export PATH="${NDK}:${PATH}"
	export CC=aarch64-linux-android34-clang
	;;
esac
echo "compiler path: $(type -p "${CC:-gcc}")"
branch_name=$(git rev-parse --abbrev-ref HEAD)
if ! "${scriptdir}"/net-snmp-configure "${branch_name}"; then
    echo "========================================"
    echo "Configure failed. Dumping config.log:"
    echo "========================================"
    cat config.log
    exit 1
fi
case "$MODE" in
    mini*)
	# Net-SNMP uses static dependencies, the Makefile.depend files have
	# been generated for MODE=regular, net-snmp-features.h includes
	# <net-snmp/library/features.h> in minimalist mode and that file is
	# generated dynamically and is not in Makefile.depend. Hence disable
	# parallel compilation for minimalist mode.
	nproc=1;;
    *)
	if type nproc >/dev/null 2>&1; then
	    nproc=$(nproc)
	else
	    nproc=1
	fi;;
esac
make -s -j"${nproc}" || exit $?
case "$MODE" in
    regular)
	if [ -e testing/fuzzing ]; then
	    make -C testing -s fuzz-tests || exit $?
	fi
	;;
esac
