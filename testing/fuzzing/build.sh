#!/bin/bash -eu

# Skip building the fuzz tests on OS/X and MinGW.
[ "$(uname)" = Linux ] || exit 0

scriptdir=$(cd "$(dirname "$0")" && pwd)

# Only set environment variables if the oss-fuzz build infrastructure is not
# used.
if [ -z "${LIB_FUZZING_ENGINE+x}" ]; then
    CC=clang
    CXX=clang++
    CFLAGS="-Wall -Werror -fsanitize=fuzzer-no-link"
    CXXFLAGS="${CFLAGS} -lssl"
    WORK=${scriptdir}
    OUT=$WORK
    LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
    if ! $CC $CFLAGS $LIB_FUZZING_ENGINE -c -xc /dev/null -o /dev/null \
	 >&/dev/null; then
	echo "Skipping compilation of fuzz tests"
	exit 0
    fi
fi

export CC CXX CFLAGS CXXFLAGS SRC WORK OUT LIB_FUZZING_ENGINE

cd "$(dirname "$(dirname "${scriptdir}")")"
$scriptdir/build-fuzz-tests.sh
