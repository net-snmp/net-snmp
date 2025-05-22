#!/bin/sh -eu

scriptdir=$(cd "$(dirname "$0")" && pwd)

# Only build the fuzz tests on Linux systems.
[ "$(uname)" = Linux ] || exit 0
# Only build the fuzz tests if not cross-compiling.
target=$($("${scriptdir}/../../net-snmp-config" --build-command) -v 2>&1 |
      sed -n 's/^Target: *//p')
echo "target=$target"
case "${target}" in
    *-linux|*-linux-gnu)
	;;
    *)
	echo "Cross-compiling - not building fuzzing tests"
	exit 0;;
esac

# Only set environment variables if the oss-fuzz build infrastructure is not
# used.
if [ -z "${LIB_FUZZING_ENGINE+x}" ]; then
    CC=clang
    CXX=clang++
    CFLAGS="-g3 -Wall -Werror -Wno-declaration-after-statement"
    CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fsanitize=address"
    CXXFLAGS="${CFLAGS}"
    WORK=${scriptdir}
    OUT=$WORK
    LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
    if ! $CC $CFLAGS $LIB_FUZZING_ENGINE -c -xc /dev/null -o /dev/null \
	 >/dev/null 2>&1; then
	echo "Skipping compilation of fuzz tests"
	exit 0
    fi
else
  # Handle OSS-Specific actions.
  # Some fuzzers will leak memory. Surpress leak checking on these as
  # ASAN will report leaks instantly and exit the fuzzing process.
  # The goal is to prioritise more important bugs for now.
  for fuzzer in transport mib agent_e2e api; do
    echo "[libfuzzer]" > "$OUT/snmp_${fuzzer}_fuzzer.options"
    echo "detect_leaks=0" >> "$OUT/snmp_${fuzzer}_fuzzer.options"
  done
fi


export CC CXX CFLAGS CXXFLAGS SRC WORK OUT LIB_FUZZING_ENGINE

cd "$(dirname "$(dirname "${scriptdir}")")"
"$scriptdir/build-fuzz-tests.sh"
