#!/bin/bash -eu

# build fuzzers. To do: switch from dynamic to static linking for external
# libraries.
libs=$(./net-snmp-config --external-libs)
for fuzzname in testing/fuzzing/*_fuzzer.c; do
    fuzzname=${fuzzname%_fuzzer.c}
    fuzzname=${fuzzname#testing/fuzzing/}
    $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx \
	testing/fuzzing/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
    $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE snmplib/.libs/libnetsnmp.a \
        agent/.libs/libnetsnmpagent.a ${libs} \
        -o "$OUT/${fuzzname}_fuzzer"
done
