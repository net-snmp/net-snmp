#!/bin/bash -eu

# build fuzzers. To do: switch from dynamic to static linking for external
# libraries.
libs=$(sed -n 's/^NSC_LNETSNMPLIBS="\(.*\)"$/\1/p' ./net-snmp-config;
       sed -n "s/^PERLLDOPTS_FOR_LIBS='\(.*\)'/\1/p" ./config.log)
for fuzzname in testing/fuzzing/*_fuzzer.c; do
    fuzzname=${fuzzname%_fuzzer.c}
    fuzzname=${fuzzname#testing/fuzzing/}
    echo "Compiling testing/fuzzing/${fuzzname}_fuzzer.c"
    $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx \
	testing/fuzzing/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
    $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE \
        apps/.libs/libnetsnmptrapd.a \
        agent/.libs/libnetsnmpagent.a \
        agent/.libs/libnetsnmpmibs.a \
        agent/helpers/.libs/libnetsnmphelpers.a \
	snmplib/.libs/libnetsnmp.a ${libs} \
        -o "$OUT/${fuzzname}_fuzzer"
done
