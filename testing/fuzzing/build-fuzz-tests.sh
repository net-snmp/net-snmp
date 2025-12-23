#!/bin/bash -eu

# build fuzzers. To do: switch from dynamic to static linking for external
# libraries.
scriptdir=$(cd "$(dirname "$0")" && pwd)
libs=$(sed -n 's/^NSC_LNETSNMPLIBS="\(.*\)"$/\1/p' ./net-snmp-config;
       sed -n "s/^PERLLDOPTS_FOR_LIBS='\(.*\)'/\1/p" ./config.log)
for fuzzname in testing/fuzzing/*_fuzzer.c; do
    {
    fuzzname=${fuzzname%_fuzzer.c}
    fuzzname=${fuzzname#testing/fuzzing/}
    echo "Compiling testing/fuzzing/${fuzzname}_fuzzer.c"
    $CC	$(${scriptdir}/../../net-snmp-config --base-cflags) \
	$CFLAGS -c -Iinclude -Iagent/mibgroup/agentx \
	-Wno-unused-command-line-argument \
	testing/fuzzing/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
    $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
	-Wno-unused-command-line-argument \
	$(${scriptdir}/../../net-snmp-config --ldflags) \
        $LIB_FUZZING_ENGINE \
        apps/.libs/libnetsnmptrapd.a \
        agent/.libs/libnetsnmpmibs.a \
        agent/.libs/libnetsnmpagent.a \
        agent/helpers/.libs/libnetsnmphelpers.a \
	snmplib/.libs/libnetsnmp.a ${libs} \
        -o "$OUT/${fuzzname}_fuzzer"
    } &
done
wait
