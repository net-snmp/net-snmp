#!/bin/bash -eu

# build fuzzers (remember to link statically)
fuzzers=(
    agentx_parse
    parse_octet_hint
    read_objid
    snmp_config
    snmp_config_mem
    snmp_mib
    snmp_parse
    snmp_parse_oid
    snmp_pdu_parse
    snmp_scoped_pdu_parse
)
krb5_libs=""
if type -p krb5-config >&/dev/null; then
    krb5_libs=$(krb5-config --libs)
fi
for fuzzname in "${fuzzers[@]}"; do
  $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx $SRC/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
  $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE snmplib/.libs/libnetsnmp.a \
        agent/.libs/libnetsnmpagent.a \
        -Wl,-no-undefined ${krb5_libs} -lcrypto -lm \
        -o $OUT/${fuzzname}_fuzzer
done
