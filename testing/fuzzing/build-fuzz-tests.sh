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
# Some but not all Linux distros support static linking with libcrypto.
case "$(rpm -qf /etc/issue.net 2>/dev/null)" in
    openSUSE*)
	crypto_lib=(-lcrypto);;
    *)
	crypto_lib=(-Wl,-Bstatic -lcrypto -Wl,-Bdynamic);;
esac
krb5_libs=()
if type -p krb5-config >&/dev/null; then
    krb5_libs=($(krb5-config --libs))
fi
for fuzzname in testing/fuzzing/*_fuzzer.c; do
    fuzzname=${fuzzname%_fuzzer.c}
    fuzzname=${fuzzname#testing/fuzzing/}
    $CC $CFLAGS -c -Iinclude -Iagent/mibgroup/agentx \
	testing/fuzzing/${fuzzname}_fuzzer.c -o $WORK/${fuzzname}_fuzzer.o
    $CXX $CXXFLAGS $WORK/${fuzzname}_fuzzer.o \
        $LIB_FUZZING_ENGINE snmplib/.libs/libnetsnmp.a \
        agent/.libs/libnetsnmpagent.a \
        "${krb5_libs[@]}" "${crypto_lib[@]}" -lm \
        -o "$OUT/${fuzzname}_fuzzer"
done
