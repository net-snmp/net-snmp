#!/bin/sh

case "$(uname)" in
    Darwin)
	# Instead of relying on the hosts file provided by the CI host, replace
	# it. See also
	# https://blog.justincarmony.com/2011/07/27/mac-os-x-lion-etc-hosts-bugs-and-dns-resolution/.
	sudo sh -c 'printf "127.0.0.1 ipv4-loopback\n::1 localhost ipv6-localhost ipv6-loopback\n" >/etc/hosts'
	;;
esac

head -n 999 /etc/hosts

scriptdir="$(dirname "$0")"

# To do: fix the tests for the disable-set, mini and read-only modes and delete
# the case statement below.
case "$MODE" in
    "")
	;;
    disable-ipv6|regular)
        ;;
    performance)
        ;;
    *)
	exit 0
        ;;
esac

case $(uname) in
    MinGW)
	;;
    *)
	if [ "$MODE" != "performance" ]; then
            "${scriptdir}"/net-snmp-run-tests
        fi
	;;
esac

# ---- Entity MIB performance scenario ---------------------------------------
# Runs only on Linux (entity_linux.c is Linux-only).
# Starts snmpd on a non-privileged port with entity debug logging enabled,
# triggers one arch_load via snmpwalk, reports per-phase timing, and fails
# if the total load exceeds ENTITY_PERF_LIMIT_MS (default 30 000 ms).
# Set MODE=performance to run this scenario exclusively.
# Results are saved to .tmp/perf-<git-short>-<date>.txt alongside the log.
if [ "$MODE" = "performance" ] || [ "$(uname)" = "Linux" ]; then
    ENTITY_PORT=11610
    ENTITY_COMMUNITY=ci_perf
    ENTITY_PERF_LIMIT_MS=${ENTITY_PERF_LIMIT_MS:-30000}
    ENTITY_LOG=$(mktemp /tmp/entity_perf_XXXXXX.log)
    ENTITY_CONF=$(mktemp /tmp/entity_perf_XXXXXX.conf)

    _git_short=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    _git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    _git_subject=$(git log -1 --pretty=%s 2>/dev/null || echo "")
    _run_date=$(date '+%Y-%m-%dT%H:%M:%S')
    _result_dir=".tmp/perf"
    _result_file="${_result_dir}/perf-${_git_short}-$(date '+%Y%m%d-%H%M%S').txt"

    printf 'rocommunity %s 127.0.0.1\n' "$ENTITY_COMMUNITY" > "$ENTITY_CONF"

    echo "==== Entity MIB performance scenario (port $ENTITY_PORT) ===="

    # Build agent if not already built
    make -s agent/snmpd 2>/dev/null || true

    agent/snmpd -f -Lo -Dentity \
        -C -c "$ENTITY_CONF" \
        "$ENTITY_PORT" \
        > "$ENTITY_LOG" 2>&1 &
    ENTITY_PID=$!

    # Wait for agent to accept requests (up to 15 s)
    _ready=0
    for _i in $(seq 1 30); do
        sleep 0.5
        if snmpget -v2c -c "$ENTITY_COMMUNITY" \
                   -r 1 -t 1 \
                   localhost:"$ENTITY_PORT" \
                   SNMPv2-MIB::sysDescr.0 \
                   >/dev/null 2>&1; then
            _ready=1
            break
        fi
    done

    if [ "$_ready" = "0" ]; then
        echo "FAIL: snmpd did not become ready within 15 s"
        kill "$ENTITY_PID" 2>/dev/null
        rm -f "$ENTITY_LOG" "$ENTITY_CONF"
        exit 1
    fi

    # Trigger arch_load
    snmpwalk -v2c -c "$ENTITY_COMMUNITY" \
             -r 1 -t 30 \
             localhost:"$ENTITY_PORT" \
             ENTITY-MIB::entPhysicalTable > /dev/null 2>&1

    sleep 0.5
    kill "$ENTITY_PID" 2>/dev/null
    wait "$ENTITY_PID" 2>/dev/null

    # Parse total load time
    _total_line=$(grep "entity: arch_load complete:" "$ENTITY_LOG" | tail -1)
    if [ -z "$_total_line" ]; then
        echo "FAIL: arch_load complete line not found in agent output"
        rm -f "$ENTITY_LOG" "$ENTITY_CONF"
        exit 1
    fi
    _total_us=$(printf '%s' "$_total_line" | sed 's/.*complete: \([0-9]*\) .*/\1/')
    _total_ms=$(( _total_us / 1000 ))

    # Save result file
    mkdir -p "$_result_dir"
    {
        printf 'date:    %s\n'   "$_run_date"
        printf 'git:     %s  (%s)\n' "$_git_short" "$_git_branch"
        printf 'commit:  %s\n'   "$_git_subject"
        printf 'limit:   %d ms\n' "$ENTITY_PERF_LIMIT_MS"
        printf 'total:   %d ms\n' "$_total_ms"
        printf 'host:    %s\n'   "$(uname -n 2>/dev/null)"
        printf 'kernel:  %s\n'   "$(uname -r 2>/dev/null)"
        printf '\n'
        grep "entity: phase" "$ENTITY_LOG"
        printf '\n'
        echo "$_total_line"
    } > "$_result_file"

    # Report to stdout
    echo "---- Per-phase timing ----"
    grep "entity: phase" "$ENTITY_LOG" || echo "(no phase lines)"
    echo "---- Summary ----"
    echo "$_total_line"
    echo "Total: ${_total_ms} ms  (limit: ${ENTITY_PERF_LIMIT_MS} ms)"
    echo "Result saved: $_result_file"

    rm -f "$ENTITY_LOG" "$ENTITY_CONF"

    if [ "$_total_ms" -gt "$ENTITY_PERF_LIMIT_MS" ]; then
        echo "FAIL: arch_load ${_total_ms} ms exceeds limit ${ENTITY_PERF_LIMIT_MS} ms"
        exit 1
    fi

    echo "PASS: arch_load completed within limit"
    echo "==== End of Entity MIB performance scenario ===="
fi
