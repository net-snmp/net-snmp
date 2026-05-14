#!/usr/bin/env bash
# Run the buildtest.yml matrix locally using Docker.
# Skips Android (needs NDK) and wolfssl (needs pre-built wolfssl).
# Usage: ci/docker-ci.sh [MODE ...]
#   With no args, runs all supported modes.
#   With args, runs only the listed modes.
# Full output is logged to /tmp/net-snmp-ci/<mode>.log.
# Progress, warnings, errors, and periodic heartbeats are printed to the terminal.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=net-snmp-deps
DOCKERFILE="${REPO_ROOT}/ci/Dockerfile.deps"
LOG_DIR=/tmp/net-snmp-ci
WORK_DIR=

cleanup() {
    [ -n "${WORK_DIR}" ] && rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

on_interrupt() {
    local sig=$1
    echo ""
    echo "==> Interrupted (${sig})"
    # EXIT trap will clean up; re-raise so the caller sees a signal exit
    trap - "${sig}"
    kill -s "${sig}" "$$"
}
trap 'on_interrupt INT'  INT
trap 'on_interrupt TERM' TERM

SUPPORTED_MODES=(regular developer disable-ipv6 disable-set mini read-only without-nl)

if [ $# -gt 0 ]; then
    MODES=("$@")
else
    MODES=("${SUPPORTED_MODES[@]}")
fi

mkdir -p "${LOG_DIR}"
WORK_DIR=$(mktemp -d)

SENTINEL="${LOG_DIR}/.image-built"
need_build=false

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "==> ${IMAGE} image not found, building ..."
    need_build=true
elif [ "${DOCKERFILE}" -nt "${SENTINEL}" ]; then
    echo "==> Dockerfile.deps changed, rebuilding ${IMAGE} ..."
    need_build=true
elif [ "${REPO_ROOT}/ci/install.sh" -nt "${SENTINEL}" ]; then
    echo "==> ci/install.sh changed, rebuilding ${IMAGE} ..."
    need_build=true
fi

if ${need_build}; then
    docker build -f "${DOCKERFILE}" -t "${IMAGE}" "${REPO_ROOT}" \
        > "${LOG_DIR}/docker-build.log" 2>&1 \
        || { echo "FAILED: docker build — see ${LOG_DIR}/docker-build.log"; exit 1; }
    touch "${SENTINEL}"
fi

# Lines that are worth showing even on a passing build/test run.
WARN_RE='warning:|error:|fatal error:|undefined reference|configure: error|Makefile:[0-9].*Error|not ok|Dubious|Failed|Result: FAIL'
PROGRESS_RE='^(Making |make[[][0-9]+[]]: (Entering|Leaving)|[[:space:]]*(CC|CCLD|CXX|CXXLD|LD|AR|GEN|YACC|LEX|RANLIB)[[:space:]])|^configure: (creating|WARNING|error)|^PASS |^FAIL |^ok |^not ok |^Result:|^Files='
HEARTBEAT_SECONDS=30

ts() { date '+%H:%M:%S'; }

filtered_run() {
    local log="$1"
    local rc_file

    shift
    rc_file=$(mktemp "${WORK_DIR}/rc.XXXXXX")
    : > "${log}"

    ( "$@"; printf '%s\n' "$?" > "${rc_file}" ) 2>&1 \
        | awk -v warn_re="${WARN_RE}" \
              -v progress_re="${PROGRESS_RE}" \
              -v heartbeat="${HEARTBEAT_SECONDS}" \
              -v logfile="${log}" '
            BEGIN { IGNORECASE = 1; last = systime() }
            {
                line = strftime("[%H:%M:%S] ") $0
                print line >> logfile
                fflush(logfile)

                if ($0 ~ warn_re || $0 ~ progress_re) {
                    print line
                    fflush()
                    last = systime()
                } else if (heartbeat > 0 && systime() - last >= heartbeat) {
                    print strftime("[%H:%M:%S]"), "... still running (log:", logfile ")"
                    fflush()
                    last = systime()
                }
            }' || true

    local rc
    rc=$(cat "${rc_file}")
    rm -f "${rc_file}"
    return "${rc}"
}

pass=()
fail=()
RUN_START=$(date '+%Y-%m-%dT%H:%M:%S')

for mode in "${MODES[@]}"; do
    log="${LOG_DIR}/${mode}.log"
    mode_start=$(date +%s)
    printf '==> %s  (log: %s)\n' "${mode}" "${log}"

    if filtered_run "${log}" docker run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -e "MODE=${mode}" \
        "${IMAGE}" \
        bash -c 'rsync -a --filter=":- .gitignore" --exclude=".git/" /src/ /build/ && cd /build && ci/build.sh && ci/test.sh'; then

        elapsed=$(( $(date +%s) - mode_start ))
        # Scan log for warnings even on success
        hits=$(grep -iE "${WARN_RE}" "${log}" || true)
        if [ -n "${hits}" ]; then
            echo "PASS (with warnings) [${elapsed}s] — ${log}"
            echo "${hits}" | sed 's/^/    /'
        else
            echo "PASS [${elapsed}s]"
        fi
        pass+=("${mode}")
    else
        elapsed=$(( $(date +%s) - mode_start ))
        echo "FAIL [${elapsed}s] — ${log}"
        grep -iE "${WARN_RE}" "${log}" | sed 's/^/    /' || true
        echo "    --- last 10 lines ---"
        tail -10 "${log}" | sed 's/^/    /'
        fail+=("${mode}")
    fi
done

echo ""
echo "Results: ${#pass[@]} passed, ${#fail[@]} failed  (started ${RUN_START})"
for m in "${fail[@]+"${fail[@]}"}"; do echo "  FAIL  ${m}  (${LOG_DIR}/${m}.log)"; done

[ ${#fail[@]} -eq 0 ]
