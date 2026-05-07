#!/usr/bin/env bash
# Run the buildtest.yml matrix locally using Docker.
# Skips Android (needs NDK) and wolfssl (needs pre-built wolfssl).
# Usage: ci/docker-ci.sh [MODE ...]
#   With no args, runs all supported modes.
#   With args, runs only the listed modes.
# Full output is logged to /tmp/net-snmp-ci/<mode>.log.
# Only warnings/errors are printed to the terminal.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=net-snmp-deps
DOCKERFILE="${REPO_ROOT}/ci/Dockerfile.deps"
LOG_DIR=/tmp/net-snmp-ci

SUPPORTED_MODES=(regular developer disable-ipv6 disable-set mini read-only without-nl)

if [ $# -gt 0 ]; then
    MODES=("$@")
else
    MODES=("${SUPPORTED_MODES[@]}")
fi

mkdir -p "${LOG_DIR}"

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

# Lines that are worth showing even on a passing build
WARN_RE='warning:|error:|fatal error:|undefined reference|configure: error|Makefile:[0-9].*Error'

ts() { date '+%H:%M:%S'; }
log_ts() { while IFS= read -r line; do printf '[%s] %s\n' "$(ts)" "${line}"; done; }

pass=()
fail=()
RUN_START=$(date '+%Y-%m-%dT%H:%M:%S')

for mode in "${MODES[@]}"; do
    log="${LOG_DIR}/${mode}.log"
    mode_start=$(date +%s)
    printf "  [%s] %-20s" "$(ts)" "${mode} ..."

    if docker run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -e "MODE=${mode}" \
        "${IMAGE}" \
        bash -c 'rsync -a --filter=":- .gitignore" --exclude=".git/" /src/ /build/ && cd /build && ci/build.sh' \
        2>&1 | log_ts > "${log}"; then

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
