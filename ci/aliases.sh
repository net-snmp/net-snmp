#!/usr/bin/env bash

# Generic filtered build helpers — source this file or add to ~/.bashrc:
#   source /path/to/ci/aliases.sh
# Or run one helper directly:
#   /path/to/ci/aliases.sh bconf [ARGS]
#   /path/to/ci/aliases.sh bmake [ARGS]
#
# bconf [ARGS]   — ./configure [ARGS]   with warning/error filter + timestamp log
# bmake  [ARGS]  — make -j$(nproc) [ARGS] with warning/error filter + timestamp log
#
# Logs go to /tmp/build-<project>/{configure,make}.log

_BUILD_WARN_RE='warning:|error:|fatal error:|undefined reference|configure: error|Makefile:[0-9].*Error'
_BUILD_PROGRESS_RE='^(Making |make[[][0-9]+[]]: (Entering|Leaving)|[[:space:]]*(CC|CCLD|CXX|CXXLD|LD|AR|GEN|YACC|LEX|RANLIB)[[:space:]])|^configure: (creating|WARNING|error)'
_BUILD_HEARTBEAT_SECONDS=30

_filtered_run() {
    local log="$1"; shift
    local rc_file
    rc_file=$(mktemp)
    mkdir -p "$(dirname "${log}")"
    : > "${log}"

    ( "$@"; echo $? > "${rc_file}" ) 2>&1 \
        | awk -v warn_re="${_BUILD_WARN_RE}" \
              -v progress_re="${_BUILD_PROGRESS_RE}" \
              -v heartbeat="${_BUILD_HEARTBEAT_SECONDS}" \
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
    rc=$(cat "${rc_file}"); rm -f "${rc_file}"
    return "${rc}"
}

bconf() {
    local log="/tmp/build-$(basename "$PWD")/configure.log"
    echo "==> configure  (log: ${log})"
    _filtered_run "${log}" ./configure "$@"
}

bmake() {
    local log="/tmp/build-$(basename "$PWD")/make.log"
    echo "==> make  (log: ${log})"
    _filtered_run "${log}" make -j"$(nproc)" "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        bconf|configure)
            shift
            bconf "$@"
            ;;
        bmake|make)
            shift
            bmake "$@"
            ;;
        -h|--help|"")
            printf 'usage: %s {bconf|bmake} [args...]\n' "$0"
            printf 'or source this file to define bconf and bmake in your shell.\n'
            ;;
        *)
            printf 'unknown helper: %s\n' "$1" >&2
            printf 'usage: %s {bconf|bmake} [args...]\n' "$0" >&2
            exit 2
            ;;
    esac
fi
