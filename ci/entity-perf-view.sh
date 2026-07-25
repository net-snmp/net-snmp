#!/bin/sh
# View and compare entity arch_load performance results from .tmp/perf/
#
# Usage:
#   ./entity-perf-view.sh            — summary table of all runs
#   ./entity-perf-view.sh <file>     — full phase breakdown for one run
#   ./entity-perf-view.sh <a> <b>    — side-by-side phase diff between two runs

PERF_DIR="$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$0")")/.tmp/perf"

# ---- helpers ----------------------------------------------------------------

_bold()  { printf '\033[1m%s\033[0m' "$1"; }
_red()   { printf '\033[31m%s\033[0m' "$1"; }
_green() { printf '\033[32m%s\033[0m' "$1"; }
_cyan()  { printf '\033[36m%s\033[0m' "$1"; }
_dim()   { printf '\033[2m%s\033[0m' "$1"; }

_field() {
    # _field <file> <key>  — extract "key:   value" from a result file
    sed -n "s/^${2}: *//p" "$1" | head -1
}

_phase_us() {
    # _phase_us <file> <phase_name>  — extract µs for a named phase
    grep "entity: phase ${2} " "$1" | sed 's/.*phase [^ ]* *\([0-9]*\) .*/\1/' | head -1
}

_all_phases() {
    # emit sorted list of phase names from a file
    grep "entity: phase " "$1" | sed 's/.*entity: phase \([^ ]*\) .*/\1/' | sort
}

_trend() {
    # _trend <old_us> <new_us>  — print Δ with colour and arrow
    old=$1; new=$2
    if [ -z "$old" ] || [ "$old" = "0" ]; then printf '    n/a'; return; fi
    delta=$(( new - old ))
    pct=$(( delta * 100 / old ))
    if [ "$delta" -gt 0 ]; then
        printf '%+5d ms (%+d%%) ' "$(( delta / 1000 ))" "$pct" | _red
        printf '▲'
    elif [ "$delta" -lt 0 ]; then
        printf '%+5d ms (%+d%%) ' "$(( delta / 1000 ))" "$pct" | _green
        printf '▼'
    else
        printf '   ±0 ms (0%%) ='
    fi
}

# ---- mode: single-file detail -----------------------------------------------

_show_one() {
    f="$1"
    date=$(_field "$f" date)
    git=$(_field "$f" git)
    commit=$(_field "$f" commit)
    total=$(_field "$f" total)
    entities=$(grep "arch_load complete" "$f" | sed 's/.*, \([0-9]*\) entities/\1/')

    _bold "=== $f ==="; echo
    printf 'Date:    %s\n' "$date"
    printf 'Git:     %s\n' "$git"
    printf 'Commit:  %s\n' "$commit"
    printf 'Total:   %s   (%s entities)\n' "$total" "$entities"
    echo
    _bold "Phase breakdown:"; echo
    printf '%-30s %8s   %8s   %s\n' "phase" "time(ms)" "entities" "heap"
    printf '%-30s %8s   %8s   %s\n' "-----" "--------" "--------" "----"
    grep "entity: phase " "$f" | while IFS= read -r line; do
        phase=$(echo "$line" | sed 's/.*entity: phase \([^ ]*\) .*/\1/')
        us=$(echo "$line"    | sed 's/.*phase [^ ]* *\([0-9]*\) .*/\1/')
        ents=$(echo "$line"  | sed 's/.*+\( *[0-9]*\) entities.*/\1/')
        heap=$(echo "$line"  | sed 's/.*heap \(.*\)/\1/')
        ms=$(( us / 1000 ))
        printf '%-30s %8d   %8s   %s\n' "$phase" "$ms" "$ents" "$heap"
    done
}

# ---- mode: two-file diff ----------------------------------------------------

_show_diff() {
    a="$1"; b="$2"

    total_a=$(_field "$a" total | sed 's/ ms//')
    total_b=$(_field "$b" total | sed 's/ ms//')
    git_a=$(_field "$a" git)
    git_b=$(_field "$b" git)
    date_a=$(_field "$a" date)
    date_b=$(_field "$b" date)

    _bold "=== Phase comparison ==="; echo
    printf 'A: %s  %s  (%s)\n' "$git_a" "$date_a" "$(_field "$a" commit)"
    printf 'B: %s  %s  (%s)\n' "$git_b" "$date_b" "$(_field "$b" commit)"
    echo
    printf '%-30s %8s   %8s   %s\n' "phase" "A (ms)" "B (ms)" "delta"
    printf '%-30s %8s   %8s   %s\n' "-----" "------" "------" "-----"

    # union of phases from both files
    { _all_phases "$a"; _all_phases "$b"; } | sort -u | while read -r phase; do
        us_a=$(_phase_us "$a" "$phase")
        us_b=$(_phase_us "$b" "$phase")
        ms_a=$(( ${us_a:-0} / 1000 ))
        ms_b=$(( ${us_b:-0} / 1000 ))
        delta_str=$(_trend "${us_a:-0}" "${us_b:-0}")
        printf '%-30s %8d   %8d   %s\n' "$phase" "$ms_a" "$ms_b" "$delta_str"
    done

    echo
    total_a_us=$(( total_a * 1000 ))
    total_b_us=$(( total_b * 1000 ))
    printf '%-30s %8s   %8s   %s\n' "TOTAL" "${total_a} ms" "${total_b} ms" \
        "$(_trend "$total_a_us" "$total_b_us")"
    echo
}

# ---- mode: summary table ----------------------------------------------------

_show_summary() {
    files=$(ls -1t "$PERF_DIR"/perf-*.txt 2>/dev/null)
    if [ -z "$files" ]; then
        echo "No results in $PERF_DIR"
        exit 0
    fi

    _bold "=== Entity arch_load performance history ==="; echo
    printf '%-22s  %-14s  %8s  %8s  %s\n' "date" "git" "total(ms)" "entities" "commit"
    printf '%-22s  %-14s  %8s  %8s  %s\n' "----" "---" "---------" "--------" "------"

    prev_total=""
    for f in $(ls -1t "$PERF_DIR"/perf-*.txt | sort); do
        date=$(_field "$f" date)
        git=$(_field "$f" git)
        commit=$(_field "$f" commit)
        total=$(_field "$f" total | sed 's/ ms//')
        entities=$(grep "arch_load complete" "$f" | sed 's/.*, \([0-9]*\) entities.*/\1/')

        if [ -n "$prev_total" ]; then
            delta=$(( total - prev_total ))
            if [ "$delta" -gt 50 ]; then
                trend=$(_red "▲$(( delta ))ms")
            elif [ "$delta" -lt -50 ]; then
                trend=$(_green "▼$(( -delta ))ms")
            else
                trend="="
            fi
            printf '%-22s  %-14s  %8d  %8s  %s  %s\n' \
                "$date" "$git" "$total" "$entities" "$trend" "$commit"
        else
            printf '%-22s  %-14s  %8d  %8s  %s\n' \
                "$date" "$git" "$total" "$entities" "$commit"
        fi
        prev_total=$total
    done

    echo
    # Show slowest phases across latest run
    latest=$(ls -1t "$PERF_DIR"/perf-*.txt 2>/dev/null | tail -1)
    if [ -n "$latest" ]; then
        _bold "Top phases by time (latest run):"; echo
        grep "entity: phase " "$latest" | \
            sed 's/.*entity: phase \([^ ]*\) *\([0-9]*\) .*/\2 \1/' | \
            sort -rn | head -5 | \
            while read -r us phase; do
                ms=$(( us / 1000 ))
                printf '  %-30s %6d ms\n' "$phase" "$ms"
            done
    fi
    echo
    echo "Files: $PERF_DIR"
    echo "Usage: $0 <file>       — full detail"
    echo "       $0 <a> <b>     — diff two runs"
}

# ---- dispatch ---------------------------------------------------------------

case $# in
    0) _show_summary ;;
    1) _show_one "$1" ;;
    2) _show_diff "$1" "$2" ;;
    *) echo "Usage: $0 [file_a [file_b]]"; exit 1 ;;
esac
