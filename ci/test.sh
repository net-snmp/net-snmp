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
# Set MODE=performance to run this scenario exclusively.
if [ "$MODE" = "performance" ] || [ "$(uname)" = "Linux" ]; then
    "${scriptdir}/entity-perf"
fi
