#!/bin/sh

case "$(uname)" in
    Darwin)
	# Instead of relying on the hosts file provided by the CI host, replace
	# it. See also
	# https://blog.justincarmony.com/2011/07/27/mac-os-x-lion-etc-hosts-bugs-and-dns-resolution/.
	sudo sh -c 'printf "127.0.0.1 localhost ipv4-loopback\n::1 localhost ipv6-localhost ipv6-loopback\n" >/etc/hosts'
	;;
esac

scriptdir="$(dirname "$0")"

build=$(sed -n '/^  \$ \.\/configure/ s/.*--build=\([^ ]*\).*/\1/p' config.log | tr -d "\"'" )
host=$(sed -n '/^  \$ \.\/configure/ s/.*--host=\([^ ]*\).*/\1/p' config.log | tr -d "\"'" )

if [ "$build" = "$host" ]; then
    "${scriptdir}"/net-snmp-run-tests
fi
