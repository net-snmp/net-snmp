#!/bin/sh

case "${TRAVIS_OS_NAME}" in
    linux)
	sudo sh -c 'apt-get install -y libmariadbclient-dev || sudo apt-get install -y libmariadb-client-lgpl-dev'

	# Add an IPv6 config - see the corresponding Travis issue
	# https://github.com/travis-ci/travis-ci/issues/8361
	sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6; printf "\n::1 localhost ipv6-localhost ipv6-loopback\n" >>/etc/hosts';;
    osx)
	# Upgrade openssl such that Net-SNMP can be built with Blumenthal
	# AES support. Disabled because this upgrade takes long and even
	# sometimes fails.
	if false; then
	    brew upgrade openssl
	fi;;
esac

if [ -n "$CIRRUS_CI" ]; then
    cat <<EOF >>/etc/hosts
127.0.0.1 localhost
::1 localhost ipv6-localhost ipv6-loopback
EOF

    pkg install -y bash
    pkg install -y gawk
    pkg install -y krb5 krb5-appl krb5-devel
    pkg install -y libssh2
    #pkg install -y openssl111
    pkg install -y perl5 perl5-devel p5-ExtUtils-MakeMaker
    pkg install -y pkgconf
    pkg install -y py27-setuptools
    if [ ! -e /usr/bin/perl ]; then
	ln -s /usr/local/bin/perl /usr/bin/perl
    fi
fi

head -n 999 /etc/hosts
