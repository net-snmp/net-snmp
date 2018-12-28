#!/bin/sh

case "${TRAVIS_OS_NAME}" in
    linux)
	# Add an IPv6 config - see the corresponding Travis issue
	# https://github.com/travis-ci/travis-ci/issues/8361
	sudo sh -c 'echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6; printf "\n::1 localhost ipv6-localhost ipv6-loopback\n" >>/etc/hosts; cat /etc/hosts';;
    osx)
	# Upgrade openssl such that Net-SNMP can be built with Blumenthal
	# AES support. Disabled because this upgrade takes long and even
	# sometimes fails.
	if false; then
	    brew upgrade openssl
	fi;;
esac
