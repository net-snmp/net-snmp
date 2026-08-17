#!/bin/sh

scriptdir="$(cd "$(dirname "$0")" && pwd)"

install_android_ndk() {
    echo "Installing Android NDK..."
    wget --quiet https://dl.google.com/android/repository/android-ndk-r27d-linux.zip
    unzip -oq android-ndk-r27d-linux.zip
}

case "$(uname)" in
    Linux)
	case "$MODE" in
	    Android)
		install_android_ndk
		packages="
		    make
		    util-linux
		"
		;;
	    *)
		packages="
		    libatm1-dev
		    libkrb5-dev
		    libmariadb-dev
		    libmariadb-dev-compat
		    libmysqlclient-dev
		    libncurses-dev
		    libncurses5-dev
		    libnl-route-3-dev
		    libpci-dev
		    libpcre2-dev
		    libpcre3-dev
		    libperl-dev
		    libsensors-dev
		    libssh-dev
		    libssl-dev
		    make
		    pkg-config
		    python3-dev
		    python3-setuptools
		    util-linux
		"
		;;
	esac
	apt-get update
	for p in ${packages}; do
	    apt-get install -qq -o=Dpkg::Use-Pty=0 -y "$p"
	done
	true
	;;
    Darwin)
	# Upgrade openssl such that Net-SNMP can be built with Blumenthal
	# AES support. Disabled because this upgrade takes long and even
	# sometimes fails.
	if false; then
	    brew upgrade openssl
	fi
	;;
    FreeBSD)
	pkg install -y bash
	pkg install -y gawk
	pkg install -y krb5 krb5-appl krb5-devel
	pkg install -y libssh2
	#pkg install -y openssl111
	pkg install -y perl5 perl5-devel p5-ExtUtils-MakeMaker
	#pkg install -y pkgconf
	pkg install -y py27-setuptools
	if [ ! -e /usr/bin/perl ]; then
	    ln -s /usr/local/bin/perl /usr/bin/perl
	fi
	;;
    OpenBSD)
	pkg_add bash gawk libssh2
	;;
esac

case "$(uname -a)" in
    MSYS*|MINGW*)
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-ada
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-fortran
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-libgfortran
	pacman --noconfirm --remove mingw-w64-x86_64-gcc-objc
	pacman --noconfirm --sync --refresh
	pacman --noconfirm --sync --needed diffutils
	pacman --noconfirm --sync --needed make
	pacman --noconfirm --sync --needed perl-ExtUtils-MakeMaker
	pacman --noconfirm --sync --needed perl-Test-Harness
	pacman --noconfirm --sync --needed procps-ng
	;;
esac
case "$(uname -a)" in
    MSYS*x86_64*)
	pacman --noconfirm --sync --needed openssl-devel
	pacman --noconfirm --sync --needed pkg-config
	;;
    MINGW64*)
	pacman --noconfirm --sync --needed mingw-w64-x86_64-gcc
	pacman --noconfirm --sync --needed mingw-w64-x86_64-libmariadbclient
	pacman --noconfirm --sync --needed mingw-w64-x86_64-openssl
	pacman --noconfirm --sync --needed mingw-w64-x86_64-pkgconf ||
	    pacman --noconfirm --sync --needed mingw-w64-x86_64-pkg-config
	export PATH="/mingw64/bin:$PATH"
	;;
esac

case "$MODE" in
    wolfssl)
	if [ -n "$SUDO_UID" ] && [ -n "$SUDO_GID" ]; then
	    if type setpriv >/dev/null 2>&1; then
		setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
			--inh-caps=-CHOWN,-SETUID,-SETGID \
			"${scriptdir}/wolfssl.sh"
	    elif [ -n "${SUDO_USER}" ]; then
		sudo -u "${SUDO_USER}" "${scriptdir}/wolfssl.sh"
	    else
		"${scriptdir}/wolfssl.sh"
	    fi
	else
	    "${scriptdir}/wolfssl.sh"
	fi
	;;
esac
