# define to include perl support
Summary: Tools and servers for the SNMP protocol
Name: net-snmp
Version: %version
Release: %release
URL: http://net-snmp.sourceforge.net/
Copyright: BSDish
Group: System Environment/Daemons
Source: http://prdownloads.sourceforge.net/net-snmp/net-snmp-%{version}.tar.gz
Patch0: net-snmp-5.0.9-with-perl.patch
Prereq: openssl
Obsoletes: cmu-snmp ucd-snmp ucd-snmp-utils
BuildRoot: /tmp/%{name}-root
Packager: The Net-SNMP Coders <http://sourceforge.net/projects/net-snmp/>
%if %{with_perl}
Requires: perl
%endif
%description

Net-SNMP provides tools and libraries relating to the Simple Network
Management Protocol including: An extensible agent, An SNMP library,
tools to request or set information from SNMP agents, tools to
generate and handle SNMP traps, etc.  Using SNMP you can check the
status of a network of computers, routers, switches, servers, ... to
evaluate the state of your network.

%if %{with_perl}
This package includes embedded perl support within the agent
%endif

%package devel
Group: Development/Libraries
Summary: The includes and static libraries from the Net-SNMP package.
Requires: net-snmp = %{version}
Obsoletes: cmu-snmp-devel ucd-snmp-devel

%description devel
The net-snmp-devel package contains headers and libraries which are
useful for building SNMP applications, agents, and sub-agents.

%if %{with_perl}
%package perlmods
Group: System Environment/Libraries
Summary: The perl modules provided with Net-SNMP
Requires: net-snmp = %{version}, perl

%description perlmods
Net-SNMP provides a number of perl modules useful when using the SNMP
protocol.  Both client and agent support modules are provided, along
with embedded perl support within the agent.
%endif

%prep
%setup -q
%if "%{version}" == "5.0.9"
%patch0 -p0
%endif

%build
%configure --with-defaults --with-sys-contact="Unknown" \
	--with-mib-modules="host disman/event-mib smux" \
	--with-sysconfdir="/etc/net-snmp"               \
	--enable-shared					\
%if %{with_perl}
	--enable-embedded-perl                          \
	--with-perl-modules="PREFIX=$RPM_BUILD_ROOT/usr INSTALLDIRS=vendor"  \
%endif
	--with-cflags="$RPM_OPT_FLAGS"

make

%install
# ----------------------------------------------------------------------
# 'install' sets the current directory to _topdir/BUILD/{name}-{version}
# ----------------------------------------------------------------------
rm -rf $RPM_BUILD_ROOT

%makeinstall

# Remove 'snmpinform' from the temporary directory because it is a
# symbolic link, which cannot be handled by the rpm installation process.
%__rm -f $RPM_BUILD_ROOT%{_prefix}/bin/snmpinform
# install the init script
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m 755 dist/snmpd-init.d $RPM_BUILD_ROOT/etc/rc.d/init.d/snmpd

%if %{with_perl}
# unneeded perl stuff
rm -rf $RPM_BUILD_ROOT/auto/Bundle
rm -f $RPM_BUILD_ROOT/perllocal.pod
rm -rf $RPM_BUILD_ROOT/Bundle

# store a copy of installed perl stuff.  It's too comlpex to predict
(xxdir=`pwd` && cd $RPM_BUILD_ROOT && find usr/lib/perl5 -type f | sed 's/^/\//' > $xxdir/net-snmp-perl-files)
%endif

%post
# ----------------------------------------------------------------------
# The 'post' script is executed just after the package is installed.
# ----------------------------------------------------------------------
# Create the symbolic link 'snmpinform' after all other files have
# been installed.
%__rm -f $RPM_INSTALL_PREFIX/bin/snmpinform
%__ln_s $RPM_INSTALL_PREFIX/bin/snmptrap $RPM_INSTALL_PREFIX/bin/snmpinform

# run ldconfig
PATH="$PATH:/sbin" ldconfig -n $RPM_INSTALL_PREFIX/lib

%preun
# ----------------------------------------------------------------------
# The 'preun' script is executed just before the package is erased.
# ----------------------------------------------------------------------
# Remove the symbolic link 'snmpinform' before anything else, in case
# it is in a directory that rpm wants to remove (at present, it isn't).
%__rm -f $RPM_INSTALL_PREFIX/bin/snmpinform

%postun
# ----------------------------------------------------------------------
# The 'postun' script is executed just after the package is erased.
# ----------------------------------------------------------------------
PATH="$PATH:/sbin" ldconfig -n $RPM_INSTALL_PREFIX/lib

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

# Install the following documentation in _defaultdocdir/{name}-{version}/
%doc AGENT.txt ChangeLog CodingStyle COPYING
%doc EXAMPLE.conf.def FAQ INSTALL NEWS PORTING TODO
%doc README README.agentx README.hpux11 README.krb5
%doc README.snmpv3 README.solaris README.thread README.win32
	 
#%config(noreplace) /etc/net-snmp/snmpd.conf
	 
#%{_datadir}/snmp/snmpconf-data
%{_datadir}/snmp

%{_bindir}
%{_sbindir}
%{_mandir}/man1/*
%{_mandir}/man3/*
%{_mandir}/man5/*
%{_mandir}/man8/*
/usr/lib/*.so*
/etc/rc.d/init.d/snmpd

%files devel
%defattr(-,root,root)

%{_includedir}
%{_libdir}/*.a
%{_libdir}/*.la

%if %{with_perl}
%files -f net-snmp-perl-files perlmods
%defattr(-,root,root)
/usr/man/man3/
%endif

%verifyscript
echo "No additional verification is done for net-snmp"

%changelog
* Fri Sep 12 2003 Wes Hardaker <hardaker@users.sourceforge.net>
- fixes for 5.0.9's perl support

* Mon Sep 01 2003 Wes Hardaker <hardaker@users.sourceforge.net>
- added perl support

* Wed Oct 09 2002 Wes Hardaker <hardaker@users.sourceforge.net>
- Incorperated most of Mark Harig's better version of the rpm spec and Makefile

* Wed Oct 09 2002 Wes Hardaker <hardaker@users.sourceforge.net>
- Made it possibly almost usable.

* Mon Apr 22 2002 Robert Story <rstory@users.sourceforge.net>
- created
