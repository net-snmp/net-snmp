Summary: Tools and servers for the SNMP protocol
Name: net-snmp
Version: 5.0.6
Release: 1
Copyright: BSD
Group: System Environment/Daemons
Source: http://prdownloads.sourceforge.net/net-snmp/net-snmp-%{version}.tar.gz
Prereq: openssl
Obsoletes: cmu-snmp ucd-snmp ucd-snmp-utils
BuildRoot: /tmp/%{name}-root
%description

Net-SNMP provides tools and libraries relating to the Simple Network
Management Protocol including: An extensible agent, An SNMP library,
tools to request or set information from SNMP agents, tools to
generate and handle SNMP traps, etc.  Using SNMP you can check the
status of a network of computers, routers, switches, servers, ... to
evaluate the state of your network.

%package devel
Group: Development/Libraries
Summary: The includes and static libraries from the Net-SNMP package.
Requires: net-snmp = %{version}
Obsoletes: cmu-snmp-devel ucd-snmp-devel

%description devel
The net-snmp-devel package contains headers and libraries which are
useful for building SNMP applications, agents, and sub-agents.

%prep
%setup -q


%build
%configure --with-defaults --with-sys-contact="Unknown" \
	--with-mib-modules="host disman/event-mib"      \
	--with-sysconfdir="/etc/net-snmp"               \
	--enable-shared					\
	--with-cflags="$RPM_OPT_FLAGS"

make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall
%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc AGENT.txt COPYING ChangeLog FAQ INSTALL NEWS PORTING
%doc README README.agentx README.cmu README.hpux11 README.krb5
%doc README.snmpv3 README.thread README.win32
	 
#%config /etc/net-snmp/snmpd.conf
	 
/usr/bin
/usr/sbin
/usr/lib/*.so*

%files devel
/usr/include
/usr/lib/*.a
/usr/lib/*.la

%changelog
* Wed Oct 09 2002 Wes Hardaker <hardaker@users.sourceforge.net>
- Made it possibly almost usable.
* Mon Apr 22 2002 Robert Story <rstory@users.sourceforge.net>
- created
