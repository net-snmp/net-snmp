Summary: 
Name: net-snmp
Version: 5.0.0
Release: 1
Copyright: This line tells how a package is
	    copyrighted.  You should use something like GPL, BSD, MIT, public
	    domain, distributable, or commercial.
Group: System Environment/Daemons
Source: http://prdownloads.sourceforge.net/net-snmp/net-snmp-5.0.2.tar.gz

%description


%prep
%setup -q


%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
install -s -m 755 eject $RPM_BUILD_ROOT/usr/bin/eject
install -m 644 eject.1 $RPM_BUILD_ROOT/usr/man/man1/eject.1

%clean
rm -rf $RPM_BUILD_ROOT


%doc AGENT.txt COPYING ChangeLog FAQ INSTALL NEWS PORTING
%doc README README.agentx README.cmu README.hpux11 README.krb5
%doc README.snmpv3 README.thread README.win32
	 
%config /usr/local/share/snmp/snmpd.conf
	 
%dir marks a single directory in a
	    file list to be included as being owned by a package.  By default,
	    if you list a directory name WITHOUT a
	    %dir macro,
	    EVERYTHING in that directory is included in the
	    file list and later installed as part of that package.
	 
%defattr allows you to set default
	    attributes for files listed after the defattr declaration.  The
	    attributes are listed in the form (mode, owner,
	    group) where the mode is the octal number representing the bit pattern for the new permissions (like
	    chmod would use), owner is the username of the
	    owner, and group is the group you would like assigned.  You may
	    leave any field to the installed default by simply placing a
	    - in its place, as was done in the mode field
	    for the example package.
	 
%files -f <filename> will
	    allow you to list your files in some arbitrary file within the build
	    directory of the sources.  This is nice in cases where you have a
	    package that can build it's own filelist.  You then just include
	    that filelist here and you don't have to specifically list the
	    files.

%changelog
* Mon Apr 22 2002 Robert Story <rstory@users.sourceforge.net>
- created
