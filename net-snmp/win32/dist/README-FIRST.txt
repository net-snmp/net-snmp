       README file for win32 binary release of Net-SNMP

DISCLAIMER

  The Authors assume no responsibility for damage or loss of system
  performance as a direct or indirect result of the use of this
  software.  This software is provided "as is" without express or
  implied warranty.


TABLE OF CONTENTS

  Disclaimer
  Table Of Contents
  Introduction
* Installation
  Installation - Perl module
* Configuration
  Build Information

  * = Required Reading.


INTRODUCTION

  This package contains a compiled binary release of Net-SNMP for Windows NT/2000.

  Documentation for using the applications is available in the Windows help file
  (Net-SNMP.chm) located in the docs directory of the installed package.  Help is also
  available from the web site at http://www.net-snmp.org/#Documentation.


INSTALLATION

  After installing using the setup wizard, perform a quick test to verify that 
  Net-SNMP was installed correctly.  Run the following from a command prompt:

    snmptranslate -IR -Td IF-MIB::linkDown

  The above command should generate:

    IF-MIB::linkDown
    linkDown NOTIFICATION-TYPE
      -- FROM       IF-MIB
      OBJECTS       { ifIndex, ifAdminStatus, ifOperStatus }
      DESCRIPTION   "A linkDown trap signifies that the SNMP entity, acting in
                an agent role, has detected that the ifOperStatus object for
                one of its communication links is about to enter the down
                state from some other state (but not from the notPresent
                state).  This other state is indicated by the included value
                of ifOperStatus."
    ::= { iso(1) org(3) dod(6) internet(1) snmpV2(6) snmpModules(3) snmpMIB(1) 
          snmpMIBObjects(1) snmpTraps(5) 3 }


  If snmptranslate can not be found, then verify that the Net-SNMP bin folder is in 
  your system path.

  If you get Module not found errors such as 'IP-MIB: Module not found', the application
  was not able to locate the mibs folder.  Verify that SNMPCONFPATH is set to the location
  of the conf folder (c:/usr/etc/snmp for example).  Also verify that there is a snmp.conf
  file in that folder that contains configuration values for mibdirs, persistenDir and
  tempFilePattern.  For example:

    mibdirs c:/usr/share/snmp/mibs
    persistentDir c:/usr/snmp/persist
    tempFilePattern C:/usr/temp/snmpdXXXXXX


INSTALLATION - PERL MODULE

  To install the Perl module under ActiveState ActivePerl 5.8 use PPM by 
  following these steps:

    cd (install folder)
    ppm install Net-SNMP.ppd

  Perform a basic test using:

    net-snmp-perl-test.pl


CONFIGURATION

  All configuration files should be placed in the %SNMPCONFPATH% folder.

  Note: All paths in configuration files should use forward slashes (Unix style), 
  NOT back slashes.  Example: c:/Program Files/net-snmp

  Included is a Perl script called snmpconf which can be used to create 
  configuration files.  

  Documentation for using the snmpconf is available in the Windows help file
  (Net-SNMP.chm) located in the docs directory of the installed package.  Help is also
  available from the web site at http://www.net-snmp.org/#Documentation.

  To run snmpconf, use the following command line.

  snmpconf.pl -c "%SNMPSHAREPATH%\snmpconf-data" -I "%SNMPCONFPATH%"


BUILD INFORMATION

  Name:			net-snmp-5.1.1-1.win32.exe
  URL:			http://www.net-snmp.org
  Build date:		April 14th, 2004
  Built by:		Alex Burger <alex_b@users.sourceforge.net>
  Installer Package by: Andy Smith <wasmith32@earthlink.net>
  
  OS:			Windows 2000 SP3
  Compiler:		MSVC++ 6.0 SP5
  Platform SDK:		February 2003
  Perl:			ActivePerl 5.8.2 build 808
  REGEX:		gnu_regex.exe (0.12) - http://people.delphiforums.com/gjc/gnu_regex.html

  Source: 		net-snmp-5.1.1.tar.gz
  Patches:		907716 - win32 built agent returns incorrect values, OIDs - bugfix-907716-tables-3
                        901434 - Support IPv6 on win32 - tosock2.sh
  Destination:  	c:\usr
  Project:		win32sdk.dsw / libdll.dsw
  Library:		netsnmp for applications, netsnmp.dll for Perl modules
  OpenSSL:		n/a


  The following are the default paths are used by the applications:

  MIBDIRS:                   c:/usr/share/snmp/mibs
  MOD:                       c:/usr/lib/dlmod
  LIB:                       c:/usr/lib
  SHARE:                     c:/usr/share/snmp
  CONF:                      c:/usr/etc/snmp
  PERSIST:                   c:/usr/snmp/persist
  NETSNMP_TEMP_FILE_PATTERN: c:/usr/temp/snmpdXXXXXX

