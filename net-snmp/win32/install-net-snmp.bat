@echo off
REM Install the Net-SNMP Project files on the local machine.
REM
REM Run this script from the base Net-SNMP source directory
REM after the successful build has completed.

REM  **** IMPORTANT NOTE ****
REM The value for INSTALL_BASE in win32\net-snmp\net-snmp-config.h, and
REM The value for INSTALL_BASE below **MUST** match

REM Use backslashes to delimit sub-directories in path.
set INSTALL_BASE="c:\Program Files\Net-SNMP"

echo Remember to run this script from the base of the source directory.

echo Creating %INSTALL_BASE% sub-directories

mkdir %INSTALL_BASE% > NUL:
mkdir %INSTALL_BASE%\bin > NUL:
mkdir %INSTALL_BASE%\conf > NUL:
mkdir %INSTALL_BASE%\lib > NUL:
mkdir %INSTALL_BASE%\share > NUL:
mkdir %INSTALL_BASE%\share\snmp > NUL:
mkdir %INSTALL_BASE%\share\snmp\mibs > NUL:
mkdir %INSTALL_BASE%\share\snmp\snmpconf-data > NUL:
mkdir %INSTALL_BASE%\share\snmp\snmpconf-data\snmp-data > NUL:
mkdir %INSTALL_BASE%\share\snmp\snmpconf-data\snmpd-data > NUL:
mkdir %INSTALL_BASE%\share\snmp\snmpconf-data\snmptrapd-data > NUL:
mkdir %INSTALL_BASE%\snmp > NUL:
mkdir %INSTALL_BASE%\snmp\persist > NUL:
mkdir %INSTALL_BASE%\include > NUL:
mkdir %INSTALL_BASE%\include\net-snmp > NUL:
mkdir %INSTALL_BASE%\include\ucd-snmp > NUL:

echo Copying MIB files to %INSTALL_BASE%\share\snmp\mibs
Copy mibs\*.txt %INSTALL_BASE%\share\snmp\mibs > NUL:

echo Copying compiled programs to %INSTALL_BASE%\bin
Copy win32\bin\*.exe %INSTALL_BASE%\bin > NUL:
Copy local\snmpconf %INSTALL_BASE%\bin > NUL:

echo Copying snmpconf files to %INSTALL_BASE%\share\snmp\snmpconf-data\snmp-data
Copy local\snmpconf.dir\snmp-data\*.* %INSTALL_BASE%\share\snmp\snmpconf-data\snmp-data > NUL:
Copy local\snmpconf.dir\snmpd-data\*.* %INSTALL_BASE%\share\snmp\snmpconf-data\snmpd-data > NUL:
Copy local\snmpconf.dir\snmptrapd-data\*.* %INSTALL_BASE%\share\snmp\snmpconf-data\snmptrapd-data > NUL:

REM
REM Copy the remaining files used only to develop
REM other software that uses Net-SNMP libraries.
REM
echo Copying link libraries to %INSTALL_BASE%\lib
Copy win32\lib\*.*   %INSTALL_BASE%\lib > NUL:

echo Copying header files to %INSTALL_BASE%\include
xcopy /E /Y include\net-snmp\*.h %INSTALL_BASE%\include\net-snmp > NUL:
xcopy /E /Y include\ucd-snmp\*.h %INSTALL_BASE%\include\ucd-snmp > NUL:
xcopy /E /Y win32\net-snmp\*.h %INSTALL_BASE%\include\net-snmp > NUL:

echo Deleting debugging files from %INSTALL_BASE%

del %INSTALL_BASE%\bin\*_d.*
del %INSTALL_BASE%\lib\*_d.*

REM
REM If built with OpenSSL, we need the DLL library, too.
REM
echo Copying DLL files to %INSTALL_BASE%
Copy win32\bin\*.dll %INSTALL_BASE%\bin > NUL:

echo Copying DLL files to %SYSTEMROOT%\System32
Copy win32\bin\*.dll %SYSTEMROOT%\System32 > NUL:

echo Done copying files to %INSTALL_BASE%

