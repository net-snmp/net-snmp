@echo off
REM
REM build Net-SNMP Perl module using nmake
REM

echo Remember to run this script from the base of the source directory.

REM INSTALL_BASE must point to the directory ABOVE the library files.
REM Generally follows what is the install-net-snmp.bat setting.

set INSTALL_BASE="c:\usr"

cd perl

REM choose the installed location...
perl Makefile.PL CAPI=TRUE -NET-SNMP-PATH=%INSTALL_BASE%

REM Or, if the libraries have been built, look back in the build directory.
REM perl Makefile.PL CAPI=TRUE -NET-SNMP-IN-SOURCE=TRUE

echo Make the Perl SNMP modules.
nmake /nologo > nmake.out
echo If errors are seen stop here and review perl\nmake.out.
pause

echo Test the Perl SNMP modules.
nmake /nologo test > nmaketest.out 2>&1
echo If no errors are seen, review test results in perl\nmaketest.out.

cd ..
