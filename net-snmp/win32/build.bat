@echo off

REM play with SNMPCONFPATH, to pass the perl conf.t test
REM this play is harmless otherwise

set saveXXSNMPCONFPATH=%SNMPCONFPATH%
set SNMPCONFPATH=t;%SNMPCONFPATH%

cd win32 > NUL: 2>&1

perl build.pl

set SNMPCONFPATH=saveXXSNMPCONFPATH

