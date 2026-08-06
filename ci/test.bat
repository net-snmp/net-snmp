@echo on
goto %BUILD%
echo "Error: unknown build type %BUILD%"
goto eof

:MSVCDYNAMIC64
call %~dp0find_vc.bat
call "%VCVARSPATH%\vcvars64.bat"
set PATH=C:\OpenSSL-Win64\bin;c:\perl-msvc\bin;%PATH%
if exist "C:\OpenSSL-Win64\bin\ossl-modules" (set "OPENSSL_MODULES=C:\OpenSSL-Win64\bin\ossl-modules") else if exist "C:\OpenSSL-Win64\lib\ossl-modules" (set "OPENSSL_MODULES=C:\OpenSSL-Win64\lib\ossl-modules") else (set "OPENSSL_MODULES=C:\OpenSSL-Win64\bin")
set MIBDIRS=%CD%\mibs
cd win32
nmake /nologo perl_test
if %errorlevel% neq 0 exit /b %errorlevel%
cd ..
goto eof

:MSVCSTATIC64
goto eof

:INSTALLER
goto eof

:MinGW32
goto eof

:MSYS2
goto eof

:MinGW64
rem C:\msys64\usr\bin\bash --login -c 'set -x; cd "${APPVEYOR_BUILD_FOLDER}"; ci/net-snmp-run-tests'
goto eof

:Cygwin32
goto eof
c:\cygwin\bin\bash --login -c 'set -x; cd "${APPVEYOR_BUILD_FOLDER}"; ci/net-snmp-run-tests'
goto eof

:Cygwin64
goto eof
c:\cygwin64\bin\bash --login -c 'set -x; cd "${APPVEYOR_BUILD_FOLDER}"; ci/net-snmp-run-tests'
goto eof

:eof
