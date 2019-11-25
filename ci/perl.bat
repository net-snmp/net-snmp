REM Download and install Perl
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
echo on
set PERL_VERSION=5.31.6
set INST_DRV=c:
set INST_TOP=c:\perl-msvc
rd /q /s %INST_TOP%
curl https://www.cpan.org/src/5.0/perl-%PERL_VERSION%.tar.gz -o perl-%PERL_VERSION%.tar.gz
if %errorlevel% neq 0 goto build_error
tar xaf perl-%PERL_VERSION%.tar.gz
if %errorlevel% neq 0 goto build_error
cd perl-%PERL_VERSION%\win32
if %errorlevel% neq 0 goto build_error
(echo CCTYPE=MSVC140 && echo INST_DRV=%INST_DRV% && echo INST_TOP=%INST_TOP% && type Makefile | findstr /r /v "^CCTYPE" | findstr /r /v "^INST_DRV" | findstr /r /v "^INST_TOP") > Makefile2
if %errorlevel% neq 0 goto build_error
del Makefile
if %errorlevel% neq 0 goto build_error
ren Makefile2 Makefile
if %errorlevel% neq 0 goto build_error
findstr /r "^CCTYPE" Makefile
findstr /r "^INST_DRV" Makefile
findstr /r "^INST_TOP" Makefile
nmake
if %errorlevel% neq 0 goto build_error
nmake install
if %errorlevel% neq 0 goto build_error
set PATH=%INST_TOP%\bin;%PATH%
where perl
perl -v
cd ..\..
set INST_DRV=
set INST_TOP=
exit

:build_error
set e=%errorlevel%
exit /b %e%
