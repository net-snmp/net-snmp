REM Download and install OpenSSL
set "FOLDERS=C:\OpenSSL-Win32 C:\OpenSSL-v11-Win32 C:\OpenSSL-Win64 C:\OpenSSL-v11-Win64"
for %%D in (%FOLDERS%) do (
    if exist "%%D\" (
        rmdir /s /q "%%D" 2>nul
    )
)
powershell -ExecutionPolicy Bypass -File "%~dp0openssl.ps1" "%~dp0openssl.exe"
if %errorlevel% neq 0 exit /b %errorlevel%
"%~dp0openssl.exe" /suppressmsgboxes /silent /norestart /nocloseapplications /log=openssl-installation-log.txt /dir=C:\OpenSSL-Win64
set EXIT_CODE=%errorlevel%
if exist "%~dp0openssl.exe" del "%~dp0openssl.exe"
if %EXIT_CODE% neq 0 exit /b %EXIT_CODE%
