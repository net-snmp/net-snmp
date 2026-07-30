REM Download and install OpenSSL
set "FOLDERS=C:\OpenSSL-Win32 C:\OpenSSL-v11-Win32 C:\OpenSSL-Win64 C:\OpenSSL-v11-Win64"
for %%D in (%FOLDERS%) do (
    if exist "%%D\" (
        rmdir /s /q "%%D" 2>nul
    )
)
powershell -ExecutionPolicy Bypass -File "%~dp0openssl.ps1"
if %errorlevel% neq 0 exit /b %errorlevel%
.\openssl.exe /suppressmsgboxes /silent /norestart /nocloseapplications /log=openssl-installation-log.txt /dir=C:\OpenSSL-Win64
rem type openssl-installation-log.txt
