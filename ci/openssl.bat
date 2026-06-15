REM Download and install OpenSSL
rmdir /s /q C:\OpenSSL-Win32
rmdir /s /q C:\OpenSSL-v11-Win32
rmdir /s /q C:\OpenSSL-Win64
rmdir /s /q C:\OpenSSL-v11-Win64
powershell -ExecutionPolicy Bypass -File "%~dp0openssl.ps1"
if %errorlevel% neq 0 exit /b %errorlevel%
.\openssl.exe /suppressmsgboxes /silent /norestart /nocloseapplications /log=openssl-installation-log.txt /dir=C:\OpenSSL-Win64
rem type openssl-installation-log.txt
