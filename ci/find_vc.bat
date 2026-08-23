@echo off
set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%vswhere%" (
    for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
            set "VCVARSPATH=%%i\VC\Auxiliary\Build"
            goto :eof
        )
    )
)
set p=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build
if exist "%p%" set "VCVARSPATH=%p%"
set p=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build
if exist "%p%" set "VCVARSPATH=%p%"
set p=C:\Program Files\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build
if exist "%p%" set "VCVARSPATH=%p%"
