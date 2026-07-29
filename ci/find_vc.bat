@echo off
set p=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build
if exist "%p%" set "VCVARSPATH=%p%"
set p=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary/Build
if exist "%p%" set "VCVARSPATH=%p%"
