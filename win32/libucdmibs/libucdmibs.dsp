# Microsoft Developer Studio Project File - Name="libucdmibs" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libucdmibs - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libucdmibs.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libucdmibs.mak" CFG="libucdmibs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libucdmibs - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libucdmibs - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "libucdmibs - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "../lib"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "." /I ".." /I "..\..\agent" /I "..\..\snmplib" /I "..\..\agent\mibgroup" /I "..\.." /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../lib/ucdmibs.lib"

!ELSEIF  "$(CFG)" == "libucdmibs - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "../lib"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Od /I "." /I ".." /I "..\..\agent" /I "..\..\snmplib" /I "..\..\agent\mibgroup" /I "..\.." /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /ZI /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../lib/ucdmibs_d.lib"

!ENDIF 

# Begin Target

# Name "libucdmibs - Win32 Release"
# Name "libucdmibs - Win32 Debug"
# Begin Group "mibII"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\agent\mibgroup\mibII\snmp_mib.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\mibII\system_mib.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\mibII\sysORTable.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\mibII\vacm_vars.c
# End Source File
# End Group
# Begin Group "examples"
# Begin Source File

SOURCE=..\..\agent\mibgroup\examples\example.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\examples\ucdDemoPublic.c
# End Source File
# End Group
# Begin Group "ucd-snmp"

# PROP Default_Filter ""
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\disk.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\errormib.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\extensible.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\file.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\loadave.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\pass.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\proc.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\registry.c"
# End Source File
# Begin Source File

SOURCE="..\..\agent\mibgroup\ucd-snmp\versioninfo.c"
# End Source File
# End Group
# Begin Group "snmpv3"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\agent\mibgroup\snmpv3\snmpEngine.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\snmpv3\snmpMPDStats.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\snmpv3\usmStats.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\snmpv3\usmUser.c
# End Source File
# End Group
# Begin Group "target"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\agent\mibgroup\target\snmpTargetAddrEntry.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\target\snmpTargetParamsEntry.c
# End Source File
# End Group
# Begin Source File

SOURCE=..\..\agent\mib_modules.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\smux\smux.c
# End Source File
# Begin Source File

SOURCE=..\..\agent\mibgroup\util_funcs.c
# End Source File
# End Target
# End Project
