!verbose 3
!include "WinMessages.NSH"
!verbose 4

; AddToPath - Adds the given dir to the search path.
;        Input - head of the stack
;        Note - Win9x systems requires reboot

Function AddToPath
  Exch $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5

  # don't add if the path doesn't exist
  IfFileExists $0 "" AddToPath_done
  
  ReadEnvStr $1 PATH
  
  # If length of PATH returned is 0, we couldn't read the environment variable (unlikely) or
  # it's empty because it's > 1024 characters long.  NSIS only supports variables up to 1024 
  # characters unless we're using the 8192 length version, which we are not.  
  # Note:  On XP (at least), the string read using ReadEnvStr is shorter than we would expect.
  # During testing, when the PATH was 1020 characters long, StrLen of the path returned 984.
  # When manipulating the path on XP, use the registry instead.
  StrLen $4 "$1"
  # MessageBox MB_ICONINFORMATION|MB_OK "PATH length: $4..."
  IntCmp $4 0 Path_Too_Short1
  Goto AddToPath_Cont1
  
  Path_Too_Short1:
  # PATH is empty.  Display warning.
  MessageBox MB_ICONINFORMATION|MB_OK "Your PATH variable could not be read, probably because it is longer than 1024 characters (installer limitation).  Please add the folder $0 to your PATH using the System Control Panel."
  goto AddToPath_done

  AddToPath_Cont1:
  
  Push "$1;"
  Push "$0;"
  Call StrStr
  Pop $2
  StrCmp $2 "" "" AddToPath_done
  Push "$1;"
  Push "$0\;"
  Call StrStr
  Pop $2
  StrCmp $2 "" "" AddToPath_done
  GetFullPathName /SHORT $3 $0
  Push "$1;"
  Push "$3;"
  Call StrStr
  Pop $2
  StrCmp $2 "" "" AddToPath_done
  Push "$1;"
  Push "$3\;"
  Call StrStr
  Pop $2
  StrCmp $2 "" "" AddToPath_done

  Call IsNT
  Pop $1
  StrCmp $1 1 AddToPath_NT
    ; Not on NT
    StrCpy $1 $WINDIR 2
    FileOpen $1 "$1\autoexec.bat" a
    FileSeek $1 -1 END
    FileReadByte $1 $2
    IntCmp $2 26 0 +2 +2 # DOS EOF
      FileSeek $1 -1 END # write over EOF
    FileWrite $1 "$\r$\nSET PATH=%PATH%;$3$\r$\n"
    FileClose $1
    SetRebootFlag true
    Goto AddToPath_done

  AddToPath_NT:
    ;ReadRegStr $1 HKCU "Environment" "PATH"
    ReadRegStr $1 HKLM 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' "PATH"

    StrCpy $2 $1 1 -1 # copy last char
    StrCmp $2 ";" 0 +2 # if last char == ;
      StrCpy $1 $1 -1 # remove last char

    # Make sure old PATH is not empty..
    StrLen $4 "$1"
    #MessageBox MB_ICONINFORMATION|MB_OK "Reg PATH length: $4..."
    IntCmp $4 0 Path_Too_Short2
    Goto AddToPath_Cont2
    Path_Too_Short2:
    # PATH is empty.  Display warning.
    MessageBox MB_ICONINFORMATION|MB_OK "Your PATH variable could not be read, probably because it is longer than 1024 characters (installer limitation).  Please add the folder $0 to your PATH using the System Control Panel."
    goto AddToPath_done
    AddToPath_Cont2:

    # Make sure new PATH won't be too long.
    StrLen $5 "$0"
    IntOp $4 $4 + $5
    IntCmp $4 1022 "" "" Path_Too_Long3
    Goto AddToPath_Cont3
    Path_Too_Long3:
    MessageBox MB_ICONINFORMATION|MB_OK "Your new PATH variable could not be set as it would be greater than 1024 characters (installer limitation).  Please add the folder $0 to your PATH using the System Control Panel."
    goto AddToPath_done
    AddToPath_Cont3:

    StrCpy $0 "$1;$0"

    ;WriteRegExpandStr HKCU "Environment" "PATH" $0
    WriteRegExpandStr HKLM 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' "PATH" $0
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  AddToPath_done:
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd

; RemoveFromPath - Remove a given dir from the path
;     Input: head of the stack

Function un.RemoveFromPath
  Exch $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6

  IntFmt $6 "%c" 26 # DOS EOF

  Call un.IsNT
  Pop $1
  StrCmp $1 1 unRemoveFromPath_NT
    ; Not on NT
    StrCpy $1 $WINDIR 2
    FileOpen $1 "$1\autoexec.bat" r
    GetTempFileName $4
    FileOpen $2 $4 w
    GetFullPathName /SHORT $0 $0
    StrCpy $0 "SET PATH=%PATH%;$0"
    Goto unRemoveFromPath_dosLoop

    unRemoveFromPath_dosLoop:
      FileRead $1 $3
      StrCpy $5 $3 1 -1 # read last char
      StrCmp $5 $6 0 +2 # if DOS EOF
        StrCpy $3 $3 -1 # remove DOS EOF so we can compare
      StrCmp $3 "$0$\r$\n" unRemoveFromPath_dosLoopRemoveLine
      StrCmp $3 "$0$\n" unRemoveFromPath_dosLoopRemoveLine
      StrCmp $3 "$0" unRemoveFromPath_dosLoopRemoveLine
      StrCmp $3 "" unRemoveFromPath_dosLoopEnd
      FileWrite $2 $3
      Goto unRemoveFromPath_dosLoop
      unRemoveFromPath_dosLoopRemoveLine:
        SetRebootFlag true
        Goto unRemoveFromPath_dosLoop

    unRemoveFromPath_dosLoopEnd:
      FileClose $2
      FileClose $1
      StrCpy $1 $WINDIR 2
      Delete "$1\autoexec.bat"
      CopyFiles /SILENT $4 "$1\autoexec.bat"
      Delete $4
      Goto unRemoveFromPath_done

  unRemoveFromPath_NT:
    ;ReadRegStr $1 HKCU "Environment" "PATH"
    ReadRegStr $1 HKLM 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' "PATH"
    StrCpy $5 $1 1 -1 # copy last char
    StrCmp $5 ";" +2 # if last char != ;
      StrCpy $1 "$1;" # append ;
    Push $1
    Push "$0;"
    Call un.StrStr ; Find `$0;` in $1
    Pop $2 ; pos of our dir
    StrCmp $2 "" unRemoveFromPath_done
      ; else, it is in path
      # $0 - path to add
      # $1 - path var
      StrLen $3 "$0;"
      StrLen $4 $2
      StrCpy $5 $1 -$4 # $5 is now the part before the path to remove
      StrCpy $6 $2 "" $3 # $6 is now the part after the path to remove
      StrCpy $3 $5$6

      StrCpy $5 $3 1 -1 # copy last char
      StrCmp $5 ";" 0 +2 # if last char == ;
        StrCpy $3 $3 -1 # remove last char

      ;WriteRegExpandStr HKCU "Environment" "PATH" $3
      WriteRegExpandStr HKLM 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' "PATH" $3
      SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  unRemoveFromPath_done:
    Pop $6
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd

###########################################
#            Utility Functions            #
###########################################

; IsNT
; no input
; output, top of the stack = 1 if NT or 0 if not
;
; Usage:
;   Call IsNT
;   Pop $R0
;  ($R0 at this point is 1 or 0)

!macro IsNT un
Function ${un}IsNT
  Push $0
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  StrCmp $0 "" 0 IsNT_yes
  ; we are not NT.
  Pop $0
  Push 0
  Return

  IsNT_yes:
    ; NT!!!
    Pop $0
    Push 1
FunctionEnd
!macroend
!insertmacro IsNT ""
!insertmacro IsNT "un."

; StrStr
; input, top of stack = string to search for
;        top of stack-1 = string to search in
; output, top of stack (replaces with the portion of the string remaining)
; modifies no other variables.
;
; Usage:
;   Push "this is a long ass string"
;   Push "ass"
;   Call StrStr
;   Pop $R0
;  ($R0 at this point is "ass string")

!macro StrStr un
Function ${un}StrStr
Exch $R1 ; st=haystack,old$R1, $R1=needle
  Exch    ; st=old$R1,haystack
  Exch $R2 ; st=old$R1,old$R2, $R2=haystack
  Push $R3
  Push $R4
  Push $R5
  StrLen $R3 $R1
  StrCpy $R4 0
  ; $R1=needle
  ; $R2=haystack
  ; $R3=len(needle)
  ; $R4=cnt
  ; $R5=tmp
  loop:
    StrCpy $R5 $R2 $R3 $R4
    StrCmp $R5 $R1 done
    StrCmp $R5 "" done
    IntOp $R4 $R4 + 1
    Goto loop
done:
  StrCpy $R1 $R2 "" $R4
  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Exch $R1
FunctionEnd
!macroend
!insertmacro StrStr ""
!insertmacro StrStr "un."
