dnl @synopsis AC_PROMPT_USER_NO_DEFINE(VARIABLENAME,QUESTION,[DEFAULT])
dnl
dnl Asks a QUESTION and puts the results in VARIABLENAME with an optional
dnl DEFAULT value if the user merely hits return.
dnl
dnl @version 1.15
dnl @author Wes Hardaker <hardaker@users.sourceforge.net>
dnl
AC_DEFUN([AC_PROMPT_USER_NO_DEFINE],
dnl changequote(<<, >>) dnl
dnl <<
[
if test "x$defaults" = "xno"; then
echo $ECHO_N "$2 ($3): $ECHO_C"
read tmpinput <&AS_ORIGINAL_STDIN_FD
if test "$tmpinput" = "" -a "$3" != ""; then
  tmpinput="$3"
fi
eval $1=\"$tmpinput\"
else
tmpinput="$3"
eval $1=\"$tmpinput\"
fi
]
dnl >>
dnl changequote([, ])
) dnl done AC_PROMPT_USER

dnl @synopsis AC_PROMPT_USER(VARIABLENAME,QUESTION,[DEFAULT],QUOTED)
dnl
dnl Asks a QUESTION and puts the results in VARIABLENAME with an optional
dnl DEFAULT value if the user merely hits return.  Also calls 
dnl AC_DEFINE_UNQUOTED() on the VARIABLENAME for VARIABLENAMEs that should
dnl be entered into the config.h file as well.  If QUOTED is "quoted" then
dnl the result will be defined within quotes.
dnl
dnl @version 1.15
dnl @author Wes Hardaker <hardaker@users.sourceforge.net>
dnl
AC_DEFUN([AC_PROMPT_USER],
[
MSG_CHECK=`echo "$2" | tail -1`
AC_CACHE_CHECK($MSG_CHECK, ac_cv_user_prompt_$1,
[echo "" >&AC_FD_MSG
AC_PROMPT_USER_NO_DEFINE($1,[$2],$3)
eval ac_cv_user_prompt_$1=\$$1
echo $ECHO_N "setting $MSG_CHECK to...  $ECHO_C" >&AC_FD_MSG
])
if test "$ac_cv_user_prompt_$1" != "none"; then
  if test "x$4" = "xquoted" -o "x$4" = "xQUOTED"; then
    AC_DEFINE_UNQUOTED($1,"$ac_cv_user_prompt_$1")
  else
    AC_DEFINE_UNQUOTED($1,$ac_cv_user_prompt_$1)
  fi
fi
]) dnl

dnl
dnl Add a search path to the LIBS and CFLAGS variables
dnl
AC_DEFUN([AC_ADD_SEARCH_PATH],[
  if test "x$1" != x -a -d $1; then
     if test -d $1/lib; then
       LDFLAGS="-L$1/lib $LDFLAGS"
     fi
     if test -d $1/include; then
	CPPFLAGS="-I$1/include $CPPFLAGS"
     fi
  fi
])

dnl
dnl Store information for displaying later.
dnl
AC_DEFUN([AC_MSG_CACHE_INIT],[
  rm -f configure-summary
])

AC_DEFUN([AC_MSG_CACHE_ADD],[
  cat >> configure-summary << EOF
  $1
EOF
])

AC_DEFUN([AC_MSG_CACHE_DISPLAY],[
  echo ""
  echo "---------------------------------------------------------"
  echo "            Net-SNMP configuration summary:"
  echo "---------------------------------------------------------"
  echo ""
  cat configure-summary
  echo ""
  echo "---------------------------------------------------------"
  echo ""
])

AC_DEFUN([AC_MSG_MODULE_DBG],
[
  if test $module_debug = 1; then
    echo $1 $2 $3 $4
  fi
]
)

dnl @synopsis NETSNMP_SEARCH_LIBS(FUNCTION, SEARCH-LIBS, [ACTION-IF-FOUND],
dnl             [ACTION-IF-NOT-FOUND], [OTHER-LIBRARIES], [TARGET-VARIABLE])
dnl Similar to AC_SEARCH_LIBS but changes TARGET-VARIABLE instead of LIBS
dnl If TARGET-VARIABLE is unset then LIBS is used
AC_DEFUN([NETSNMP_SEARCH_LIBS],
[m4_pushdef([netsnmp_target],m4_ifval([$6],[$6],[LIBS]))
 AC_CACHE_CHECK([for library containing $1],
    [netsnmp_cv_func_$1_]netsnmp_target,
    [netsnmp_func_search_save_LIBS="$LIBS"
     m4_if([netsnmp_target], [LIBS],
         [netsnmp_target_val="$LIBS"
          netsnmp_temp_LIBS="$5 ${LIBS}"],
         [netsnmp_target_val="$netsnmp_target"
          netsnmp_temp_LIBS="${netsnmp_target_val} $5 ${LIBS}"])
     netsnmp_result=no
     LIBS="${netsnmp_temp_LIBS}"
     AC_LINK_IFELSE([AC_LANG_CALL([],[$1])],
         [netsnmp_result="none required"],
         [for netsnmp_cur_lib in $2 ; do
              LIBS="-l${netsnmp_cur_lib} ${netsnmp_temp_LIBS}"
              AC_LINK_IFELSE([AC_LANG_CALL([],[$1])],
                  [netsnmp_result=-l${netsnmp_cur_lib}
                   break])
          done])
     LIBS="${netsnmp_func_search_save_LIBS}"
     [netsnmp_cv_func_$1_]netsnmp_target="${netsnmp_result}"])
 if test "${[netsnmp_cv_func_$1_]netsnmp_target}" != "no" ; then
    if test "${[netsnmp_cv_func_$1_]netsnmp_target}" != "none required" ; then
       netsnmp_target="${netsnmp_result} ${netsnmp_target_val}"
    fi
    $3
 m4_ifval([$4], [else
    $4])
 fi
 m4_popdef([netsnmp_target])])
