dnl AC_PROMPT_USER_NO_DEFINE(VARIABLE,PROMPT,[DEFAULT])
AC_DEFUN(AC_PROMPT_USER_NO_DEFINE,
dnl changequote(<<, >>) dnl
dnl <<
[
echo $ac_n "$2 ($3): $ac_c"
read tmpinput
if test "$tmpinput" = "" -a "$3" != ""; then
  tmpinput="$3"
fi
eval $1=\"$tmpinput\"
]
dnl >>
dnl changequote([, ])
) dnl done AC_PROMPT_USER

AC_DEFUN(AC_PROMPT_USER,
[
MSG_CHECK=`echo "$2" | tail -1`
AC_MSG_CHECKING($MSG_CHECK)
AC_CACHE_VAL(ac_cv_user_prompt_$1,
echo ""
AC_PROMPT_USER_NO_DEFINE($1,[$2],$3)
eval ac_cv_user_prompt_$1=\$$1
echo $ac_n "setting $MSG_CHECK to...  $ac_c"
) dnl
if test "$ac_cv_user_prompt_$1" != "none"; then
  if test "$4" != ""; then
    AC_DEFINE_UNQUOTED($1,"$ac_cv_user_prompt_$1")
  else
    AC_DEFINE_UNQUOTED($1,$ac_cv_user_prompt_$1)
  fi
fi
AC_MSG_RESULT($ac_cv_user_prompt_$1)
]
) dnl
