dnl AC_PROMPT_USER_NO_DEFINE(VARIABLE,PROMPT,[DEFAULT])
AC_DEFUN(AC_PROMPT_USER_NO_DEFINE,
dnl changequote(<<, >>) dnl
dnl <<
[
if test "x$defaults" = "xno"; then
echo $ac_n "$2 ($3): $ac_c"
read tmpinput
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

AC_DEFUN(AC_PROMPT_USER,
[
MSG_CHECK=`echo "$2" | tail -1`
AC_CACHE_CHECK($MSG_CHECK, ac_cv_user_prompt_$1,
[echo ""
AC_PROMPT_USER_NO_DEFINE($1,[$2],$3)
eval ac_cv_user_prompt_$1=\$$1
echo $ac_n "setting $MSG_CHECK to...  $ac_c"
])
if test "$ac_cv_user_prompt_$1" != "none"; then
  if test "$4" != ""; then
    AC_DEFINE_UNQUOTED($1,"$ac_cv_user_prompt_$1")
  else
    AC_DEFINE_UNQUOTED($1,$ac_cv_user_prompt_$1)
  fi
fi
]) dnl

dnl AC_CHECK_IFNET_FOR(SUBSTRUCT,DEFINE,[no])
AC_DEFUN(AC_CHECK_IFNET_FOR,[
dnl check for $1 in struct ifnet
AC_CACHE_CHECK(for ifnet.$1,
	ac_cv_struct_ifnet_$2,
[
if test "x$3" = "x"; then
  defineit="= 0"
else
  defineit=""
fi
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
],[
struct ifnet dergel; 
dergel.$1 $defineit;
], ac_cv_struct_ifnet_$2=yes, ac_cv_struct_ifnet_$2=no )
])

if test "x$ac_cv_struct_ifnet_$2" = "xyes"; then
  AC_DEFINE_UNQUOTED(STRUCT_IFNET_HAS_$2)
fi

])
