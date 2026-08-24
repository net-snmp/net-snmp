dnl
dnl Add a search path to the LIBS and CPPFLAGS variables
dnl
AC_DEFUN([AC_ADD_SEARCH_PATH],[
  if test "x$1" != x -a -d $1; then
     if test -d $1/lib; then
       LDFLAGS="-L$1/lib $LDFLAGS"
     fi
     if test -d $1/include; then
	if test "x$GCC" = "xyes"; then
	  CPPFLAGS="-isystem $1/include $CPPFLAGS"
	else
	  CPPFLAGS="-I$1/include $CPPFLAGS"
	fi
     fi
  fi
])

