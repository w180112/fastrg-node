#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(libutils, 1.0, w180112@gmail.com)
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([common.h])
AC_CONFIG_HEADERS([config.h])
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_AR

# Checks for libraries.
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h memory.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h termio.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([alarm bzero gettimeofday inet_ntoa memmove socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
