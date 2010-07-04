# -*- Autoconf -*-
# tlssh/configure.ac
#

AC_PREREQ(2.61)
AC_INIT([tlssh], [0.02], [thomas@habets.pp.se])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/tlssh.cc])
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_CHECK_LIB([util], [openpty])
AC_CHECK_LIB([ssl], [SSL_new])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([recv], [socket])
AC_SEARCH_LIBS([send], [socket])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h netinet/in6.h stdlib.h \
string.h sys/socket.h sys/time.h unistd.h memory.h sys/uio.h \
ifaddrs.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_VOLATILE

# Checks for library functions.
#AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memcpy gettimeofday memset socket sqrt strerror strtoul])

EL_GETPW_R_POSIX
EL_GETPW_R_DRAFT

# Output
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
