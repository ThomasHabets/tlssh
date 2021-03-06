# -*- Autoconf -*-
# tlssh/configure.ac
#

AC_PREREQ(2.61)
AC_INIT([tlssh], [0.07], [thomas@habets.se])
AC_CONFIG_AUX_DIR([config])
#AC_CONFIG_MACRO_DIR(config)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/tlssh.cc])
AC_CONFIG_HEADER(config.h)
AC_CONFIG_SUBDIRS([libopenpty])

AC_CONFIG_SUBDIRS([monotonic_clock])
AC_SEARCH_LIBS([clock_gettime], [rt])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([m], [sqrt])
AC_CHECK_LIB([util], [openpty])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([recv], [socket])
AC_SEARCH_LIBS([send], [socket])
AC_CHECK_LIB([crypto], [X509_STORE_new])
AC_CHECK_LIB([ssl], [SSL_pending])

AC_SEARCH_LIBS([clock_get_dbl], [monotonic_clock])

if test "x$ac_cv_lib_util_openpty" = "xno"; then
   PKG_CHECK_MODULES([OPENPTY], [libopenpty >= 0])
fi

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h netinet/in6.h stdlib.h \
string.h sys/socket.h sys/time.h unistd.h memory.h sys/uio.h \
ifaddrs.h pty.h wordexp.h util.h utmp.h utmpx.h \
])
AC_CHECK_HEADER([openssl/ssl.h],[],
	AC_ERROR("can't find openssl development files"))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_C_VOLATILE

# Checks for library functions.
#AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memcpy gettimeofday memset socket sqrt strerror strtoul \
daemon setresuid setresgid logwtmp basename forkpty clearenv cfmakeraw \
wordexp login_tty login \
SSL_new \
])

EL_GETPW_R_POSIX
EL_GETPW_R_DRAFT

AC_CHECK_MEMBER(struct tcp_md5sig.tcpm_prefixlen,
		       [AC_DEFINE([HAVE_TCPMD5_EXT], 1,
		       [Define if you have TCP MD5 EXT])],
		       [],
		       [[#include <netinet/tcp.h>]])

AC_CHECK_MEMBER(struct utmp.ut_time,
		       [AC_DEFINE([HAVE_UTMP_TIME], 1,
		       [Define if you have struct utmp.ut_time])],
		       [],
		       [[
#include <time.h>
#include <utmp.h>
]])

AC_CHECK_MEMBER(struct utmp.ut_pid,
		       [AC_DEFINE([HAVE_UTMP_PID], 1,
		       [Define if you have struct utmp.ut_pid])],
		       [],
		       [[
#include <time.h>
#include <utmp.h>
]])

AC_CHECK_MEMBER(struct utmp.ut_id,
		       [AC_DEFINE([HAVE_UTMP_ID], 1,
		       [Define if you have struct utmp.ut_id])],
		       [],
		       [[
#include <time.h>
#include <utmp.h>
]])

AC_CHECK_MEMBER(struct utmp.ut_tv,
		       [AC_DEFINE([HAVE_UTMP_TV], 1,
		       [Define if you have struct utmp.ut_tv])],
		       [],
		       [[
#include <time.h>
#include <utmp.h>
]])

AC_CHECK_MEMBER(struct utmp.ut_user,
		       [AC_DEFINE([HAVE_UTMP_USER], 1,
		       [Define if you have struct utmp.ut_user])],
		       [],
		       [[
#include <time.h>
#include <utmp.h>
]])

# Enabled PIC/PIE
CFLAGS="$CFLAGS -fPIC"
CXXFLAGS="$CXXFLAGS -fPIC"
LDFLAGS="$LDFLAGS -pie -Wl,-z,now -Wl,-z,relro"

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  Debug Build....: $debug
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  C++ Compiler...: $CXX $CXXFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
