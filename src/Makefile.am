# tlssh/src/Makefile.am

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = tlssh
sbin_PROGRAMS = tlsshd

AM_CFLAGS=-I$(top_srcdir)/monotonic_clock/include

tlssh_SOURCES = \
tlssh.cc sslsocket.cc socket.cc fdwrap.cc configparser.cc util.cc \
xgetpwnam.c tlssh_common.cc cfmakeraw.c wordexp.c \
$(top_srcdir)/monotonic_clock/src/monotonic_common.c

tlsshd_SOURCES = \
tlsshd.cc sslsocket.cc socket.cc xgetpwnam.c fdwrap.cc configparser.cc \
util.cc tlsshd-ssl.cc tlsshd-shell.cc tlssh_common.cc cfmakeraw.c forkpty.c \
openpty_solaris.c setresuid.c clearenv.c daemon.c logwtmp.c wordexp.c \
login_tty.c \
$(top_srcdir)/monotonic_clock/src/monotonic_common.c

if HAVE_CLOCK_MONOTONIC
tlssh_SOURCES += $(top_srcdir)/monotonic_clock/src/monotonic_clock.c
tlsshd_SOURCES += $(top_srcdir)/monotonic_clock/src/monotonic_clock.c
else
tlssh_SOURCES += $(top_srcdir)/monotonic_clock/src/monotonic_generic.c
tlsshd_SOURCES += $(top_srcdir)/monotonic_clock/src/monotonic_generic.c
endif
