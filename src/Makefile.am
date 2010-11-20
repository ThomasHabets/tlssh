# tlssh/src/Makefile.am

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = tlssh
sbin_PROGRAMS = tlsshd

tlssh_SOURCES = \
tlssh.cc sslsocket.cc socket.cc fdwrap.cc configparser.cc util.cc \
xgetpwnam.c tlssh_common.cc cfmakeraw.c wordexp.c

tlsshd_SOURCES = \
tlsshd.cc sslsocket.cc socket.cc xgetpwnam.c fdwrap.cc configparser.cc \
util.cc tlsshd-ssl.cc tlsshd-shell.cc tlssh_common.cc cfmakeraw.c forkpty.c \
openpty_solaris.c setresuid.c clearenv.c daemon.c logwtmp.c wordexp.c \
login_tty.c

if HAVE_CLOCK_MONOTONIC
tlssh_SOURCES += ../monotonic_clock/src/monotonic_clock.c
tlsshd_SOURCES += ../monotonic_clock/src/monotonic_clock.c
else
tlssh_SOURCES += ../monotonic_clock/src/monotonic_generic.c
tlsshd_SOURCES += ../monotonic_clock/src/monotonic_generic.c
endif
