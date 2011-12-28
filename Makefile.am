# tlssh/Makefile.am

# Don't complain about "missing" standard GNU files
include $(top_srcdir)/Makefile.am.common

# Documentation
man_MANS=doc/tlssh.1 doc/tlsshd.8 doc/tlssh.conf.5 doc/tlsshd.conf.5
doc: manpages
	ln -fs ../src
	doxygen Doxyfile

manpages:
	yodl2man -o doc/tlssh.1 doc/tlssh.yodl
	yodl2man -o doc/tlssh.conf.5 doc/tlssh.conf.yodl
	yodl2man -o doc/tlsshd.8 doc/tlsshd.yodl
	yodl2man -o doc/tlsshd.conf.5 doc/tlsshd.conf.yodl


# Programs
bin_PROGRAMS = tlssh
sbin_PROGRAMS = tlsshd

AM_CFLAGS=-I$(top_srcdir)/monotonic_clock/include \
-I$(top_srcdir)/libopenpty/include \
@AM_CFLAGS@

tlssh_SOURCES = \
src/tlssh.cc \
src/sslsocket.cc \
src/socket.cc \
src/fdwrap.cc \
src/configparser.cc \
src/util.cc \
src/xgetpwnam.c \
src/tlssh_common.cc \
src/cfmakeraw.c \
src/wordexp.c \
src/gaiwrap.cc

tlsshd_SOURCES = \
src/tlsshd.cc \
src/sslsocket.cc \
src/socket.cc \
src/xgetpwnam.c \
src/fdwrap.cc \
src/configparser.cc \
src/util.cc \
src/tlsshd-ssl.cc \
src/tlsshd-shell.cc \
src/tlssh_common.cc \
src/cfmakeraw.c \
src/forkpty.c \
src/setresuid.c \
src/clearenv.c \
src/daemon.c \
src/logwtmp.c \
src/wordexp.c \
src/login_tty.c \
src/gaiwrap.cc

TESTS=socket_test sslsocket_test
TEST_FLAGS=-std=gnu++0x
TEST_FLAGS+=-fprofile-arcs -ftest-coverage
TEST_LDADD=-lgtest -lpthread
noinst_PROGRAMS=$(TESTS)

socket_test_SOURCES=src/socket_test.cc src/socket.cc src/fdwrap.cc src/gaiwrap.cc
socket_test_CXXFLAGS=$(TEST_FLAGS)
socket_test_LDFLAGS=$(TEST_FLAGS)
socket_test_LDADD=$(TEST_LDADD)

sslsocket_test_SOURCES=src/sslsocket_test.cc src/sslsocket.cc src/socket.cc src/fdwrap.cc \
src/util.cc src/xgetpwnam.c src/gaiwrap.cc
sslsocket_test_CXXFLAGS=$(TEST_FLAGS)
sslsocket_test_LDFLAGS=$(TEST_FLAGS)
sslsocket_test_LDADD=$(TEST_LDADD)

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -fr config.guess config.sub build-stamp autom4te.cache/
	rm -f Makefile.in configure autoscan*.log debian/debhelper.log
	rm -f debian/substvars debian/files
	rm -fr debian/tmp
	rm -f config/install-sh config/missing config/depcomp
