# tlssh/src/Makefile.am

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = tlssh
sbin_PROGRAMS = tlsshd

AM_CFLAGS=-I$(top_srcdir)/monotonic_clock/include \
-I$(top_srcdir)/libopenpty/include \
@AM_CFLAGS@

tlssh_SOURCES = \
tlssh.cc sslsocket.cc socket.cc fdwrap.cc configparser.cc util.cc \
xgetpwnam.c tlssh_common.cc cfmakeraw.c wordexp.c gaiwrap.cc

tlsshd_SOURCES = \
tlsshd.cc sslsocket.cc socket.cc xgetpwnam.c fdwrap.cc configparser.cc \
util.cc tlsshd-ssl.cc tlsshd-shell.cc tlssh_common.cc cfmakeraw.c forkpty.c \
setresuid.c clearenv.c daemon.c logwtmp.c wordexp.c \
login_tty.c gaiwrap.cc

TESTS=socket_test sslsocket_test
TEST_FLAGS=-std=gnu++0x
TEST_FLAGS+=-fprofile-arcs -ftest-coverage
TEST_LDADD=-lgtest -lpthread
noinst_PROGRAMS=$(TESTS)

socket_test_SOURCES=socket_test.cc socket.cc fdwrap.cc gaiwrap.cc
socket_test_CXXFLAGS=$(TEST_FLAGS)
socket_test_LDFLAGS=$(TEST_FLAGS)
socket_test_LDADD=$(TEST_LDADD)

sslsocket_test_SOURCES=sslsocket_test.cc sslsocket.cc socket.cc fdwrap.cc \
util.cc xgetpwnam.c gaiwrap.cc
sslsocket_test_CXXFLAGS=$(TEST_FLAGS)
sslsocket_test_LDFLAGS=$(TEST_FLAGS)
sslsocket_test_LDADD=$(TEST_LDADD)
