# tlssh/src/Makefile.am

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = tlssh tlsshd
tlssh_SOURCES = \
tlssh.cc sslsocket.cc socket.cc fdwrap.cc configparser.cc util.cc \
xgetpwnam.c

tlsshd_SOURCES = \
tlsshd.cc sslsocket.cc socket.cc xgetpwnam.c fdwrap.cc configparser.cc \
util.cc tlsshd-ssl.cc tlsshd-shell.cc

