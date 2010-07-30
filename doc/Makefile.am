# tlssh/doc/Makefile.am

include $(top_srcdir)/Makefile.am.common
doc: manpages
	ln -fs ../src
	doxygen Doxyfile

man_MANS=tlssh.1 tlsshd.8 tlssh.conf.5 tlsshd.conf.5
manpages:
	yodl2man -o tlssh.1 tlssh.yodl
	yodl2man -o tlssh.conf.5 tlssh.conf.yodl
	yodl2man -o tlsshd.8 tlsshd.yodl
	yodl2man -o tlsshd.conf.5 tlsshd.conf.yodl
