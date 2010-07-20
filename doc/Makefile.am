# tlssh/doc/Makefile.am

include $(top_srcdir)/Makefile.am.common
doc: manpages
	ln -fs ../src
	doxygen Doxyfile

manpages: tlssh.1 tlsshd.8 tlssh.conf.5 tlsshd.conf.5

%.1 %.5 %.8: %.yodl
	yodl2man -o $@ $<
