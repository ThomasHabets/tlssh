# tlssh/doc/Makefile.am

include $(top_srcdir)/Makefile.am.common
doc: manpages
	ln -fs ../src
	doxygen Doxyfile

man_MANS=tlssh.1 tlsshd.8 tlssh.conf.5 tlsshd.conf.5
manpages: $(man_MANS)

%.1 %.5 %.8: %.yodl
	yodl2man -o $@ $<
