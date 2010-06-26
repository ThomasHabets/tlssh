# tlssh/Makefile.am

# Don't complain about "missing" standard GNU files
include $(top_srcdir)/Makefile.am.common

SUBDIRS=src

mrproper: maintainer-clean
	rm -f aclocal.m4 configure.scan depcomp missing install-sh config.h.in
	rm -f Makefile.in configure autoscan*.log debian/debhelper.log
	rm -f debian/substvars debian/files
	rm -fr debian/tmp
	rm -f config/install-sh config/missing config/depcomp
