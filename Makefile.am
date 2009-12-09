AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

#noinst_HEADERS = src/ncurses-module.h \
#	src/QC_Panel.h \
#	src/QC_Window.h
#
#EXTRA_DIST = COPYING ChangeLog AUTHORS README \
#	RELEASE-NOTES \
#	test/ncurses.q \
#	examples/hanoi.q \
#	examples/worm.q \
#	docs/ncurses-module-doc.html \
#	qore-ncurses-module.spec

ACLOCAL_AMFLAGS=-I m4

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

