AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

noinst_HEADERS = src/ssh2-module.h \
	src/ssh2.h \
	src/SSH2Client.h \
	src/SFTPClient.h \
	src/SSH2Channel.h \
	src/QC_SSH2Base.h

EXTRA_DIST = COPYING ChangeLog AUTHORS README \
	RELEASE-NOTES \
	test/ssh2-test.q \
	docs/ssh2-module-doc.html \
	qore-ssh2-module.spec

ACLOCAL_AMFLAGS=-I m4

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

