AUTOMAKE_OPTIONS = foreign

DOXYGEN_QORE_API_FILTER=docs/doxygen-api-filter.q
DOXYGEN_OUTPUT=docs/ssh2

DOXYFILES = docs/doxyfile \
	docs/mainpage.doxygen \
	docs/SSH2Base.qc \
	docs/SSH2Client.qc \
	docs/SFTPClient.qc \
	docs/SSH2Channel.qc

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
	qore-ssh2-module.spec

ACLOCAL_AMFLAGS=-I m4

if COND_DOXYGEN
DX_CLEANFILES = ${DOXYFILES}
docs/ssh2/html: $(DOXYFILES)
	cd docs; $(DOXYGEN_CMD) doxyfile;
	$(DOXYGEN_QORE_API_FILTER) --post $(DOXYGEN_OUTPUT)/html/*html
	$(DOXYGEN_QORE_API_FILTER) --post $(DOXYGEN_OUTPUT)/html/search/*html

doxygen-doc: docs/ssh2/html

EXTRA_DIST += docs/ssh2/html

else
doxygen-doc:
	echo no doxygen support
endif

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

mostlyclean-local:
	rm -rf ${DOXYGEN_OUTPUT} ${DX_CLEANFILES}

docs/mainpage.doxygen: docs/mainpage.doxygen.tmpl
	$(DOXYGEN_QORE_API_FILTER) -l $<

docs/doxyfile: docs/doxyfile.tmpl
	sed s/__VERSION__/${VERSION}/ $< > $@

docs/SSH2Base.qc: src/QC_SSH2Base.cc
	$(DOXYGEN_QORE_API_FILTER) $< $@

docs/SSH2Client.qc: src/QC_SSH2Client.cc
	$(DOXYGEN_QORE_API_FILTER) $< $@

docs/SFTPClient.qc: src/QC_SFTPClient.cc
	$(DOXYGEN_QORE_API_FILTER) $< $@

docs/SSH2Channel.qc: src/QC_SSH2Channel.cc
	$(DOXYGEN_QORE_API_FILTER) $< $@

