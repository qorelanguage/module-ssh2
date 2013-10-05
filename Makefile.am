modverdir = $(libdir)/$(mymodverdir)

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

noinst_HEADERS = src/ssh2-module.h \
	src/ssh2.h \
	src/SSH2Client.h \
	src/SFTPClient.h \
	src/SSH2Channel.h \
	src/QC_SSH2Base.h

EXTRA_DIST = COPYING.LGPL COPYING.MIT ChangeLog AUTHORS README \
	RELEASE-NOTES \
	src/QC_SSH2Base.qpp \
	src/QC_SSH2Client.qpp \
	src/QC_SSH2Channel.qpp \
	src/QC_SFTPClient.qpp \
	test/ssh2-test.q \
	qore-ssh2-module.spec

ACLOCAL_AMFLAGS=-I m4

if COND_DOXYGEN
DOX = ssh2
DOXYGEN_OUTPUT=docs/ssh2/html

DOXYFILES = docs/doxyfile docs/mainpage.doxygen
DOXYFILES_SRC = docs/doxyfile.tmpl docs/footer_template.html
QDX = qdx
DX_CLEANFILES = ${DOXYFILES}

docs/ssh2/html: $(DOXYFILES)
	cd docs; $(DOXYGEN_CMD) doxyfile;
	$(QDX) --post $(DOXYGEN_OUTPUT)/*html
	$(QDX) --post $(DOXYGEN_OUTPUT)/search/*html

docs/mainpage.doxygen: docs/mainpage.doxygen.tmpl
	$(QDX) -d $< $@

docs/doxyfile: docs/doxyfile.tmpl
	sed s/__VERSION__/${VERSION}/ $< > $@

doxygen-doc: $(DOXYGEN_OUTPUT)

EXTRA_DIST += $(DOXYGEN_OUTPUT)

html-local: $(DOXYGEN_OUTPUT)

install-html-local:
	for dox in $(DOX); do $(MKDIR_P) $(DESTDIR)$(datadir)/$(PACKAGE)/docs/$$dox/html/search; done
	for dir in $(DOXYGEN_OUTPUT); do \
	   for f in $$dir/*; do if [ -f $$f ]; then $(INSTALL_DATA) $$f $(DESTDIR)$(datadir)/$(PACKAGE)/$$dir; fi; done; \
	   for f in $$dir/search/*; do $(INSTALL_DATA) $$f $(DESTDIR)$(datadir)/$(PACKAGE)/$$dir/search; done; \
	done

clean-local:
	$(RM) -rf $(DOXYGEN_OUTPUT)

uninstall-local:
	$(RM) -rf $(DESTDIR)$(datadir)/$(PACKAGE)/docs

mostlyclean-local:
	rm -rf ${DOXYGEN_OUTPUT} ${DX_CLEANFILES}

else
doxygen-doc:
	echo no doxygen support
endif

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
