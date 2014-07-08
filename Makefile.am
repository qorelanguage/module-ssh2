moddir = $(userlibdir)

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

noinst_HEADERS = src/ssh2-module.h \
	src/ssh2.h \
	src/SSH2Client.h \
	src/SFTPClient.h \
	src/SSH2Channel.h \
	src/QC_SSH2Base.h

USER_MODULES = qlib/SftpPoller.qm

EXTRA_DIST = COPYING.LGPL COPYING.MIT ChangeLog AUTHORS README \
	RELEASE-NOTES \
	src/QC_SSH2Base.qpp \
	src/QC_SSH2Client.qpp \
	src/QC_SSH2Channel.qpp \
	src/QC_SFTPClient.qpp \
	test/ssh2-test.q \
        $(USER_MODULES) \
	qore-ssh2-module.spec

ACLOCAL_AMFLAGS=-I m4

dist_mod_DATA = $(USER_MODULES)

if COND_DOXYGEN
DOX = ssh2 SftpPoller
DOXYGEN_OUTPUT=docs/ssh2/html docs/SftpPoller/html
DOXYFILES = docs/doxyfile docs/mainpage.doxygen
DOXYFILES_SRC = docs/doxyfile.tmpl docs/footer_template.html
QLIB_TMP_DOXYFILES = docs/qlib/SftpPoller.qm.dox.h docs/qlib/Doxyfile.SftpPoller docs/ssh2.tag docs/SftpPoller.tag
QDX = qdx
DX_CLEANFILES = ${DOXYFILES} $(QLIB_TMP_DOXYFILES)

docs/qlib/Doxyfile.SftpPoller: docs/qlib/Doxyfile.tmpl
	$(QDX) -M=qlib/SftpPoller.qm:qlib/SftpPoller.qm.dox.h $< $@

docs/qlib/SftpPoller.qm.dox.h: qlib/SftpPoller.qm
	$(QDX) $< $@

docs/SftpPoller/html: docs/qlib/SftpPoller.qm.dox.h docs/qlib/Doxyfile.SftpPoller
	cd docs; $(DOXYGEN_CMD) qlib/Doxyfile.SftpPoller
	$(QDX) --post docs/SftpPoller/html/*html
	$(QDX) --post docs/SftpPoller/html/search/*html

docs/ssh2/html: $(DOXYFILES)
	cd docs; $(DOXYGEN_CMD) doxyfile;
	$(QDX) --post docs/ssh2/html/*html
	$(QDX) --post docs/ssh2/html/search/*html

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
