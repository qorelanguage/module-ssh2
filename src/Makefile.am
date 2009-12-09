

SSH2_SOURCES = ssh2-module.cc SSH2Client.cc SFTPClient.cc


lib_LTLIBRARIES = ssh2.la
ssh2_la_SOURCES = $(SSH2_SOURCES)
ssh2_la_LDFLAGS = -module -avoid-version $(LIBSSH2_LDFLAGS) $(QORE_LDFLAGS)

AM_CPPFLAGS = $(LIBSSH2_CPPFLAGS) $(QORE_CPPFLAGS)

if COND_PROFILE
AM_CXXFLAGS = -g -pg
else
if COND_DEBUG
AM_CXXFLAGS = -g
endif
endif

#libtool: $(LIBTOOL_DEPS)
#	$(SHELL) ./config.status --recheck

install-exec-hook:
	mv $(DESTDIR)$(libdir)/ssh2.$(MODULE_SUFFIX) $(DESTDIR)$(libdir)/ssh2-api-$(MODULE_API).qmod
	rm -f $(DESTDIR)$(libdir)/ssh2.la

