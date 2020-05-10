%define mod_ver 1.4

%{?_datarootdir: %global mydatarootdir %_datarootdir}
%{!?_datarootdir: %global mydatarootdir /usr/share}

%define module_api %(qore --latest-module-api 2>/dev/null)
%define module_dir %{_libdir}/qore-modules
%global user_module_dir %{mydatarootdir}/qore-modules/

%if 0%{?sles_version}

%define dist .sles%{?sles_version}

%else
%if 0%{?suse_version}

# get *suse release major version
%define os_maj %(echo %suse_version|rev|cut -b3-|rev)
# get *suse release minor version without trailing zeros
%define os_min %(echo %suse_version|rev|cut -b-2|rev|sed s/0*$//)

%if %suse_version > 1010
%define dist .opensuse%{os_maj}_%{os_min}
%else
%define dist .suse%{os_maj}_%{os_min}
%endif

%endif
%endif

# see if we can determine the distribution type
%if 0%{!?dist:1}
%define rh_dist %(if [ -f /etc/redhat-release ];then cat /etc/redhat-release|sed "s/[^0-9.]*//"|cut -f1 -d.;fi)
%if 0%{?rh_dist}
%define dist .rhel%{rh_dist}
%else
%define dist .unknown
%endif
%endif

Summary: SSH2 module for Qore
Name: qore-ssh2-module
Version: %{mod_ver}
Release: 1%{dist}
License: LGPL
Group: Development/Languages
URL: http://www.qoretechnologies.com/qore
Source: http://prdownloads.sourceforge.net/qore/%{name}-%{version}.tar.bz2
#Source0: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: gcc-c++
BuildRequires: qore-devel >= 0.9
BuildRequires: qore
BuildRequires: libssh2-devel >= 1.1
BuildRequires: openssl-devel
Requires: /usr/bin/env
Requires: qore-module(abi)%{?_isa} = %{module_api}

%description
SSH2 module for the Qore Programming Language.


%if 0%{?suse_version}
%debug_package
%endif

%prep
%setup -q
./configure RPM_OPT_FLAGS="$RPM_OPT_FLAGS" --prefix=/usr --disable-debug

%build
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{module_dir}
mkdir -p $RPM_BUILD_ROOT/%{user_module_dir}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/qore-ssh2-module
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{module_dir}
%{user_module_dir}
%doc COPYING.LGPL COPYING.MIT README RELEASE-NOTES AUTHORS

%package doc
Summary: SSH2 module for Qore
Group: Development/Languages

%description doc
SSH2 module for the Qore Programming Language.

This RPM provides API documentation, test and example programs


%files doc
%defattr(-,root,root,-)
%doc docs/ssh2/ docs/SftpPoller/ test/

%changelog
* Sun May 10 2020 David Nichols <david@qore.org> - 1.4
- updated to version 1.4

* Sun Jan 26 2018 David Nichols <david@qore.org> - 1.3
- updated to version 1.3

* Thu Feb 2 2017 David Nichols <david@qore.org> - 1.2
- updated to version 1.2

* Thu Feb 2 2017 Pavel Kveton <pavel.kveton@qoretechnologies.org> - 1.1
- updated to version 1.1

* Sat Dec 7 2013 David Nichols <david@qore.org> - 1.0
- updated to version 1.0

* Fri Aug 16 2013 David Nichols <david@qore.org> - 0.9.9
- updated to version 0.9.9

* Mon Aug 5 2013 David Nichols <david@qore.org> - 0.9.8.1
- updated to version 0.9.8.1

* Tue Mar 12 2013 David Nichols <david@qore.org> - 0.9.8
- updated to version 0.9.8

* Fri Jun 8 2012 David Nichols <david@qore.org> - 0.9.7
- updated for qpp build

* Mon Dec 19 2011 David Nichols <david@qore.org> - 0.9.7
- updated to version 0.9.7

* Mon Dec 20 2010 David Nichols <david@qore.org>
- updated to version 0.9.6

* Wed Jun 16 2010 David Nichols <david@qore.org>
- updated to version 0.9.5

* Mon Jan 11 2010 David Nichols <david_nichols@users.sourceforge.net>
- initial spec file for ssh2 module
