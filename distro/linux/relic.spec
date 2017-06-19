Name: relic
Version: 1.0
Release: 1%{?dist}
Summary: Client to the relic secure package signing service
License: Apache 2.0
URL: http://github.com/sassoftware/relic
Source0: relic.tar
Group: Utilities/File
BuildArch: x86_64

%package server
Requires: %{name} = %{version}-%{release}
Requires: rubygem-einhorn
Summary: Secure package signing service
Group: Utilities/File

%package audit
Requires: %{name} = %{version}-%{release}
Summary: Audit client for relic
Group: Utilities/File

%define confdir %{_sysconfdir}/relic
%define systemddir %{_prefix}/lib/systemd/system

%description
Relic is a service for signing RPMs and other package types using a PKCS#11
Hardware Security Module (HSM) or other token. It also includes functions for
creating keys, manipulating tokens, and a client for accessing a remote signing
server.

%description server
This package contains the relic signing service and startup files.

%description audit
relic-audit subscribes to audit events on one or more AMQP message brokers and
saves records to a database or log file.

%prep
%autosetup

%install
mkdir -p %{buildroot}%{systemddir}
mkdir -p %{buildroot}%{confdir}/{certs,server,audit.d}
mkdir -p %{buildroot}%{_localstatedir}/log/relic{,-audit}
install -D relic %{buildroot}%{_bindir}/relic
install -D relic-einhorn %{buildroot}%{_libexecdir}/relic-einhorn
install -D relic.yml %{buildroot}%{confdir}/relic.yml
install -D audit.yml %{buildroot}%{confdir}/audit.yml
install -D logrotate.conf %{buildroot}%{_sysconfdir}/logrotate.d/relic
install relic.service relic-audit.service %{buildroot}%{systemddir}/

%clean
rm -rf %{buildroot}

%files
%attr(0755,root,root)           %{_bindir}/relic
%attr(0755,root,root) %dir      %{confdir}

%files server
%attr(0755,root,root)           %{_libexecdir}/relic-einhorn
%attr(0644,root,root)           %{systemddir}/relic.service
%attr(0755,root,root) %dir      %{confdir}/certs
%attr(0640,root,relic) %config(noreplace) %{confdir}/relic.yml
%attr(0750,root,relic) %dir     %{confdir}/server
%attr(0750,relic,relic) %dir    %{_localstatedir}/log/relic
%attr(0644,root,root)           %{_sysconfdir}/logrotate.d/relic

%files audit
%attr(0644,root,root)           %{systemddir}/relic-audit.service
%attr(0755,root,root) %dir      %{confdir}/audit.d
%attr(0644,root,root) %config(noreplace) %{confdir}/audit.yml
%attr(0750,relic-audit,relic-audit) %dir    %{_localstatedir}/log/relic-audit

%changelog

%pre server
getent group relic >/dev/null || groupadd -r relic
getent passwd relic >/dev/null || useradd -r -g relic \
    -d / relic -s /sbin/nologin -c "relic package signing service"

%pre audit
getent group relic-audit >/dev/null || groupadd -r relic-audit
getent passwd relic-audit >/dev/null || useradd -r -g relic-audit \
    -d / relic-audit -s /sbin/nologin -c "relic audit service"

%post server
/bin/systemctl daemon-reload

%post audit
/bin/systemctl daemon-reload

%preun server
if [ $1 -eq 0 ] ; then
        # removal, not upgrade
        systemctl --no-reload disable --now relic.service > /dev/null 2>&1 || :
fi

%preun audit
if [ $1 -eq 0 ] ; then
        systemctl --no-reload disable --now relic-audit.service > /dev/null 2>&1 || :
fi

%postun server
if [ $1 -ge 1 ] ; then
        # upgrade, not removal
        # try-reload not available on centos 7 unfortunately
        if systemctl -q is-active relic.service; then
                systemctl reload relic.service >/dev/null 2>&1 || :
        fi
fi

%postun audit
if [ $1 -ge 1 ] ; then
        # upgrade, not removal
        systemctl try-restart relic-audit.service >/dev/null 2>&1 || :
fi
