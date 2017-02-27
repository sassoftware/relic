Name: relic
Version: 1.0
Release: 1%{?dist}
Summary: Secure package signing service
License: Apache 2.0
URL: http://github.com/sassoftware/relic
Source0: https://jenkins2.unx.sas.com/view/Licensing/job/licensing-relic/lastSuccessfulBuild/artifact/build/relic-redhat-%{version}.tar.gz
Group: Utilities/File
BuildArch: x86_64

%define confdir %{_sysconfdir}/relic
%define systemddir %{_prefix}/lib/systemd/system

%description
Relic is a service for signing RPMs and other package types using a PKCS#11
Hardware Security Module (HSM) or other token. It also includes functions for
creating keys, manipulating tokens, and a client for accessing a remote signing
server.

%prep
%autosetup -n relic-redhat-%{version}

%install
mkdir -p %{buildroot}%{systemddir}
mkdir -p %{buildroot}%{confdir}/{certs,server,audit.d}
mkdir -p %{buildroot}%{_localstatedir}/log/relic{,-audit}
install -D relic %{buildroot}%{_bindir}/relic
install -D relic-audit %{buildroot}%{_bindir}/relic-audit
install -D relic.yml %{buildroot}%{confdir}/relic.yml
install -D audit.yml %{buildroot}%{confdir}/audit.yml
install relic.service relic.socket relic-audit.service %{buildroot}%{systemddir}/

%clean
rm -rf %{buildroot}

%files
%attr(0755,root,root)           %{_bindir}/relic
%attr(0755,root,root)           %{_bindir}/relic-audit
%attr(0644,root,root)           %{systemddir}/relic.service
%attr(0644,root,root)           %{systemddir}/relic-audit.service
%attr(0644,root,root)           %{systemddir}/relic.socket
%attr(0755,root,root) %dir      %{confdir}
%attr(0755,root,root) %dir      %{confdir}/audit.d
%attr(0755,root,root) %dir      %{confdir}/certs
%attr(0640,root,relic) %config  %{confdir}/relic.yml
%attr(0640,root,relic) %config  %{confdir}/audit.yml
%attr(0750,root,relic) %dir     %{confdir}/server
%attr(0750,relic,relic) %dir    %{_localstatedir}/log/relic
%attr(0750,relic-audit,relic-audit) %dir    %{_localstatedir}/log/relic-audit

%changelog

%pre
getent group relic >/dev/null || groupadd -r relic
getent passwd relic >/dev/null || useradd -r -g relic \
    -d / relic -s /sbin/nologin -c "relic package signing service"
getent group relic-audit >/dev/null || groupadd -r relic-audit
getent passwd relic-audit >/dev/null || useradd -r -g relic-audit \
    -d / relic-audit -s /sbin/nologin -c "relic audit service"

%post
/bin/systemctl daemon-reload

%preun
if [ $1 -eq 0 ] ; then
        # removal, not upgrade
        systemctl --no-reload disable --now relic.service relic.socket relic-audit.service > /dev/null 2>&1 || :
fi

%postun
if [ $1 -ge 1 ] ; then
        # upgrade, not removal
        systemctl try-restart relic.service >/dev/null 2>&1 || :
        systemctl try-restart relic-audit.service >/dev/null 2>&1 || :
fi
