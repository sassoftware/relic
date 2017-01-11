Name: relic
Version: 1.1.0
Release: 1%{?dist}
Summary: Secure package signing service
License: Apache 2.0
URL: http://github.com/sassoftware/relic
Source0: relic
Source1: relic.service
Source2: relic.socket
Source3: relic.yml
Group: Utilities/File
BuildArch: x86_64
Packager: Michael Tharp <michael.tharp@sas.com>

%define confdir %{_sysconfdir}/relic
%define systemddir %{_prefix}/lib/systemd/system

%description
Relic is a service for signing RPMs and other package types using a PKCS#11
Hardware Security Module (HSM) or other token. It also includes functions for
creating keys, manipulating tokens, and a client for accessing a remote signing
server.

%prep

%install
install -D %{SOURCE0} %{buildroot}%{_bindir}/relic
install -D %{SOURCE1} %{buildroot}%{systemddir}/relic.service
install -D %{SOURCE2} %{buildroot}%{systemddir}/relic.socket
install -D %{SOURCE3} %{buildroot}%{confdir}/relic.yml
mkdir -p %{buildroot}%{confdir}/{certs,server} %{buildroot}%{_localstatedir}/log/relic

%clean
rm -rf %{buildroot}

%files
%attr(0755,root,root)           %{_bindir}/relic
%attr(0644,root,root)           %{systemddir}/relic.service
%attr(0644,root,root)           %{systemddir}/relic.socket
%attr(0755,root,root) %dir      %{confdir}
%attr(0755,root,root) %dir      %{confdir}/certs
%attr(0640,root,relic) %config  %{confdir}/relic.yml
%attr(0750,root,relic) %dir     %{confdir}/server
%attr(0750,relic,relic) %dir    %{_localstatedir}/log/relic

%changelog

%pre
getent group relic >/dev/null || groupadd -r relic
getent passwd relic >/dev/null || useradd -r -g relic \
    -d / relic -s /sbin/nologin -c "relic package signing service"

%post
/bin/systemctl daemon-reload

%preun
if [ $1 -eq 0 ] ; then
        # removal, not upgrade
        systemctl --no-reload disable --now relic.service relic.socket > /dev/null 2>&1 || :
fi

%postun
if [ $1 -ge 1 ] ; then
        # upgrade, not removal
        systemctl try-restart relic.service >/dev/null 2>&1 || :
fi
