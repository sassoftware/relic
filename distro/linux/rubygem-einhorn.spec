%global gem_name einhorn
%if 0%{?rhel} == 6
%global gem_dir %(ruby -rubygems -e 'puts Gem::dir' 2>/dev/null)
%global gem_docdir %{gem_dir}/doc/%{gem_name}-%{version}
%global gem_cache %{gem_dir}/cache/%{gem_name}-%{version}.gem
%global gem_spec %{gem_dir}/specifications/%{gem_name}-%{version}.gemspec
%global gem_instdir %{gem_dir}/gems/%{gem_name}-%{version}
%endif

Summary: Language-independent shared socket manager
Name: rubygem-%{gem_name}
Version: 0.7.5
Release: 1%{?dist}
Group: Development/Languages
License: MIT
URL: https://github.com/stripe/einhorn
Source0: https://github.com/stripe/einhorn/archive/v%{version}.tar.gz

%if 0%{?rhel} == 6
Requires: ruby(abi) = 1.8
%else
Requires: ruby(release)
%endif
%if 0%{?fedora}
BuildRequires: rubygems-devel
%endif
BuildRequires: rubygems
BuildArch: noarch
Provides: rubygem(%{gem_name}) = %{version}
%description
Einhorn makes it easy to run (and keep alive) multiple copies of a single long-lived process. If that process is a server listening on some socket, Einhorn will open the socket in the master process so that it's shared among the workers.

%prep
%setup -n %{gem_name}-%{version}
tar -tzf %{SOURCE0} |cut -d/ -f2- |grep -v /$ >files
sed -i -e 's/git ls-files/cat files/' %{gem_name}.gemspec

%build
gem build %{gem_name}.gemspec

%gem_install

%install
mkdir -p %{buildroot}%{gem_dir}
cp -a ./%{gem_dir}/* %{buildroot}%{gem_dir}/

mkdir -p %{buildroot}%{_bindir}
cp -a ./%{_bindir}/* %{buildroot}%{_bindir}

%files
%{_bindir}/einhorn
%{_bindir}/einhornsh
%exclude %{gem_cache}
%doc %{gem_docdir}
%{gem_instdir}
%{gem_spec}
