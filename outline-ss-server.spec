%global gomodulesmode GO111MODULE=auto

Name:		outline-ss-server
Version:	0.0.2
Release:	1%{?dist}
Summary:	Outline server
License:	MIT
URL:		http://stingr.net
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	golang
BuildRequires:  systemd
Requires(pre): shadow-utils
%{?systemd_requires}

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%description
Outline server but NOT IN DOCKER

%prep
%setup -q

%build
%gobuild -o bin/outline-ss-server github.com/Jigsaw-Code/outline-ss-server/cmd/outline-ss-server

%install

%{__install} -d $RPM_BUILD_ROOT%{_bindir}
%{__install} -v -D -t $RPM_BUILD_ROOT%{_bindir} bin/%{name}
%{__install} -d $RPM_BUILD_ROOT%{_unitdir}
%{__install} -v -D -t $RPM_BUILD_ROOT%{_unitdir} %{name}.service
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%{__install} -m 644 -T %{name}.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/outline-ss-server
%{__install} -m 644 -T config_example.yml %{buildroot}%{_sysconfdir}/outline-ss-server/config.yml

%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%config(noreplace) %{_sysconfdir}/outline-ss-server/config.yml

%changelog
