%define debug_package %{nil}
%global gomodulesmode GO111MODULE=auto

Name:		outline-ss-server
Version:	0.0.1
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
%systemd_post %{name}.service %{name}.socket outline-ss-metrics.socket

%preun
%systemd_preun %{name}.service %{name}.socket outline-ss-metrics.socket

%postun
%systemd_postun_with_restart %{name}.service %{name}.socket outline-ss-metrics.socket

%description
Outline server but NOT IN DOCKER

%prep
%setup -q

%build
export LDFLAGS=""
%gobuild -o bin/outline-ss-server github.com/Jigsaw-Code/outline-ss-server

%install

%{__install} -d $RPM_BUILD_ROOT%{_bindir}
%{__install} -v -D -t $RPM_BUILD_ROOT%{_bindir} bin/%{name}
%{__install} -d $RPM_BUILD_ROOT%{_unitdir}
%{__install} -v -D -t $RPM_BUILD_ROOT%{_unitdir} %{name}.service
%{__install} -v -D -t $RPM_BUILD_ROOT%{_unitdir} %{name}.socket
%{__install} -v -D -t $RPM_BUILD_ROOT%{_unitdir} outline-ss-metrics.socket
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%{__install} -m 644 -T %{name}.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/outline-ss-server
%{__install} -m 644 -T config_example.yml %{buildroot}%{_sysconfdir}/outline-ss-server/config.yml

%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%{_unitdir}/%{name}.socket
%{_unitdir}/outline-ss-metrics.socket
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%config(noreplace) %{_sysconfdir}/outline-ss-server/config.yml

%changelog
