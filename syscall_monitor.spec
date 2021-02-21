Summary: syscall monitor utils
Name: syscall_monitor
Version: 1.0
Release: 0.0
License: GPL
Vendor: wang Qiang <wang1131695576@outlook.com>

BuildRequires: audit
BuildRequires: make gcc
BuildRequires: kernel-devel
BuildRequires: kernel-headers

Requires(post): kmod
Requires(preun): systemd
Requires(postun): systemd kmod



%description
monitor syscall when process like stopping

%prep
rm -rf syscall-monitor
git clone https://github.com/frankQAQ-wang/syscall-monitor.git
%build
cd syscall-monitor
make
%install
cd syscall-monitor
mkdir -p $RPM_BUILD_ROOT/{usr/sbin,usr/bin,etc/bash_completion.d/,usr/lib/systemd/system,usr/lib/modules/$(uname -r)/sysmon}
cp module/syscall_monitor.ko $RPM_BUILD_ROOT/usr/lib/modules/$(uname -r)/sysmon
cp process/sysmond $RPM_BUILD_ROOT/usr/sbin/
cp process/sysmonctl $RPM_BUILD_ROOT/usr/bin/
cp process/sysmonctl.cmp $RPM_BUILD_ROOT/etc/bash_completion.d/sysmonctl
cp sysmon.service $RPM_BUILD_ROOT/usr/lib/systemd/system/
%post
depmod
systemctl daemon-reload
systemctl enable sysmon
systemctl start sysmon
%preun
systemctl stop sysmon
systemctl disable sysmon
%postun
systemctl daemon-reload
depmod

%files
%attr(644,root,root) /etc/bash_completion.d/sysmonctl
%attr(644,root,root) /usr/lib/systemd/system/sysmon.service
%attr(644,root,root) /usr/lib/modules/*/sysmon/syscall_monitor.ko
%attr(755,root,root) /usr/sbin/sysmond
%attr(755,root,root) /usr/bin/sysmonctl
