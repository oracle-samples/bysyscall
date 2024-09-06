# BPF-based system call bypass SPEC file

%define name        bysyscall
%define rel	    1 
%define release     %{rel}%{?dist}
%define version     0.1
%global _unitdir    /usr/lib/systemd/system/	

License:        GPLv2 WITH Linux-syscall-note
Name:           %{name}
Summary:        BPF-based system call bypass
Group:          Development/Tools
Requires:       libbpf >= 1.0
Requires:       libcap
BuildRequires:  libbpf-devel >= 1.0
BuildRequires:  libcap-devel
BuildRequires:	bpftool >= 4.18
BuildRequires:  clang >= 11
BuildRequires:  clang-libs >= 11
BuildRequires:  llvm >= 11
BuildRequires:  llvm-libs >= 11
BuildRequires:	python3-docutils
Version:        %{version}
Release:        %{release}
Source:         bysyscall-%{version}.tar.bz2
Prefix:         %{_prefix}

%description
Service consisting of daemon (bysyscall) and library
to support avoiding system call overhead in Linux via BPF
sharing of system call data with userspace.

%prep
%setup -q -n bysyscall-%{version}

%build
make

%install
rm -Rf %{buildroot}
%make_install

%files
%defattr(-,root,root)
%{_sbindir}/bysyscall
%{_unitdir}/bysyscall.service
%{_libdir}/libbysyscall.so
%{_mandir}/*/*

%license LICENSE.txt

%changelog
* Fri Jul 12 2024 Alan Maguire <alan.maguire@oracle.com> - 0.1-1
- Initial packaging support
