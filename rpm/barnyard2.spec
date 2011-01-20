# $Id$
# Snort.org's SPEC file for Snort

################################################################
# rpmbuild Package Options
# ========================
#       --with mysql
#               Builds a binary/package with support for MySQL.
#
#       --with postgresql
#               Builds a binary/package with support for PostgreSQL.
#
#       --with oracle
#               Builds a binary/package with support for Oracle.
#
# See pg 399 of _Red_Hat_RPM_Guide_ for rpmbuild --with and --without options.
################################################################

# Other useful bits
%define OracleHome /opt/oracle/OraHome1
%define SnortRulesDir %{_sysconfdir}/snort/rules
%define noShell /bin/false

# Default of no MySQL, but --with mysql will enable it
%define mysql 0
%{?_with_mysql:%define mysql 1}
# Default of no PostgreSQL, but --with postgresql will enable it
%define postgresql 0
%{?_with_postgresql:%define postgresql 1}

# Default of no Oracle, but --with oracle will enable it
%define oracle 0
%{?_with_oracle:%define oracle 1}

%define realname barnyard2


Summary: Snort Log Backend 
Name: barnyard2
Version: 1.9
Release: 1%{?dist}
License: GPL
Group: Applications/Internet
Source0: http://www.securixlive.com/download/barnyard2/%{name}-%{version}.tar.gz
Source2: %{name}.config
Source3: %{name}
Url: http://www.securixlive.com/barnyard2/
BuildRoot: %{_tmppath}/%{name}-%{version}-root


%description
Barnyard has 3 modes of operation:
One-shot, continual, continual w/ checkpoint.  In one-shot mode,
barnyard will process the specified file and exit.  In continual mode,
barnyard will start with the specified file and continue to process
new data (and new spool files) as it appears.  Continual mode w/
checkpointing will also use a checkpoint file (or waldo file in the
snort world) to track where it is.  In the event the barnyard process
ends while a waldo file is in use, barnyard will resume processing at
the last entry as listed in the waldo file.


%package mysql
Summary: barnyard2 with MySQL support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}
%if %{mysql}
Requires: mysql
BuildRequires: mysql-devel
%endif
%description mysql
barnyard2 binary compiled with mysql support.

%package postgresql
Summary: barnyard2 with PostgreSQL support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}
%if %{postgresql}
Requires: postgresql
BuildRequires: postgresql-devel
%endif
%description postgresql
barnyard2 binary compiled with postgresql support.

%package oracle
Summary: barnyard2 with Oracle support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}
%description oracle
barnyard2 binary compiled with Oracle support.

EXPERIMENTAL!!  I don't have a way to test this, so let me know if it works!
ORACLE_HOME=%{OracleHome}

%prep
%setup -q -n barnyard2-%{version}


%build

%configure --sysconfdir=%{_sysconfdir}/snort  \
   %if %{postgresql}
	--with-postgresql \
   %endif
   %if %{oracle}
	--with-oracle \
   %endif
   %if %{mysql}
	--with-mysql-libraries=/usr/%{_lib} \
   %endif
make

%install
%makeinstall 

%{__install} -d -p $RPM_BUILD_ROOT%{_sysconfdir}/{sysconfig,rc.d/init.d,snort} 
%{__install} -d -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/contrib
%{__install} -d -p $RPM_BUILD_ROOT%{_mandir}/man8
%{__install} -d -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc
%{__install} -m 644 etc/barnyard2.conf $RPM_BUILD_ROOT%{_sysconfdir}/snort/
%{__install} -m 644 $RPM_SOURCE_DIR/barnyard2.config $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/barnyard2
%{__install} -m 755 $RPM_SOURCE_DIR/barnyard2 $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d/barnyard2
%{__install} -m 644 doc/* $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc/

#clean up file that isn't where it should be
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/barnyard2.conf

%clean
if [ -d $RPM_BUILD_ROOT ] && [ "$RPM_BUILD_ROOT" != "/"  ] ; then
	rm -rf $RPM_BUILD_ROOT
fi

%files
%defattr(-,root,root)
%doc LICENSE doc/
%attr(755,root,root)       %{_bindir}/barnyard2
%attr(640,root,root) %config %{_sysconfdir}/snort/barnyard2.conf
%attr(755,root,root) %config %{_sysconfdir}/rc.d/init.d/barnyard2
%attr(644,root,root) %config %{_sysconfdir}/sysconfig/barnyard2

%changelog
* Mon Jan 10 2011 Jason Haar <jhaar@sf.net>
- updated spec file

* Sat Jan 16 2010 Ian Firns <firnsy@securixlive.com>
- barnyard2-1.8-beta2

* Mon Sep 13 2009 Tom McLaughlin <tmclaugh@sdf.lonestar.org>
- barnyard2-1.7-beta2

* Mon Apr 27 2009 Jason Haar <jhaar@users.sf.net> 
- Converted barnyard-0.2.0 .spec 

* Wed Sep 13 2006 Matthew Hall <matt@ecsc.co.uk> 0.2.0-3%{?dist}
- Apply Colin Grady's schema patches

* Tue Jun 06 2006 Fabien Bourdaire <fabien@ecsc.co.uk> 0.2.0-1%{?dist}
- Build for FireHat 2.0 

* Sat Sep 04 2004 Ralf Spenneberg <ralf@spenneberg.net>
- migrated to Barnyard 0.2.0 and Fedora Core 2

* Sun Apr 13 2003 Ralf Spenneberg <ralf@spenneberg.net>
- changed numbering scheme to reflect RH 8.0

* Wed Apr 09 2003 Ralf Spenneberg <ralf@spenneberg.net>
- based on Barnyard Final Release 0.1.0

* Tue Oct 22 2002 Ralf Spenneberg <ralf@spenneberg.de>
- based on Barnyard Release Candidate 3
- built on RedHat 8.0

* Wed Jul 24 2002 Ralf Spenneberg <ralf@spenneberg.de>
- based on Barnyard Release Candidate 2
- removed classification.config gen-msg.map sid-msg.map

* Sat Apr 06 2002 Ralf Spenneberg <ralf@spenneberg.de>
- Based on Barnyard Beta 4
- Created barnyard rpm

