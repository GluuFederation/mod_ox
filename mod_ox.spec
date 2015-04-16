Name:           mod_ox
Version:        0.1
Release:        1%{?dist}
Summary:        Gluu Apache web plugin 
Group:          System Environment/Daemons 
License:        GPLv2 
URL:            http://www.gluu.org
Source0:        mod_ox-%{version}.tar.gz
BuildRequires:  libtool, httpd-dev, libcurl-devel, gcc-c++, openssl-devel
Requires:       memcached

%description
mod_ox is an access control apache module that 
enables an application server to support OpenID
Connect and UMA endpoints. mod_ox is written 
in C.



%prep
%setup -q


%build
chmod +x autogen.sh
./autogen.sh --with-apxs
%configure
make 


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc



%changelog
