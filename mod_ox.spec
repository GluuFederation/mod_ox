Name:           mod_ox
Version:        0.1
Release:        1%{?dist}
Summary:        Gluu Apache web plugin 
Group:          System Environment/Daemons 
License:        GPLv2 
URL:            http://www.gluu.org
Source0:        mod_ox-%{version}.tar.gz
BuildRequires:  libtool, httpd-devel, libcurl-devel, gcc-c++, openssl-devel
Requires:       httpd, memcached

%description
mod_ox is an access control apache module that 
enables an application server to support OpenID
Connect and UMA endpoints. mod_ox is written 
in C.



%prep
%setup -q


%build
chmod +x autogen.sh
./autogen.sh --with-apxs=/usr/sbin/apxs
#%configure
make 


%install
rm -rf $RPM_BUILD_ROOT
sudo make install 
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/httpd/modules/
cp src/.libs/mod_ox.so $RPM_BUILD_ROOT/%{_libdir}/httpd/modules/


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc ChangeLog AUTHORS README README.md NEWS COPYING INSTALL
%{_libdir}/httpd/modules/mod_ox.so


%changelog
* Thu Apr 16 2015 Adrian Alves <adrian@gluu.org> - 0.1-1
- Initial build
