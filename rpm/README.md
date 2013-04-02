* Ensure you can build barnyard2
* Install rpmbuild (sudo yum install libtool libpcap-devel postgresql-devel make rpm-build)
* Download and build:
```
# Download the tarball
mkdir -p ~/rpmbuild/SOURCES/
wget -O ~/rpmbuild/SOURCES/barnyard2-1.12.tar.gz https://github.com/firnsy/barnyard2/archive/v2-1.12.tar.gz
wget https://raw.github.com/firnsy/barnyard2/master/rpm/barnyard2.spec

# Build the rpm:
rpmbuild -ba --with postgresql barnyard2.spec
```
* Find it in ~/rpmbuild/RPMS/
