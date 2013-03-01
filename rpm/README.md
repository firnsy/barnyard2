* Ensure you can build barnyard2
* Install rpmbuild
* cd <this-directory>
* Download the tarball
```
wget -O ~/rpmbuild/SOURCES/barnyard2-2-1.12.tar.gz https://github.com/firnsy/barnyard2/archive/v2-1.12.tar.gz
```
* Build the rpm: `rpmbuild -ba --with postgresql barnyard2.spec`
* Find it in ~/rpmbuild/RPMS/
