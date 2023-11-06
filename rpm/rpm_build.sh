rm -f /root/rpmbuild/SOURCES/v2-1.14.tar.gz
( cd /root/projects && tar cfzv /root/rpmbuild/SOURCES/v2-1.14.tar.gz barnyard2-1.14 )
rpmbuild -ba --target x86_64 barnyard2.spec
