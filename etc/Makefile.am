## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

EXTRA_DIST = barnyard2.conf 

install-data-am:
	test -e $(sysconfdir)/barnyard2.conf || install -m 600 $(top_srcdir)/etc/barnyard2.conf $(sysconfdir)
