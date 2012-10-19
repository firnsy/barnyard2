## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

EXTRA_DIST = barnyard2.conf 

install-data-am:
	test -e $(DESTDIR)$(sysconfdir) || \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	test -e $(DESTDIR)$(sysconfdir)/barnyard2.conf || \
		$(INSTALL_DATA) -m 600 $(top_srcdir)/etc/barnyard2.conf \
		$(DESTDIR)$(sysconfdir)/barnyard2.conf
