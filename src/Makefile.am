## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = barnyard2

barnyard2_SOURCES = barnyard2.c barnyard2.h \
bounds.h \
checksum.h \
debug.c debug.h \
decode.c decode.h \
fatal.h \
ipv6_port.h \
generators.h \
log.c log.h \
log_text.c log_text.h \
map.c map.h \
mstring.c mstring.h \
parser.c parser.h \
pcap_pkthdr32.h \
plugbase.c plugbase.h \
rules.h \
sf_types.h \
spooler.c spooler.h \
strlcatu.c strlcatu.h \
strlcpyu.c strlcpyu.h \
timersub.h \
twofish.c twofish.h \
unified2.h \
util.c util.h

barnyard2_LDADD = output-plugins/libspo.a \
input-plugins/libspi.a \
sfutil/libsfutil.a

SUBDIRS = sfutil output-plugins input-plugins

INCLUDES = -Isfutil
