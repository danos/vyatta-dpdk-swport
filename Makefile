#
# Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

CFLAGS += $(shell pkg-config --cflags libdpdk) -fPIC -march=native
LDFLAGS += $(shell pkg-config --libs libdpdk) -Wl,--version-script=vyatta-dpdk-swport.map
LIBDIR := $(DESTDIR)/usr/lib/$(shell dpkg-architecture -qDEB_BUILD_MULTIARCH)
INCDIR := $(DESTDIR)/usr/include/vyatta-dataplane
CFILES := src/vyatta_swport.c
OFILES := $(patsubst %.c,%.o,$(CFILES))
NAME := libvyatta-dpdk-swport.so.1
SYMLINK := libvyatta-dpdk-swport.so
PKGCONF := vyatta-dpdk-swport.pc
VERSION := $(shell dpkg-parsechangelog --show-field Version)

all: $(NAME) $(PKGCONF)

%.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

$(NAME): $(OFILES)
	$(CC) -pthread $(CFLAGS) -o $@ $(OFILES) \
            -shared -Wl,-z,relro -Wl,-z,undef -Wl,-soname,$@ $(LDFLAGS)

clean:
	rm -f $(OFILES)
	rm -f $(NAME) 
	rm -f $(PKGCONF)

install: $(NAME) $(PKGCONF)
	install -d $(LIBDIR)/pkgconfig
	install -d $(INCDIR)
	install -m 0755 $(NAME) $(LIBDIR)
	ln -rsf $(LIBDIR)/$(NAME) $(LIBDIR)/$(SYMLINK)
	install -m 0644 include/* $(INCDIR)
	install -m 0644 $(PKGCONF) $(LIBDIR)/pkgconfig

$(PKGCONF):
	sed -e "s|@version@|${VERSION}|g" \
		-e "s|@libdir@|${LIBDIR}|g" \
		-e "s|@includedir@|${INCDIR}|g" \
		$(PKGCONF).in > $(PKGCONF)
