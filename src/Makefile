#
# Rhonabwy Library
#
# Makefile used to build the software
#
# Copyright 2020-2021 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation;
# version 2.1 of the License.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this library.	If not, see <http://www.gnu.org/licenses/>.
#
PROJECT_NAME=rhonabwy
PROJECT_DESCRIPTION=JWK, JWKS, JWS, JWE and JWT library
PROJECT_BUGREPORT_PATH=https://github.com/babelouest/rhonabwy/issues
PKGCONF_REQ=
PKGCONF_REQ_PRIVATE=
RHONABWY_INCLUDE=../include
PKGCONFIG_FILE=../librhonabwy.pc
PKGCONFIG_TEMPLATE=../librhonabwy.pc.in
DESTDIR=/usr/local
CONFIG_FILE=$(RHONABWY_INCLUDE)/rhonabwy-cfg.h
CONFIG_TEMPLATE=$(RHONABWY_INCLUDE)/rhonabwy-cfg.h.in
CC=gcc
CFLAGS+=-c -pedantic -std=gnu99 -fPIC -Wall -Werror -Wextra -D_REENTRANT -I$(RHONABWY_INCLUDE) $(ADDITIONALFLAGS) $(CPPFLAGS)
LIBS=-L$(DESTDIR)/lib -lc -lorcania -lyder $(LULFIUS) -ljansson -lgnutls -lz $(LDFLAGS)
SONAME=-soname
OBJECTS=jwk.o jwks.o jws.o jwe.o jwt.o misc.o
OUTPUT=librhonabwy.so
VERSION_MAJOR=0
VERSION_MINOR=9
VERSION_PATCH=999990

ifdef ECDHFLAG
ENABLE_ECDH=1
else
ENABLE_ECDH=0
endif

ifdef DISABLE_CURL
R_WITH_CURL=0
else
R_WITH_CURL=1
LULFIUS=-lcurl
endif

.PHONY: all clean

all: release

$(CONFIG_FILE):
	@cp $(CONFIG_TEMPLATE) $(CONFIG_FILE)
	@echo Config file $(CONFIG_FILE) generated
	@sed -i -e 's/$${PROJECT_VERSION}/$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_MAJOR}/$(VERSION_MAJOR)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_MINOR}/$(VERSION_MINOR)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_PATCH}/$(VERSION_PATCH)/g' $(CONFIG_FILE)        
	@sed -i -e 's/$${PROJECT_VERSION_NUMBER}/$(shell printf '%02d' $(VERSION_MAJOR))$(shell printf '%02d' $(VERSION_MINOR))$(shell printf '%02d' $(VERSION_PATCH))/g' $(CONFIG_FILE)        
	@if [ "$(ENABLE_ECDH)" = "1" ]; then \
		sed -i -e 's/\#cmakedefine R_ECDH_ENABLED/\#define R_ECDH_ENABLED/g' $(CONFIG_FILE); \
		echo "ECDH SUPPORT    ENABLED"; \
	else \
		sed -i -e 's/\#cmakedefine R_ECDH_ENABLED/\/* #undef R_ECDH_ENABLED *\//g' $(CONFIG_FILE); \
		echo "ECDH SUPPORT    DISABLED"; \
	fi
	@if [ "$(R_WITH_CURL)" = "1" ]; then \
		sed -i -e 's/\#cmakedefine R_WITH_CURL/\#define R_WITH_CURL/g' $(CONFIG_FILE); \
		echo "USE ULFIUS      ENABLED"; \
	else \
		sed -i -e 's/\#cmakedefine R_WITH_CURL/\/* #undef R_WITH_CURL *\//g' $(CONFIG_FILE); \
		echo "USE ULFIUS      DISABLED"; \
	fi

$(PKGCONFIG_FILE):
	@cp $(PKGCONFIG_TEMPLATE) $(PKGCONFIG_FILE)
	@echo Pkgconfig file $(PKGCONFIG_FILE) generated
	@sed -i -e 's#@CMAKE_INSTALL_PREFIX@#$(DESTDIR)#g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@CMAKE_INSTALL_LIBDIR@/lib/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@CMAKE_INSTALL_INCLUDEDIR@/include/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PROJECT_NAME@/$(PROJECT_NAME)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PROJECT_DESCRIPTION@/$(PROJECT_DESCRIPTION)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's|@PROJECT_BUGREPORT_PATH@|$(PROJECT_BUGREPORT_PATH)|g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@LIBRARY_VERSION@/$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PKGCONF_REQ@/$(PKGCONF_REQ)/g' $(PKGCONFIG_FILE)
	@sed -i -e 's/@PKGCONF_REQ_PRIVATE@/$(PKGCONF_REQ_PRIVATE)/g' $(PKGCONFIG_FILE)

target: $(OBJECTS)

%.o: %.c $(RHONABWY_INCLUDE)/rhonabwy.h
	$(CC) $(CFLAGS) $<

librhonabwy.so: $(CONFIG_FILE) $(OBJECTS)
	$(CC) -shared -fPIC -Wl,$(SONAME),$(OUTPUT) -o $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(OBJECTS) $(LIBS)
	ln -sf $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(OUTPUT)

clean:
	rm -f *.o *.so *.a $(OUTPUT) $(OUTPUT).* $(PKGCONFIG_FILE) $(CONFIG_FILE)

install: all $(PKGCONFIG_FILE)
	install $(OUTPUT).$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH) $(DESTDIR)/lib
	mkdir -p $(DESTDIR)/lib/pkgconfig/ $(DESTDIR)/include
	install -m644 $(PKGCONFIG_FILE) $(DESTDIR)/lib/pkgconfig/
	install -m644 $(RHONABWY_INCLUDE)/rhonabwy.h $(DESTDIR)/include
	install -m644 $(CONFIG_FILE) $(DESTDIR)/include
	-ldconfig $(DESTDIR)/lib

uninstall:
	rm -f $(DESTDIR)/lib/$(OUTPUT) $(DESTDIR)/lib/librhonabwy.a
	rm -f $(DESTDIR)/lib/$(OUTPUT).*
	rm -f $(DESTDIR)/include/rhonabwy.h
	rm -f $(DESTDIR)/include/$(CONFIG_FILE)
	rm -f $(DESTDIR)/lib/pkgconfig/$(PKGCONFIG_FILE)

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: librhonabwy.so

release: ADDITIONALFLAGS=-O3

release: librhonabwy.so
