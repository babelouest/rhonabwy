#
# rnbyc: Rhonabwy command-line tool
#
# Makefile used to build the software
#
# Copyright 2020 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation;
# version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
CC=gcc
RHONABWY_INCLUDE=../../include
RHONABWY_LOCATION=../../src
DESTDIR=/usr/local

CFLAGS+=-Wall -I$(RHONABWY_INCLUDE) $(ADDITIONALFLAGS) $(CPPFLAGS)
LIBS=-lc -lrhonabwy -lorcania -lyder -ljansson -lgnutls -L$(RHONABWY_LOCATION)
RHONABWY_LIBRARY=../../src/librhonabwy.so

all: rnbyc

all: ADDITIONALFLAGS= -O3

clean:
	rm -f *.o rnbyc valgrind.txt

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: rnbyc

$(RHONABWY_LIBRARY):
	cd $(RHONABWY_LOCATION) && $(MAKE) debug

rnbyc: $(RHONABWY_LIBRARY) rnbyc.c
	$(CC) -o rnbyc $(CFLAGS) rnbyc.c $(LIBS)

install: rnbyc
	install -m755 rnbyc $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/rnbyc
