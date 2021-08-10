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
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes
CLAIMS='{"plop":"grut"}'

all: rnbyc

all: ADDITIONALFLAGS= -O3

clean:
	rm -f *.o rnbyc valgrind-*.txt priv.jwks pub.jwks symkey.jwks token?.jwt

debug: ADDITIONALFLAGS=-DDEBUG -g -O0

debug: rnbyc

$(RHONABWY_LIBRARY):
	cd $(RHONABWY_LOCATION) && $(MAKE) debug

rnbyc: $(RHONABWY_LIBRARY) rnbyc.c
	$(CC) -o rnbyc $(CFLAGS) rnbyc.c $(LIBS)

install: rnbyc
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/man/man1/
	install -m755 rnbyc $(DESTDIR)/bin
	install -m644 rnbyc.1 $(DESTDIR)/man/man1/

uninstall:
	rm -f $(DESTDIR)/bin/rnbyc

manpage: rnbyc
	help2man ./rnbyc -s 1 -n "JWK and JWT parser and generator" > rnbyc.1

test: test-jwks test-serialize test-parse

test-jwks: debug
	# JWKS
	$(VALGRIND_COMMAND) ./rnbyc -h 2>valgrind-01.txt
	$(VALGRIND_COMMAND) ./rnbyc -v 2>valgrind-02.txt
	$(VALGRIND_COMMAND) ./rnbyc --error 2>valgrind-03.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -j -g RSA2048 -o priv.jwks -p pub.jwks 2>valgrind-04.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -f priv.jwks -f pub.jwks 2>valgrind-05.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -g oct256 -k "oct-1" -o symkey.jwks 2>valgrind-06.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -g EC256 -n 4 2>valgrind-07.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -g EC384 -a "plop" -e "grut" 2>valgrind-08.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -g Ed25519 2>valgrind-09.txt
	$(VALGRIND_COMMAND) ./rnbyc -j -g error 2>valgrind-10.txt || true
	cat priv.jwks | $(VALGRIND_COMMAND) ./rnbyc -j -i 2>valgrind-11.txt
	
test-serialize: debug
	# Serialize JWT
	$(VALGRIND_COMMAND) ./rnbyc -s 'error' 2>valgrind-20.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) 2>valgrind-21.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K symkey.jwks -a HS256 1>token0.jwt 2>valgrind-22.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P pub.jwks 2>valgrind-23.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P pub.jwks -l RSA1_5 1>token1.jwt 2>valgrind-24.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P priv.jwks -l RSA1_5 2>valgrind-25.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P pub.jwks -l RSA-OAEP 1>token4.jwt 2>valgrind-26.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P priv.jwks -l RSA-OAEP 2>valgrind-27.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P pub.jwks -l RSA-OAEP-256 1>token5.jwt 2>valgrind-28.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P priv.jwks -l RSA-OAEP-256 2>valgrind-29.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K priv.jwks 2>valgrind-30.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K priv.jwks -a RS256 1>token2.jwt 2>valgrind-31.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K pub.jwks -a RS256 2>valgrind-32.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K priv.jwks -P pub.jwks -a RS256 -l RSA1_5 1>token3.jwt 2>valgrind-33.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K priv.jwks -P pub.jwks -a RS256 -l RSA-OAEP 1>token6.jwt 2>valgrind-34.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K priv.jwks -P pub.jwks -a RS256 -l RSA-OAEP-256 1>token7.jwt 2>valgrind-35.txt
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -K token0.jwt 2>valgrind-36.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -s $(CLAIMS) -P token0.jwt 2>valgrind-37.txt || true

test-parse: debug
	# Parse JWT
	$(VALGRIND_COMMAND) ./rnbyc -t "error" 2>valgrind-40.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token0.jwt) 2>valgrind-41.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token1.jwt) 2>valgrind-42.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token1.jwt) -P pub.jwks 2>valgrind-43.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token1.jwt) -K priv.jwks 2>valgrind-44.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token2.jwt) 2>valgrind-45.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token2.jwt) -K priv.jwks 2>valgrind-46.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token2.jwt) -P pub.jwks 2>valgrind-47.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token3.jwt) 2>valgrind-48.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token3.jwt) -K priv.jwks 2>valgrind-49.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token3.jwt) -P pub.jwks 2>valgrind-50.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token3.jwt) -P pub.jwks -K priv.jwks 2>valgrind-51.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token4.jwt) 2>valgrind-52.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token4.jwt) -K priv.jwks 2>valgrind-53.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token4.jwt) -P pub.jwks 2>valgrind-54.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token4.jwt) -P pub.jwks -K priv.jwks 2>valgrind-55.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token5.jwt) 2>valgrind-56.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token5.jwt) -K priv.jwks 2>valgrind-57.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token5.jwt) -P pub.jwks 2>valgrind-58.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token5.jwt) -P pub.jwks -K priv.jwks 2>valgrind-59.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token6.jwt) 2>valgrind-60.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token6.jwt) -K priv.jwks 2>valgrind-61.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token6.jwt) -P pub.jwks 2>valgrind-62.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token6.jwt) -P pub.jwks -K priv.jwks 2>valgrind-63.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token7.jwt) 2>valgrind-64.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token7.jwt) -K priv.jwks 2>valgrind-65.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token7.jwt) -P pub.jwks 2>valgrind-66.txt || true
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token7.jwt) -P pub.jwks -K priv.jwks 2>valgrind-67.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token1.jwt) -P pub.jwks -H true -C false 2>valgrind-68.txt
	$(VALGRIND_COMMAND) ./rnbyc -t $(shell cat token1.jwt) -P pub.jwks -H false -C false 2>valgrind-69.txt
