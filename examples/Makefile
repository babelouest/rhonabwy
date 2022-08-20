#
# Rhonabwy library
#
# Makefile used to build the examples
#
# License: MIT
#

RHONABWY_INCLUDE=../include
RHONABWY_LOCATION=../src
RHONABWY_LIBRARY=$(RHONABWY_LOCATION)/librhonabwy.so
CC=gcc
CFLAGS+=-Wall -I$(RHONABWY_INCLUDE) -DDEBUG -g -O0 $(CPPFLAGS)
LDFLAGS=-lc -L$(RHONABWY_LIBRARY) -lrhonabwy
TARGET=jwt-sign-rs256 jwt-verify-es256 jwt-encrypt-pbes2-h256 jwt-decrypt-rsa-oaep256 jwks-parse-extract

all: build

clean:
	rm -f $(TARGET)

$(RHONABWY_LIBRARY): $(RHONABWY_LOCATION)/misc.c $(RHONABWY_LOCATION)/jwk.c $(RHONABWY_LOCATION)/jwks.c $(RHONABWY_LOCATION)/jws.c $(RHONABWY_LOCATION)/jwe.c $(RHONABWY_LOCATION)/jwt.c $(RHONABWY_INCLUDE)/rhonabwy.h
	cd $(RHONABWY_LOCATION) && $(MAKE) debug $*

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build: $(TARGET)
