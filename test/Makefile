#
# Iddawc library
#
# Makefile used to build the tests
#
# Public domain, no copyright. Use at your own risk.
#

RHONABWY_INCLUDE=../include
RHONABWY_LOCATION=../src
RHONABWY_LIBRARY=$(RHONABWY_LOCATION)/librhonabwy.so
CC=gcc
CFLAGS+=-Wall -D_REENTRANT -I$(RHONABWY_INCLUDE) -DDEBUG -g -O0 $(CPPFLAGS)
LDFLAGS=-lc -lorcania -lyder -ljansson -lgnutls -lrhonabwy -L$(RHONABWY_LOCATION) $(shell pkg-config --libs check) -lulfius
VALGRIND_COMMAND=valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all
TARGET_JWK=jwk_core jwk_import jwk_export jwks_core
TARGET_JWS=jws_core jws_hmac jws_rsa jws_ecdsa jws_rsapss jws_json
TARGET_JWE=jwe_core jwe_rsa jwe_dir jwe_aesgcm jwe_kw jwe_pbes2 jwe_rsa_oaep jwe_ecdh jwe_json
TARGET_JWT=jwt_core jwt_sign jwt_encrypt jwt_nested
TARGET=$(TARGET_JWK) $(TARGET_JWS) $(TARGET_JWE) $(TARGET_JWT) misc cookbook
VERBOSE=0
MEMCHECK=0
CERT=cert

all: test

clean:
	rm -f *.o $(TARGET) *.log valgrind-*.txt $(CERT)/*.crt $(CERT)/*.key

$(CERT)/server.key:
	./$(CERT)/create-cert.sh

$(RHONABWY_LIBRARY): $(RHONABWY_LOCATION)/misc.c $(RHONABWY_LOCATION)/jwk.c $(RHONABWY_LOCATION)/jwks.c $(RHONABWY_LOCATION)/jws.c $(RHONABWY_LOCATION)/jwe.c $(RHONABWY_LOCATION)/jwt.c $(RHONABWY_INCLUDE)/rhonabwy.h
	cd $(RHONABWY_LOCATION) && $(MAKE) debug  $*

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test_%: % $(RHONABWY_LIBRARY) $(CERT)/server.key
	@if [ "$(VERBOSE)" = "0" ] && [ "$(MEMCHECK)" = "0" ]; then \
		LD_LIBRARY_PATH=$(RHONABWY_LOCATION):${LD_LIBRARY_PATH} ./run_test.sh ./$^; \
	elif [ "$(MEMCHECK)" = "0" ]; then \
		LD_LIBRARY_PATH=$(RHONABWY_LOCATION):${LD_LIBRARY_PATH} ./$^ ; \
	else \
		CK_FORK=no LD_LIBRARY_PATH=$(RHONABWY_LOCATION):${LD_LIBRARY_PATH} $(VALGRIND_COMMAND) ./$^ 2>valgrind-$@.txt; \
	fi

test-jwk: $(RHONABWY_LIBRARY) $(TARGET_JWK) test_jwk_core test_jwk_import test_jwk_export test_jwks_core

test-jws: $(RHONABWY_LIBRARY) $(TARGET_JWS) test_jws_core test_jws_hmac test_jws_rsa test_jws_ecdsa test_jws_rsapss test_jws_json

test-jwe: $(RHONABWY_LIBRARY) $(TARGET_JWE) test_jwe_core test_jwe_rsa test_jwe_dir test_jwe_aesgcm test_jwe_kw test_jwe_pbes2 test_jwe_rsa_oaep test_jwe_ecdh test_jwe_json

test-jwt: $(RHONABWY_LIBRARY) $(TARGET_JWT) test_jwt_core test_jwt_sign test_jwt_encrypt test_jwt_nested

test: $(RHONABWY_LIBRARY) $(TARGET) test_misc test_cookbook test-jwk test-jws test-jwe test-jwt

check: test
