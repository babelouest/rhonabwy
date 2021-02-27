# Rhonabwy - JWK, JWKS, JWS, JWE and JWT library

[![View on jwt.io](http://jwt.io/img/badge.svg)](https://jwt.io)
![C/C++ CI](https://github.com/babelouest/rhonabwy/workflows/C/C++%20CI/badge.svg)

- Create, modify, parse, import or export [JSON Web Keys](https://tools.ietf.org/html/rfc7517) (JWK) and JSON Web Keys Set (JWKS)
- Create, modify, parse, validate or serialize [JSON Web Signatures](https://tools.ietf.org/html/rfc7515) (JWS)
- Create, modify, parse, validate or serialize [JSON Web Encryption](https://tools.ietf.org/html/rfc7516) (JWE)
- Create, modify, parse, validate or serialize [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT)

JWT Relies on JWS and JWE functions, so it supports the same functionalities as the other 2. JWT functionalities also support nesting serialization (JWE nested in a JWS or the opposite).

- Supported Cryptographic Algorithms (`alg`) for Digital Signatures and MACs:

| "alg" Param Value | Digital Signature or MAC Algorithm | Supported |
|---|---|---|
| HS256 | HMAC using SHA-256 |**YES**|
| HS384 | HMAC using SHA-384 |**YES**|
| HS512 | HMAC using SHA-512 |**YES**|
| RS256 | RSASSA-PKCS1-v1_5 using SHA-256 |**YES**|
| RS384 | RSASSA-PKCS1-v1_5 using SHA-384 |**YES**|
| RS512 | RSASSA-PKCS1-v1_5 using SHA-512 |**YES**|
| ES256 | ECDSA using P-256 and SHA-256 |**YES** (1)|
| ES384 | ECDSA using P-384 and SHA-384 |**YES** (1)|
| ES512 | ECDSA using P-521 and SHA-512 |**YES** (1)|
| PS256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |**YES** (1)|
| PS384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |**YES** (1)|
| PS512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |**YES** (1)|
| none | No digital signature or MAC performed |**YES**|
| EdDSA | Digital Signature with Ed25519 Elliptic Curve |**YES** (1)|
| ES256K | Digital Signature with secp256k1 Curve Key |**YES** (1)|

(1) GnuTLS 3.6 minimum is required for ECDSA, Ed25519 (EDDSA), ES256K and RSA-PSS signatures.

- Supported Encryption Algorithm (`enc`) for JWE payload encryption:

| "enc" Param Value | Content Encryption Algorithm | Supported |
|---|---|---|
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in Section 5.2.3 |**YES**|
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in Section 5.2.4 |**YES**|
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in Section 5.2.5 |**YES**|
| A128GCM | AES GCM using 128-bit key |**YES**|
| A192GCM | AES GCM using 192-bit key |**YES** (2)|
| A256GCM | AES GCM using 256-bit key |**YES**|

- Supported Cryptographic Algorithms (`alg`) for Key Management:

| "alg" Param Value | Key Management Algorithm | Supported |
|---|---|---|
| RSA1_5 | RSAES-PKCS1-v1_5 |**YES**|
| RSA-OAEP | RSAES OAEP using default parameters |**YES**|
| RSA-OAEP-256 | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |**YES**|
| A128KW | AES Key Wrap with default initial value using 128-bit key |**YES**|
| A192KW | AES Key Wrap with default initial value using 192-bit key |**YES**|
| A256KW | AES Key Wrap with default initial value using 256-bit key |**YES**|
| dir | Direct use of a shared symmetric key as the CEK |**YES**|
| ECDH-ES | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |*NO*|
| ECDH-ES+A128KW | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" |**YES**(3)|
| ECDH-ES+A192KW | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" |**YES**(3)|
| ECDH-ES+A256KW | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" |**YES**(3)|
| A128GCMKW | Key wrapping with AES GCM using 128-bit key |**YES**|
| A192GCMKW | Key wrapping with AES GCM using 192-bit key |**YES**(2)|
| A256GCMKW | Key wrapping with AES GCM using 256-bit key |**YES**|
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping |**YES**|
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping |**YES**|
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping |**YES**|

(2) GnuTLS 3.6.14 minimum is required for `A192GCM` enc and `A192GCMKW` key wrapping algorithm.

(3) GnuTLS 3.6 minimum with [FIPS140-2 mode enabled](https://www.gnutls.org/manual/html_node/FIPS140_002d2-mode.html)

## ECDH-ES support

As for now, ECDH-ES key management support is implemented, but experimental. You need GnuTLS with [FIPS140-2 mode enabled](https://www.gnutls.org/manual/html_node/FIPS140_002d2-mode.html) and please know that memory leaks have been detected but can't be fixed for now.

# rnbyc, Rhonabwy command-line tool 

This command-line program can be used to:

- Generate and/or parse keys and output the result in a JWKS or a public/private pair of JWKS files.
- Parse, decrypt, and/or verify signature of a JWT, using given key
- Serialize a JWT, the JWT can be signed, encrypted or nested

Example commands to generate a RSA2048 key pair, serialize a JWT signed with the private key, then parse the serialized token and verifies the signature with the public key.

```shell
$ rnbyc -j -g RSA2048 -o priv.jwks -p pub.jwks
$ rnbyc -s '{"iss":"https://rhonabwy.tld","aud":"abcxyz1234"}' -K priv.jwks -a RS256
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImVNdnI3bktBX2I5QUI4NGpMU05zTFFKZHRmdHpadnllV2M1V0VVMjhnRFkifQ.eyJpc3MiOiJodHRwczovL3Job25hYnd5LnRsZCIsImF1ZCI6ImFiY3h5ejEyMzQifQ.j6v-yxcWvHhyLIc-r3Nzn5rCF9yeJJzgyLSHW_10wREfckspbzf8UTof5Zsrwg8JvKNlJ4Tt4ZffJC4BkkehdBYXPrgcfq9NtvNYsRmAdiNJhOXtZCU9j9X89j2xhY7pRBgWENI9c3730cmAUgaC-IUKsoNRw_dd-eboyrgYKIzUCYRnuwqDB31T2oUSVjy6CckoenyoeHJhHg-x384G-g4ovP1l-L4YpjgCyr6BR8mjBFwHU56MP6hNN299HpUd56usQ3vMn7z5hL6QqE92qz-SsJBySrv8whLWjjN9J4Wq5g3_R7Qw00x60bFnuCDhPBjg3EPXXGqlI0x0vwgwHw
$ rnbyc -P pub.jwks -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImVNdnI3bktBX2I5QUI4NGpMU05zTFFKZHRmdHpadnllV2M1V0VVMjhnRFkifQ.eyJpc3MiOiJodHRwczovL3Job25hYnd5LnRsZCIsImF1ZCI6ImFiY3h5ejEyMzQifQ.j6v-yxcWvHhyLIc-r3Nzn5rCF9yeJJzgyLSHW_10wREfckspbzf8UTof5Zsrwg8JvKNlJ4Tt4ZffJC4BkkehdBYXPrgcfq9NtvNYsRmAdiNJhOXtZCU9j9X89j2xhY7pRBgWENI9c3730cmAUgaC-IUKsoNRw_dd-eboyrgYKIzUCYRnuwqDB31T2oUSVjy6CckoenyoeHJhHg-x384G-g4ovP1l-L4YpjgCyr6BR8mjBFwHU56MP6hNN299HpUd56usQ3vMn7z5hL6QqE92qz-SsJBySrv8whLWjjN9J4Wq5g3_R7Qw00x60bFnuCDhPBjg3EPXXGqlI0x0vwgwHw
Token signature verified
{
  "iss": "https://rhonabwy.tld",
  "aud": "abcxyz1234"
}
```

Check its [documentation](tools/rnbyc/README.md)

# API Documentation

Documentation is available in the documentation page: [https://babelouest.github.io/rhonabwy/](https://babelouest.github.io/rhonabwy/)

Example program to parse and verify the signature of a JWT using its public key in JWK format:

```C
/**
 * To compile this program run:
 * gcc -o demo_rhonabwy demo_rhonabwy.c -lrhonabwy
 */
#include <stdio.h>
#include <rhonabwy.h>

int main(void) {
  const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ."
  "eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ."
  "ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A";
  
  const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";
  
  unsigned char output[2048];
  size_t output_len = 2048;
  jwk_t * jwk;
  jwt_t * jwt;
  char * claims;

  if (r_jwk_init(&jwk) == RHN_OK) {
    if (r_jwt_init(&jwt) == RHN_OK) {
      if (r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str) == RHN_OK) {
        if (r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, output, &output_len, 0) == RHN_OK) {
          printf("Exported key:\n%.*s\n", (int)output_len, output);
          if (r_jwt_parse(jwt, token, 0) == RHN_OK) {
            if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
              claims = r_jwt_get_full_claims_str(jwt);
              printf("Verified payload:\n%s\n", claims);
              r_free(claims);
            } else {
              fprintf(stderr, "Error r_jwt_verify_signature\n");
            }
          } else {
            fprintf(stderr, "Error r_jwt_parse\n");
          }
        } else {
          fprintf(stderr, "Error r_jwk_export_to_pem_der\n");
        }
      } else {
        fprintf(stderr, "Error r_jwk_import_from_json_str\n");
      }
      r_jwt_free(jwt);
    } else {
      fprintf(stderr, "Error r_jwt_init\n");
    }
    r_jwk_free(jwk);
  } else {
    fprintf(stderr, "Error r_jwk_init\n");
  }
  return 0;
}
```

# Installation

Rhonabwy is available in the following distributions.

[![Packaging status](https://repology.org/badge/vertical-allrepos/rhonabwy.svg)](https://repology.org/project/rhonabwy/versions)

## Dependencies

Rhonabwy is based on [GnuTLS](https://www.gnutls.org/), [Jansson](http://www.digip.org/jansson/), [zlib](https://www.zlib.net/), [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/), [libcurl](https://curl.haxx.se/libcurl/) and libsystemd (if possible), you must install those libraries first before building Rhonabwy.

## Prerequisites

You need [Orcania](https://github.com/babelouest/orcania), [Yder](https://github.com/babelouest/yder), [Ulfius](https://github.com/babelouest/ulfius).

Those libraries are included in the package `rhonabwy-dev-full_{x.x.x}_{OS}_{ARCH}.tar.gz` in the [Latest release](https://github.com/babelouest/rhonabwy/releases/latest) page. If you're building with CMake, they will be automatically downloaded and installed if missing.

## Pre-compiled packages

You can install Rhonabwy with a pre-compiled package available in the [release pages](https://github.com/babelouest/rhonabwy/releases/latest/).

## Manual install

### CMake - Multi architecture

[CMake](https://cmake.org/download/) minimum 3.5 is required.

Run the CMake script in a sub-directory, example:

```shell
$ git clone https://github.com/babelouest/rhonabwy.git
$ cd rhonabwy/
$ mkdir build
$ cd build
$ cmake ..
$ make && sudo make install
```

The available options for CMake are:
- `-DWITH_JOURNALD=[on|off]` (default `on`): Build with journald (SystemD) support
- `-BUILD_RHONABWY_TESTING=[on|off]` (default `off`): Build unit tests
- `-DINSTALL_HEADER=[on|off]` (default `on`): Install header file `rhonabwy.h`
- `-DBUILD_RPM=[on|off]` (default `off`): Build RPM package when running `make package`
- `-DCMAKE_BUILD_TYPE=[Debug|Release]` (default `Release`): Compile with debugging symbols or not
- `-DBUILD_STATIC=[on|off]` (default `off`): Compile static library
- `-DBUILD_RHONABWY_DOCUMENTATION=[on|off]` (default `off`): Build documentation with doxygen
- `-DWITH_ECDH=[on|off]` (default `off`): Allow ECDH-ES for JWE key exchange management

### Good ol' Makefile

Download Rhonabwy from GitHub repository, compile and install.

```shell
$ git clone https://github.com/babelouest/rhonabwy.git
$ cd rhonabwy/src
$ make
$ sudo make install
```

To enable ECDH-ES key exchange management, you can pass the option `ECDHFLAG=1` to the make command.

```shell
$ cd rhonabwy/src
$ make ECDHFLAG=1
$ sudo make install
```

By default, the shared library and the header file will be installed in the `/usr/local` location. To change this setting, you can modify the `DESTDIR` value in the `src/Makefile`.

Example: install Rhonabwy in /tmp/lib directory

```shell
$ cd src
$ make && make DESTDIR=/tmp install
```

You can install Rhonabwy without root permission if your user has write access to `$(DESTDIR)`.
A `ldconfig` command is executed at the end of the install, it will probably fail if you don't have root permission, but this is harmless.
If you choose to install Rhonabwy in another directory, you must set your environment variable `LD_LIBRARY_PATH` properly.
