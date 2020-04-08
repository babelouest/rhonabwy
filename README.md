# Rhonabwy - JWK, JWKS, JWS, JWE and JWT library

[![Build Status](https://travis-ci.com/babelouest/rhonabwy.svg?branch=master)](https://travis-ci.com/babelouest/rhonabwy)
![C/C++ CI](https://github.com/babelouest/rhonabwy/workflows/C/C++%20CI/badge.svg)

- Create, modify, parse, import or export [JSON Web Keys](https://tools.ietf.org/html/rfc7517) (JWK) and JSON Web Keys Set (JWKS)
- Create, modify, parse, validate or serialize [JSON Web Signatures](https://tools.ietf.org/html/rfc7515) (JWS)
- Create, modify, parse, validate or serialize [JSON Web Encryption](https://tools.ietf.org/html/rfc7516) (JWE) **limited and experimental!**
- Create, modify, parse, validate or serialize [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT)

JWT Relies on JWS and JWE functions, so it supports the same functionnalities as the other 2. JWT functionnalities also support nesting serilization (JWE nested in a JWS or the opposite).

- Supported Cryptographic Algorithms for Digital Signatures and MACs:

| "alg" Param Value | Digital Signature or MAC Algorithm | Supported |
|---|---|---|
| HS256 | HMAC using SHA-256 |YES|
| HS384 | HMAC using SHA-384 |YES|
| HS512 | HMAC using SHA-512 |YES|
| RS256 | RSASSA-PKCS1-v1_5 using SHA-256 |YES|
| RS384 | RSASSA-PKCS1-v1_5 using SHA-384 |YES|
| RS512 | RSASSA-PKCS1-v1_5 using SHA-512 |YES|
| ES256 | ECDSA using P-256 and SHA-256 |YES|
| ES384 | ECDSA using P-384 and SHA-384 |YES|
| ES512 | ECDSA using P-521 and SHA-512 |YES|
| PS256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |YES|
| PS384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |YES|
| PS512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |YES|
| none | No digital signature or MAC performed |YES|
| EdDSA | Digital Signature with Ed25519 Elliptic Curve |YES|

**JWE support is experimental and limited, please use with great caution!**

- Supported Encryption Algorithm (`enc`) for JWE payload encryption:

| "enc" Param Value | Content Encryption Algorithm | Supported |
|---|---|---|
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in Section 5.2.3 |YES|
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in Section 5.2.4 |YES|
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in Section 5.2.5 |YES|
| A128GCM | AES GCM using 128-bit key |YES|
| A192GCM | AES GCM using 192-bit key |NO|
| A256GCM | AES GCM using 256-bit key |YES|

- Supported Cryptographic Algorithms for Key Management:

| "alg" Param Value | Key Management Algorithm | Supported |
|---|---|---|
| RSA1_5 | RSAES-PKCS1-v1_5 | YES |
| RSA-OAEP | RSAES OAEP using default parameters | NO |
| RSA-OAEP-256 | RSAES OAEP using SHA-256 and MGF1 with SHA-256 | NO |
| A128KW | AES Key Wrap with default initial value using 128-bit key | NO |
| A192KW | AES Key Wrap with default initial value using 192-bit key | NO |
| A256KW | AES Key Wrap with default initial value using 256-bit key | NO |
| dir | Direct use of a shared symmetric key as the CEK | YES |
| ECDH-ES | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF | NO |
| ECDH-ES+A128KW | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" | NO |
| ECDH-ES+A192KW | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" | NO |
| ECDH-ES+A256KW | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" | NO |
| A128GCMKW | Key wrapping with AES GCM using 128-bit key | YES |
| A192GCMKW | Key wrapping with AES GCM using 192-bit key | NO |
| A256GCMKW | Key wrapping with AES GCM using 256-bit key | YES |
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping | NO |
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping | NO |
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping | NO |

# API Documentation

Documentation is available in the documentation page: [https://babelouest.github.io/rhonabwy/](https://babelouest.github.io/rhonabwy/)

Example program to parse and verify the signature of a JWT using its publick key in JWK format:

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

## Pre-compiled packages

You can install Rhonabwy with a pre-compiled package available in the [release pages](https://github.com/babelouest/rhonabwy/releases/latest/).

## Manual install

### Prerequisites

You must install [liborcania](https://github.com/babelouest/orcania), [libyder](https://github.com/babelouest/yder), [libulfius](https://github.com/babelouest/ulfius), [jansson](http://www.digip.org/jansson/), [zlib](https://www.zlib.net/) and [GnuTLS](https://www.gnutls.org/) first before building librhonabwy.

Orcania, Yder and Ulfius will be automatically installed if they are missing and you're using cmake.

GnuTLS is required, 3.6 minimum for ECDSA, Ed25519 (EDDSA) and RSA-PSS signatures.

### CMake - Multi architecture

[CMake](https://cmake.org/download/) minimum 3.5 is required.

Run the cmake script in a subdirectory, example:

```shell
$ git clone https://github.com/babelouest/rhonabwy.git
$ cd rhonabwy/
$ mkdir build
$ cd build
$ cmake ..
$ make && sudo make install
```

The available options for cmake are:
- `-DWITH_JOURNALD=[on|off]` (default `on`): Build with journald (SystemD) support
- `-BUILD_RHONABWY_TESTING=[on|off]` (default `off`): Build unit tests
- `-DINSTALL_HEADER=[on|off]` (default `on`): Install header file `rhonabwy.h`
- `-DBUILD_RPM=[on|off]` (default `off`): Build RPM package when running `make package`
- `-DCMAKE_BUILD_TYPE=[Debug|Release]` (default `Release`): Compile with debugging symbols or not
- `-DBUILD_STATIC=[on|off]` (default `off`): Compile static library
- `-DBUILD_RHONABWY_DOCUMENTATION=[on|off]` (default `off`): Build documentation with doxygen

### Good ol' Makefile

Download rhonabwy from github repository, compile and install.

```shell
$ git clone https://github.com/babelouest/rhonabwy.git
$ cd rhonabwy/src
$ make
$ sudo make install
```

By default, the shared library and the header file will be installed in the `/usr/local` location. To change this setting, you can modify the `DESTDIR` value in the `src/Makefile`.

Example: install rhonabwy in /tmp/lib directory

```shell
$ cd src
$ make && make DESTDIR=/tmp install
```

You can install Rhonabwy without root permission if your user has write access to `$(DESTDIR)`.
A `ldconfig` command is executed at the end of the install, it will probably fail if you don't have root permission, but this is harmless.
If you choose to install Rhonabwy in another directory, you must set your environment variable `LD_LIBRARY_PATH` properly.
