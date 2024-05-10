# Rhonabwy

[![View on jwt.io](http://jwt.io/img/badge.svg)](https://jwt.io)
![C/C++ CI](https://github.com/babelouest/rhonabwy/workflows/C/C++%20CI/badge.svg)

## Disclaimer

This library is a personal project mostly developped by myself on my free time, with gracious help from users.

Several bugs and security issues were found and fixed in this library but there are probably more left. Nevertheless I have less time to work on it.

If you are looking for alternatives, there are multiple other JOSE libraries that can fit demanding needs, see [https://jwt.io/libraries](https://jwt.io/libraries) for example.

## Javascript Object Signing and Encryption (JOSE) library - JWK, JWKS, JWS, JWE and JWT

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
| ES256 | ECDSA using P-256 and SHA-256 |**YES**(1)|
| ES384 | ECDSA using P-384 and SHA-384 |**YES**(1)|
| ES512 | ECDSA using P-521 and SHA-512 |**YES**(1)|
| PS256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |**YES**(1)|
| PS384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |**YES**(1)|
| PS512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |**YES**(1)|
| none | No digital signature or MAC performed |**YES**|
| EdDSA | Digital Signature with Ed25519 Elliptic Curve |**YES**(1)|
| ES256K | Digital Signature with secp256k1 Curve Key |*NO*|

(1) GnuTLS 3.6 minimum is required for ECDSA, Ed25519 (EdDSA) and RSA-PSS signatures.

- Supported Encryption Algorithm (`enc`) for JWE payload encryption:

| "enc" Param Value | Content Encryption Algorithm | Supported |
|---|---|---|
| A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in Section 5.2.3 |**YES**|
| A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in Section 5.2.4 |**YES**|
| A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in Section 5.2.5 |**YES**|
| A128GCM | AES GCM using 128-bit key |**YES**|
| A192GCM | AES GCM using 192-bit key |**YES** (2)|
| A256GCM | AES GCM using 256-bit key |**YES**|

(2) GnuTLS 3.6.14 minimum is required for `A192GCM` enc.

- Supported Cryptographic Algorithms (`alg`) for Key Management:

| "alg" Param Value | Key Management Algorithm | Supported |
|---|---|---|
| RSA1_5 | RSAES-PKCS1-v1_5 |**YES**|
| RSA-OAEP | RSAES OAEP using default parameters |**YES**(3)|
| RSA-OAEP-256 | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |**YES**|
| A128KW | AES Key Wrap with default initial value using 128-bit key |**YES**(3)|
| A192KW | AES Key Wrap with default initial value using 192-bit key |**YES**(3)|
| A256KW | AES Key Wrap with default initial value using 256-bit key |**YES**(3)|
| dir | Direct use of a shared symmetric key as the CEK |**YES**|
| ECDH-ES | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |**YES**(4)|
| ECDH-ES+A128KW | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" |**YES**(4)|
| ECDH-ES+A192KW | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" |**YES**(4)|
| ECDH-ES+A256KW | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" |**YES**(4)|
| A128GCMKW | Key wrapping with AES GCM using 128-bit key |**YES**|
| A192GCMKW | Key wrapping with AES GCM using 192-bit key |**YES**(5)|
| A256GCMKW | Key wrapping with AES GCM using 256-bit key |**YES**|
| PBES2-HS256+A128KW | PBES2 with HMAC SHA-256 and "A128KW" wrapping |**YES**(5)|
| PBES2-HS384+A192KW | PBES2 with HMAC SHA-384 and "A192KW" wrapping |**YES**(5)|
| PBES2-HS512+A256KW | PBES2 with HMAC SHA-512 and "A256KW" wrapping |**YES**(5)|

(3) Nettle 3.4 minimum is required for RSA-OAEP and AES key Wrap

(4) Nettle 3.6 minimum is required for ECDH-ES

(5) GnuTLS 3.6.14 minimum is required for `A192GCMKW`, `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` and  `PBES2-HS512+A256KW` key wrapping algorithms.

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
  const char token[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ."                                     // Header
                       "eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ."                                         // Claims
                       "ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"; // Signature

  const char jwk_pubkey_ecdsa_str[] = "{"
                                        "\"kty\":\"EC\","
                                        "\"crv\":\"P-256\","
                                        "\"alg\":\"ES256\","
                                        "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
                                        "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
                                        "\"kid\":\"1\","
                                        "\"use\":\"sig\""
                                      "}";

  unsigned char output[2048];
  size_t output_len = 2048;
  jwk_t * jwk = NULL;
  jwt_t * jwt = NULL;
  char * claims;

  if ((jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str)) != NULL && (jwt = r_jwt_quick_parse(token, R_PARSE_NONE, 0)) != NULL) {
    if (r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, output, &output_len, 0) == RHN_OK) {
      printf("Exported key:\n%.*s\n", (int)output_len, output);
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        claims = r_jwt_get_full_claims_str(jwt);
        printf("Verified payload:\n%s\n", claims);
        r_free(claims);
      } else {
        fprintf(stderr, "Error r_jwt_verify_signature\n");
      }
    } else {
      fprintf(stderr, "Error r_jwk_export_to_pem_der\n");
    }
  } else {
    fprintf(stderr, "Error parsing\n");
  }
  r_jwk_free(jwk);
  r_jwt_free(jwt);

  return 0;
}
```

# Examples

Some example programs are available in the [examples](examples/) directory.

# Installation

Rhonabwy is available in the following distributions.

[![Packaging status](https://repology.org/badge/vertical-allrepos/rhonabwy.svg)](https://repology.org/project/rhonabwy/versions)

## Dependencies

Rhonabwy is based on [Nettle](https://www.lysator.liu.se/~nisse/nettle/), [GnuTLS](https://www.gnutls.org/), [Jansson](http://www.digip.org/jansson/), [zlib](https://www.zlib.net/), [libcurl](https://curl.haxx.se/libcurl/) and libsystemd (if possible), you must install those libraries first before building Rhonabwy.

You also need [check](https://libcheck.github.io/check/) and [Ulfius](https://github.com/babelouest/ulfius) to run the tests.

## Prerequisites

You need [Orcania](https://github.com/babelouest/orcania) and [Yder](https://github.com/babelouest/yder).

Those libraries are included in the package `rhonabwy-dev-full_{x.x.x}_{OS}_{ARCH}.tar.gz` in the [Latest release](https://github.com/babelouest/rhonabwy/releases/latest) page. If you're building with CMake, they will be automatically downloaded and installed if missing.

## Manual install

### CMake - Multi architecture

[CMake](https://cmake.org/download/) minimum 3.5 is required.

Last Rhonabwy release: [https://github.com/babelouest/rhonabwy/releases/latest/](https://github.com/babelouest/rhonabwy/releases/latest/)

Run the CMake script in a sub-directory, example:

```shell
$ cd <rhonabwy_source>
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
- `-DWITH_CURL=[on|off]` (default `on`): Use libcurl to download remote content

### Good ol' Makefile

Download Rhonabwy from GitHub repository, compile and install.

Last Rhonabwy release: [https://github.com/babelouest/rhonabwy/releases/latest/](https://github.com/babelouest/rhonabwy/releases/latest/)

```shell
$ cd rhonabwy/src
$ make
$ sudo make install
```

To disable curl library on build (to avoid its dependencies), you can pass the option `DISABLE_CURL=1` to the make command.

```shell
$ cd rhonabwy/src
$ make DISABLE_CURL=1
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
