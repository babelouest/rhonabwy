# Rhonabwy - JWK library

[![Build Status](https://travis-ci.com/babelouest/rhonabwy.svg?branch=master)](https://travis-ci.com/babelouest/rhonabwy)
![C/C++ CI](https://github.com/babelouest/rhonabwy/workflows/C/C++%20CI/badge.svg)

Create, modify, parse or export Json Web Keys as defined in the [RFC 7517](https://tools.ietf.org/html/rfc7517).

```C
jwk_t * jwk;
const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
unsigned char output[2048];
size_t output_len = 2048;

if (r_init_jwk(&jwk) == RHN_OK) {
  if (r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str) == RHN_OK) {
    if (r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, output, &output_len) == RHN_OK) {
      printf("exported key:\n%.*s\n", output_len, output);
    }
  }
  r_free_jwk(jwk);
}
```

# Installation

## Pre-compiled packages

You can install Rhonabwy with a pre-compiled package available in the [release pages](https://github.com/babelouest/rhonabwy/releases/latest/).

## Manual install

### Prerequisites

You must install [liborcania](https://github.com/babelouest/orcania), [libyder](https://github.com/babelouest/yder), [libulfius](https://github.com/babelouest/ulfius), [jansson](http://www.digip.org/jansson/) and [GnuTLS](https://www.gnutls.org/) first before building librhonabwy. Orcania, Yder and Ulfius will be automatically installed if missing and you're using cmake.

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

# API Documentation

Documentation is available in the documentation page: [https://babelouest.github.io/rhonabwy/](https://babelouest.github.io/rhonabwy/)
