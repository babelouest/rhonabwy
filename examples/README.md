# Rhonabwy examples use

These sample code show basic use of a JWT:
- Serialize a signed JWT
- Parse a serialized JWT signed and verify its signature
- Serialize an encrypted JWT
- Parse a serialized JWT encrypted and decrypt its content

Basic use of JWK and JWKS:
- Parse keys in different formats
- Insert these JWK in a JWKS structure
- Get a JWK from the JWKS by its index
- Get a JWK from the JWKS by its KID
- Get only the RSA keys of a JWKS with a simple search

## Build an example


```C
$ make # to build all files
$ make jwt-verify-es256 # to build one example
```
