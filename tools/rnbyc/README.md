# rnbyc: Rhonabwy command-line tool

Copyright 2020-2021 Nicolas Mora <mail@babelouest.org>

This program is free software; you can redistribute it and/or modify it under the terms of the GPL3 License.

## Overview

This command-line program can be used to:

- Generate and/or parse keys and output the result in a JWKS or a public/private pair of JWKS files.
- Parse, decrypt, and/or verify signature of a JWT, using given key
- Serialize a JWT, the JWT can be signed, encrypted or nested

## Options

Options available:

```shell
-j --jwks
	Action: JWKS, parse or generate keys and output JWKS
-g --generate <type>
	Generate a key pair or a symmetric key
	<type> - values available:
	RSA[key size] (default key size: 4096), EC256, EC384, EC521, Ed25519, oct[key size] (default key size: 128 bits)
-i --stdin
	Reads key to parse from stdin
-f --in-file
	Reads key to parse from a file
-k --key-id
	Specifies the key-id to add to the current key
-a --alg
	Action: JWKS - Specifies the alg value to add to the current key
	Action: Serialize - Specifies the alg value to sign the token
-e --enc
	Specifies the enc value to encrypt the token (default A128CBC)
-l --enc-alg
	Specifies the encryption algorithm for key management of the token
-o --out-file
	Specifies the output file for the private keys (or all the keys if no public file is specified) in the JWKS
-p --out-file-public
	Specifies the output file for the public keys in the JWKS
-n --indent
	JWKS output spaces indentation: 0 is compact mode, default is 2 spaces indent
-x --split
	Split JWKS output in public and private keys
-t --parse-token
	Action: Parse token
-s --serialize-token
	Action: serialize given claims in a token
-H --header
	Display header of a parsed token, default false
-C --claims
	Display claims of a parsed token, default true
-P --public-key
	Specifies the public key to for key management encryption or signature verification
	Public key must be in JWKS format and can be either a JWKS string or a path to a JWKS file
-K --private-key
	Specifies the private key to for key management decryption or signature generation
	Public key must be in JWKS format and can be either a JWKS string or a path to a JWKS file
-W --password
	Specifies the password for key management encryption/decryption using PBES2 alg or signature generation/verification using HS alg
-u --x5u-flags
	Set x5u flags to retrieve online certificate, values available are:
		cert: ignore server certificate errors (self-signed, expired, etc.)
		follow: follow jwks_uri redirection if any
		values can be contatenated, e.g. --x5u-flags cert,follow
-v --version
	Print rnbyc's current version
-h --help
	Print this message
-d --debug
	Display debug messages
```

## Examples

Here are some examples on how to use rnbyc

### Parses a X509 certificate file in PEM format and outputs a JWKS

```shell
$ rnbyc -j -f /path/to/certificate.crt
{
  "keys": [
    {
      "kty": "RSA",
      "n": "AKe2TcuJhv-r1BBl7Z-TqgxILj70q7ckFcDLNS_2ksBR-UkCnrI8UsBBfejZFDCztt29x-AmWJanMsCv01kZsasOVwWSwteg9BAPmFTsP6LjNH2Lye-vTJ06uG_4yHDt3csgaypf_1HSq89u3jtxEXb-52ECjR-gMAIWFju9aPG2dTP9SjUuhN8RhWdHnQxqEbpaecYTDinWJ8qddtHeL1HbbkHQaKOeh2s0Zi8ylp65QkHp892n9n3yvtmspYhjoC0tpj4JZSCcSmfGoCBvJSqhh7OYOWtAmLADUgyIt5tXw2AQjEgZ1bs-SZrCjBFS9yBH7_nDHRO9eSxBFZbhLZG8wauML74hdyZAXYLHtV537tdO50pKScBK-_NYhIocSqlzFshgKkvz3OxdfX3zKr-Nrrbjv55dT6woY-wBl876t_ntQhJyGV-4MboRuO7OAlNdaeumoAAoUHX6zQ7xAdTyEU-p8CEkZbOH6V95jtCQ3le2d6oAWU2E7LRgyiQQ1w",
      "e": "AQAB",
      "kid": "yy4hDdTpyRau82hjUv-JWFwjGfqAxBs8qVH87fgdcOE",
      "x5c": [
        "MIIEJjCCAo6gAwIBAgIUSbEidpFdnCljFBk1LLqjmYfax3owDQYJKoZIhvcNAQELBQAwLDEVMBMGA1UEAwwMZ2xld2x3eWRfd3d3MRMwEQYDVQQKEwpiYWJlbG91ZXN0MB4XDTIwMDUzMDE3MDk1NVoXDTIyMDQzMDE3MDk1NVowLDEVMBMGA1UEAwwMZ2xld2x3eWRfd3d3MRMwEQYDVQQKEwpiYWJlbG91ZXN0MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp7ZNy4mG/6vUEGXtn5OqDEguPvSrtyQVwMs1L/aSwFH5SQKesjxSwEF96NkUMLO23b3H4CZYlqcywK/TWRmxqw5XBZLC16D0EA+YVOw/ouM0fYvJ769MnTq4b/jIcO3dyyBrKl//UdKrz27eO3ERdv7nYQKNH6AwAhYWO71o8bZ1M/1KNS6E3xGFZ0edDGoRulp5xhMOKdYnyp120d4vUdtuQdBoo56HazRmLzKWnrlCQenz3af2ffK+2ayliGOgLS2mPgllIJxKZ8agIG8lKqGHs5g5a0CYsANSDIi3m1fDYBCMSBnVuz5JmsKMEVL3IEfv+cMdE715LEEVluEtkbzBq4wvviF3JkBdgse1Xnfu107nSkpJwEr781iEihxKqXMWyGAqS/Pc7F19ffMqv42utuO/nl1PrChj7AGXzvq3+e1CEnIZX7gxuhG47s4CU11p66agAChQdfrNDvEB1PIRT6nwISRls4fpX3mO0JDeV7Z3qgBZTYTstGDKJBDXAgMBAAGjQDA+MAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUUktENOwWOjO+sDBnvyWGDmCVxQUwDQYJKoZIhvcNAQELBQADggGBAJI6N3YtfkdfZNv3NWPKGnSn7dXwFETk0PiBsURIv4B8DWxT4mtUGT6/x+ElVB//TIaK7P93uhmpZCM3DxMQCy8jR/ecA54cA+mAjQD2/4tBf2oRG34SfOsIW11ZPwfm3DRh95kZbjC4xCKGlCn6t/df/4CCDaLYPMReemy/3FynFxIO95hNV2+CPt1vzcDZfCkoBUoeN9b5q8nIXenajs3Cj4+w5Moiju0Ucg8X7tsTEjVre5M4Vtbc8BtvBOZ/qAS0Di2G1OXjkHBTMdIkcp/cHnm2f8rW3MljWowHSdu2dVYnkTyeqme1q7c613zdKp8YR0JR/ICxlwQQcHoxrFpok3dk//CVdDewcFG1KztJm458ppikOts9zjtvxlSU4diff3ofXdvVvjoYRkL1+89enCavLsaSqapUS8Jzz6BZrIUGWMDRoUZzRY41xLc2hqmABQSKNI8d1NE1sxmENS/YePS909uD4C9KRWY0z5x6/+LkRPRP0IkhHZXcMp+bIw=="
      ]
    }
  ]
}
```

### Generates a ECDSA 256 bits key pair in a single JWKS and specifies the kid

```shell
$ rnbyc -j -g ec256 -k key1
{
  "keys": [
    {
      "kty": "EC",
      "x": "AN64-jEEs_0zQfuUJI-9Rik6hkYMrIDHzSUfT3jlrA-q",
      "y": "APmN2Hk4SxihpBzQAZRVHlpxJS6O_0q-k8JgCcN-hj88",
      "d": "BvC2P98BQsYiMHqPqqfsguXe2Vl92JmZnB6Pj0jTHsM",
      "crv": "P-256",
      "kid": "key-1",
      "alg": "ES256"
    },
    {
      "kty": "EC",
      "x": "AN64-jEEs_0zQfuUJI-9Rik6hkYMrIDHzSUfT3jlrA-q",
      "y": "APmN2Hk4SxihpBzQAZRVHlpxJS6O_0q-k8JgCcN-hj88",
      "crv": "P-256",
      "kid": "key-1",
      "alg": "ES256"
    }
  ]
}
```

### Parses a X509 private and public key files, generates a RSA 2048 key pair, and generates a 384 bits oct key, specifies the kid, the alg and the enc value, and splits the result into separate public and private JWKS.

```shell
$ rnbyc -j -f /path/to/certificate.crt
```

### Serializes a claims into signed JWT using RS256 alg and the specified private RSA key

```shell
$ rnbyc -s '{"aud":"xyz123","nonce":"nonce1234"}' -K priv.jwks -a RS256
```

### Serializes a claims into encrypted JWT using RSA1_5 alg, A256GCM enc and the specified public RSA key

```shell
$ rnbyc -s '{"aud":"xyz123","nonce":"nonce1234"}' -P pub.jwks -l RSA1_5 -e A256GCM
```

### Serializes a claims into encrypted JWT using PBES2-HS256+A128KW alg, A256GCM enc and the specified password

```shell
$ rnbyc -s '{"aud":"xyz123","nonce":"nonce1234"}' -W ThisIsThePassword -l PBES2-HS256+A128KW -e A256GCM
```

### Serializes a claims into nested JWT using RS256 signatur alg, RSA1_5 encryption alg, A256GCM enc and the specified public RSA key

```shell
$ rnbyc -s '{"aud":"xyz123","nonce":"nonce1234"}' -P pub.jwks -l RSA1_5 -e A256GCM -K priv.jwks -a RS256
```

### Parses a signed JWT to display claims

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJZcXVEeXlNamJvWU4xSkU2TWVQQWVORk5lTzJUN0thTDcydTRQcUYySTgifQ.eyJhdWQiOiJ4eXoxMjMiLCJub25jZSI6Im5vbmNlMTIzNCJ9.ARpZkLEDAMLDfbcdowyHeb7fg00U06NHRnXCn2SiDMy1wE9SGJT3br-til-BXHJ0HoiSZ4HGhgTEaRf317bhy8jhHHVSJngWSncBxXzNe8cJ3A-bXZJBeTo5wKmxcwqgen744rAG5cmszC0KYR0rAXoqFDgPxxmw-EiFvgOfwn-COUS_ofdruc3BPyK-wuMNFMjqaQMi5RnTPuQZkSmmJkHGoRkAl0oafkKVvOL9VvO29It_b5Sk6uAHViczSY7A2v9oCQvGXML6aN8fqqQivM3ArCxWaDRXrWzO22SL3Qy11blrrCh-JJmKTcrHUjx2Ozacy1ecVXwc__h9Kn_AtA
```

### Parses a signed JWT to display header only

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJZcXVEeXlNamJvWU4xSkU2TWVQQWVORk5lTzJUN0thTDcydTRQcUYySTgifQ.eyJhdWQiOiJ4eXoxMjMiLCJub25jZSI6Im5vbmNlMTIzNCJ9.ARpZkLEDAMLDfbcdowyHeb7fg00U06NHRnXCn2SiDMy1wE9SGJT3br-til-BXHJ0HoiSZ4HGhgTEaRf317bhy8jhHHVSJngWSncBxXzNe8cJ3A-bXZJBeTo5wKmxcwqgen744rAG5cmszC0KYR0rAXoqFDgPxxmw-EiFvgOfwn-COUS_ofdruc3BPyK-wuMNFMjqaQMi5RnTPuQZkSmmJkHGoRkAl0oafkKVvOL9VvO29It_b5Sk6uAHViczSY7A2v9oCQvGXML6aN8fqqQivM3ArCxWaDRXrWzO22SL3Qy11blrrCh-JJmKTcrHUjx2Ozacy1ecVXwc__h9Kn_AtA -H true -C false
```

### Parses a signed JWT to verify the signature and display claims

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjJZcXVEeXlNamJvWU4xSkU2TWVQQWVORk5lTzJUN0thTDcydTRQcUYySTgifQ.eyJhdWQiOiJ4eXoxMjMiLCJub25jZSI6Im5vbmNlMTIzNCJ9.ARpZkLEDAMLDfbcdowyHeb7fg00U06NHRnXCn2SiDMy1wE9SGJT3br-til-BXHJ0HoiSZ4HGhgTEaRf317bhy8jhHHVSJngWSncBxXzNe8cJ3A-bXZJBeTo5wKmxcwqgen744rAG5cmszC0KYR0rAXoqFDgPxxmw-EiFvgOfwn-COUS_ofdruc3BPyK-wuMNFMjqaQMi5RnTPuQZkSmmJkHGoRkAl0oafkKVvOL9VvO29It_b5Sk6uAHViczSY7A2v9oCQvGXML6aN8fqqQivM3ArCxWaDRXrWzO22SL3Qy11blrrCh-JJmKTcrHUjx2Ozacy1ecVXwc__h9Kn_AtA -P pub.jwks
```

### Parses an encrypted JWT to decrypt its content and display claims

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiMllxdUR5eU1qYm9ZTjFKRTZNZVBBZU5GTmVPMlQ3S2FMNzJ1NFBxRjJJOCJ9.cK5l8oRaOqCYB1G-z06B2F9aJupLIrKHcwjOn-WhImMn9Vy5kF0USVIPHVHDoUcOISG7uA_tfHM0bkWyb-wWu4UW3jrWLAWltGOQQZEbLKYrLEJFmqqBeMKJ01_3bpbRYIRrqB96N50HJKu9EH_8c5OL3d-m9QIhNh37wa7Vu63tZgLlYVEHoGVOZF0eBWV-fWH-My76Sp5ZA3XsR5BjmbDOzzutFWlucMEjWS8GeSM5ibkkTjSJCsY7PpghQA8LUKshLY4PifwyBmlc51GzKOTkFBtxeDx4ixAMSsTdc72sN9-zjr733jp3DAwaxfjQC5QxDGeAI1DG53iEqD8Y0g.I_Ei-Ioi-IH3MENa.fJfo6fssSJ-6LNZHwlYH2t0Rg4w1vKTLrMo54QswuRenCfoBOBcUaIBD6Y-Id_Ms.AeiVJjZFR-w-c5wiyBmcGw -K priv.jwks
```

### Parses an encrypted JWT to decrypt its content and display claims using a password

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiJOQjVuUnJlUko1cyIsInAyYyI6NDA5NiwiZW5jIjoiQTI1NkdDTSJ9.w0v_Pu139guygbyCQExbb_AJJlEAFRikDT81JOyVBXeWrMSlcDgWRg.b6-7JtOdIzvbUTY4.j-R30XnnMUxu7A7ZE1zExv9cRZq5Cg9FbASqgvGyVSPPsrfg.KKsXDsnNDSmvz_atWvuNGg -W ThisIsThePassword
```

### Parses a nested JWT to decrypt its content, verify signature and display header and claims

```shell
$ rnbyc -t eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiMllxdUR5eU1qYm9ZTjFKRTZNZVBBZU5GTmVPMlQ3S2FMNzJ1NFBxRjJJOCJ9.r-benEaVi8BRAKPDGTJl48L0LqjnDCZbC_krSbyjpy-iN0Fhli0R724uBkr69aU6L1MceK2RtS30FwsUrOx8ySJmC3FuEf4UgqGsrlAwa0PnkIgxCKld5x1YRKIkOL01HXYgjnlU45PCtknnST7f4TWbBh24_gsKQXoiC1_viqavsk0aGBkLnAfmIAuEgMvroBqcX8S9XaLW8z3MzZ9u-9CyeqYSjQns_FlCBqqDDQTmf7WPZf0Yr3TxzdDvHR60Cf0cS2kbMh6bYAI6IO7rh63mALuxt64W2on-Gf8zAPx8MSkiiRkDqQurqgxGDZLOFD4xF3R7bm2yF6GtSnfbAQ.lVRM-vp5sP5pmT8C.1AdxJPtT3RDktUm_bZeWok6gWJBBm5_lm33eKM5kF4wGj_C9Q2jtoXgdUeaw7cojQdCVCIAFZs67dOfPl8Hj0SnJq0RGV2XTpmmWeuFglyQKur7H65SLzoQf6MHJVlrYon3S5TD6d82WvmJfOh2gNGcyo9Yj1fLxwr3DLGmV_5YZa46lqiT00VPKbmuLYO_wm4kw4A6juQCqholzX1htzd-L4IMMc3FdWwtTu7rCT7Fg9acRXB0F-Bhjmc3s9nLJNFysfdG2qxvWcgK8-uin0gePUm1kpGGEoUHMoXQfc0vA8cs2QlIzXgMKpSHM-hYkVWtyMFnRP0rbql0GysEwGS70Tmmbp378XnpHyZnF9ZSIwvyPkeefVWG4GsiguL2yBKZ4QFzWCkyKGvXg4MfAJnsY7xGfP7QSTlfStPcnslij0xAVw0ilzSW8q3TpEUsDO3bpbENgIxQEjFoHFzm3vycB-071RYxEeNHHki00f3nl_VQRVhiOWMD6mYsf_dx2R7vmu-wF_mc-gzO_jk5lmQG9ZW0dWI-ofp9aFqayjLTQ_IbSofLlIHhvW5tlrV0DOdgMpfcYH6h0rA9T7ur9GRmcRPDr9G1MAY8vmpKhYlk38sOaql5W3icjjdXJLo9KTuk6FJ1Hed8ZcYiXgLlA5nhmEtfGTahL4VHgwVwWlFc.H-esLtlVR9GM9Hn4EnmxBQ -K priv.jwks -P pub.jwks -H true
```
