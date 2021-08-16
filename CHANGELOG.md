# Rhonabwy Changelog

## 0.9.999990

- Use type `rhn_int_t` for integer property values instead of `int`
- Rename `r_jwks_import_from_str` to `r_jwks_import_from_json_str`
- Fix `kty` bugs with JWKs
- Fix bug with `r_jwe_compute_hmac_tag` to work with AES-CBC keys larger than 32 bytes (Thanks wbanga!)
- Force using `*_unsecure` functions to manage unsecured JWS or JWT with no signature
- Use Nettle's `ecc_point_mul` instead of GnuTLS' ECDH implementation
- Add macro `RHONABWY_CHECK_VERSION`

## 0.9.9999

- Support JSON format for JWE and JWS
- Improve JWKS import
- Improve `r_jwk_extract_pubkey` by copying properties `x5c`, `x5u`, `x5t` and `x5t#S256` to the public keys
- Fix `AES-GCM` encryption by removing padding
- Add `r_jws_set_properties`, `r_jwe_set_properties`, `r_jwt_set_properties`
- Add `r_jws_set_full_header_json_t`, `r_jws_set_full_header_json_str`
- Add `r_jwe_set_full_header_json_t`, `r_jwe_set_full_header_json_str`
- Add `r_jwt_set_full_header_json_t`, `r_jwt_set_full_header_json_str`
- Add `r_jwt_set_enc_cypher_key`, `r_jwt_get_enc_cypher_key`, `r_jwt_generate_enc_cypher_key`
- Add `r_jwt_set_enc_iv`, `r_jwt_get_enc_iv`
- Add `r_jwt_set_claims`
- Add `r_jwe_serialize_json_str`, `r_jwe_serialize_json_t`, `r_jwe_parse_json_str`, `r_jwe_parse_json_t`
- Add `r_jwe_compact_parsen`, `r_jwe_compact_parse` to parse JWE in compact mode
- Add `r_jwe_parse_json_str`, `r_jwe_parsen_json_str`, `r_jwe_parse_json_t` to parse JWE in JSON mode
- Improve `r_jwe_decrypt` and `r_jwe_decrypt_key` to support JWE serialized in General JSON format with multiple recipients
- Add `r_jws_serialize_json_str`, `r_jws_serialize_json_t`, `r_jws_parse_json_str`, `r_jws_parse_json_t`
- Add `r_jws_compact_parsen`, `r_jws_compact_parse` to parse JWS in compact mode
- Add `r_jws_parse_json_str`, `r_jws_parsen_json_str`, `r_jws_parse_json_t` to parse JWS in JSON mode
- Improve `r_jws_verify_signature` to support JWS serialized in General JSON format with multiple signatures
- Allow deflate payload in JWS with header property `{zip:"DEF"}`

## 0.9.999

- Remove `ES256K` signature algorithm support
- Implement `r_jwt_get_sig_kid`, `r_jwt_get_enc_kid`, `r_jwe_get_kid`, `r_jws_get_kid`

## 0.9.99

- Fix get symmetric key length
- Implement CEK `A128KW`, `A192KW` and `A256KW`
- Fix `r_library_info_json_t` output because `A***GCMKW` were supported before, not `A***KW`
- Implement CEK `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`
- Implement CEK `RSA-OAEP`, `RSA-OAEP-256`
- Implement CEK `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`
- Implement signature algorithm `ES256K`
- Add `r_jwk_import_from_password`
- Allow to disable ulfius if not needed

## 0.9.13

- Add `r_jwk_thumbprint`, thumbprint of a jwk_t based on the RFC 7638
- Test `x5c` validity on `r_jwk_is_valid`
- Breaking changes: refactor functions `r_jwk_import_from_x5u`, `r_jwks_export_to_gnutls_privkey` and `r_jwk_export_to_gnutls_privkey`
- Add `r_jwk_is_valid_x5u` to check the validity of a remote certificate
- Add `r_jwk_validate_x5c_chain` to validate the full `x5c` or `x5u` chain
- Bugfixes

## 0.9.12

- Add rnbyc manpage
- Small bugfixes

## 0.9.11

- Support `A192GCMKW` and `A192GCM` with GnuTLS >= 3.6.14
- Add command-line program `rnbyc` to generate, parse and serialize keys (JWK, JWKS) and tokens (JWT)
- Remove whitespaces on token parse
- Fix default header value `typ` in a JWT

## 0.9.10

- Do not overwrite header value `typ` in a JWT if one is already set
- Small bugfixes
- Add function `r_jwk_export_to_gnutls_crt`
- Add `x5c` when importing certificate
- Fix AES GCM encryption/decryption

## 0.9.9

- Fix JWE payload encryption with AES-GCM
- Add `x5u_flag` value `R_FLAG_IGNORE_REMOTE` to avoid downloading remote keys if not required
- Add functions `r_jwt_set_full_claims_json_str`, `r_jwt_get_type`, `r_jwa_alg_to_str`, `r_jwa_enc_to_str`
- Add API documentation
- Add support for key management algorithms `A128GCMKW` and `A256GCMKW`
- Add functions `r_jwt_decrypt_nested`, `r_jwt_verify_signature_nested`, `r_jwt_parsen`, `r_jwe_parsen` and `r_jws_parsen`
- Add function `r_jwt_validate_claims` to validate claims
- Add functions `r_jw[se]_add_keys_json_str`, `r_jw[se]_add_keys_json_t`, `r_jw[se]_add_keys_pem_der`, `r_jw[se]_add_keys_gnutls`, `r_jw[se]_add_key_symmetric`
- Add functions `r_jwt_add_[sign|enc]_keys_json_str`, `r_jwt_add_[sign|enc]_keys_json_t`, `r_jwt_add_[sign|enc]_keys_pem_der`, `r_jwt_add_[sign|enc]_keys_gnutls`, `r_jwt_add_[sign|enc]_key_symmetric`

## 0.9.8

- Add [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT) support
- Another set of refactoring

## 0.9.7

- Add [JSON Web Encryption](https://tools.ietf.org/html/rfc7516) (JWE) support
- Refactor functions names
- Add `r_library_info_json_t`, `r_library_info_json_str` and `r_free`

## 0.9.6

- Add [JSON Web Signature](https://tools.ietf.org/html/rfc7515) (JWS) support
- Add `r_jwk_import_from_x5u`, `r_jwk_import_from_symmetric_key`, `r_jwk_export_to_symmetric_key`
- Add `r_jwk_copy`, `r_jwk_equal`
- Add `r_jwks_copy`, `r_jwks_equal` and `r_jwks_empty`
- Rename functions `r_init_???` to `r_???_init` and `r_free_???` to r_???_free` to be consistent

## 0.9.5

- Add `r_jwks_get_by_kid`
- Rename flags `R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE` and `R_X5U_FLAG_FOLLOW_REDIRECT` to `R_FLAG_IGNORE_SERVER_CERTIFICATE` and `R_FLAG_FOLLOW_REDIRECT`

## 0.9.4

- Add `r_jwks_import_from_uri`
- Fix memory leaks

## 0.9.3

- Allow import jwks when jwks array is empty

## 0.9.2

- Parses `JWK` in `json_t *` or `char *` format
- Imports `gnutls`, `PEM` or `DER` keys to `JWK`
- Exports `JWK` to `json_t *`, `char *`, `gnutls`, `PEM` or `DER`
- Retrieves and extract keys in `x5c` or `x5u` fields
- Manages `JWKS` as a set of `JWK`
