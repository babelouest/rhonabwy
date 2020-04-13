# Rhonabwy Changelog

## 0.9.9

- Fix JWE payload encryption with AES-GCM
- Add `x5u_flag` value `R_FLAG_IGNORE_REMOTE` to avoid downloading remote keys if not required
- Add functions `r_jwt_set_full_claims_json_str`, `r_jwt_get_type`, `jwa_alg_to_str`, `jwa_enc_to_str`
- Add API documentation
- Add support for key management algorithms `A128GCMKW` and `A256GCMKW`
- Add functions `r_jwt_decrypt_nested`, `r_jwt_verify_signature_nested`, `r_jwt_parsen`, `r_jwe_parsen` and `r_jws_parsen`
- Add function `r_jwt_validate_claims` to validate claims
- Add functions `r_jw[se]_add_keys_json_str`, `r_jw[se]_add_keys_json_t`, `r_jw[se]_add_keys_pem_der`, `r_jw[se]_add_keys_gnutls`
- Add functions `r_jwt_add_[sign|enc]_keys_json_str`, `r_jwt_add_[sign|enc]_keys_json_t`, `r_jwt_add_[sign|enc]_keys_pem_der`, `r_jwt_add_[sign|enc]_keys_gnutls`

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
