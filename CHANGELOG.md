# Rhonabwy Changelog

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
