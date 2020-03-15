# Rhonabwy Changelog

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
