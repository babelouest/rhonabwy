/**
 *
 * Rhonabwy Javascript Object Signing and Encryption (JOSE) library
 *
 * Example program with a signed token using ES256 verified with the corresponding public key
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * To compile with gcc, use the following command:
 * gcc -o jwt-verify-es256 jwt-verify-es256.c -lrhonabwy
 *
 */

#include <stdio.h>
#include <rhonabwy.h>

const char token[] = "eyJzdHIiOiJhIHZhbHVlIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYiLCJraWQiOiIxIn0."                // header
                     "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiYWJjZDEyMzQiLCJpYXQiOjE0NjY1NzEzNjB9."   // payload
                     "NFG06xZA7rscnn5nrW9X2Yd00wgXkmMUjo1JAYUmrKH0ez09x8NDP4z03DV1X-0lYCcFNZ_Fu7dyb9hSYGXE7g"; // signature

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"kid\":\"1\",\"alg\":\"ES256\"}";

int main(void) {
  jwk_t * jwk = NULL;
  jwt_t * jwt = NULL;
  const char * aud, * iss;
  rhn_int_t iat;

  // Imports EC public key to verify the token signature
  if (NULL != (jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str))) {
    // Parse the token into a jwt_t structure
    if (NULL != (jwt = r_jwt_quick_parse(token, R_PARSE_NONE, 0))) {
      // Verify the token signature with the public key
      if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
        // Get token claims to use them in your program
        aud = r_jwt_get_claim_str_value(jwt, "aud");
        iss = r_jwt_get_claim_str_value(jwt, "iss");
        iat = r_jwt_get_claim_int_value(jwt, "iat");
        printf("Token signature verified.\n\n");
        printf("Payload claims\n- aud: %s\n- iss: %s\n- iat %"RHONABWY_INTEGER_FORMAT"\n", aud, iss, iat);
      } else {
        printf("Token signature invalid!\n");
      }
    } // else handle r_jwt_quick_parse error
  } // else handle r_jwk_quick_import error

  // Deallocate the jwt and the jwk used
  r_jwk_free(jwk);
  r_jwt_free(jwt);

  return 0;
}
