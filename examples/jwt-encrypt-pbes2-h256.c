/**
 *
 * Rhonabwy Javascript Object Signing and Encryption (JOSE) library
 *
 * Example program with a encrypted token using PBES2-H256
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * To compile with gcc, use the following command:
 * gcc -o jwt-encrypt-pbes2-h256 jwt-encrypt-pbes2-h256.c -lrhonabwy
 *
 */

#include <stdio.h>
#include <rhonabwy.h>

const char password[] = "secret";

int main(void) {
  jwk_t * jwk = NULL;
  jwt_t * jwt = NULL;
  char * token = NULL;

  // Import password to encrypt the AES key used to encrypt the payload
  if (NULL != (jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, password))) {
    // Initialize the jwt_t structure
    if (RHN_OK == r_jwt_init(&jwt)) {
      // Initialize jwt's content
      // The payload will have the following content {"aud": "abcd1234", "iat": 1466571360, "iss": "https://example.com"}
      // The header will have the following content {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256", "p2c": 4096, "p2s": "xxxxxxxxxxx", "typ": "JWT", "zip": "DEF"}
      // The "zip": "DEF" header specifies that the payload is compressed before encryption
      if (RHN_OK == r_jwt_set_properties(jwt, RHN_OPT_ENC_ALG, R_JWA_ALG_PBES2_H256,
                                              RHN_OPT_ENC, R_JWA_ENC_A128CBC,
                                              RHN_OPT_HEADER_STR_VALUE, "zip", "DEF",
                                              RHN_OPT_CLAIM_STR_VALUE, "iss", "https://example.com",
                                              RHN_OPT_CLAIM_STR_VALUE, "aud", "abcd1234",
                                              RHN_OPT_CLAIM_INT_VALUE, "iat", 1466571360,
                                              RHN_OPT_NONE)) {
        token = r_jwt_serialize_encrypted(jwt, jwk, 0);
        printf("token: %s\n", token);
        r_free(token);
      } // else handle r_jwt_set_properties error
    } // else handle r_jwt_init error
  } // else handle r_jwk_quick_import error

  // Deallocate the jwt and the jwk used
  r_jwk_free(jwk);
  r_jwt_free(jwt);

  return 0;
}
