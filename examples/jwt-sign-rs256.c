/**
 *
 * Rhonabwy Javascript Object Signing and Encryption (JOSE) library
 *
 * Example program with a signed JWT using RS256
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * To compile with gcc, use the following command:
 * gcc -o jwt-sign-rs256 jwt-sign-rs256.c -lrhonabwy
 *
 */

#include <stdio.h>
#include <rhonabwy.h>

const char sign_key[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                        "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                        "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                        "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                        "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                        "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                        "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                        "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                        "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                        "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                        "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                        "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                        "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                        "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

int main(void) {
  jwk_t * jwk = NULL;
  jwt_t * jwt = NULL;
  char * token = NULL;

  // Imports RSA private key to sign the token
  if (NULL != (jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, sign_key))) {
    // Initialize the jwt_t structure
    if (RHN_OK == r_jwt_init(&jwt)) {
      // Initialize jwt's content
      // The payload will have the following content {"aud": "abcd1234", "iat": 1466571360, "iss": "https://example.com"}
      // The header will have the following content {"alg": "RS256", "kid": "2011-04-29", "str": "a value", "typ": "JWT"}
      if (RHN_OK == r_jwt_set_properties(jwt, RHN_OPT_SIG_ALG, R_JWA_ALG_RS256,
                                              RHN_OPT_HEADER_STR_VALUE, "str", "a value",
                                              RHN_OPT_CLAIM_STR_VALUE, "iss", "https://example.com",
                                              RHN_OPT_CLAIM_STR_VALUE, "aud", "abcd1234",
                                              RHN_OPT_CLAIM_INT_VALUE, "iat", 1466571360,
                                              RHN_OPT_NONE)) {
        // Serialize the JWT using the RSA provate key to sign the token
        token = r_jwt_serialize_signed(jwt, jwk, 0);
        printf("Token: %s\n", token);
        // Deallocate the seralized token
        r_free(token);
      } // else handle r_jwt_set_properties error
    } // else handle r_jwt_init error
  } // else handle r_jwk_quick_import error

  // Deallocate the jwt and the jwk used
  r_jwk_free(jwk);
  r_jwt_free(jwt);

  return 0;
}
