/**
 *
 * Rhonabwy Javascript Object Signing and Encryption (JOSE) library
 *
 * Example program with a JWKS
 * - Parse keys and insert into a JWKS
 *   - Extract keys using an index or a kid
 *   - Search for a subset of the JWKS containing the RSA keys only
 * - Get JWKS content from a remote location using an url
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * License MIT
 *
 * To compile with gcc, use the following command:
 * gcc -o jwks-parse-extract jwks-parse-extract.c -lrhonabwy
 *
 */

#include <stdio.h>
#include <rhonabwy.h>

const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";

const unsigned char rsa_2048_pub[] = "-----BEGIN PUBLIC KEY-----\n"\
                                     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"\
                                     "uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"\
                                     "iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"\
                                     "ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"\
                                     "6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"\
                                     "K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"\
                                     "BwIDAQAB\n"\
                                     "-----END PUBLIC KEY-----\n";

const char jwk_key_256_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\",\"kid\":\"8\"}";

const char password[] = "secret";

const unsigned char symkey[] = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206};

const char jwks_uri[] = "https://example.com/jwks";

int main(void) {
  jwks_t * jwks = NULL, * jwks_sub = NULL;
  jwk_t * jwk = NULL;
  char * output = NULL;

  // Import several keys in jwks
  if (NULL != (jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_privkey_rsa_str,
                                          R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str,
                                          R_IMPORT_PEM, R_X509_TYPE_PUBKEY, rsa_2048_pub, sizeof(rsa_2048_pub),
                                          R_IMPORT_JSON_STR, jwk_key_256_1,
                                          R_IMPORT_PASSWORD, password,
                                          R_IMPORT_SYMKEY, symkey, sizeof(symkey),
                                          R_IMPORT_NONE))) {
    // Display the JWKS content
    output = r_jwks_export_to_json_str(jwks, 1);
    printf("##### Imported JWKS #####\n");
    printf("JWKS content:\n%s\n\n", output);
    r_free(output);

    // Get the second key in the JWKS (index 1 because arrays start at 0!)
    jwk = r_jwks_get_at(jwks, 1);
    output = r_jwk_export_to_json_str(jwk, 1);
    printf("Second JWK content:\n%s\n\n", output);
    r_free(output);
    r_jwk_free(jwk);

    // Get the key with the kid '8' in the JWKS
    jwk = r_jwks_get_by_kid(jwks, "8");
    output = r_jwk_export_to_json_str(jwk, 1);
    printf("JWK with the kid '8' content:\n%s\n\n", output);
    r_free(output);
    r_jwk_free(jwk);

    // Search for RSA keys
    jwks_sub = r_jwks_search_json_str(jwks, "{\"kty\":\"RSA\"}");
    // Display the result JWKS
    output = r_jwks_export_to_json_str(jwks_sub, 1);
    printf("JWKS with RSA keys only content:\n%s\n", output);
    r_free(output);
    r_jwks_free(jwks_sub);

    printf("##### Imported JWKS #####\n\n");
    r_jwks_free(jwks);
  }

  // Get jwks content from remote url
  if (NULL != (jwks = r_jwks_quick_import(R_IMPORT_JKU, jwks_uri, 0, R_IMPORT_NONE))) {
    // Display the JWKS content
    output = r_jwks_export_to_json_str(jwks, 1);
    printf("##### Remote JWKS #####\n");
    printf("JWKS content:\n%s\n", output);
    r_free(output);

    r_jwks_free(jwks);
    printf("##### Remote JWKS #####\n");
  }
  return 0;
}
