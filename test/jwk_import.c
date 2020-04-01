/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <rhonabwy.h>
#include <orcania.h>
#include <yder.h>
#include <ulfius.h>

#define HTTPS_PORT 7462

const unsigned char symmetric_key[] = "secret";
const unsigned char symmetric_key_b64url[] = "c2VjcmV0";

const char jwk_simple_hmac[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
const char jwk_simple_rsa[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
const char jwk_simple_ecdsa[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_kty[] = "{\"kty\":\"ECC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_crv[] = "{\"kty\":\"EC\",\"crv\":\"P-256C\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_x[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":42,\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","\
                                              "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_y[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":42,\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_use[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":42,\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_kid[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                 "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":42}";
const char jwk_pubkey_ecdsa_str_missing_x[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_missing_y[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_b64_x[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\";error;\","\
                                                  "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_invalid_b64_y[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                  "\"y\":\";error;\",\"use\":\"enc\",\"kid\":\"1\"}";

const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                     "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str_invalid_k[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                               "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":42,\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str_invalid_b64_k[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                   "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\";error;\","\
                                                   "\"use\":\"enc\",\"kid\":\"1\"}";

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                  "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                  "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                  ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_n[] = "{\"kty\":\"RSA\",\"n\":42,\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_e[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"\
                                             "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs"\
                                             "8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls"\
                                             "1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":42,\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_alg[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc"\
                                              "_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSq"\
                                              "zs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"\
                                              "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS257\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_b64_n[] = "{\"kty\":\"RSA\",\"n\":\";error;\""\
                                                ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_b64_e[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\";error;\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

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
const char jwk_privkey_rsa_str_invalid_d[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                             "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                             "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                             "w\",\"e\":\"AQAB\",\"d\":42,\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                             "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                             "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                             "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                             "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                             "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                             "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                             "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_p[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                             "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                             "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                             "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                             "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                             "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                             "C8Q\",\"p\":42,\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                             "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                             "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                             "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                             "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                             "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                             "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_q[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                             "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                             "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                             "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                             "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                             "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                             "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                             "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":42,\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                             "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                             "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                             "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                             "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_dp[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                              "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                              "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                              "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                              "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                              "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                              "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                              "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                              "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                              "k\",\"dp\":42,\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                              "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                              "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                              "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_dq[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                              "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                              "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                              "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                              "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                              "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                              "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                              "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                              "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                              "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                              "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":42,\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                              "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_qi[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
                                              "k\",\"qi\":42,\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_d[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                                 "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                                 "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                                 "w\",\"e\":\"AQAB\",\"d\":\";error;\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                                 "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                                 "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                                 "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                                 "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                                 "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                                 "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                                 "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_p[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                                 "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                                 "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                                 "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                                 "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                                 "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                                 "C8Q\",\"p\":\";error;\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                                 "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                                 "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                                 "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                                 "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                                 "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                                 "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_q[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                                 "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                                 "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                                 "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                                 "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                                 "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                                 "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                                 "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\";error;\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                                 "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                                 "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                                 "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                                 "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_dp[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                                  "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                                  "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                                  "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                                  "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                                  "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                                  "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                                  "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                                  "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                                  "k\",\"dp\":\";error;\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                                  "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                                  "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                                  "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_dq[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                                  "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                                  "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                                  "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                                  "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                                  "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                                  "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                                  "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                                  "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                                  "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                                  "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\";error;\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                                  "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str_invalid_b64_qi[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
                                                  "k\",\"qi\":\";error;\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_x5c_only[] = "{\"alg\": \"RS256\",\"x5c\":[\""\
                                        "MIIG5QIBAAKCAYEAly6gaJEHu5aO4ckg/wInRdD4Zzcxuq+Oa6MYbAh/bby04RWM"\
                                        "kNkEeaihPVPo4i/siZWwj5CxAMiJbFXC/xwW82T4hqTngD6CkvHwC8VrH0y2S1/C"\
                                        "vBA3SLegSZ0lNjI1wV7m684uzxxo3CnvSNEs85gq0qjGcMbN+4OeJEWcmpJ+ylTr"\
                                        "v+AHMMruIkqwneAYTNaz/PUzVH7BURjdm3RqFNxM3afOske8LSnU27ximVejzTs/"\
                                        "vzZ50r6/Zx7ZNI1jkw5AACWsobcvVuN8p4d5PWG1hLob8xYkhUdz43A6xFGxjI5d"\
                                        "KQ/xmOopZiO6z90CcLr26Mgqm8y0KkAEsjdWdIxuihaITc30Qz8fO8PlcJYl4HYW"\
                                        "U2/FLrCYcbuqC9O+Yl6nn0fIVNbQiZnLtwgLZOFgXPDpVSQAbbQiobhEBFZ2MO6v"\
                                        "vLw2wxxeHzu870J76XssQMnwWbBjqxWoR7WmMyVWAFzlzPD4HnbABoGjCwxSZXYC"\
                                        "vp02ZRZcRLjplWJxAgMBAAECggGBAIclvWv8ymbdbplUzVRpvmXhK05JvwDeU3jR"\
                                        "cdGRvyiAW0ojk2chOajwIEPMsRESOme8EvwkIrdKjd70w75+g93NU4Y6AGFagCuQ"\
                                        "cEB1mQ9/6i5zSogIDwPIc1ebTVqng/p7Nf9yb9Hh2bOHIUt9Aqw4SX/MNKk4b4b5"\
                                        "3/MY76gWcZW6WI1MXeE2Z67sCfr4C4EVJg1pvRs5vOMcUW7YoMRJM8Wqb1JcYlIV"\
                                        "ZR2RyKq/98RNxOzQbBMDReOPZiheg1dtyxxcAcE2vZG8EFaxdGdY+CSgxwnHilqR"\
                                        "SpuUqki3OAJfJindNltrzY290T3k5Rcfi1NoOPnM9m/iGvnZNAHfHOrZk83jm4DQ"\
                                        "dBnEHF9Qq6GDtViCBJQhjCI8tsYsR5QnaHMjf8ZJagy3Yl8qJIIDNJ2XS5AR3N0o"\
                                        "3PgZzEAlYFEBFhxCrpEu3/+xlZ5IU5FFzjGYro13SSbv5+ShCKhtCJ+TQY3cGURy"\
                                        "UGskNurhcBCX1ymqNBopYi+O82j6KQKBwQDJOC+iXoY9dJ8agI8EDKkQyPGgH6dt"\
                                        "HFX47AhBJw1T+HnJhx/c07aP+Kd/ppdYGuOKFiausJQHfK9oQB0PqtU4HdIdicVb"\
                                        "gIXJgFH8EIteGXJIrtIrGDGa4037Pz0zU+pZ1Qsf/t340C/lfjUlQhukCK5MTsMQ"\
                                        "ERzfRXfJrz7K1D957jj/EaYnT4KginLKOaHauu+zc+g+ZaUTUkDBKj0vp9Z5IlBm"\
                                        "kwFXpUNuIrCrVpIgwWlBrmbjzF5nakbwj48CgcEAwFch06YJSw/+lbZabAVnn2Gd"\
                                        "IJO6NT+bYRcnGLuMlhHHmoRArOu27deXVv4Qoso5+aYjybB6+waU0APcJtfqsnXD"\
                                        "2xmFuugcYrVwHzuznhNCBCp6yTNCjgQVxkxay5G+sKsdeCCohwAh+2F68S++mlVr"\
                                        "gluwNG2OEG4vppFIKLsYgpzFF2pRmVIZpW+FT2udeobN45tDf4hGb3P8ogsGQNdl"\
                                        "By5p35LiWbx/+I+862opKnqxsHQn2VJ3nbuMge3/AoHBAJuu/xvvaomN+7Ozl/OY"\
                                        "IA6+ikRLeWywKcxoQpK2Nlervf6wr3RZ0bxetKnNKPegBkDGlrM+J6oLTGOqh1Gh"\
                                        "6Up7uB/mgm4jaF/ZCpWt70alBYk6yZ1SIL8n8yPbb+yQlpdegDcHKJLj8Mrs9Q2Y"\
                                        "sm4d0U10+vMpal9NDjtbfYfM5DfgmvSuoRF1MSopNFtGb/YeAGul2CC+4BOs5jEO"\
                                        "Dz0Z7JTYecCDKNy5HwzNhkdqubDiNB//YdgKPVhiH/Tr/QKBwQCDPjFPyTkIJibS"\
                                        "o3Z5xQpbH/FmnEbwNLHigzjjUH5ynDk2P04ecE0HaBfVfVF+szzyE6LR6gFQrsH2"\
                                        "WtvrCWQVV/RH2dd9nQpZdHLIbSV4FK30R8Q27Cpa24C8Kbe+tnmG9YwLP0WfsMB/"\
                                        "VpncX3bQur68WbIXZDYPEhCjuPijCl+EKFL4UkzRsMrdLwapFcaEJ93vlC9vo15k"\
                                        "iKF3NMyUjCVczBfkPccD8nLj+biwbmUenlAHFotmaDZExAfxVKMCgcBsiCFcnhxJ"\
                                        "ljOUQVNzTV7fMhWdyyys+sixhhdiOTiNDZJAFkff1oV8TRN8WeRNDvYRVVBtZkXU"\
                                        "AKsjnC1Pv7dTfsDODmwZ48pLMsWjCBd30TipNx4SJuGEO+mWNgopGsROvbI/AViy"\
                                        "9AOcQlid5VG2h9hBVqP1UWJceTGchUdm2E0qMdotH8JgFruDr6q7p12vfmVHgpMU"\
                                        "FFjl/aadFjIXaVtCVG/OOr90SWvQ19Z/1wVqqCUguP4RUcB0geZeP+A=\"]}";
const char jwk_privkey_rsa_x5c_invalid_x5c_content[] = "{\"alg\": \"RS256\",\"x5c\":[\";error;\"]}";

const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
const char jwk_key_symmetric_invalid_k[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":42}";
const char jwk_key_symmetric_invalid_b64_k[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\";error;\"}";

const char jwk_pubkey_rsa_x5c_str[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                      "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                      "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                      "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                      "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                      "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                      "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                      "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                      "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                      "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                      "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                      "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                      "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                      "MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]}";
const char jwk_pubkey_rsa_x5c_str_invalid_x5c[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                                  "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                                  "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                                  "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[42]}";
const char jwk_pubkey_rsa_x5c_str_invalid_x5c_content[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                                          "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                                          "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                                          "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[\";error;\"]}";
const char jwk_pubkey_rsa_x5c_only[] = "{\"alg\": \"RS256\",\"x5c\":[\"MIIFkjCCBHqgAwIBAgIQRXroN0ZOdRkBAAAAAAPunzANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJVUzEeMBw"\
                                       "GA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE4MTAxMDA3MTk0NVoXDTE5MTAwOTA3MTk0NVowbDELMAkGA"\
                                       "1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxGzAZBgNVBAMTEmF0dGV"\
                                       "zdC5hbmRyb2lkLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANjXkz0eK1SE4m+/G5wOo+XGSECrqdn88sCpR7fs14fK0Rh3ZCYZLFHqB"\
                                       "k6AmZVw2K9FG0O9rRPeQDIVRyE30QunS9ugHC4eg9ovvOm+QdZ2p93XhzunQEhUWXCxADIEGJK3S2aAfze99PLS29hLcQuYXHDaC7OZqNnosiOGifs8v1j"\
                                       "i6H/xhltCZe2lJ+7GutzexKpxvpE/tZSfbY905qSlBh9fpj015cjnQFkUsAUwmKVAUueUz4tKcFK4pevNLaxEAl+OkilMtIYDacD5nel4xJiys413hagqW"\
                                       "0Whh5FP39hGk9E/BwQTjazSxGdvX0m6xFYhh/2VMyZjT4KzPJECAwEAAaOCAlgwggJUMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATA"\
                                       "MBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQqBQwGWoJBa1oTKqupo4W6xT6j2DAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBkBggrBgEFBQcBA"\
                                       "QRYMFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFvMTArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmN"\
                                       "ydDAdBgNVHREEFjAUghJhdHRlc3QuYW5kcm9pZC5jb20wIQYDVR0gBBowGDAIBgZngQwBAgIwDAYKKwYBBAHWeQIFAzAvBgNVHR8EKDAmMCSgIqAghh5od"\
                                       "HRwOi8vY3JsLnBraS5nb29nL0dUUzFPMS5jcmwwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdwCkuQmQtBhYFIe7E6LMZ3AKPDWYBPkb37jjd80OyA3cEAA"\
                                       "AAWZdD3PLAAAEAwBIMEYCIQCSZCWeLJvsiVW6Cg+gj/9wYTJRzu4Hiqe4eY4c/myzjgIhALSbi/Thzczqtij3dk3vbLcIW3Ll2B0o75GQdhMigbBgAHUAV"\
                                       "hQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0AAAFmXQ9z5AAABAMARjBEAiBcCwA9j7NTGXP278z4hr/uCHiAFLyoCq2K0+yLRwJUbgIgf8gHjvp"\
                                       "w2mB1ESjq2Of3A0AEAwCknCaEKFUyZ7f/QtIwDQYJKoZIhvcNAQELBQADggEBAI9nTfRKIWgtlWl3wBL55ETV6kazsphW1yAc5Dum6XO41kZzwJ61wJmdR"\
                                       "RT/UsCIy1KEt2c0EjglnJCF2eawcEWlLQY2XPLyFjkWQNbShB1i4W2NRGzPht3m1b49hbstuXM6tX5CyEHnTh8Bom4/WlFihzhgn81Dldogz/K2UwM6S6C"\
                                       "B/SExkiVfv+zbJ0rjvg94AldjUfUwkI9VNMjEP5e8ydB3oLl6glpCeF5dgfSX4U9x35oj/IId3UE/dPpb/qgGvskfdeztmUte/KSmriwcgUWWeXfTbI3zs"\
                                       "ikwZbkpmRYKmjPmhv4rlizGCGt8Pn8pq8M2KDf/P3kVot3e18Q=\",\"MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMS"\
                                       "AwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAw"\
                                       "NDJaFw0yMTEyMTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3QgU2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwgg"\
                                       "EiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnvUA0Qk28FgICfKqC9EksC4T2fWBYk/jCf"\
                                       "C3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRrmBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++AcxGNhr59qM/9il71I2dN8FG"\
                                       "fcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmKFsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7XrJfoucBZEqFJ"\
                                       "JSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEw"\
                                       "EB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8GA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEB"\
                                       "BCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3"\
                                       "NyMi5jcmwwPwYDVR0gBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOC"\
                                       "AQEAGoA+Nnn78y6pRjd9XlQWNa7HTgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoNFvhsO9tvBCOIazpswWC9aJ9xju"\
                                       "4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrzmqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wWIRdAvKLWZu/axBVb"\
                                       "zYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZUSpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==\"]}";

const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":[\"https://www.example.com/x509\"]}";

const char jwk_pubkey_rsa_x5u_only_rsa_pub[] = "{\"alg\": \"RS256\",\"x5u\":[\"https://localhost:7462/x5u_rsa_crt\"]}";
const char jwk_pubkey_rsa_x5u_only_ecdsa_pub[] = "{\"alg\": \"RS256\",\"x5u\":[\"https://localhost:7462/x5u_ecdsa_crt\"]}";

const char jwk_pubkey_rsa_x5u_str_invalid_x5u[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"\
                                                  "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ"\
                                                  "zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqD"\
                                                  "Kgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":42}";
const char jwk_pubkey_rsa_x5u_str_invalid_x5u_protocol[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                                           "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                                           "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                                           ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":[\"http://www.example.com/x509\"]}";

const char jwk_invalid_json[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"";
const char jwk_invalid_json_container[] = "[{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}]";

const unsigned char rsa_2048_pub[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
"uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
"iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
"ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
"6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
"K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
"BwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const unsigned char rsa_2048_pub_der[] = 
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\
uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\
iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\
ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\
6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\
K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\
BwIDAQAB";

const unsigned char rsa_2048_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDC2kwAziXUf33m\n"
"iqWp0yG6o259+nj7hpQLC4UT0Hmz0wmvreDJ/yNbSgOvsxvVdvzL2IaRZ+Gi5mo0\n"
"lswWvL6IGz7PZO0kXTq9sdBnNqMOx27HddV9e/2/p0MgibJTbgywY2Sk23QYhJpq\n"
"Kq/nU0xlBfSaI5ddZ2RC9ZNkVeGawUKYksTruhAVJqviHN8BoK6VowP5vcxyyOWH\n"
"TK9KruDqzCIhqwRTeo0spokBkTN/LCuhVivcHAzUiJVtB4qAiTI9L/zkzhjpKz9P\n"
"45aLU54rj011gG8U/6E1USh5nMnPkr+d3oLfkhfS3Zs3kJVdyFQWZpQxiTaI92Fd\n"
"2wLvbS0HAgMBAAECggEAD8dTnkETSSjlzhRuI9loAtAXM3Zj86JLPLW7GgaoxEoT\n"
"n7lJ2bGicFMHB2ROnbOb9vnas82gtOtJsGaBslmoaCckp/C5T1eJWTEb+i+vdpPp\n"
"wZcmKZovyyRFSE4+NYlU17fEv6DRvuaGBpDcW7QgHJIl45F8QWEM+msee2KE+V4G\n"
"z/9vAQ+sOlvsb4mJP1tJIBx9Lb5loVREwCRy2Ha9tnWdDNar8EYkOn8si4snPT+E\n"
"3ZCy8mlcZyUkZeiS/HdtydxZfoiwrSRYamd1diQpPhWCeRteQ802a7ds0Y2YzgfF\n"
"UaYjNuRQm7zA//hwbXS7ELPyNMU15N00bajlG0tUOQKBgQDnLy01l20OneW6A2cI\n"
"DIDyYhy5O7uulsaEtJReUlcjEDMkin8b767q2VZHb//3ZH+ipnRYByUUyYUhdOs2\n"
"DYRGGeAebnH8wpTT4FCYxUsIUpDfB7RwfdBONgaKewTJz/FPswy1Ye0b5H2c6vVi\n"
"m2FZ33HQcoZ3wvFFqyGVnMzpOwKBgQDXxL95yoxUGKa8vMzcE3Cn01szh0dFq0sq\n"
"cFpM+HWLVr84CItuG9H6L0KaStEEIOiJsxOVpcXfFFhsJvOGhMA4DQTwH4WuXmXp\n"
"1PoVMDlV65PYqvhzwL4+QhvZO2bsrEunITXOmU7CI6kilnAN3LuP4HbqZgoX9lqP\n"
"I31VYzLupQKBgGEYck9w0s/xxxtR9ILv5XRnepLdoJzaHHR991aKFKjYU/KD7JDK\n"
"INfoAhGs23+HCQhCCtkx3wQVA0Ii/erM0II0ueluD5fODX3TV2ZibnoHW2sgrEsW\n"
"vFcs36BnvIIaQMptc+f2QgSV+Z/fGsKYadG6Q+39O7au/HB7SHayzWkjAoGBAMgt\n"
"Fzslp9TpXd9iBWjzfCOnGUiP65Z+GWkQ/SXFqD+SRir0+m43zzGdoNvGJ23+Hd6K\n"
"TdQbDJ0uoe4MoQeepzoZEgi4JeykVUZ/uVfo+nh06yArVf8FxTm7WVzLGGzgV/uA\n"
"+wtl/cRtEyAsk1649yW/KHPEIP8kJdYAJeoO8xSlAoGAERMrkFR7KGYZG1eFNRdV\n"
"mJMq+Ibxyw8ks/CbiI+n3yUyk1U8962ol2Q0T4qjBmb26L5rrhNQhneM4e8mo9FX\n"
"LlQapYkPvkdrqW0Bp72A/UNAvcGTmN7z5OCJGMUutx2hmEAlrYmpLKS8pM/p9zpK\n"
"tEOtzsP5GMDYVlEp1jYSjzQ=\n"
"-----END PRIVATE KEY-----\n";

const unsigned char rsa_2048_priv_der[] = 
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDC2kwAziXUf33m\
iqWp0yG6o259+nj7hpQLC4UT0Hmz0wmvreDJ/yNbSgOvsxvVdvzL2IaRZ+Gi5mo0\
lswWvL6IGz7PZO0kXTq9sdBnNqMOx27HddV9e/2/p0MgibJTbgywY2Sk23QYhJpq\
Kq/nU0xlBfSaI5ddZ2RC9ZNkVeGawUKYksTruhAVJqviHN8BoK6VowP5vcxyyOWH\
TK9KruDqzCIhqwRTeo0spokBkTN/LCuhVivcHAzUiJVtB4qAiTI9L/zkzhjpKz9P\
45aLU54rj011gG8U/6E1USh5nMnPkr+d3oLfkhfS3Zs3kJVdyFQWZpQxiTaI92Fd\
2wLvbS0HAgMBAAECggEAD8dTnkETSSjlzhRuI9loAtAXM3Zj86JLPLW7GgaoxEoT\
n7lJ2bGicFMHB2ROnbOb9vnas82gtOtJsGaBslmoaCckp/C5T1eJWTEb+i+vdpPp\
wZcmKZovyyRFSE4+NYlU17fEv6DRvuaGBpDcW7QgHJIl45F8QWEM+msee2KE+V4G\
z/9vAQ+sOlvsb4mJP1tJIBx9Lb5loVREwCRy2Ha9tnWdDNar8EYkOn8si4snPT+E\
3ZCy8mlcZyUkZeiS/HdtydxZfoiwrSRYamd1diQpPhWCeRteQ802a7ds0Y2YzgfF\
UaYjNuRQm7zA//hwbXS7ELPyNMU15N00bajlG0tUOQKBgQDnLy01l20OneW6A2cI\
DIDyYhy5O7uulsaEtJReUlcjEDMkin8b767q2VZHb//3ZH+ipnRYByUUyYUhdOs2\
DYRGGeAebnH8wpTT4FCYxUsIUpDfB7RwfdBONgaKewTJz/FPswy1Ye0b5H2c6vVi\
m2FZ33HQcoZ3wvFFqyGVnMzpOwKBgQDXxL95yoxUGKa8vMzcE3Cn01szh0dFq0sq\
cFpM+HWLVr84CItuG9H6L0KaStEEIOiJsxOVpcXfFFhsJvOGhMA4DQTwH4WuXmXp\
1PoVMDlV65PYqvhzwL4+QhvZO2bsrEunITXOmU7CI6kilnAN3LuP4HbqZgoX9lqP\
I31VYzLupQKBgGEYck9w0s/xxxtR9ILv5XRnepLdoJzaHHR991aKFKjYU/KD7JDK\
INfoAhGs23+HCQhCCtkx3wQVA0Ii/erM0II0ueluD5fODX3TV2ZibnoHW2sgrEsW\
vFcs36BnvIIaQMptc+f2QgSV+Z/fGsKYadG6Q+39O7au/HB7SHayzWkjAoGBAMgt\
Fzslp9TpXd9iBWjzfCOnGUiP65Z+GWkQ/SXFqD+SRir0+m43zzGdoNvGJ23+Hd6K\
TdQbDJ0uoe4MoQeepzoZEgi4JeykVUZ/uVfo+nh06yArVf8FxTm7WVzLGGzgV/uA\
+wtl/cRtEyAsk1649yW/KHPEIP8kJdYAJeoO8xSlAoGAERMrkFR7KGYZG1eFNRdV\
mJMq+Ibxyw8ks/CbiI+n3yUyk1U8962ol2Q0T4qjBmb26L5rrhNQhneM4e8mo9FX\
LlQapYkPvkdrqW0Bp72A/UNAvcGTmN7z5OCJGMUutx2hmEAlrYmpLKS8pM/p9zpK\
tEOtzsP5GMDYVlEp1jYSjzQ=";

const unsigned char ecdsa_521_pub[] = "-----BEGIN PUBLIC KEY-----\n"
"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA/axE26pXWXesAjcTP/2Tfe4EcF4A\n"
"3LuqgpIFzrftiztViq0+5deUvfcxuPIFk+ANVinlAOzgZWpFS0kheI7KJAYA3fOH\n"
"n5ZTU08AAjau0CoZe9GSPUC4cnSy1nqetiKBW0YpBvhaY5FXnngvfHUHdmkFSVLC\n"
"S6N+LXoi/dm0Fbo6snE=\n"
"-----END PUBLIC KEY-----\n";
const unsigned char ecdsa_521_pub_der[] = 
"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA/axE26pXWXesAjcTP/2Tfe4EcF4A\
3LuqgpIFzrftiztViq0+5deUvfcxuPIFk+ANVinlAOzgZWpFS0kheI7KJAYA3fOH\
n5ZTU08AAjau0CoZe9GSPUC4cnSy1nqetiKBW0YpBvhaY5FXnngvfHUHdmkFSVLC\
S6N+LXoi/dm0Fbo6snE=";

const unsigned char ecdsa_521_priv[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MIHcAgEBBEIAp6rxb2PoAISjCCTxpTQOxv5arJ/N6Xibr0eyOAnlWcVk34m1W532\n"
"3/6TcPGTtFQgEX9TWjNcp9W8HIuIyRdLnsKgBwYFK4EEACOhgYkDgYYABAD9rETb\n"
"qldZd6wCNxM//ZN97gRwXgDcu6qCkgXOt+2LO1WKrT7l15S99zG48gWT4A1WKeUA\n"
"7OBlakVLSSF4jsokBgDd84efllNTTwACNq7QKhl70ZI9QLhydLLWep62IoFbRikG\n"
"+FpjkVeeeC98dQd2aQVJUsJLo34teiL92bQVujqycQ==\n"
"-----END EC PRIVATE KEY-----\n";
const unsigned char ecdsa_521_priv_der[] = 
"MIHcAgEBBEIAp6rxb2PoAISjCCTxpTQOxv5arJ/N6Xibr0eyOAnlWcVk34m1W532\
3/6TcPGTtFQgEX9TWjNcp9W8HIuIyRdLnsKgBwYFK4EEACOhgYkDgYYABAD9rETb\
qldZd6wCNxM//ZN97gRwXgDcu6qCkgXOt+2LO1WKrT7l15S99zG48gWT4A1WKeUA\
7OBlakVLSSF4jsokBgDd84efllNTTwACNq7QKhl70ZI9QLhydLLWep62IoFbRikG\
+FpjkVeeeC98dQd2aQVJUsJLo34teiL92bQVujqycQ==";

const unsigned char x509_cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIBejCCASGgAwIBAgIUUmwvBcKwJSWZMLC9xtUYQhh/YicwCgYIKoZIzj0EAwIw\n"
"EzERMA8GA1UEAwwIZ2xld2x3eWQwHhcNMTkwNjEyMTY0MjExWhcNMjkwNjA5MTY0\n"
"MjExWjATMREwDwYDVQQDDAhnbGV3bHd5ZDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
"A0IABKP9Eu2Rzt15pKqriLiniryG9zsabCq+aNneB+mmIDwRkjaqpKeGwztLEHBG\n"
"TrHh9poToHkaxUuFE/wVD+9GscGjUzBRMB0GA1UdDgQWBBQQv5dX9gxGFfEDD2Zu\n"
"jZQT3FTitDAfBgNVHSMEGDAWgBQQv5dX9gxGFfEDD2ZujZQT3FTitDAPBgNVHRMB\n"
"Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBqkd3kqcKZ/gEsnAVi5sQR3gB04\n"
"U8JNjzPwv//HmV/FAiBT45X52j1G6QGPg82twWR7CZiHbJPe26drWkkoDeT/QQ==\n"
"-----END CERTIFICATE-----\n";
const unsigned char x509_cert_der[] = 
"MIIBejCCASGgAwIBAgIUUmwvBcKwJSWZMLC9xtUYQhh/YicwCgYIKoZIzj0EAwIw\
EzERMA8GA1UEAwwIZ2xld2x3eWQwHhcNMTkwNjEyMTY0MjExWhcNMjkwNjA5MTY0\
MjExWjATMREwDwYDVQQDDAhnbGV3bHd5ZDBZMBMGByqGSM49AgEGCCqGSM49AwEH\
A0IABKP9Eu2Rzt15pKqriLiniryG9zsabCq+aNneB+mmIDwRkjaqpKeGwztLEHBG\
TrHh9poToHkaxUuFE/wVD+9GscGjUzBRMB0GA1UdDgQWBBQQv5dX9gxGFfEDD2Zu\
jZQT3FTitDAfBgNVHSMEGDAWgBQQv5dX9gxGFfEDD2ZujZQT3FTitDAPBgNVHRMB\
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBqkd3kqcKZ/gEsnAVi5sQR3gB04\
U8JNjzPwv//HmV/FAiBT45X52j1G6QGPg82twWR7CZiHbJPe26drWkkoDeT/QQ==";

const unsigned char error_pem[] = "-----BEGIN ERROR FROM OUTER SPACE-----";

#define HTTPS_CERT_KEY "-----BEGIN PRIVATE KEY-----\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDr90HrswgEmln/\
rXeNqYq0boIvas5wu27hmeHDdGGKtkCWIWGAo9GUy45xqsI4mDl3bOWS+pmb/3yi\
+nhe+BmYHvEqUFo1JfUcVMxaNEbdd9REytMjKdOS+kkLf++BBRoZI/g8DggIu+Ri\
dOSypk+pUECyQxROsyCrB/FgXuKbyC4QNl7fqZxMSpzw7jsWCZiwFv4pu8kMqzDG\
2wTl/r/4STyK4Pj2TVa/JVzbZbH7VfcjT8MdMsXvKhlmPywjbqo70Hnmt3cnakYF\
X+07ncx/5mjYYd3eSFgiNXr7WNw2rhFKtfTUcjrqSw9FDxmHFWUU76mwJyUo02N9\
ViakSoQpAgMBAAECggEBAJp/VBwdJpzM6yxqyaJpZbXpvTeKuQw6zMjN1nIBG3SV\
DAjAZnSxziGcffGSmoQvt0CoflAT4MuxJkwXrwSPcUKWz9Sis82kwq4AH6TYIaYU\
NVmtazzUwAC1+2maJJjXXFUlpfy8Oypsy4ZjfvIxzmrPbuzI2t0Ej9kr5DDzL3BL\
CWQ/U7w7y4KC0Pnq1ueIzM+UJIfvI0ldUcXHWsAnjyQzwgFBC35qDOfDTw0YUJv+\
ElfFFcGYCA+9wlQyhM/zhAWqKgZ2mwAS6WykgbSc7j4NDjlmZwf4ZuTxbDUV1kBX\
pPH21snqO42CFpw9hRUAA0W0XydCIfUhH8/6tH9enQECgYEA+rM9f6cUk3c7aLWs\
hnauVqJuyGhgCkMyF9sSxgfcs87OVLNuGgaTIfwcT/7oxAY8G7sY44cbk1ZRhh7y\
6kf01xqiJeXxBQei1qiJxMb2gukvpeY81s2Mg9og5d9qbEhLzp8TdiRJHxLIiGwF\
xOM69CpugKN4T0Zum7EBGeSvmBECgYEA8PRG5SRTE4JwzGtLuTbMbjYTqyEjXAkB\
zo33a92znA0EXEeLCl845EUgzUkSkeN/T/uyWRjj0hrPU99UaaXHt3bc+lrDHrc7\
WFAR3QoAfFFJPIqqwiHcBDdTeAozQ8IOqFIxspl72RukuRdeQR3EdfcF9TUZyUbU\
k8SuRioggpkCgYA2scgnA3KvwYGKlKgxJc9fQ0zcGDlrw8E4BymPXsO9zs6hGAxb\
TTfoYDJlGX361kli22zQpvdTK6/ZjQL+LfiyvTLHBeWRbVsPbfGwpp+9a9ZjYVnA\
m1OeqIYo4Jc9TICNcZMzYTM6vkRVzwtrKw//mQpGsmNbGEilWvaciZHtoQKBgQDo\
FDBQtir6SJIConm9/ETtBlLtai6Xj+lYnK6qC1DaxkLj6tjF9a9jVh3g/DfRopBW\
ZnSCkpGkJcR54Up5s35ofCkdTdxPsmaLihuaje6nztc+Y8VS1LAIs41GunRkF/5s\
KzbI8kIyfAitag+Toms+v93SLwIWNo27gh3lYOANSQKBgQDIidSO3fzB+jzJh7R0\
Yy9ADWbBsLxc8u+sBdxmZBGl+l4YZWNPlQsnsafwcpJWT3le6N7Ri3iuOZw9KiGe\
QDkc7olxUZZ3pshg+cOORK6jVE8v6FeUlLnxpeAWa4C4JDawGPTOBct6bVBl5sxi\
7GaqDcEK1TSxc4cUaiiPDNNXQA==\
-----END PRIVATE KEY-----"
#define HTTPS_CERT_PEM "-----BEGIN CERTIFICATE-----\
MIIDhTCCAm2gAwIBAgIJANrO2RnCbURLMA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV\
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\
aWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNzA0MjgxNTA0\
NDVaFw0xODA0MjgxNTA0NDVaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21l\
LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNV\
BAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOv3\
QeuzCASaWf+td42pirRugi9qznC7buGZ4cN0YYq2QJYhYYCj0ZTLjnGqwjiYOXds\
5ZL6mZv/fKL6eF74GZge8SpQWjUl9RxUzFo0Rt131ETK0yMp05L6SQt/74EFGhkj\
+DwOCAi75GJ05LKmT6lQQLJDFE6zIKsH8WBe4pvILhA2Xt+pnExKnPDuOxYJmLAW\
/im7yQyrMMbbBOX+v/hJPIrg+PZNVr8lXNtlsftV9yNPwx0yxe8qGWY/LCNuqjvQ\
eea3dydqRgVf7TudzH/maNhh3d5IWCI1evtY3DauEUq19NRyOupLD0UPGYcVZRTv\
qbAnJSjTY31WJqRKhCkCAwEAAaNQME4wHQYDVR0OBBYEFPFfmGA3jO9koBZNGNZC\
T/dZHZyHMB8GA1UdIwQYMBaAFPFfmGA3jO9koBZNGNZCT/dZHZyHMAwGA1UdEwQF\
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIc8Yuom4vz82izNEV+9bcCvuabcVwLH\
Qgpv5Nzy/W+1hDoqfMfKNwOSdUB7jZoDaNDG1WhjKGGCLTAx4Hx+q1LwUXvu4Bs1\
woocge65bl85h10l2TxxnlT5BIJezm5r3NiZSwOK2zxxIEyL4vh+b/xqQblBEkR3\
e4/A4Ugn9Egh8GdpF4klGp4MjjpRyAVI7BDaleAhvDSfPmm7ylHJ2y7CLI9ApOQY\
glwRuTmowAZQtaSiE1Ox7QtWj858HDzzTZyFWRG/MNqQptn7AMTPJv3DivNfDNPj\
fYxFAheH3CjryHqqR9DD+d9396W8mqEaUp+plMwSjpcTDSR4rEQkUJg=\
-----END CERTIFICATE-----"
const unsigned char rsa_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIEWTCCAsGgAwIBAgIUJyAFwqkMTppNiyU8gFOK4WUC1GgwDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0xOTEyMDYxMzU1MzlaFw0yMDExMjAxMzU1MzlaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MIIBojANBgkqhkiG9w0BAQEFAAOC\n"
"AY8AMIIBigKCAYEAsUWjL3wK1B/dQbXbhSXaodF0gXMNlZg3ZecjZIJOKgXGDVOn\n"
"V0ly4evW8xkn8F2gC3TYJXik7efdhGdiaYul9kyzpPBr53ELHMmAeI/I1rnF4pgI\n"
"wfN1vBsaDwJw9w0R6FQ9fxDUIte47WdElEHhtST9V874mMehsSUG4xM2qiBvvbWw\n"
"X0KCyKk6BY/CdyljUjAPUShcVysKUTyfefew38KUVTVpk2vWLlN+a41iC/gxGvLt\n"
"H142LDiDx/s+Kh37f4paD2zsEw5McF81eiKTAfrraIC1Gj2BxyEj6n2EjqyI+NFR\n"
"sSUmqfPoFgiMzlEWj4P8AwvfE9jbjXz/E0GOISiXt4L+06U7rLoGHFri5oVI6KUk\n"
"LAOwwwTri+ikeQFx68IKvhytBiX1O+XHh51JZyyC+fcKKN+/ATgGKIiR63M5UWYx\n"
"O2JkVkPvpzORKJUivePFQbkEcxYZb9VqoVZ04sfpfGb3h2douzBrKbkDP/Jf+O0J\n"
"PKDTltrUJOpZbYhVAgMBAAGjdjB0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI\n"
"KwYBBQUHAwIwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUiZGaRSyAyraAdeo5\n"
"wJc+0Ks7IOcwHwYDVR0jBBgwFoAU0marYk/GnTVDeDbie2BY15qCu0QwDQYJKoZI\n"
"hvcNAQELBQADggGBAGINVR+lskHnxkYvPkgCQG+nGqovI28W6rtx8a5xM/6rtsVs\n"
"5jCu1nnJd32YNjDsySxsbkhXjW0WjGR7cEsnmcOITeP4kLLVzh1vm6sZa/9vX1fh\n"
"M5pTUTYTHYozl6TA85CtBd7oC/AB2Gwh5q1kJ3wmGwmCY8mqPftP+plyFTSbCwAH\n"
"BZSfCgsMpffILDzPgViU54BehfpfljZcmGJnnGKEnTRvUr84/NlmKEdhw9rKyod5\n"
"KKieGneVzpPeiyXrzUEJuGkmLtVLpvNdDdB5+6rN0hK+bFyB3NA+gASIiekuM7Q+\n"
"4RgroWwTF7fq1XUhX3aexOI2eTx0B2bBpD28TcYvqo6Y+aBKHVbo8gnbMr5IoIkI\n"
"rYz8CXrbbZFRilsHRQgzyEmTq/Wp0GVt/zakMF7suA8nl/AQcKDOWGBnEFc+okAe\n"
"K0P/4R4UnQSPU8SfsFBGxm4PXN4BZktZ10LC/xKMJBkdSD0vTLce9Sx7xR4PUIaN\n"
"n2x0D4zZG7px73kB0Q==\n"
"-----END CERTIFICATE-----";
const unsigned char ecdsa_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDNjCCAZ6gAwIBAgIUDzxOEj+8WUrLa1M97arwkEo5gEwwDQYJKoZIhvcNAQEL\n"
"BQAwMjEbMBkGA1UEAwwSZ2xld2x3eWRfcGFja2VkX2NhMRMwEQYDVQQKEwpiYWJl\n"
"bG91ZXN0MB4XDTE5MTIwNjEzNTYxM1oXDTIwMTEyMDEzNTYxM1owYDEYMBYGA1UE\n"
"AwwPZ2xld2x3eWRfcGFja2VkMSIwIAYDVQQLExlBdXRoZW50aWNhdG9yIEF0dGVz\n"
"dGF0aW9uMRMwEQYDVQQKEwpiYWJlbG91ZXN0MQswCQYDVQQGEwJDQTBZMBMGByqG\n"
"SM49AgEGCCqGSM49AwEHA0IABOjeoVGraskp+jax8TTOXy92o6PGGN2Tl3XshqN/\n"
"XZnfkyxxLxKvJ0igfQ4Qy4/9w8PGjVilnY4zR3y25VJ7KLejYTBfMAwGA1UdEwEB\n"
"/wQCMAAwDwYDVR0PAQH/BAUDAweAADAdBgNVHQ4EFgQU34GPDg2bLIneLKIfjYjU\n"
"NuiU170wHwYDVR0jBBgwFoAUlOaykWFTL+EV/0PHksB2Dh1k1KAwDQYJKoZIhvcN\n"
"AQELBQADggGBAFHNuUQUkZaunXfV3qSemhlyHH1hnt6YXJLIl2IKugg/mg8hga2C\n"
"dBN7MMcVYpXtNI8AKfSIZRu3v16OMIajCIh7PYGa5asbJZgtOkbvfc58eaWhzl8U\n"
"B0j89aGlntZs3WWINYgqfzBS6Pw3SJ5iVTpS+xH2JSWxZYX3uvEDkVkw1VjmyyN3\n"
"ZX0tkFTKQB3GNFZwesxoRKizsu8r+tCIqgfqRTG7FIOa/UB3MXVClA//+TCnW2RI\n"
"48JzjY/YhO54pWVsblHAQwMOmuHlJrnfLFPvBqFx5mi8Z5jHfZipsNksIteKFdtG\n"
"3FvjQYIj2wJM9k7XHrQ3szxwvq9Ss2cyCBPArrKVpBTibypIkON9R2Peocr3HkUx\n"
"YYhu3pNumaSdGzL0r7A2iGIXy9orIAQ8f1i7iaYDBWs/PkJ340iHRZtSuez8F+GN\n"
"NUV15utv9AMvahkCI5ZS71TAv4AFjsZpsvYuCvpUUPdZpC+r9lk8H1wa4VA+mujL\n"
"2Yxh1fFV7ONNjA==\n"
"-----END CERTIFICATE-----";

int callback_x5u_rsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)ecdsa_crt);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_rhonabwy_import_from_json_str)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_simple_hmac), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_simple_rsa), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_simple_ecdsa), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_kty), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_crv), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_x), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_y), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_use), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_kid), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_missing_x), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_missing_y), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_b64_x), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_b64_y), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str_invalid_k), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str_invalid_b64_k), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_n), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_b64_n), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_e), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_b64_e), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_alg), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_d), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_d), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_p), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_p), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_q), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_q), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_dp), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_dp), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_dq), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_dq), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_qi), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_b64_qi), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_invalid_k), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_invalid_b64_k), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_only), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str_invalid_x5c), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str_invalid_x5c_content), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_x5c_only), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_x5c_invalid_x5c_content), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str_invalid_x5u), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str_invalid_x5u_protocol), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_invalid_json), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_invalid_json_container), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_symmetric_key(NULL, symmetric_key, o_strlen((const char *)symmetric_key)), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_symmetric_key(jwk, NULL, o_strlen((const char *)symmetric_key)), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_symmetric_key(jwk, symmetric_key, 0), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_symmetric_key(jwk, symmetric_key, o_strlen((const char *)symmetric_key)), RHN_OK);
  ck_assert_str_eq("oct", r_jwk_get_property_str(jwk, "kty"));
  ck_assert_str_eq((const char *)symmetric_key_b64url, r_jwk_get_property_str(jwk, "k"));
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_json_t)
{
  jwk_t * jwk;
  json_t * j_input;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_kty, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_crv, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_x, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_y, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_use, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_kid, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdsa_str_invalid_k, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_n, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_e, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_alg, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_d, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_p, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_q, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_dp, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_dq, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_qi, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_key_symmetric, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_key_symmetric_invalid_k, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5c_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5c_str_invalid_x5c, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5u_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5u_str_invalid_x5u, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_invalid_json_container, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_pem)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, rsa_2048_pub, o_strlen((const char *)rsa_2048_pub)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, ecdsa_521_pub, o_strlen((const char *)ecdsa_521_pub)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, x509_cert, o_strlen((const char *)x509_cert)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, rsa_2048_priv, o_strlen((const char *)rsa_2048_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ecdsa_521_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, error_pem, o_strlen((const char *)error_pem)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_der)
{
  jwk_t * jwk;
  unsigned char der_decoded[4096];
  size_t der_dec_len = 0;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(rsa_2048_pub_der, o_strlen((const char *)rsa_2048_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(ecdsa_521_pub_der, o_strlen((const char *)ecdsa_521_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(x509_cert_der, o_strlen((const char *)x509_cert_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(rsa_2048_priv_der, o_strlen((const char *)rsa_2048_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(ecdsa_521_priv_der, o_strlen((const char *)ecdsa_521_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_x5u)
{
  jwk_t * jwk;
  int type;
  struct _u_instance instance;
  unsigned int bits = 0;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, HTTPS_CERT_KEY, HTTPS_CERT_PEM), U_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_X509_TYPE_CERTIFICATE, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7462/x5u_rsa_crt"), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_X509_TYPE_CERTIFICATE, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7462/x5u_ecdsa_crt"), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_key_type)
{
  jwk_t * jwk;
  int type;
  struct _u_instance instance;
  unsigned int bits = 0;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, HTTPS_CERT_KEY, HTTPS_CERT_PEM), U_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 16);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_only), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_x5c_only), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_ecdsa_pub), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
  
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_extract_pubkey)
{
  jwk_t * jwk_privkey, * jwk_pubkey;
  int type;
  unsigned int bits = 0;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_privkey, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, rsa_2048_priv, o_strlen((const char *)rsa_2048_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_extract_pubkey(jwk_privkey, jwk_pubkey, 0), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_privkey, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ecdsa_521_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_extract_pubkey(jwk_privkey, jwk_pubkey, 0), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 512);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk_privkey, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, rsa_2048_pub, o_strlen((const char *)rsa_2048_pub)), RHN_OK);
  ck_assert_int_ne(r_jwk_extract_pubkey(jwk_privkey, jwk_pubkey, 0), RHN_OK);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWK import function tests");
  tc_core = tcase_create("test_rhonabwy_import");
  tcase_add_test(tc_core, test_rhonabwy_import_from_json_str);
  tcase_add_test(tc_core, test_rhonabwy_import_from_json_t);
  tcase_add_test(tc_core, test_rhonabwy_import_from_pem);
  tcase_add_test(tc_core, test_rhonabwy_import_from_der);
  tcase_add_test(tc_core, test_rhonabwy_import_from_x5u);
  tcase_add_test(tc_core, test_rhonabwy_key_type);
  tcase_add_test(tc_core, test_rhonabwy_extract_pubkey);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWK import tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
