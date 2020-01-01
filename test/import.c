/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <rhonabwy.h>
#include <orcania.h>

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

const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str_invalid_d[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":42,\"use\":\"enc\",\"kid\":\"1\"}";

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"\
                                   "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ"\
                                   "zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqD"\
                                   "Kgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_n[] = "{\"kty\":\"RSA\",\"n\":42,\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_e[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_"\
                                             "BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs"\
                                             "8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls"\
                                             "1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":42,\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_invalid_alg[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc"\
                                               "_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSq"\
                                               "zs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw"\
                                               "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS257\",\"kid\":\"2011-04-29\"}";

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

const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
const char jwk_key_symmetric_invalid_k[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":42}";

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

const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"\
                                       "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ"\
                                       "zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqD"\
                                       "Kgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":\"https://www.example.com/x509\"}";
const char jwk_pubkey_rsa_x5u_str_invalid_x5u[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"\
                                                   "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ"\
                                                   "zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqD"\
                                                   "Kgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":42}";

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

START_TEST(test_rhonabwy_import_from_json_str)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_kty), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_crv), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_x), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_y), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_use), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str_invalid_kid), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_ecdsa_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_ecdsa_str_invalid_d), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_n), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_e), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_str_invalid_alg), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_d), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_p), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_q), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_dp), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_dq), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str_invalid_qi), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_key_symmetric), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_key_symmetric_invalid_k), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str_invalid_x5c), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str_invalid_x5u), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_invalid_json), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_invalid_json_container), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_json_t)
{
  jwk_t * jwk;
  json_t * j_input;
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_kty, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_crv, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_x, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_y, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_use, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_kid, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdsa_str_invalid_d, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_n, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_e, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_str_invalid_alg, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_d, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_p, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_q, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_dp, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_dq, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_rsa_str_invalid_qi, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_key_symmetric, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_key_symmetric_invalid_k, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5c_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5c_str_invalid_x5c, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5u_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_OK);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_pubkey_rsa_x5u_str_invalid_x5u, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_invalid_json_container, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_import_from_json_t(jwk, j_input), R_ERROR_PARAM);
  json_decref(j_input);
  r_free_jwk(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_pem)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, rsa_2048_pub, o_strlen((const char *)rsa_2048_pub)), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, ecdsa_521_pub, o_strlen((const char *)ecdsa_521_pub)), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, x509_cert, o_strlen((const char *)x509_cert)), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, rsa_2048_priv, o_strlen((const char *)rsa_2048_priv)), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ecdsa_521_priv, o_strlen((const char *)ecdsa_521_priv)), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, error_pem, o_strlen((const char *)error_pem)), R_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_ERROR_PARAM);
  r_free_jwk(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_import_from_der)
{
  jwk_t * jwk;
  unsigned char der_decoded[4096];
  size_t der_dec_len = 0;
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(o_base64_decode(rsa_2048_pub_der, o_strlen((const char *)rsa_2048_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_DER, der_decoded, der_dec_len), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(o_base64_decode(ecdsa_521_pub_der, o_strlen((const char *)ecdsa_521_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_DER, der_decoded, der_dec_len), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(o_base64_decode(x509_cert_der, o_strlen((const char *)x509_cert_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_DER, der_decoded, der_dec_len), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(o_base64_decode(rsa_2048_priv_der, o_strlen((const char *)rsa_2048_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(o_base64_decode(ecdsa_521_priv_der, o_strlen((const char *)ecdsa_521_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), R_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), R_OK);
  r_free_jwk(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_key_type)
{
  jwk_t * jwk;
  int type;
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_ecdsa_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_privkey_rsa_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_key_symmetric), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  ck_assert_int_eq(r_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), R_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk)), R_KEY_TYPE_NONE);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_free_jwk(jwk);
  
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy import function tests");
  tc_core = tcase_create("test_rhonabwy_import");
  tcase_add_test(tc_core, test_rhonabwy_import_from_json_str);
  tcase_add_test(tc_core, test_rhonabwy_import_from_json_t);
  tcase_add_test(tc_core, test_rhonabwy_import_from_pem);
  tcase_add_test(tc_core, test_rhonabwy_import_from_der);
  tcase_add_test(tc_core, test_rhonabwy_key_type);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy import tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
