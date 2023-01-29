/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

#include <check.h>
#include <rhonabwy.h>
#include <orcania.h>
#include <yder.h>
#include <ulfius.h>

#define HTTPS_PORT 7462
#define FULLCHAIN1_FILE "cert/fullchain1.crt"
#define FULLCHAIN2_FILE "cert/fullchain2.crt"
#define FULLCHAIN_ERROR_FILE "cert/fullchain-error.crt"
#define HTTPS_CERT_KEY "cert/server.key"
#define HTTPS_CERT_PEM "cert/server.crt"

const unsigned char symmetric_key[] = "secret";
const unsigned char symmetric_key_b64url[] = "c2VjcmV0";

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
const char jwk_pubkey_secp256k1_str[] = "{\"crv\":\"secp256k1\",\"kid\":\"JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw\",\"kty\":\"EC\","
                                        "\"x\":\"dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A\",\"y\":\"36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA\"}";

const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                     "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str_invalid_k[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                               "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":42,\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str_invalid_b64_k[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                                   "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\";error;\","\
                                                   "\"use\":\"enc\",\"kid\":\"1\"}";

const char jwk_privkey_eddsa_str[] = "{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","\
                                     "\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}";
const char jwk_privkey_eddsa_str_invalid_d[] = "{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","\
                                               "\"d\":42}";
const char jwk_privkey_eddsa_str_invalid_b64_d[] = "{\"kty\":\"OKP\",\"use\":\"sig\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\","\
                                                   "\"d\":\";error;\"}";

const char jwk_privkey_ecdh_str[] = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\","
                                    "\"d\":\"RVqkt2ZmEiUY-OGyag9rXe7vsDm2BQ_XykdxhLv9pd4\"}";
const char jwk_privkey_ecdh_str_invalid_d[] = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\","
                                    "\"d\":42}";
const char jwk_privkey_ecdh_str_invalid_b64_d[] = "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\","
                                    "\"d\":\";error;\"}";

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

const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
const char jwk_key_symmetric_invalid_k[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":42}";
const char jwk_key_symmetric_invalid_b64_k[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\";error;\"}";

const char jwk_pubkey_rsa_x5c_str[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"AL64zn8_QnHYMeZ0LncoXaEde1fiLm1jHjmQsF_449IYALM9if6amFtPDy"\
                                      "2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf_u3WG7K-IiZhtELto_A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1qu"\
                                      "GmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel-W1GC8ugMhyr4_p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqP"\
                                      "pnjL1XyW-oyVVkaZdklLQp2Btgt9qr21m42f4wTw-Xrp6rCKNb0\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
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
                                       "zYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZUSpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==\"],\""\
                                       "kty\":\"RSA\"}";
const char jwk_pubkey_rsa_x5c_only_invalid_type[] = "{\"alg\": \"ES256\",\"x5c\":[\"MIIFkjCCBHqgAwIBAgIQRXroN0ZOdRkBAAAAAAPunzANBgkqhkiG9w0BAQsFADBCMQswCQYDVQQGEwJVUzEeMBw"\
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
                                                    "zYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZUSpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==\"],\""\
                                                    "kty\":\"EC\"}";

const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"sUWjL3wK1B_dQbXbhSXaodF0gXMNlZg3ZecjZIJOKgXGDVOnV0ly4evW8xkn8F2gC3TYJXik7efdhGdiaYul9kyzpPBr53"\
                                       "ELHMmAeI_I1rnF4pgIwfN1vBsaDwJw9w0R6FQ9fxDUIte47WdElEHhtST9V874mMehsSUG4xM2qiBvvbWwX0KCyKk6BY_CdyljUjAPUShcVysKUTyfefew"\
                                       "38KUVTVpk2vWLlN-a41iC_gxGvLtH142LDiDx_s-Kh37f4paD2zsEw5McF81eiKTAfrraIC1Gj2BxyEj6n2EjqyI-NFRsSUmqfPoFgiMzlEWj4P8AwvfE9"\
                                       "jbjXz_E0GOISiXt4L-06U7rLoGHFri5oVI6KUkLAOwwwTri-ikeQFx68IKvhytBiX1O-XHh51JZyyC-fcKKN-_ATgGKIiR63M5UWYxO2JkVkPvpzORKJUi"\
                                       "vePFQbkEcxYZb9VqoVZ04sfpfGb3h2douzBrKbkDP_Jf-O0JPKDTltrUJOpZbYhV\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-"\
                                       "29\",\"x5u\":\"https://localhost:7464/x5u_rsa_crt\"}";

const char jwk_pubkey_rsa_x5u_only_rsa_pub[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7464/x5u_rsa_crt\"}";
const char jwk_pubkey_rsa_x5u_only_ecdsa_pub[] = "{\"kty\":\"EC\",\"alg\":\"ES256\",\"x5u\":\"https://localhost:7464/x5u_ecdsa_crt\"}";
const char jwk_pubkey_rsa_x5u_only_eddsa_pub[] = "{\"kty\":\"OKP\",\"alg\":\"ES256\",\"x5u\":\"https://localhost:7464/x5u_eddsa_crt\"}";
const char jwk_pubkey_rsa_x5u_only_ecdsa_pub_invalid_type[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7464/x5u_ecdsa_crt\"}";

const char jwk_pubkey_rsa_x5u_str_invalid_x5u[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWK"\
                                                  "RXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZ"\
                                                  "zu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqD"\
                                                  "Kgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":42}";
const char jwk_pubkey_rsa_x5u_str_invalid_x5u_protocol[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                                           "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                                           "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                                           ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":\"http://www.example.com/x509\"}";

const char jwk_invalid_json[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"";
const char jwk_invalid_json_container[] = "[{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}]";

const char jwk_privkey_rsa_x5c_x5u_x5t_x5ts256_str[] = 
"{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
"HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\","\
"\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
"b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
"DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
"BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
"DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
"G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
"p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
"Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
"qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
"MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
"MPvACWpkA6SdS4xSvdXK3IVfOWA==\"],\"x5u\":\"https://localhost:7464/x5u_rsa_crt\",\"x5t\":\"abcd\",\"x5t#S256\":\"abcdS256\"}";

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

const unsigned char ed25519_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MC4CAQAwBQYDK2VwBCIEIGHd6sDtpeBmGNOiJ/KG8Xa85bywgofA0jAZH/1f3Xnj\n"
"-----END PRIVATE KEY-----";
const unsigned char ed25519_priv_der[] = "MC4CAQAwBQYDK2VwBCIEIGHd6sDtpeBmGNOiJ/KG8Xa85bywgofA0jAZH/1f3Xnj";

const unsigned char ed448_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MEcCAQAwBQYDK2VxBDsEOTpVxVqZcGq1PfqUS+Tct02m1uSsb30rIiBuartRwFqo\n"
"9NeuVKd9K0YVM9biq3X7WW1kDOdPK0nBog==\n"
"-----END PRIVATE KEY-----";
const unsigned char ed448_priv_der[] = 
"MEcCAQAwBQYDK2VxBDsEOTpVxVqZcGq1PfqUS+Tct02m1uSsb30rIiBuartRwFqo"
"9NeuVKd9K0YVM9biq3X7WW1kDOdPK0nBog==";

const unsigned char x25519_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MC4CAQAwBQYDK2VuBCIEIHgz5JhbrOOKkJIqxQnnSpKGC1ncvqPBwCGIFJtsVeVT\n"
"-----END PRIVATE KEY-----";
const unsigned char x25519_priv_der[] = "MC4CAQAwBQYDK2VuBCIEIHgz5JhbrOOKkJIqxQnnSpKGC1ncvqPBwCGIFJtsVeVT";

const unsigned char x448_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MEYCAQAwBQYDK2VvBDoEOKBu7PIoYBVNeVQ8erUnN7B6M+Jtmvdjl/GMmoxZ00DA\n"
"OicTWxiiQZCn0bzut2UqtQ6ay/oN0y75\n"
"-----END PRIVATE KEY-----";
const unsigned char x448_priv_der[] = 
"MEYCAQAwBQYDK2VvBDoEOKBu7PIoYBVNeVQ8erUnN7B6M+Jtmvdjl/GMmoxZ00DA"
"OicTWxiiQZCn0bzut2UqtQ6ay/oN0y75";

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
const unsigned char eddsa_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDLDCCAZSgAwIBAgIUTuClu4hNHMPpKcw6+rjDqVXaQVkwDQYJKoZIhvcNAQEL\n"
"BQAwMjEbMBkGA1UEAwwSZ2xld2x3eWRfcGFja2VkX2NhMRMwEQYDVQQKEwpiYWJl\n"
"bG91ZXN0MB4XDTIxMDgzMDE0MzY1OVoXDTIyMDgxNTE0MzY1OVowYDEYMBYGA1UE\n"
"AwwPZ2xld2x3eWRfcGFja2VkMSIwIAYDVQQLExlBdXRoZW50aWNhdG9yIEF0dGVz\n"
"dGF0aW9uMRMwEQYDVQQKEwpiYWJlbG91ZXN0MQswCQYDVQQGEwJDQTAqMAUGAytl\n"
"cAMhAIouRueZYs1tzatbfdECcJwHwun+WXzH3CBy8BJxJYcLo4GFMIGCMCEGCysG\n"
"AQQBguUcAQEEBBIEEEJDREVGR0hJUFFSU1RVVlcwDAYDVR0TAQH/BAIwADAPBgNV\n"
"HQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBS6GVmW2tFiBlvcLopMuEv2UFlTRTAfBgNV\n"
"HSMEGDAWgBRYdd7pkDm7ZUQq0dg+usf8qHk4DjANBgkqhkiG9w0BAQsFAAOCAYEA\n"
"K7L+G+skxijb+9onGRpnsJ98JTBiPMoyvvTzmkw54JiYufG3fkbumM+TRohyydEQ\n"
"4bZT/yiO8KJz3Y3D7QKKDxZTPm6/lGlrFVzlJ18CNvRoypvws1VOik6iroJBvCQO\n"
"YpiuKlcK+g7kQxGkk5i/2roohzxJHFUqJ6vKGRsxg3GySBSCS+BjLPHQckUnQhdP\n"
"WcNthoYnqNpSwyAIWgQ6D/Hus7nUI3EVzDmXPwWYRhxtuBVMhw9nWi7xO89kQGjl\n"
"zcCFzVI23ktwTDBt1XNHlxwuqnWKDBdPFd+UJvplE9tcr2I5IoLf+wtUx9/8zPcS\n"
"cYWbe1bTykoZXGFJJaVU+58sT9CseICfScCwwMgd2kZ7zFtgceOqaOuIgAoD0ub2\n"
"2YbXZ/M+B1Z1TDQ2qF+KdHBQvrp8bbf0Y3CMgPPzJmABuzVSOxazqBSgMSufrlzA\n"
"s0nRjPr3UZRaPv5RDpGk8eqGU7szhTrMpr0/lX30YNuXndPWfD/axRvvAH0EtvhI\n"
"-----END CERTIFICATE-----";

const char x5u_fullchain1_crt[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7465/x5u_fullchain1\"}";
const char x5u_fullchain2_crt[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7465/x5u_fullchain2\"}";
const char x5u_fullchain_error_crt[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7465/x5u_fullchain_error\"}";
const char x5u_fullchain1_trucated_crt[] = "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"x5u\":\"https://localhost:7465/x5u_fullchain1_trucated\"}";

static char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
  }
  
  return buffer;
}

int callback_x5u_rsa_priv (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_2048_priv);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_rsa_pubkey (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_2048_pub);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_error (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, "ZXJyb3I=");
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_rsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)ecdsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_eddsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)eddsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_fullchain1 (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * cert_file = get_file_content(FULLCHAIN1_FILE);
  ulfius_set_string_body_response(response, 200, cert_file);
  o_free(cert_file);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_fullchain2 (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * cert_file = get_file_content(FULLCHAIN2_FILE);
  ulfius_set_string_body_response(response, 200, cert_file);
  o_free(cert_file);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_fullchain_error (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * cert_file = get_file_content(FULLCHAIN_ERROR_FILE);
  ulfius_set_string_body_response(response, 200, cert_file);
  o_free(cert_file);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_fullchain1_trucated (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * cert_file = get_file_content(FULLCHAIN1_FILE);
  cert_file[o_strlen(cert_file)-30] = '\0';
  ulfius_set_string_body_response(response, 200, cert_file);
  o_free(cert_file);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_rhonabwy_import_from_json_str)
{
  jwk_t * jwk;
  struct _u_instance instance;
  char * http_key, * http_cert;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7464, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_secp256k1_str), RHN_OK);
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
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_eddsa_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_eddsa_str_invalid_d), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_eddsa_str_invalid_b64_d), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdh_str), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdh_str_invalid_d), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdh_str_invalid_b64_d), RHN_ERROR_PARAM);
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
  
#ifdef R_WITH_CURL
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str_invalid_x5u), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str_invalid_x5u_protocol), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_invalid_json), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_invalid_json_container), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
#ifdef R_WITH_CURL
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  r_jwk_free(jwk);
#endif
  
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
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_password(NULL, (const char *)symmetric_key), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_password(jwk, NULL), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_password(jwk, ""), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_password(jwk, (const char *)symmetric_key), RHN_OK);
  ck_assert_str_eq("oct", r_jwk_get_property_str(jwk, "kty"));
  ck_assert_str_eq((const char *)symmetric_key_b64url, r_jwk_get_property_str(jwk, "k"));
  r_jwk_free(jwk);
  
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
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
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_eddsa_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_eddsa_str_invalid_d, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_ERROR_PARAM);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdh_str, JSON_DECODE_ANY, NULL), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_t(jwk, j_input), RHN_OK);
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_ne(j_input = json_loads(jwk_privkey_ecdh_str_invalid_d, JSON_DECODE_ANY, NULL), NULL);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, rsa_2048_pub, o_strlen((const char *)rsa_2048_pub)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC));
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, ecdsa_521_pub, o_strlen((const char *)ecdsa_521_pub)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, ecdsa_521_pub, o_strlen((const char *)ecdsa_521_pub)), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC));
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, x509_cert, o_strlen((const char *)x509_cert)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, x509_cert, o_strlen((const char *)x509_cert)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC));
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, rsa_2048_priv, o_strlen((const char *)rsa_2048_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, rsa_2048_priv, o_strlen((const char *)rsa_2048_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ecdsa_521_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, ecdsa_521_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, error_pem, o_strlen((const char *)error_pem)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, error_pem, o_strlen((const char *)error_pem)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ed25519_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, ed25519_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);

#if GNUTLS_VERSION_NUMBER >= 0x03060e
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, ed448_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, ed448_priv, o_strlen((const char *)ecdsa_521_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);
#endif

#if 0 // Disabled for now
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, x25519_priv, o_strlen((const char *)x25519_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, x25519_priv, o_strlen((const char *)x25519_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, x448_priv, o_strlen((const char *)x448_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_UNSPECIFIED, R_FORMAT_PEM, x448_priv, o_strlen((const char *)x448_priv)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_ne(0, r_jwk_key_type(jwk, NULL, 0) & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE));
  r_jwk_free(jwk);
#endif
#endif
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
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
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
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(ed25519_priv_der, o_strlen((const char *)ed25519_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

#if GNUTLS_VERSION_NUMBER >= 0x03060e
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(ed448_priv_der, o_strlen((const char *)ed448_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif

#if 0 // Disabled for now
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(x25519_priv_der, o_strlen((const char *)x25519_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(o_base64_decode(x448_priv_der, o_strlen((const char *)x448_priv_der), der_decoded, &der_dec_len), 1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_DER, der_decoded, der_dec_len), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
#endif
}
END_TEST

START_TEST(test_rhonabwy_import_from_gnutls)
{
  gnutls_privkey_t privkey;
  gnutls_x509_privkey_t x509_key;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;
  gnutls_datum_t data;
  jwk_t * jwk;

  gnutls_privkey_init(&privkey);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_init(&x509_key));
  data.data = (unsigned char *)rsa_2048_priv;
  data.size = sizeof(rsa_2048_priv);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_privkey_import_x509(privkey, x509_key, 0));
  ck_assert_int_eq(RHN_OK, r_jwk_init(&jwk));
  ck_assert_int_eq(RHN_OK, r_jwk_import_from_gnutls_privkey(jwk, privkey));
  gnutls_privkey_deinit(privkey);
  gnutls_x509_privkey_deinit(x509_key);
  r_jwk_free(jwk);

  gnutls_pubkey_init(&pubkey);
  data.data = (unsigned char *)rsa_2048_pub;
  data.size = sizeof(rsa_2048_pub);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_int_eq(RHN_OK, r_jwk_init(&jwk));
  ck_assert_int_eq(RHN_OK, r_jwk_import_from_gnutls_pubkey(jwk, pubkey));
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  gnutls_x509_crt_init(&crt);
  data.data = (unsigned char *)x509_cert;
  data.size = sizeof(x509_cert);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_int_eq(RHN_OK, r_jwk_init(&jwk));
  ck_assert_int_eq(RHN_OK, r_jwk_import_from_gnutls_x509_crt(jwk, crt));
  gnutls_x509_crt_deinit(crt);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_import_from_x5u)
{
#ifdef R_WITH_CURL
  jwk_t * jwk;
  int type;
  unsigned int bits = 0;
#endif
  struct _u_instance instance;
  char * http_key, * http_cert;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7463, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
#ifdef R_WITH_CURL
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_crt"), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_ecdsa_crt"), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
#endif
  
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_import_from_x5u_x5c_invalid)
{
#ifdef R_WITH_CURL
  jwk_t * jwk;
#endif
  struct _u_instance instance;
  char * http_key, * http_cert;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7463, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_priv", NULL, 0, &callback_x5u_rsa_priv, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_pubkey", NULL, 0, &callback_x5u_rsa_pubkey, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/error", NULL, 0, &callback_x5u_error, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
#ifdef R_WITH_CURL
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_priv"), RHN_ERROR);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_pubkey"), RHN_ERROR);
  ck_assert_int_eq(r_jwk_import_from_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/error"), RHN_ERROR);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_x5c(jwk, (const char *)rsa_2048_priv_der), RHN_ERROR);
  ck_assert_int_eq(r_jwk_import_from_x5c(jwk, (const char *)rsa_2048_pub_der), RHN_ERROR);
  ck_assert_int_eq(r_jwk_import_from_x5c(jwk, "ZXJyb3I="), RHN_ERROR);
  r_jwk_free(jwk);
  
  o_free(http_key);
  o_free(http_cert);
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
  char * http_key, * http_cert;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7464, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_eddsa_crt", NULL, 0, &callback_x5u_eddsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
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
  ck_assert_int_ne(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
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
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
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
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 128);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_REMOTE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2056);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#ifdef R_WITH_CURL
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_REMOTE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_only), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_REMOTE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_only_invalid_type), RHN_ERROR_PARAM);
  ck_assert_int_eq((type = r_jwk_key_type(jwk, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_REMOTE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#ifdef R_WITH_CURL
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 3072);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_ecdsa_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);

  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_eddsa_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_ERROR_PARAM);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);

  bits = 0;
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_ecdsa_pub_invalid_type), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid_x5u(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_ERROR_PARAM);
  ck_assert_int_ne((type = r_jwk_key_type(jwk, &bits, R_FLAG_IGNORE_SERVER_CERTIFICATE)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk);
#endif
#endif
  
  o_free(http_key);
  o_free(http_cert);
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
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
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
  ck_assert_int_eq(bits, 521);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EC, 0);
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
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_x5c_x5u_x5t_x5ts256_str), RHN_OK);
  ck_assert_int_eq(r_jwk_extract_pubkey(jwk_privkey, jwk_pubkey, 0), RHN_OK);
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 2048);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk_pubkey, "x5c"), r_jwk_get_property_array_size(jwk_privkey, "x5c"));
  ck_assert_str_eq(r_jwk_get_property_array(jwk_pubkey, "x5c", 0), r_jwk_get_property_array(jwk_privkey, "x5c", 0));
  ck_assert_str_eq(r_jwk_get_property_str(jwk_pubkey, "x5u"), r_jwk_get_property_str(jwk_privkey, "x5u"));
  ck_assert_str_eq(r_jwk_get_property_str(jwk_pubkey, "x5t"), r_jwk_get_property_str(jwk_privkey, "x5t"));
  ck_assert_str_eq(r_jwk_get_property_str(jwk_pubkey, "x5t#S256"), r_jwk_get_property_str(jwk_privkey, "x5t#S256"));
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_append_x5c)
{
  jwk_t * jwk;
  char * http_cert = get_file_content(HTTPS_CERT_PEM);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, rsa_crt, o_strlen((const char *)rsa_crt)), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 1);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 0), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5c", 1), NULL);
  ck_assert_int_eq(r_jwk_append_x5c(NULL, R_FORMAT_PEM, rsa_crt, o_strlen((const char *)rsa_crt)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_append_x5c(jwk, R_FORMAT_DER, rsa_crt, o_strlen((const char *)rsa_crt)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_append_x5c(jwk, R_FORMAT_PEM, NULL, o_strlen((const char *)rsa_crt)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_append_x5c(jwk, R_FORMAT_PEM, rsa_crt, o_strlen((const char *)rsa_crt)-30), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_append_x5c(jwk, R_FORMAT_PEM, rsa_crt, o_strlen((const char *)rsa_crt)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 1), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5c", 2), NULL);
  ck_assert_int_eq(r_jwk_append_x5c(jwk, R_FORMAT_PEM, (const unsigned char *)http_cert, o_strlen(http_cert)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 3);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 1), NULL);
  ck_assert_ptr_ne(r_jwk_get_property_array(jwk, "x5c", 2), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5c", 3), NULL);
  o_free(http_cert);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_parse_x5c)
{
  jwk_t * jwk;
  char * cert_file;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content("cert/fullchain1.crt"), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  o_free(cert_file);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_validate_xc5_chain)
{
  jwk_t * jwk;
  char * cert_file;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content(FULLCHAIN1_FILE), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, 0), RHN_OK);
  o_free(cert_file);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content(FULLCHAIN2_FILE), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, 0), RHN_OK);
  o_free(cert_file);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content(FULLCHAIN1_FILE), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)-30), RHN_ERROR_PARAM);
  o_free(cert_file);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content(FULLCHAIN_ERROR_FILE), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, 0), RHN_ERROR_INVALID);
  o_free(cert_file);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), -1);
  ck_assert_ptr_ne(cert_file = get_file_content(FULLCHAIN1_FILE), NULL);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)cert_file, o_strlen(cert_file)), RHN_OK);
  ck_assert_int_eq(r_jwk_get_property_array_size(jwk, "x5c"), 2);
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "x5c", "error"), RHN_OK);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, 0), RHN_ERROR_INVALID);
  o_free(cert_file);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_validate_x5u_chain)
{
#ifdef R_WITH_CURL
  jwk_t * jwk;
#endif
  struct _u_instance instance;
  char * http_key, * http_cert;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7465, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_fullchain1", NULL, 0, &callback_x5u_fullchain1, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_fullchain2", NULL, 0, &callback_x5u_fullchain2, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_fullchain1_trucated", NULL, 0, &callback_x5u_fullchain1_trucated, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_fullchain_error", NULL, 0, &callback_x5u_fullchain_error, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);

#ifdef R_WITH_CURL
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, x5u_fullchain1_crt), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, x5u_fullchain2_crt), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, x5u_fullchain_error_crt), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_ERROR_INVALID);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, x5u_fullchain1_trucated_crt), RHN_OK);
  ck_assert_ptr_ne(r_jwk_get_property_str(jwk, "x5u"), NULL);
  ck_assert_int_eq(r_jwk_validate_x5c_chain(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_ERROR_INVALID);
  r_jwk_free(jwk);
#endif

  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_quick_import)
{
  jwk_t * jwk;
  json_t * j_input;
  unsigned char der_decoded[4096];
  size_t der_dec_len = 0;
  struct _u_instance instance;
  char * http_key, * http_cert;
  gnutls_privkey_t privkey;
  gnutls_x509_privkey_t x509_key;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;
  gnutls_datum_t data;
  
  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7463, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str));
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str_invalid_kty));
  
  ck_assert_ptr_ne(NULL, j_input = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_T, j_input));
  json_decref(j_input);
  r_jwk_free(jwk);
  
  ck_assert_ptr_ne(NULL, j_input = json_loads(jwk_pubkey_ecdsa_str_invalid_kty, JSON_DECODE_ANY, NULL));
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_JSON_T, j_input));
  json_decref(j_input);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PEM, R_X509_TYPE_PUBKEY, rsa_2048_pub, sizeof(rsa_2048_pub)));
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_PEM, R_X509_TYPE_PUBKEY, error_pem, sizeof(error_pem)));

  ck_assert_int_eq(o_base64_decode(rsa_2048_pub_der, o_strlen((const char *)rsa_2048_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_DER, R_X509_TYPE_PUBKEY, der_decoded, der_dec_len));
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_OK);
  r_jwk_free(jwk);

  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_DER, R_X509_TYPE_PUBKEY, der_decoded+40, der_dec_len-40));

  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_privkey_init(&privkey));
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_init(&x509_key));
  data.data = (unsigned char *)rsa_2048_priv;
  data.size = sizeof(rsa_2048_priv);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_privkey_import_x509(privkey, x509_key, 0));
  ck_assert_ptr_ne(RHN_OK, jwk = r_jwk_quick_import(R_IMPORT_G_PRIVKEY, privkey));
  gnutls_privkey_deinit(privkey);
  gnutls_x509_privkey_deinit(x509_key);
  r_jwk_free(jwk);

  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_G_PRIVKEY, NULL));
  
  gnutls_pubkey_init(&pubkey);
  data.data = (unsigned char *)rsa_2048_pub;
  data.size = sizeof(rsa_2048_pub);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_G_PUBKEY, pubkey));
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_G_PUBKEY, NULL));
  
  gnutls_x509_crt_init(&crt);
  data.data = (unsigned char *)x509_cert;
  data.size = sizeof(x509_cert);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_G_CERT, crt));
  gnutls_x509_crt_deinit(crt);
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_G_CERT, NULL));
  
#ifdef R_WITH_CURL

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_crt"));
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/error"));
  
#if GNUTLS_VERSION_NUMBER >= 0x030600

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_ecdsa_crt"));
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/error"));
#endif
#endif
  
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_SYMKEY, symmetric_key, sizeof(symmetric_key)));
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jwk_quick_import(R_IMPORT_SYMKEY, NULL, sizeof(symmetric_key)));
  
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, symmetric_key));
  r_jwk_free(jwk);
  
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
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
  tcase_add_test(tc_core, test_rhonabwy_import_from_gnutls);
  tcase_add_test(tc_core, test_rhonabwy_import_from_x5u);
  tcase_add_test(tc_core, test_rhonabwy_import_from_x5u_x5c_invalid);
  tcase_add_test(tc_core, test_rhonabwy_key_type);
  tcase_add_test(tc_core, test_rhonabwy_extract_pubkey);
  tcase_add_test(tc_core, test_rhonabwy_append_x5c);
  tcase_add_test(tc_core, test_rhonabwy_parse_x5c);
  tcase_add_test(tc_core, test_rhonabwy_validate_xc5_chain);
  tcase_add_test(tc_core, test_rhonabwy_validate_x5u_chain);
  tcase_add_test(tc_core, test_rhonabwy_quick_import);
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
  r_global_init();
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  r_global_close();
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
