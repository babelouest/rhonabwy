/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination..."

#if defined(R_ECDH_ENABLED) && GNUTLS_VERSION_NUMBER >= 0x030600

#define TOKEN "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMgo.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_CIPHER_KEY "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.IEru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_IV "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPEQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FEbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_TAG "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PE8wi2GGHqzww"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGH"
#define TOKEN_INVALID_HEADER_B64 ";error;.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_CIPHER_KEY_B64 "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.;error;.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.;error;.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.;error;.OwcQLpd3_PZ8wi2GGHqzww"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhcHUiOiJjR3h2Y0FvIiwiYXB2IjoiWjNKMWRBbyIsImtpZCI6IjEiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiQU13cm02anpoX2d3M1Zmb0xZNE4zSmktSU55aU9NNEZYbnJHODhqOUdodWEiLCJ5IjoiUlJOUFV3dlhDRUV3TVhmOElOcW9GYnYwWHpaNTVGSEN3dEV5cGhReFIwMCIsImNydiI6IlAtMjU2In19.Izru9wTpv5FPlPp7jpDZkueMZ3luMjXBaI2s0YgUtMiDPBAgXw8_GA.aKgPGQYvpPwHsQiDOeTFoQ.3syjxFimN-u5zY8t-mwIcZwVshIfYbzcxXID7FTbqdAKPWKlWfOdkXpk6V_u5p25U73Izv9qgr1UaWQAzaLli-LqFXptmCyciipYJc2BRhw.;error;"

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                     "\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";
const char jwk_pubkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\","\
                                       "\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\""\
                                      ",\"d\":\"KMRJaGpxVer0w9lMjIY_UrjC067tZdEJkL5eaiBVWi8\",\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_x25519_str[] = "{\"kty\":\"OKP\",\"use\":\"enc\",\"crv\":\"X25519\",\"x\":\"AuQ7nbIvxilE4nzzRoS_C_cmpqMx-kcXNkcAyy46fWM\"}";
const char jwk_privkey_x25519_str[] = "{\"kty\":\"OKP\",\"d\":\"-NOCJItqI-R-AFsq1cLNLAIpfIf-otm7x2psH5EXJoo\","
                                      "\"use\":\"enc\",\"crv\":\"X25519\",\"x\":\"AuQ7nbIvxilE4nzzRoS_C_cmpqMx-kcXNkcAyy46fWM\"}";
const char jwk_privkey_x25519_str_2[] = "{\"kty\":\"OKP\",\"d\":\"kcIdGcJVDgzC6KLd9I1P7of4RJvXxZZmilCh_f-0K8Q\","
                                        "\"use\":\"enc\",\"crv\":\"X25519\",\"x\":\"JIrudOxnjSYGNO6Jsa7Bp00juLU10XB6ZutgPgpfEyE\"}";
const char jwk_pubkey_x448_str[] = "{\"kty\":\"OKP\",\"use\":\"enc\",\"crv\":\"X448\",\"x\":\"W46m2SwV-XgAWMqvPQe0KLy_-0CsHhb5r6y11aj7bJBK1F2fvWg02iEsGd5JyA5A3qllofTJwoQ\"}";
const char jwk_privkey_x448_str[] = "{\"kty\":\"OKP\",\"d\":\"DFFZ-8-3Q7xEBHV0VVC1JmBL4oMrRo9zDKqLIJF1GEJgNGgrBYY5CrsoZbgs6NOurHTp73o6jhM\","
                                    "\"use\":\"enc\",\"crv\":\"X448\",\"x\":\"W46m2SwV-XgAWMqvPQe0KLy_-0CsHhb5r6y11aj7bJBK1F2fvWg02iEsGd5JyA5A3qllofTJwoQ\"}";
const char jwk_privkey_x448_str_2[] = "{\"kty\":\"OKP\",\"d\":\"k_-0MeUxtYskqQkpSxWCKMhLCVfDbhW5pMysvAF84v7C9RI9cm5imhkAMs3ngjXAqUlAnwmQtRI\","
                                      "\"use\":\"enc\",\"crv\":\"X448\",\"x\":\"sXZMHweV1nAKE5sZ-z8Sp-Sbd0dYXbzqpjGMwPHORP1K1gsKLaQvLSmy4yStLRVPGoTCW8IPqyw\"}";

static void test_encrypt_decrypt_ok(jwa_alg alg, jwa_enc enc) {
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test alg %s, enc %s", r_jwa_alg_to_str(alg), r_jwa_enc_to_str(enc));
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, alg), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, enc), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}

static void test_decrypt_invalid_key(jwa_alg alg, jwa_enc enc) {
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test invalid key alg %s, enc %s", r_jwa_alg_to_str(alg), r_jwa_enc_to_str(enc));
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, alg), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, enc), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}

START_TEST(test_rhonabwy_encrypt_decrypt_ok)
{
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A128CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A192CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A256CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A128GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A192GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A256GCM);

  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A128CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A192CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A256CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A128GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A192GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A256GCM);

  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A128CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A192CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A256CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A128GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A192GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A256GCM);

  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A128CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A192CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A256CBC);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A128GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A192GCM);
  test_encrypt_decrypt_ok(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A256GCM);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_x25519_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test X25519");
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_x25519_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_x25519_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_x448_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test X25519");
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_x448_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_x448_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_invalid_parameters)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey;

  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", ";not a base64;"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", ";not a base64;"), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", ";not a base64;"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", ";not a base64;"), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", ";not a base64;"), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", ";not a base64;"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", NULL), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_invalid_key)
{
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A128CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A192CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A256CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A128GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A192GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES, R_JWA_ENC_A256GCM);

  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A128CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A192CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A256CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A128GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A192GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A128KW, R_JWA_ENC_A256GCM);

  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A128CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A192CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A256CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A128GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A192GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A192KW, R_JWA_ENC_A256GCM);

  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A128CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A192CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A256CBC);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A128GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A192GCM);
  test_decrypt_invalid_key(R_JWA_ALG_ECDH_ES_A256KW, R_JWA_ENC_A256GCM);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_invalid_x25519_key)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test invalid key X25519");
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_x25519_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_x25519_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_invalid_x448_key)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  y_log_message(Y_LOG_LEVEL_DEBUG, "Test invalid key X25519");
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_x448_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_x448_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "cGxvcAo"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Z3J1dAo"), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_invalid_key_type)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, NULL, 0), NULL);
  
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_parse_token_invalid)
{
  jwe_t * jwe_decrypt;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER_KEY_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_IV_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_token_invalid)
{
  jwe_t * jwe_decrypt;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_IV, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG_LEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_flood_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_rfc_ok)
{
  const char eph[] = " {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"}",
  bob[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\"}";
  jwk_t * jwk_eph, * jwk_bob;
  jwe_t * jwe;
  char * token;
  unsigned char expected_key[] = {86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26};
  
  ck_assert_int_eq(r_jwk_init(&jwk_eph), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_bob), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_eph, eph), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_bob, bob), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_eph, jwk_bob), RHN_OK);

  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apu", "QWxpY2U"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "apv", "Qm9i"), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  o_free(token);
  
  ck_assert_int_eq(sizeof(expected_key), jwe->key_len);
  ck_assert_int_eq(0, memcmp(jwe->key, expected_key, jwe->key_len));
  
  r_jwk_free(jwk_eph);
  r_jwk_free(jwk_bob);
  r_jwe_free(jwe);
}
END_TEST

#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE ECDH-ES encryption tests");
  tc_core = tcase_create("test_rhonabwy_ecdh_es");
#if defined(R_ECDH_ENABLED) && GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_x25519_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_x448_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_invalid_parameters);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_invalid_key);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_invalid_x25519_key);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_invalid_x448_key);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_invalid_key_type);
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_flood_ok);
  tcase_add_test(tc_core, test_rhonabwy_rfc_ok);
#endif
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE ECDH-ES encryption tests");
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
