/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
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
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"1\"}";

#define JWT_CLAIM_ISS "https://rhonabwy.tld"
#define JWT_CLAIM_SUB "rhon_sub"
#define JWT_CLAIM_AUD "dave_lopper"
#define JWT_CLAIM_EXP 30
#define JWT_CLAIM_NBF 30
#define JWT_CLAIM_IAT 30
#define JWT_CLAIM_JTI "jit1234Xyz"
#define JWT_CLAIM_SCOPE "scope1"
#define JWT_CLAIM_AGE 42
#define JWT_CLAIM_VERIFIED json_true()

START_TEST(test_rhonabwy_init)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_alg)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jwt_set_sign_alg(NULL, R_JWA_ALG_ES256), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_ES256);
  
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS512), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_RS512);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_enc_alg)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jwt_set_enc_alg(NULL, R_JWA_ALG_RSA1_5), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_RSA1_5);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_ECDH_ES), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_ECDH_ES);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jwt_get_header_str_value(jwt, "keystr"));
  ck_assert_int_eq(42, r_jwt_get_header_int_value(jwt, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jwt_get_header_json_t_value(jwt, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_header_str_value(jwt, "error"));
  ck_assert_int_eq(0, r_jwt_get_header_int_value(jwt, "error"));
  ck_assert_ptr_eq(NULL, r_jwt_get_header_json_t_value(jwt, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_full_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_header = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value), * j_result;
  
  ck_assert_ptr_ne(j_header, NULL);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(json_equal(j_header, (j_result = r_jwt_get_full_header_json_t(jwt))) , 1);
  json_decref(j_value);
  json_decref(j_header);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_claim)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_claim)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  ck_assert_int_eq(42, r_jwt_get_claim_int_value(jwt, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jwt_get_claim_json_t_value(jwt, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "error"));
  ck_assert_int_eq(0, r_jwt_get_claim_int_value(jwt, "error"));
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_json_t_value(jwt, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_full_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));
  
  json_decref(j_value);
  json_decref(j_claims);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_full_claims_str)
{
  jwt_t * jwt;
  char str_value[] = "{\"str\":\"grut\",\"int\":42,\"obj\":true}";
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, str_value), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));
  
  json_decref(j_value);
  json_decref(j_claims);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_full_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), 
         * j_claims, 
         * j_expected = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected));
  
  json_decref(j_value);
  json_decref(j_claims);
  json_decref(j_expected);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_append_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), 
         * j_claims, 
         * j_expected_1 = json_pack("{sssi}", "keystr", "value", "keyint", 42),
         * j_expected_2 = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected_1));
  json_decref(j_claims);
  
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected_2));
  
  json_decref(j_value);
  json_decref(j_claims);
  json_decref(j_expected_1);
  json_decref(j_expected_2);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_sign_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_sign_jwks)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk_privkey_rsa), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_privkey_sign));
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_pubkey_sign));
  ck_assert_int_eq(r_jwt_add_sign_jwks(jwt, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_privkey_sign));
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_pubkey_sign));
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_enc_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_enc_jwks)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk_privkey_rsa), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_privkey_enc));
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_pubkey_enc));
  ck_assert_int_eq(r_jwt_add_enc_jwks(jwt, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_privkey_enc));
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_pubkey_enc));
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_validate_claims)
{
  jwt_t * jwt;
  time_t now;

  time(&now);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, JWT_CLAIM_SUB, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, JWT_CLAIM_AUD, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, JWT_CLAIM_JTI, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", JWT_CLAIM_ISS), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sub", JWT_CLAIM_SUB), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, JWT_CLAIM_SUB, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", JWT_CLAIM_AUD), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, JWT_CLAIM_AUD, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "jti", JWT_CLAIM_JTI), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, JWT_CLAIM_JTI, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "exp", (now+JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, now+1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, (now+JWT_CLAIM_EXP+JWT_CLAIM_EXP), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "nbf", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, now-1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, (now-JWT_CLAIM_NBF-JWT_CLAIM_NBF), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iat", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, now-1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, (now-JWT_CLAIM_IAT-JWT_CLAIM_IAT), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", JWT_CLAIM_SCOPE), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "age", JWT_CLAIM_AGE), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE-1, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "verified", JWT_CLAIM_VERIFIED), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", json_null(), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", NULL, R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, JWT_CLAIM_AUD,
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL,
                                              R_JWT_CLAIM_SUB, NULL,
                                              R_JWT_CLAIM_AUD, NULL,
                                              R_JWT_CLAIM_JTI, NULL,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_STR, "scope", NULL,
                                              R_JWT_CLAIM_JSN, "verified", NULL,
                                              R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, "error",
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, JWT_CLAIM_AUD,
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_STR, "error", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  r_jwt_free(jwt);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWT core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_add_test(tc_core, test_rhonabwy_sign_alg);
  tcase_add_test(tc_core, test_rhonabwy_enc_alg);
  tcase_add_test(tc_core, test_rhonabwy_set_header);
  tcase_add_test(tc_core, test_rhonabwy_get_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_header);
  tcase_add_test(tc_core, test_rhonabwy_set_claim);
  tcase_add_test(tc_core, test_rhonabwy_get_claim);
  tcase_add_test(tc_core, test_rhonabwy_set_full_claims);
  tcase_add_test(tc_core, test_rhonabwy_set_full_claims_str);
  tcase_add_test(tc_core, test_rhonabwy_get_full_claims);
  tcase_add_test(tc_core, test_rhonabwy_append_claims);
  tcase_add_test(tc_core, test_rhonabwy_set_sign_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_sign_jwks);
  tcase_add_test(tc_core, test_rhonabwy_set_enc_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_enc_jwks);
  tcase_add_test(tc_core, test_rhonabwy_validate_claims);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT core tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
