/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define TOKEN "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_HEADER "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6Ij.eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_HEADER_B64 ";error;.eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_CLAIMS "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cn.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.;error;.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQeyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_A"
#define TOKEN_INVALID_SIGNATURE "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.eyJzdHIiOiJwbG9wIiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.ooXNEt3JWFGMuvkGUM-szUOU1QTu4DvyC3qQP64UGeeJQuMGupBCVATnGkiqNLiPSJ9uBsjZbyUrWe8z7Iag_6"

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
const char jwk_pubkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\""\
                                      ",\"d\":\"KMRJaGpxVer0w9lMjIY_UrjC067tZdEJkL5eaiBVWi8\",\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\","\
                                       "\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";

START_TEST(test_rhonabwy_sign_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  r_jwk_free(jwk_privkey_ecdsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, jwk_privkey_ecdsa, 0), NULL);
  
  r_jwk_free(jwk_privkey_ecdsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_without_set_sign_alg)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_rsa, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_signature_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_signature_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_signature_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWT sign function tests");
  tc_core = tcase_create("test_rhonabwy_sign");
  tcase_add_test(tc_core, test_rhonabwy_sign_error);
  tcase_add_test(tc_core, test_rhonabwy_sign_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_sign_with_key_in_serialize);
  tcase_add_test(tc_core, test_rhonabwy_sign_without_set_sign_alg);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_key);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_key_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_signature_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_signature_ok);
  tcase_add_test(tc_core, test_rhonabwy_verify_signature_with_add_keys_ok);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT sign tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
