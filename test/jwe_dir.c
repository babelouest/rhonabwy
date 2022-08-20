/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination..."

#define TOKEN "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_HEADER_B64 ";error;..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..;error;.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.;error-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.;error"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2IcxrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_IV "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE5ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8a4pm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_TAG "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7x4gAA"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA4321"

const char jwk_key_128_1[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"Zd3bPKCfbPc2A6sh3M7dIbzgD6PS-qIwsbN79VgN5PY\"}";
const char jwk_key_128_2[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"ELG-YDhuRKg-6zH2QTR7Tug2zYz7v3coGLx_VWkcnVs\"}";
const char jwk_key_192_1[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"4-Jq38RkFa06N3L-fImTzgWgW3E2IDDAaPQm0eDn_kYAW4lT4NYHB-Qit5vepNn7\"}";
const char jwk_key_256_1[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"5CErcN-egEJlhCe8qCWhGRt2y99bFfBTiZUZcfPbO2ry2OSxri41Vm9nJUZvd6SNPBCJCIxOveW7sgV4AXoQMg\"}";

START_TEST(test_rhonabwy_encrypt_decrypt_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  char * token = NULL;
  size_t key_len = 0;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_ptr_ne(r_jwe_get_cypher_key(jwe, &key_len), NULL);
  ck_assert_int_eq(r_jwe_set_cypher_key(jwe_decrypt, r_jwe_get_cypher_key(jwe, NULL), key_len), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_with_jwk)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk_privkey, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_OK);
  
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_with_invalid_jwk)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_privkey_2;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_2, jwk_key_128_2), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk_privkey, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey_2, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_privkey_2);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_with_jwk_invalid_key_size)
{
  jwe_t * jwe;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, jwk_privkey, 0), NULL);
  
  
  o_free(token);
  r_jwe_free(jwe);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_parse_token_invalid)
{
  jwe_t * jwe_decrypt;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
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
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_key_128_1), RHN_OK);
  
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

START_TEST(test_rhonabwy_decrypt_token_ok)
{
  jwe_t * jwe_decrypt;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_key_128_1), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_OK);
  
  r_jwk_free(jwk_privkey);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_check_key_length)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_1, * jwk_2;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_2), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_1, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_2, jwk_key_256_1), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_1, 0)), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_DIR), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_2, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_1, 0), RHN_OK);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_2, 0), RHN_OK);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_2, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_1, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_1);
  r_jwk_free(jwk_2);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE dir key encryption tests");
  tc_core = tcase_create("test_rhonabwy_dir");
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_with_jwk);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_with_invalid_jwk);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_with_jwk_invalid_key_size);
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_ok);
  tcase_add_test(tc_core, test_rhonabwy_check_key_length);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE dir key encryption tests");
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
