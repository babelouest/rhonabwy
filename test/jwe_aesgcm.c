/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define TOKEN "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklL.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_ENCRYPTED_KEY "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-P63Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_IV "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XW6hRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFF6oUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_TAG "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.86_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaq"
#define TOKEN_INVALID_HEADER_B64 ";error;.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.;error;.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.;error;.8v_65BtY-tYA1QzBaqUcKA"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9.xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.;error;"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaXYiOiJTTWdHekVEMHBNY05wQk00IiwidGFnIjoiclYwdnZPX1JMZTBJRDNuam5wcklLZyJ9xB-j-EVsBqwgxSMQEfsJzGfCuvsbw9ZmcbrYKFmeHiQ.XWChRAUirGixPLf5_-Pa3Q.Ck5akPNhJPlTKH30kFuadoOwcQuV1AUmLtOYjGFFsoUEr1U2H0y49zrNc6TTmlkX1T2TRTOPAaTqtb1_1YEg8A.8v_65BtY-tYA1QzBaqUcKA"

const char jwk_key_128_1[] = "{\"kty\":\"oct\",\"k\":\"Zd3bPKCfbPc2A6sh3M7dIbzgD6PS-qIwsbN79VgN5PY\"}";
const char jwk_key_128_2[] = "{\"kty\":\"oct\",\"k\":\"ELG-YDhuRKg-6zH2QTR7Tug2zYz7v3coGLx_VWkcnVs\"}";

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
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_ENCRYPTED_KEY, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_IV, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG_LEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_invalid_privkey)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_enc, * jwk_dec;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_enc), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_dec), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_enc, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_dec, jwk_key_128_2), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128GCMKW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk_enc, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_dec, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwk_free(jwk_enc);
  r_jwk_free(jwk_dec);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128GCMKW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_2_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128GCMKW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_flood_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128GCMKW), RHN_OK);
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
  
  r_jwk_free(jwk);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE AES GCM key encryption tests");
  tc_core = tcase_create("test_rhonabwy_aesgcm");
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_invalid_privkey);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_2_ok);
  tcase_add_test(tc_core, test_rhonabwy_flood_ok);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE AES GCM key encryption tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
