/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

START_TEST(test_rhonabwy_info_json_t)
{
  json_t * j_info_control = r_library_info_json_t();
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[ssss]s[sssss]}}",
                            "version", RHONABWY_VERSION_STR,
                            "jws",
                              "alg",
                                "none",
                                "HS256",
                                "HS384",
                                "HS512",
                                "RS256",
                                "RS384",
                                "RS512",
                            "jwe",
                              "alg",
                                "RSA1_5",
                                "A128KW",
                                "A256KW",
                                "dir",
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512",
                                "A128GCM",
                                "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "enc"), json_string("A192GCM"));
#endif

  ck_assert_ptr_ne(j_info, NULL);
  ck_assert_ptr_ne(j_info_control, NULL);
  ck_assert_int_eq(json_equal(j_info, j_info_control), 1);
  json_decref(j_info);
  json_decref(j_info_control);
}
END_TEST

START_TEST(test_rhonabwy_info_str)
{
  char * j_info_control_str = r_library_info_json_str();
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[ssss]s[sssss]}}",
                            "version", RHONABWY_VERSION_STR,
                            "jws",
                              "alg",
                                "none",
                                "HS256",
                                "HS384",
                                "HS512",
                                "RS256",
                                "RS384",
                                "RS512",
                            "jwe",
                              "alg",
                                "RSA1_5",
                                "A128KW",
                                "A256KW",
                                "dir",
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512",
                                "A128GCM",
                                "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "enc"), json_string("A192GCM"));
#endif
  json_t * j_info_control_parsed = json_loads(j_info_control_str, JSON_DECODE_ANY, NULL);

  ck_assert_ptr_ne(j_info, NULL);
  ck_assert_ptr_ne(j_info_control_str, NULL);
  ck_assert_ptr_ne(j_info_control_parsed, NULL);
  ck_assert_int_eq(json_equal(j_info, j_info_control_parsed), 1);
  json_decref(j_info);
  json_decref(j_info_control_parsed);
  r_free(j_info_control_str);
}
END_TEST

START_TEST(test_rhonabwy_alg_conversion)
{
  ck_assert_int_eq(r_str_to_jwa_alg("none"), R_JWA_ALG_NONE);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_NONE), "none");
  ck_assert_int_eq(r_str_to_jwa_alg("HS256"), R_JWA_ALG_HS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS256), "HS256");
  ck_assert_int_eq(r_str_to_jwa_alg("HS384"), R_JWA_ALG_HS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS384), "HS384");
  ck_assert_int_eq(r_str_to_jwa_alg("HS512"), R_JWA_ALG_HS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS512), "HS512");
  ck_assert_int_eq(r_str_to_jwa_alg("ES256"), R_JWA_ALG_ES256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES256), "ES256");
  ck_assert_int_eq(r_str_to_jwa_alg("ES384"), R_JWA_ALG_ES384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES384), "ES384");
  ck_assert_int_eq(r_str_to_jwa_alg("ES512"), R_JWA_ALG_ES512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES512), "ES512");
  ck_assert_int_eq(r_str_to_jwa_alg("RS256"), R_JWA_ALG_RS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS256), "RS256");
  ck_assert_int_eq(r_str_to_jwa_alg("RS384"), R_JWA_ALG_RS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS384), "RS384");
  ck_assert_int_eq(r_str_to_jwa_alg("RS512"), R_JWA_ALG_RS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS512), "RS512");
  ck_assert_int_eq(r_str_to_jwa_alg("PS256"), R_JWA_ALG_PS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS256), "PS256");
  ck_assert_int_eq(r_str_to_jwa_alg("PS384"), R_JWA_ALG_PS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS384), "PS384");
  ck_assert_int_eq(r_str_to_jwa_alg("PS512"), R_JWA_ALG_PS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS512), "PS512");
  ck_assert_int_eq(r_str_to_jwa_alg("EdDSA"), R_JWA_ALG_EDDSA);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_EDDSA), "EdDSA");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA1_5"), R_JWA_ALG_RSA1_5);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA1_5), "RSA1_5");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA-OAEP"), R_JWA_ALG_RSA_OAEP);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP), "RSA-OAEP");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA-OAEP-256"), R_JWA_ALG_RSA_OAEP_256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP_256), "RSA-OAEP-256");
  ck_assert_int_eq(r_str_to_jwa_alg("A128KW"), R_JWA_ALG_A128KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A128KW), "A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A192KW"), R_JWA_ALG_A192KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A192KW), "A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A256KW"), R_JWA_ALG_A256KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A256KW), "A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("dir"), R_JWA_ALG_DIR);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_DIR), "dir");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES"), R_JWA_ALG_ECDH_ES);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES), "ECDH-ES");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A128KW"), R_JWA_ALG_ECDH_ES_A128KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A128KW), "ECDH-ES+A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A192KW"), R_JWA_ALG_ECDH_ES_A192KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A192KW), "ECDH-ES+A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A256KW"), R_JWA_ALG_ECDH_ES_A256KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A256KW), "ECDH-ES+A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A128GCMKW"), R_JWA_ALG_A128GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A128GCMKW), "A128GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("A192GCMKW"), R_JWA_ALG_A192GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A192GCMKW), "A192GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("A256GCMKW"), R_JWA_ALG_A256GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A256GCMKW), "A256GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS256+A128KW"), R_JWA_ALG_PBES2_H256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H256), "PBES2-HS256+A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS384+A192KW"), R_JWA_ALG_PBES2_H384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H384), "PBES2-HS384+A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS512+A256KW"), R_JWA_ALG_PBES2_H512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H512), "PBES2-HS512+A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("error"), R_JWA_ALG_UNKNOWN);
  ck_assert_ptr_eq(r_jwa_alg_to_str(R_JWA_ALG_UNKNOWN), NULL);
}
END_TEST

START_TEST(test_rhonabwy_enc_conversion)
{
  ck_assert_int_eq(r_str_to_jwa_enc("A128CBC-HS256"), R_JWA_ENC_A128CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A128CBC), "A128CBC-HS256");
  ck_assert_int_eq(r_str_to_jwa_enc("A192CBC-HS384"), R_JWA_ENC_A192CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A192CBC), "A192CBC-HS384");
  ck_assert_int_eq(r_str_to_jwa_enc("A256CBC-HS512"), R_JWA_ENC_A256CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A256CBC), "A256CBC-HS512");
  ck_assert_int_eq(r_str_to_jwa_enc("A128GCM"), R_JWA_ENC_A128GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A128GCM), "A128GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("A192GCM"), R_JWA_ENC_A192GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A192GCM), "A192GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("A256GCM"), R_JWA_ENC_A256GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A256GCM), "A256GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("error"), R_JWA_ENC_UNKNOWN);
  ck_assert_ptr_eq(r_jwa_enc_to_str(R_JWA_ENC_UNKNOWN), NULL);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy misc tests");
  tc_core = tcase_create("test_rhonabwy_misc");
  tcase_add_test(tc_core, test_rhonabwy_info_json_t);
  tcase_add_test(tc_core, test_rhonabwy_info_str);
  tcase_add_test(tc_core, test_rhonabwy_alg_conversion);
  tcase_add_test(tc_core, test_rhonabwy_enc_conversion);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy misc tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
