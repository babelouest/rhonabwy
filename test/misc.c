/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

START_TEST(test_rhonabwy_info_json_t)
{
  json_t * j_info_control = r_library_info_json_t();
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[s]s[sss]}}",
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
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
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
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[s]s[sss]}}",
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
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
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

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy misc tests");
  tc_core = tcase_create("test_rhonabwy_misc");
  tcase_add_test(tc_core, test_rhonabwy_info_json_t);
  tcase_add_test(tc_core, test_rhonabwy_info_str);
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
