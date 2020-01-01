/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <rhonabwy.h>

START_TEST(test_rhonabwy_init)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_init_jwk(NULL), R_ERROR_PARAM);
  ck_assert_int_eq(r_init_jwk(&jwk), R_OK);
  
  r_free_jwk(jwk);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy core tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
