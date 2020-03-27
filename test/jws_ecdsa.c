/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/gnutls.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define ES256_TOKEN "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.8SGjljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"
#define ES256_TOKEN_INVALID_HEADER "eyJhbGciOiJFUzI1NiIsImtpZCI6Ij.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.8SGjljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"
#define ES256_TOKEN_INVALID_HEADER_B64 ";error;.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.8SGjljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"
#define ES256_TOKEN_INVALID_PAYLOAD_B64 "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.;error;.8SGjljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"
#define ES256_TOKEN_INVALID_SIGNATURE "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.8S6jljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"
#define ES256_TOKEN_INVALID_DOTS "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEifQVGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.8SGjljD8Zrj9nZRXFbWny8KYLokjvnuFersudKTYCU7LyiOHed81goqaW3J1gDY-8zIjGnT_EV2YZsT7GVyBjQ"

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                     "\"use\":\"enc\",\"kid\":\"1\",\"alg\":\"ES256\"}";
const char jwk_pubkey_ecdsa_no_alg_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                           "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_no_alg_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                             "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                             "\"use\":\"enc\",\"kid\":\"1\"}";

const char jwk_pubkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\""\
                                      ",\"d\":\"KMRJaGpxVer0w9lMjIY_UrjC067tZdEJkL5eaiBVWi8\",\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\","\
                                       "\"crv\":\"P-256\",\"kid\":\"2\",\"alg\":\"ES256\"}";
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0Cg\",\"kid\":\"1\"}";
const char jwk_pubkey_eddsa_str[] = "{\"kty\":\"EC\",\"x\":\"vG-37qz4ywqzukNS-jMAfXSSA7V28y0vv9RxlibxgPw\","\
                                    "\"crv\":\"Ed25519\",\"kid\":\"3\"}";
const char jwk_privkey_eddsa_str[] = "{\"kty\":\"EC\",\"x\":\"vG-37qz4ywqzukNS-jMAfXSSA7V28y0vv9RxlibxgPw\","\
                                     "\"d\":\"DGw7wgt65TPJAxEjuUmCjTjmafg4mKUPj3S3iAVoTYQ\",\"crv\":\"Ed25519\",\"kid\":\"3\"}";

#if GNUTLS_VERSION_NUMBER >= 0x030500
START_TEST(test_rhonabwy_serialize_error_header)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_eq(r_jws_serialize(jws, NULL, 0), NULL);
  ck_assert_ptr_eq(r_jws_serialize(NULL, jwk_privkey, 0), NULL);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_serialize_error_payload)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWS_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_eq(r_jws_serialize(jws, NULL, 0), NULL);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_set_alg_serialize_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWS_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  
  o_free(token);
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_no_set_alg_serialize_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  
  o_free(token);
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_serialize_with_key_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWS_ALG_ES256), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, jwk_privkey, 0)), NULL);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key", "value"), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws, jwk_privkey, 0)), NULL);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key2", "value2"), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws, jwk_privkey, 0)), NULL);
  o_free(token);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_parse_token_invalid_content)
{
  jws_t * jws;
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN_INVALID_PAYLOAD_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, "error", 0), RHN_ERROR_PARAM);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_token)
{
  jws_t * jws;
  size_t payload_len = 0;
  const unsigned char * payload = NULL;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_ptr_ne((payload = r_jws_get_payload(jws, &payload_len)), NULL);
  ck_assert_int_eq(R_JWS_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_int_gt(payload_len, 0);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)payload, payload_len));
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_verify_token_invalid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(R_JWS_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
}
END_TEST

START_TEST(test_rhonabwy_verify_token_invalid_key_type)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
}
END_TEST

START_TEST(test_rhonabwy_verify_token_invalid_kid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWS_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  r_jwk_set_property_str(jwk_pubkey, "kid", "42");
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_verify_token_valid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWS_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_OK);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_verify_token_multiple_keys_valid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ES256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWS_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str_2), RHN_OK);
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  r_jwk_free(jwk_pubkey);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_str), RHN_OK);
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  r_jwk_free(jwk_pubkey);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  r_jws_free(jws);
  
}
END_TEST

START_TEST(test_rhonabwy_set_alg_serialize_verify_ok)
{
  jws_t * jws_sign, * jws_verify;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_sign), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_verify), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_ecdsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws_sign, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws_sign, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWS_ALG_ES256), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWS_ALG_ES384), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWS_ALG_ES512), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  r_jws_free(jws_sign);
  r_jws_free(jws_verify);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
}
END_TEST

START_TEST(test_rhonabwy_eddsa_serialize_verify_ok)
{
  jws_t * jws_sign, * jws_verify;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_sign), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_verify), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_eddsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_eddsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws_sign, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws_sign, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWS_ALG_EDDSA), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  y_log_message(Y_LOG_LEVEL_DEBUG, "token %s", token);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  r_jws_free(jws_sign);
  r_jws_free(jws_verify);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
}
END_TEST

#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWS ECDSA function tests");
  tc_core = tcase_create("test_rhonabwy_ecdsa");
#if GNUTLS_VERSION_NUMBER >= 0x030500
  tcase_add_test(tc_core, test_rhonabwy_serialize_error_header);
  tcase_add_test(tc_core, test_rhonabwy_serialize_error_payload);
  tcase_add_test(tc_core, test_rhonabwy_set_alg_serialize_ok);
  tcase_add_test(tc_core, test_rhonabwy_no_set_alg_serialize_ok);
  tcase_add_test(tc_core, test_rhonabwy_serialize_with_key_ok);
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid_content);
  tcase_add_test(tc_core, test_rhonabwy_parse_token);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_invalid_key_type);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_invalid_kid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_valid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_multiple_keys_valid);
  tcase_add_test(tc_core, test_rhonabwy_set_alg_serialize_verify_ok);
  tcase_add_test(tc_core, test_rhonabwy_eddsa_serialize_verify_ok);
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
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWS ECDSA tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
