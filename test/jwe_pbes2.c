/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

void
pbkdf2_hmac_sha384 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst);

void
pbkdf2_hmac_sha512 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst);

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define TOKEN "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQw.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_ENCRYPTED_KEY "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjav.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_IV "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pl.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgA0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_TAG "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2Aw"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cS"
#define TOKEN_INVALID_HEADER_B64 ";error;ciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.;error;8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.;error;mfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9.vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R;error;"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJzIjoiTGZfbk9xdU9TM1UiLCJwMmMiOjQwOTZ9vyYTdkjdPIv0DwxxaN1d0lILGkGXNiH8KzWb6nl8azjCJINwQ0Yjaw.jbfmnTw8AlsH9XwNIfc_pA.2hcZHvkmfnSQcnzVJ97T9kylIpZDBPtx43ODFye1l0Jf-IjB757r9cQHgmE5kdT9C_rmv4CGXf9ExVYVgX0AQA.p_gD5xAAVJOFs3R9cSb2ow"

const char jwk_key_128_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}";
const char jwk_key_128_2[] = "{\"kty\":\"oct\",\"k\":\"CAkKCwwNDg8QERITFBUWFw\"}";
const char jwk_key_192_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX\"}";
const char jwk_key_256_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}";

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
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H256), RHN_OK);
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

START_TEST(test_rhonabwy_encrypt_decrypt_pbes2_hs256_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_pbes2_hs384_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H384), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_pbes2_hs512_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H512), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  r_jwk_free(jwk);
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
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_256_1), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H256), RHN_OK);
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

START_TEST(test_rhonabwy_rfc_example)
{
  const char jwe_a_c[] = 
  "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MDk2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ.TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA.Ye9j1qs22DmRSAddIh-VnA.AwhB8lxrlKjFn02LGWEqg27H4Tg9fyZAbFv3p5ZicHpj64QyHC44qqlZ3JEmnZTgQowIqZJ13jbyHB8LgePiqUJ1hf6M2HPLgzw8L-mEeQ0jvDUTrE07NtOerBk8bwBQyZ6g0kQ3DEOIglfYxV8-FJvNBYwbqN1Bck6d_i7OtjSHV-8DIrp-3JcRIe05YKy3Oi34Z_GOiAc1EK21B11c_AE11PII_wvvtRiUiG8YofQXakWd1_O98Kap-UgmyWPfreUJ3lJPnbD4Ve95owEfMGLOPflo2MnjaTDCwQokoJ_xplQ2vNPz8iguLcHBoKllyQFJL2mOWBwqhBo9Oj-O800as5mmLsvQMTflIrIEbbTMzHMBZ8EFW9fWwwFu0DWQJGkMNhmBZQ-3lvqTc-M6-gWA6D8PDhONfP2Oib2HGizwG1iEaX8GRyUpfLuljCLIe1DkGOewhKuKkZh04DKNM5Nbugf2atmU9OP0Ldx5peCUtRG1gMVl7Qup5ZXHTjgPDr5b2N731UooCGAUqHdgGhg0JVJ_ObCTdjsH4CF1SJsdUhrXvYx3HJh2Xd7CwJRzU_3Y1GxYU6-s3GFPbirfqqEipJDBTHpcoCmyrwYjYHFgnlqBZRotRrS95g8F95bRXqsaDY7UgQGwBQBwy665d0zpvTasvfXf_c0MWAl-neFaKOW_Px6g4EUDjG1GWSXV9cLStLw_0ovdApDIFLHYHePyagyHjouQUuGiq7BsYwYrwaF06tgB8hV8omLNfMEmDPJaZUzMuHw6tBDwGkzD-tS_ub9hxrpJ4UsOWnt5rGUyoN2N_c1-TQlXxm5oto14MxnoAyBQBpwIEgSH3Y4ZhwKBhHPjSo0cdwuNdYbGPpb-YUvF-2NZzODiQ1OvWQBRHSbPWYz_xbGkgD504LRtqRwCO7CC_CyyURi1sEssPVsMJRX_U4LFEOc82TiDdqjKOjRUfKK5rqLi8nBE9soQ0DSaOoFQZiGrBrqxDsNYiAYAmxxkos-i3nX4qtByVx85sCE5U_0MqG7COxZWMOPEFrDaepUV-cOyrvoUIng8i8ljKBKxETY2BgPegKBYCxsAUcAkKamSCC9AiBxA0UOHyhTqtlvMksO7AEhNC2-YzPyx1FkhMoS4LLe6E_pFsMlmjA6P1NSge9C5G5tETYXGAn6b1xZbHtmwrPScro9LWhVmAaA7_bxYObnFUxgWtK4vzzQBjZJ36UTk4OTB-JvKWgfVWCFsaw5WCHj6Oo4jpO7d2yN7WMfAj2hTEabz9wumQ0TMhBduZ-QON3pYObSy7TSC1vVme0NJrwF_cJRehKTFmdlXGVldPxZCplr7ZQqRQhF8JP-l4mEQVnCaWGn9ONHlemczGOS-A-wwtnmwjIB1V_vgJRf4FdpV-4hUk4-QLpu3-1lWFxrtZKcggq3tWTduRo5_QebQbUUT_VSCgsFcOmyWKoj56lbxthN19hq1XGWbLGfrrR6MWh23vk01zn8FVwi7uFwEnRYSafsnWLa1Z5TpBj9GvAdl2H9NHwzpB5NqHpZNkQ3NMDj13Fn8fzO0JB83Etbm_tnFQfcb13X3bJ15Cz-Ww1MGhvIpGGnMBT_ADp9xSIyAM9dQ1yeVXk-AIgWBUlN5uyWSGyCxp0cJwx7HxM38z0UIeBu-MytL-eqndM7LxytsVzCbjOTSVRmhYEMIzUAnS1gs7uMQAGRdgRIElTJESGMjb_4bZq9s6Ve1LKkSi0_QDsrABaLe55UY0zF4ZSfOV5PMyPtocwV_dcNPlxLgNAD1BFX_Z9kAdMZQW6fAmsfFle0zAoMe4l9pMESH0JB4sJGdCKtQXj1cXNydDYozF7l8H00BV_Er7zd6VtIw0MxwkFCTatsv_R-GsBCH218RgVPsfYhwVuT8R4HarpzsDBufC4r8_c8fc9Z278sQ081jFjOja6L2x0N_ImzFNXU6xwO-Ska-QeuvYZ3X_L31ZOX4Llp-7QSfgDoHnOxFv1Xws-D5mDHD3zxOup2b2TppdKTZb9eW2vxUVviM8OI9atBfPKMGAOv9omA-6vv5IxUH0-lWMiHLQ_g8vnswp-Jav0c4t6URVUzujNOoNd_CBGGVnHiJTCHl88LQxsqLHHIu4Fz-U2SGnlxGTj0-ihit2ELGRv4vO8E1BosTmf0cx3qgG0Pq0eOLBDIHsrdZ_CCAiTc0HVkMbyq1M6qEhM-q5P6y1QCIrwg.0HFmhOzsQ98nNWJjIHkR7A";
  const unsigned char content[] = {123, 34, 107, 116, 121, 34, 58, 34, 82, 83, 65, 34, 44, 34, 107, 105, 100, 34, 58, 34, 106, 117, 108, 105, 101, 116, 64, 99, 97, 112, 117, 108, 101, 116, 46, 108, 105, 116, 34, 44, 34, 117, 115, 101, 34, 58, 34, 101, 110, 99, 34, 44, 34, 110, 34, 58, 34, 116, 54, 81, 56, 80, 87, 83, 105, 49, 100, 107, 74, 106, 57, 104, 84, 80, 56, 104, 78, 89, 70, 108, 118, 97, 100, 77, 55, 68, 102, 108, 87, 57, 109, 87, 101, 112, 79, 74, 104, 74, 54, 54, 119, 55, 110, 121, 111, 75, 49, 103, 80, 78, 113, 70, 77, 83, 81, 82, 121, 79, 49, 50, 53, 71, 112, 45, 84, 69, 107, 111, 100, 104, 87, 114, 48, 105, 117, 106, 106, 72, 86, 120, 55, 66, 99, 86, 48, 108, 108, 83, 52, 119, 53, 65, 67, 71, 103, 80, 114, 99, 65, 100, 54, 90, 99, 83, 82, 48, 45, 73, 113, 111, 109, 45, 81, 70, 99, 78, 80, 56, 83, 106, 103, 48, 56, 54, 77, 119, 111, 113, 81, 85, 95, 76, 89, 121, 119, 108, 65, 71, 90, 50, 49, 87, 83, 100, 83, 95, 80, 69, 82, 121, 71, 70, 105, 78, 110, 106, 51, 81, 81, 108, 79, 56, 89, 110, 115, 53, 106, 67, 116, 76, 67, 82, 119, 76, 72, 76, 48, 80, 98, 49, 102, 69, 118, 52, 53, 65, 117, 82, 73, 117, 85, 102, 86, 99, 80, 121, 83, 66, 87, 89, 110, 68, 121, 71, 120, 118, 106, 89, 71, 68, 83, 77, 45, 65, 113, 87, 83, 57, 122, 73, 81, 50, 90, 105, 108, 103, 84, 45, 71, 113, 85, 109, 105, 112, 103, 48, 88, 79, 67, 48, 67, 99, 50, 48, 114, 103, 76, 101, 50, 121, 109, 76, 72, 106, 112, 72, 99, 105, 67, 75, 86, 65, 98, 89, 53, 45, 76, 51, 50, 45, 108, 83, 101, 90, 79, 45, 79, 115, 54, 85, 49, 53, 95, 97, 88, 114, 107, 57, 71, 119, 56, 99, 80, 85, 97, 88, 49, 95, 73, 56, 115, 76, 71, 117, 83, 105, 86, 100, 116, 51, 67, 95, 70, 110, 50, 80, 90, 51, 90, 56, 105, 55, 52, 52, 70, 80, 70, 71, 71, 99, 71, 49, 113, 115, 50, 87, 122, 45, 81, 34, 44, 34, 101, 34, 58, 34, 65, 81, 65, 66, 34, 44, 34, 100, 34, 58, 34, 71, 82, 116, 98, 73, 81, 109, 104, 79, 90, 116, 121, 115, 122, 102, 103, 75, 100, 103, 52, 117, 95, 78, 45, 82, 95, 109, 90, 71, 85, 95, 57, 107, 55, 74, 81, 95, 106, 110, 49, 68, 110, 102, 84, 117, 77, 100, 83, 78, 112, 114, 84, 101, 97, 83, 84, 121, 87, 102, 83, 78, 107, 117, 97, 65, 119, 110, 79, 69, 98, 73, 81, 86, 121, 49, 73, 81, 98, 87, 86, 86, 50, 53, 78, 89, 51, 121, 98, 99, 95, 73, 104, 85, 74, 116, 102, 114, 105, 55, 98, 65, 88, 89, 69, 82, 101, 87, 97, 67, 108, 51, 104, 100, 108, 80, 75, 88, 121, 57, 85, 118, 113, 80, 89, 71, 82, 48, 107, 73, 88, 84, 81, 82, 113, 110, 115, 45, 100, 86, 74, 55, 106, 97, 104, 108, 73, 55, 76, 121, 99, 107, 114, 112, 84, 109, 114, 77, 56, 100, 87, 66, 111, 52, 95, 80, 77, 97, 101, 110, 78, 110, 80, 105, 81, 103, 79, 48, 120, 110, 117, 84, 111, 120, 117, 116, 82, 90, 74, 102, 74, 118, 71, 52, 79, 120, 52, 107, 97, 51, 71, 79, 82, 81, 100, 57, 67, 115, 67, 90, 50, 118, 115, 85, 68, 109, 115, 88, 79, 102, 85, 69, 78, 79, 121, 77, 113, 65, 68, 67, 54, 112, 49, 77, 51, 104, 51, 51, 116, 115, 117, 114, 89, 49, 53, 107, 57, 113, 77, 83, 112, 71, 57, 79, 88, 95, 73, 74, 65, 88, 109, 120, 122, 65, 104, 95, 116, 87, 105, 90, 79, 119, 107, 50, 75, 52, 121, 120, 72, 57, 116, 83, 51, 76, 113, 49, 121, 88, 56, 67, 49, 69, 87, 109, 101, 82, 68, 107, 75, 50, 97, 104, 101, 99, 71, 56, 53, 45, 111, 76, 75, 81, 116, 53, 86, 69, 112, 87, 72, 75, 109, 106, 79, 105, 95, 103, 74, 83, 100, 83, 103, 113, 99, 78, 57, 54, 88, 53, 50, 101, 115, 65, 81, 34, 44, 34, 112, 34, 58, 34, 50, 114, 110, 83, 79, 86, 52, 104, 75, 83, 78, 56, 115, 83, 52, 67, 103, 99, 81, 72, 70, 98, 115, 48, 56, 88, 98, 111, 70, 68, 113, 75, 117, 109, 51, 115, 99, 52, 104, 51, 71, 82, 120, 114, 84, 109, 81, 100, 108, 49, 90, 75, 57, 117, 119, 45, 80, 73, 72, 102, 81, 80, 48, 70, 107, 120, 88, 86, 114, 120, 45, 87, 69, 45, 90, 69, 98, 114, 113, 105, 118, 72, 95, 50, 105, 67, 76, 85, 83, 55, 119, 65, 108, 54, 88, 118, 65, 82, 116, 49, 75, 107, 73, 97, 85, 120, 80, 80, 83, 89, 66, 57, 121, 107, 51, 49, 115, 48, 81, 56, 85, 75, 57, 54, 69, 51, 95, 79, 114, 65, 68, 65, 89, 116, 65, 74, 115, 45, 77, 51, 74, 120, 67, 76, 102, 78, 103, 113, 104, 53, 54, 72, 68, 110, 69, 84, 84, 81, 104, 72, 51, 114, 67, 84, 53, 84, 51, 121, 74, 119, 115, 34, 44, 34, 113, 34, 58, 34, 49, 117, 95, 82, 105, 70, 68, 80, 55, 76, 66, 89, 104, 51, 78, 52, 71, 88, 76, 84, 57, 79, 112, 83, 75, 89, 80, 48, 117, 81, 90, 121, 105, 97, 90, 119, 66, 116, 79, 67, 66, 78, 74, 103, 81, 120, 97, 106, 49, 48, 82, 87, 106, 115, 90, 117, 48, 99, 54, 73, 101, 100, 105, 115, 52, 83, 55, 66, 95, 99, 111, 83, 75, 66, 48, 75, 106, 57, 80, 97, 80, 97, 66, 122, 103, 45, 73, 121, 83, 82, 118, 118, 99, 81, 117, 80, 97, 109, 81, 117, 54, 54, 114, 105, 77, 104, 106, 86, 116, 71, 54, 84, 108, 86, 56, 67, 76, 67, 89, 75, 114, 89, 108, 53, 50, 122, 105, 113, 75, 48, 69, 95, 121, 109, 50, 81, 110, 107, 119, 115, 85, 88, 55, 101, 89, 84, 66, 55, 76, 98, 65, 72, 82, 75, 57, 71, 113, 111, 99, 68, 69, 53, 66, 48, 102, 56, 48, 56, 73, 52, 115, 34, 44, 34, 100, 112, 34, 58, 34, 75, 107, 77, 84, 87, 113, 66, 85, 101, 102, 86, 119, 90, 50, 95, 68, 98, 106, 49, 112, 80, 81, 113, 121, 72, 83, 72, 106, 106, 57, 48, 76, 53, 120, 95, 77, 79, 122, 113, 89, 65, 74, 77, 99, 76, 77, 90, 116, 98, 85, 116, 119, 75, 113, 118, 86, 68, 113, 51, 116, 98, 69, 111, 51, 90, 73, 99, 111, 104, 98, 68, 116, 116, 54, 83, 98, 102, 109, 87, 122, 103, 103, 97, 98, 112, 81, 120, 78, 120, 117, 66, 112, 111, 79, 79, 102, 95, 97, 95, 72, 103, 77, 88, 75, 95, 108, 104, 113, 105, 103, 73, 52, 121, 95, 107, 113, 83, 49, 119, 89, 53, 50, 73, 119, 106, 85, 110, 53, 114, 103, 82, 114, 74, 45, 121, 89, 111, 49, 104, 52, 49, 75, 82, 45, 118, 122, 50, 112, 89, 104, 69, 65, 101, 89, 114, 104, 116, 116, 87, 116, 120, 86, 113, 76, 67, 82, 86, 105, 68, 54, 99, 34, 44, 34, 100, 113, 34, 58, 34, 65, 118, 102, 83, 48, 45, 103, 82, 120, 118, 110, 48, 98, 119, 74, 111, 77, 83, 110, 70, 120, 89, 99, 75, 49, 87, 110, 117, 69, 106, 81, 70, 108, 117, 77, 71, 102, 119, 71, 105, 116, 81, 66, 87, 116, 102, 90, 49, 69, 114, 55, 116, 49, 120, 68, 107, 98, 78, 57, 71, 81, 84, 66, 57, 121, 113, 112, 68, 111, 89, 97, 78, 48, 54, 72, 55, 67, 70, 116, 114, 107, 120, 104, 74, 73, 66, 81, 97, 106, 54, 110, 107, 70, 53, 75, 75, 83, 51, 84, 81, 116, 81, 53, 113, 67, 122, 107, 79, 107, 109, 120, 73, 101, 51, 75, 82, 98, 66, 121, 109, 88, 120, 107, 98, 53, 113, 119, 85, 112, 88, 53, 69, 76, 68, 53, 120, 70, 99, 54, 70, 101, 105, 97, 102, 87, 89, 89, 54, 51, 84, 109, 109, 69, 65, 117, 95, 108, 82, 70, 67, 79, 74, 51, 120, 68, 101, 97, 45, 111, 116, 115, 34, 44, 34, 113, 105, 34, 58, 34, 108, 83, 81, 105, 45, 119, 57, 67, 112, 121, 85, 82, 101, 77, 69, 114, 80, 49, 82, 115, 66, 76, 107, 55, 119, 78, 116, 79, 118, 115, 53, 69, 81, 112, 80, 113, 109, 117, 77, 118, 113, 87, 53, 55, 78, 66, 85, 99, 122, 83, 99, 69, 111, 80, 119, 109, 85, 113, 113, 97, 98, 117, 57, 86, 48, 45, 80, 121, 52, 100, 81, 53, 55, 95, 98, 97, 112, 111, 75, 82, 117, 49, 82, 57, 48, 98, 118, 117, 70, 110, 85, 54, 51, 83, 72, 87, 69, 70, 103, 108, 90, 81, 118, 74, 68, 77, 101, 65, 118, 109, 106, 52, 115, 109, 45, 70, 112, 48, 111, 89, 117, 95, 110, 101, 111, 116, 103, 81, 48, 104, 122, 98, 73, 53, 103, 114, 121, 55, 97, 106, 100, 89, 121, 57, 45, 50, 108, 78, 120, 95, 55, 54, 97, 66, 90, 111, 79, 85, 117, 57, 72, 67, 74, 45, 85, 115, 102, 83, 79, 73, 56, 34, 125}, 
  cek[] = {111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112, 161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182}, 
  iv[] = {97, 239, 99, 214, 171, 54, 216, 57, 145, 72, 7, 93, 34, 31, 149, 156}, 
  passphrase_a_c[] = "Thus from my lips, by yours, my sin is purged.";
  char * token;
  
  jwe_t * jwe;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_symmetric_key(jwk, passphrase_a_c, sizeof(passphrase_a_c)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, content, sizeof(content)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_PBES2_H256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "p2s", "2WCTcJZ1Rvd_CJuJripQ1w"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_int_value(jwe, "p2c", 4096), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "cty", "jwk+json"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_cypher_key(jwe, cek, sizeof(cek)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_iv(jwe, iv, sizeof(iv)), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  ck_assert_str_eq(jwe_a_c, token);
  r_jwe_free(jwe);
  o_free(token);
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe, jwe_a_c, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  
  r_jwk_free(jwk);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_pbkdf2_test_vectors)
{
  unsigned char *p = (unsigned char *)"password", *s = (unsigned char *)"salt", dk[32] = {0};
  unsigned int plen = 8, slen = 4, c, dklen = 20;
  unsigned char output384_1[] = {0xc0, 0xe1, 0x4f, 0x06, 0xe4, 0x9e, 0x32, 0xd7, 0x3f, 0x9f, 0x52, 0xdd, 0xf1, 0xd0, 0xc5, 0xc7, 0x19, 0x16, 0x09, 0x23}, 
                output512_1[] = {0x86, 0x7f, 0x70, 0xcf, 0x1a, 0xde, 0x02, 0xcf, 0xf3, 0x75, 0x25, 0x99, 0xa3, 0xa5, 0x3d, 0xc4, 0xaf, 0x34, 0xc7, 0xa6},
                output384_2[] = {0x54, 0xf7, 0x75, 0xc6, 0xd7, 0x90, 0xf2, 0x19, 0x30, 0x45, 0x91, 0x62, 0xfc, 0x53, 0x5d, 0xbf, 0x04, 0xa9, 0x39, 0x18}, 
                output512_2[] = {0xe1, 0xd9, 0xc1, 0x6a, 0xa6, 0x81, 0x70, 0x8a, 0x45, 0xf5, 0xc7, 0xc4, 0xe2, 0x15, 0xce, 0xb6, 0x6e, 0x01, 0x1a, 0x2e},
                output384_3[] = {0x55, 0x97, 0x26, 0xbe, 0x38, 0xdb, 0x12, 0x5b, 0xc8, 0x5e, 0xd7, 0x89, 0x5f, 0x6e, 0x3c, 0xf5, 0x74, 0xc7, 0xa0, 0x1c}, 
                output512_3[] = {0xd1, 0x97, 0xb1, 0xb3, 0x3d, 0xb0, 0x14, 0x3e, 0x01, 0x8b, 0x12, 0xf3, 0xd1, 0xd1, 0x47, 0x9e, 0x6c, 0xde, 0xbd, 0xcc},
                output384_5[] = {0x81, 0x91, 0x43, 0xad, 0x66, 0xdf, 0x9a, 0x55, 0x25, 0x59, 0xb9, 0xe1, 0x31, 0xc5, 0x2a, 0xe6, 0xc5, 0xc1, 0xb0, 0xee, 0xd1, 0x8f, 0x4d, 0x28, 0x3b}, 
                output512_5[] = {0x8c, 0x05, 0x11, 0xf4, 0xc6, 0xe5, 0x97, 0xc6, 0xac, 0x63, 0x15, 0xd8, 0xf0, 0x36, 0x2e, 0x22, 0x5f, 0x3c, 0x50, 0x14, 0x95, 0xba, 0x23, 0xb8, 0x68},
                output384_6[] = {0xa3, 0xf0, 0x0a, 0xc8, 0x65, 0x7e, 0x09, 0x5f, 0x8e, 0x08, 0x23, 0xd2, 0x32, 0xfc, 0x60, 0xb3}, 
                output512_6[] = {0x9d, 0x9e, 0x9c, 0x4c, 0xd2, 0x1f, 0xe4, 0xbe, 0x24, 0xd5, 0xb8, 0x24, 0x4c, 0x75, 0x96, 0x65};
  
  c = 1;
  pbkdf2_hmac_sha384(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output384_1, dk, dklen));
  pbkdf2_hmac_sha512(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output512_1, dk, dklen));
  
  c = 2;
  pbkdf2_hmac_sha384(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output384_2, dk, dklen));
  pbkdf2_hmac_sha512(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output512_2, dk, dklen));
  
  c = 4096;
  pbkdf2_hmac_sha384(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output384_3, dk, dklen));
  pbkdf2_hmac_sha512(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output512_3, dk, dklen));
  
  c = 4096;
  p = (unsigned char *)"passwordPASSWORDpassword";
  plen = 24;
  s = (unsigned char *)"saltSALTsaltSALTsaltSALTsaltSALTsalt";
  slen = 36;
  dklen = 25;
  pbkdf2_hmac_sha384(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output384_5, dk, dklen));
  pbkdf2_hmac_sha512(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output512_5, dk, dklen));
  
  p = (unsigned char *)"pass\0word";
  plen = 9;
  s = (unsigned char *)"sa\0lt";
  slen = 5;
  dklen = 16;
  pbkdf2_hmac_sha384(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output384_6, dk, dklen));
  pbkdf2_hmac_sha512(plen, p, c, slen, s, dklen, dk);
  ck_assert_int_eq(0, memcmp(output512_6, dk, dklen));
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE PBES2 encryption tests");
  tc_core = tcase_create("test_rhonabwy_pbes");
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_invalid_privkey);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_pbes2_hs256_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_pbes2_hs384_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_pbes2_hs512_ok);
  tcase_add_test(tc_core, test_rhonabwy_flood_ok);
  tcase_add_test(tc_core, test_rhonabwy_rfc_example);
  tcase_add_test(tc_core, test_rhonabwy_pbkdf2_test_vectors);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE PBES2 encryption tests");
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
