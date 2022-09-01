/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define TOKEN "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_ENCRYPTED_KEY "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-y8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_IV "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgQoD.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrg3E.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_TAG "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOB"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_7"
#define TOKEN_INVALID_HEADER_B64 ";error;iOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.;error;nK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.;error;czZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.;error;Z3gDEpAMD_79pOw"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"

const char jwk_key_invalid_small[] = "{\"kty\":\"oct\",\"k\":\"Z3J1dAo\"}";
const char jwk_key_invalid_large[] = "{\"kty\":\"oct\",\"k\":\"Z3J1dHBsb3Bjb2luZ25hYWdydXRwbG9wY29pbmduYWFncnV0cGxvcGNvaW5nbmFhZ3J1dHBsb3Bjb2luZ25hYQo\"}";
const char jwk_key_128_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}";
const char jwk_key_128_2[] = "{\"kty\":\"oct\",\"k\":\"CAkKCwwNDg8QERITFBUWFw\"}";
const char jwk_key_192_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX\"}";
const char jwk_key_256_1[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}";

#if NETTLE_VERSION_NUMBER >= 0x030400
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
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
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

START_TEST(test_rhonabwy_encrypt_decrypt_a128kw_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_128_1), RHN_OK);
  
  // R_JWA_ENC_A128CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A192CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A256CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A128GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  // R_JWA_ENC_A192GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
#endif
  
  // R_JWA_ENC_A256GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
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

START_TEST(test_rhonabwy_encrypt_decrypt_a192kw_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_192_1), RHN_OK);
  
  // R_JWA_ENC_A128CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A192CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A256CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A128GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  // R_JWA_ENC_A192GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
#endif
  
  // R_JWA_ENC_A256GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A192KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
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

START_TEST(test_rhonabwy_encrypt_decrypt_a256kw_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_256_1), RHN_OK);
  
  // R_JWA_ENC_A128CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A192CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A256CBC
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
  // R_JWA_ENC_A128GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  // R_JWA_ENC_A192GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
#endif
  
  // R_JWA_ENC_A256GCM
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
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
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A256KW), RHN_OK);
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

START_TEST(test_rhonabwy_check_key_length)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_1, * jwk_2, * jwk_3, * jwk_4;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_2), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_3), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_4), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_1, jwk_key_128_1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_2, jwk_key_256_1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_3, jwk_key_invalid_small), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_4, jwk_key_invalid_large), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_1, 0)), NULL);
  ck_assert_ptr_eq(r_jwe_serialize(jwe_enc_1, jwk_3, 0), NULL);
  ck_assert_ptr_eq(r_jwe_serialize(jwe_enc_1, jwk_4, 0), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_A256KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_2, 0)), NULL);
  ck_assert_ptr_eq(r_jwe_serialize(jwe_enc_2, jwk_3, 0), NULL);
  ck_assert_ptr_eq(r_jwe_serialize(jwe_enc_2, jwk_4, 0), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_1, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_3, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_4, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_2, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_3, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_4, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_2, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_1, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_1);
  r_jwk_free(jwk_2);
  r_jwk_free(jwk_3);
  r_jwk_free(jwk_4);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

START_TEST(test_rhonabwy_rfc_example)
{
  const char jwe_a_3[] = 
  "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ", 
  jwe_a_3_key[] = "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}";
  const unsigned char content[] = {76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46}, 
  cek[] = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207}, 
  iv[] = {3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101};
  char * token;
  
  jwe_t * jwe;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwe_a_3_key), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, content, sizeof(content)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_A128KW), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_cypher_key(jwe, cek, sizeof(cek)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_iv(jwe, iv, sizeof(iv)), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk, 0)), NULL);
  ck_assert_str_eq(jwe_a_3, token);
  r_jwe_free(jwe);
  o_free(token);
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe, jwe_a_3, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  
  r_jwk_free(jwk);
  r_jwe_free(jwe);
}
END_TEST
#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE AES Key Wrap encryption tests");
  tc_core = tcase_create("test_rhonabwy_kw");
#if NETTLE_VERSION_NUMBER >= 0x030400
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_invalid_privkey);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_a128kw_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_a192kw_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_a256kw_ok);
  tcase_add_test(tc_core, test_rhonabwy_flood_ok);
  tcase_add_test(tc_core, test_rhonabwy_check_key_length);
  tcase_add_test(tc_core, test_rhonabwy_rfc_example);
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
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE AES Key Wrap encryption tests");
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
