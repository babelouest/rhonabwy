/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"1\"}";
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
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0Cg\"}";

const unsigned char symmetric_key[] = "my-very-secret";
const unsigned char rsa_2048_pub[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
"uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
"iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
"ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
"6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
"K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
"BwIDAQAB\n"
"-----END PUBLIC KEY-----\n";
const unsigned char rsa_2048_priv[] = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDC2kwAziXUf33m\n"
"iqWp0yG6o259+nj7hpQLC4UT0Hmz0wmvreDJ/yNbSgOvsxvVdvzL2IaRZ+Gi5mo0\n"
"lswWvL6IGz7PZO0kXTq9sdBnNqMOx27HddV9e/2/p0MgibJTbgywY2Sk23QYhJpq\n"
"Kq/nU0xlBfSaI5ddZ2RC9ZNkVeGawUKYksTruhAVJqviHN8BoK6VowP5vcxyyOWH\n"
"TK9KruDqzCIhqwRTeo0spokBkTN/LCuhVivcHAzUiJVtB4qAiTI9L/zkzhjpKz9P\n"
"45aLU54rj011gG8U/6E1USh5nMnPkr+d3oLfkhfS3Zs3kJVdyFQWZpQxiTaI92Fd\n"
"2wLvbS0HAgMBAAECggEAD8dTnkETSSjlzhRuI9loAtAXM3Zj86JLPLW7GgaoxEoT\n"
"n7lJ2bGicFMHB2ROnbOb9vnas82gtOtJsGaBslmoaCckp/C5T1eJWTEb+i+vdpPp\n"
"wZcmKZovyyRFSE4+NYlU17fEv6DRvuaGBpDcW7QgHJIl45F8QWEM+msee2KE+V4G\n"
"z/9vAQ+sOlvsb4mJP1tJIBx9Lb5loVREwCRy2Ha9tnWdDNar8EYkOn8si4snPT+E\n"
"3ZCy8mlcZyUkZeiS/HdtydxZfoiwrSRYamd1diQpPhWCeRteQ802a7ds0Y2YzgfF\n"
"UaYjNuRQm7zA//hwbXS7ELPyNMU15N00bajlG0tUOQKBgQDnLy01l20OneW6A2cI\n"
"DIDyYhy5O7uulsaEtJReUlcjEDMkin8b767q2VZHb//3ZH+ipnRYByUUyYUhdOs2\n"
"DYRGGeAebnH8wpTT4FCYxUsIUpDfB7RwfdBONgaKewTJz/FPswy1Ye0b5H2c6vVi\n"
"m2FZ33HQcoZ3wvFFqyGVnMzpOwKBgQDXxL95yoxUGKa8vMzcE3Cn01szh0dFq0sq\n"
"cFpM+HWLVr84CItuG9H6L0KaStEEIOiJsxOVpcXfFFhsJvOGhMA4DQTwH4WuXmXp\n"
"1PoVMDlV65PYqvhzwL4+QhvZO2bsrEunITXOmU7CI6kilnAN3LuP4HbqZgoX9lqP\n"
"I31VYzLupQKBgGEYck9w0s/xxxtR9ILv5XRnepLdoJzaHHR991aKFKjYU/KD7JDK\n"
"INfoAhGs23+HCQhCCtkx3wQVA0Ii/erM0II0ueluD5fODX3TV2ZibnoHW2sgrEsW\n"
"vFcs36BnvIIaQMptc+f2QgSV+Z/fGsKYadG6Q+39O7au/HB7SHayzWkjAoGBAMgt\n"
"Fzslp9TpXd9iBWjzfCOnGUiP65Z+GWkQ/SXFqD+SRir0+m43zzGdoNvGJ23+Hd6K\n"
"TdQbDJ0uoe4MoQeepzoZEgi4JeykVUZ/uVfo+nh06yArVf8FxTm7WVzLGGzgV/uA\n"
"+wtl/cRtEyAsk1649yW/KHPEIP8kJdYAJeoO8xSlAoGAERMrkFR7KGYZG1eFNRdV\n"
"mJMq+Ibxyw8ks/CbiI+n3yUyk1U8962ol2Q0T4qjBmb26L5rrhNQhneM4e8mo9FX\n"
"LlQapYkPvkdrqW0Bp72A/UNAvcGTmN7z5OCJGMUutx2hmEAlrYmpLKS8pM/p9zpK\n"
"tEOtzsP5GMDYVlEp1jYSjzQ=\n"
"-----END PRIVATE KEY-----\n";

START_TEST(test_rhonabwy_init)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_payload)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_payload(NULL, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, NULL, o_strlen(PAYLOAD)), RHN_OK);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_alg)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jwe_set_alg(NULL, R_JWA_ALG_RSA1_5), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_RSA1_5);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES), RHN_OK);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_ECDH_ES);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_set_header)
{
  jwe_t * jwe;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_int_value(jwe, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_int_value(jwe, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_get_header)
{
  jwe_t * jwe;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_int_value(jwe, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jwe_get_header_str_value(jwe, "keystr"));
  ck_assert_int_eq(42, r_jwe_get_header_int_value(jwe, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jwe_get_header_json_t_value(jwe, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jwe_get_header_str_value(jwe, "error"));
  ck_assert_int_eq(0, r_jwe_get_header_int_value(jwe, "error"));
  ck_assert_ptr_eq(NULL, r_jwe_get_header_json_t_value(jwe, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_get_full_header)
{
  jwe_t * jwe;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_header = json_pack("{sssssisO}", "alg", "RSA1_5", "keystr", "value", "keyint", 42, "keyjson", j_value), * j_result;
  
  ck_assert_ptr_ne(j_header, NULL);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_header_str_value(jwe, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_int_value(jwe, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, "keyjson", j_value), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(json_equal(j_header, (j_result = r_jwe_get_full_header_json_t(jwe))) , 1);
  json_decref(j_value);
  json_decref(j_header);
  json_decref(j_result);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_set_keys)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa, * jwk_key_symmetric;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_key_symmetric), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_key_symmetric, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_key_symmetric, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_key_symmetric);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_set_jwks)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
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
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jwe->jwks_privkey));
  ck_assert_int_eq(0, r_jwks_size(jwe->jwks_pubkey));
  ck_assert_int_eq(r_jwe_add_jwks(jwe, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jwe->jwks_privkey));
  ck_assert_int_eq(2, r_jwks_size(jwe->jwks_pubkey));
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_add_keys_by_content)
{
  jwe_t * jwe;
  jwk_t * jwk_priv, * jwk_pub;
  jwks_t * jwks;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_privkey_t g_privkey;
  gnutls_pubkey_t g_pubkey;
#endif
  json_t * j_privkey, * j_pubkey;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_priv, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pub, jwk_pubkey_rsa_str), RHN_OK);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_ptr_ne(g_privkey = r_jwk_export_to_gnutls_privkey(jwk_priv, 0), NULL);
  ck_assert_ptr_ne(g_pubkey = r_jwk_export_to_gnutls_pubkey(jwk_pub, 0), NULL);
#endif
  ck_assert_ptr_ne(j_privkey = r_jwk_export_to_json_t(jwk_priv), NULL);
  ck_assert_ptr_ne(j_pubkey = r_jwk_export_to_json_t(jwk_pub), NULL);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwe_add_keys_json_t(jwe, j_privkey, j_pubkey), RHN_OK);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwe_add_keys_pem_der(jwe, R_FORMAT_PEM, rsa_2048_priv, sizeof(rsa_2048_priv), rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwe_add_key_symmetric(jwe, symmetric_key, sizeof(symmetric_key)), RHN_OK);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwe_add_keys_gnutls(jwe, g_privkey, g_pubkey), RHN_OK);
  
  jwks = r_jwe_get_jwks_privkey(jwe);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwe_get_jwks_pubkey(jwe);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
  
  r_jwe_free(jwe);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_privkey_deinit(g_privkey);
  gnutls_pubkey_deinit(g_pubkey);
#endif
  json_decref(j_privkey);
  json_decref(j_pubkey);
  r_jwk_free(jwk_priv);
  r_jwk_free(jwk_pub);
}
END_TEST

START_TEST(test_rhonabwy_copy)
{
  jwe_t * jwe, * jwe_copy;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL, * token_copy;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_privkey, jwk_pubkey), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_copy = r_jwe_copy(jwe)), NULL);
  ck_assert_ptr_ne((token_copy = r_jwe_serialize(jwe_copy, NULL, 0)), NULL);
  
  o_free(token);
  o_free(token_copy);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_copy);
}
END_TEST

START_TEST(test_rhonabwy_generate_cypher_key)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_generate_cypher_key(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_gt(jwe->key_len, 0);
  ck_assert_ptr_ne(jwe->key, NULL);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_generate_iv)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_generate_iv(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_gt(jwe->iv_len, 0);
  ck_assert_ptr_ne(jwe->iv, NULL);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_payload_invalid)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_iv(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_payload)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_payload_all_format)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);

  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  // R_JWA_ENC_A192GCM not supported by GnuTLS until 3.6.7
  //ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192GCM), RHN_OK);
  //ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  //ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  //ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  //ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  //ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_payload_invalid_key_no_tag)
{
  char payload_control[] = PAYLOAD;
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  jwe->key[18]++;
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_ne(memcmp(payload_control, jwe->payload, jwe->payload_len), 0);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_payload_zip)
{
  jwe_t * jwe;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  
  r_jwe_set_header_str_value(jwe, "zip", "DEF");
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_key_invalid)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_rsa;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, NULL, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe);
  r_jwk_free(jwk_pubkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_key_unsupported_alg)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_rsa;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_ECDH_ES), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe);
  r_jwk_free(jwk_pubkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_key_valid)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_rsa;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_OK);
  ck_assert_int_gt(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  
  r_jwe_free(jwe);
  r_jwk_free(jwk_pubkey_rsa);
}
END_TEST

#if GNUTLS_VERSION_NUMBER >= 0x030600 // This test crashes on old gnutls version (3.4 ubuntu xenial)
START_TEST(test_rhonabwy_decrypt_key_invalid_encrypted_key)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_rsa, * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_OK);
  ck_assert_int_gt(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  ck_assert_int_eq(r_jwe_decrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_ERROR_PARAM);
  if (jwe->encrypted_key_b64url[2] == 'a') {
    jwe->encrypted_key_b64url[2] = 'e';
  } else {
    jwe->encrypted_key_b64url[2] = 'a';
  }
  ck_assert_int_eq(r_jwe_decrypt_key(jwe, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwe_free(jwe);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST
#endif

START_TEST(test_rhonabwy_decrypt_key_valid)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey_rsa, * jwk_privkey_rsa;
  unsigned char key[512];
  size_t key_len = 0;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  memcpy(key, jwe->key, jwe->key_len);
  key_len = jwe->key_len;
  ck_assert_int_gt(key_len, 0);
  ck_assert_ptr_ne(key, NULL);
  ck_assert_int_eq(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  ck_assert_int_eq(r_jwe_encrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_OK);
  ck_assert_int_gt(o_strlen((const char *)jwe->encrypted_key_b64url), 0);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt_key(jwe, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_int_gt(jwe->key_len, 0);
  ck_assert_ptr_ne(jwe->key, NULL);
  ck_assert_int_eq(jwe->key_len, key_len);
  ck_assert_int_eq(0, memcmp(jwe->key, key, key_len));
  
  r_jwe_free(jwe);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_add_test(tc_core, test_rhonabwy_payload);
  tcase_add_test(tc_core, test_rhonabwy_alg);
  tcase_add_test(tc_core, test_rhonabwy_set_header);
  tcase_add_test(tc_core, test_rhonabwy_get_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_header);
  tcase_add_test(tc_core, test_rhonabwy_set_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_jwks);
  tcase_add_test(tc_core, test_rhonabwy_add_keys_by_content);
  tcase_add_test(tc_core, test_rhonabwy_copy);
  tcase_add_test(tc_core, test_rhonabwy_generate_cypher_key);
  tcase_add_test(tc_core, test_rhonabwy_generate_iv);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_all_format);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_payload_invalid_key_no_tag);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_zip);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_key_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_key_unsupported_alg);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_key_valid);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_rhonabwy_decrypt_key_invalid_encrypted_key);
#endif
  tcase_add_test(tc_core, test_rhonabwy_decrypt_key_valid);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE core tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
