/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

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

#define JWT_CLAIM_ISS "https://rhonabwy.tld"
#define JWT_CLAIM_SUB "rhon_sub"
#define JWT_CLAIM_AUD "dave_lopper"
#define JWT_CLAIM_EXP 30
#define JWT_CLAIM_NBF 30
#define JWT_CLAIM_IAT 30
#define JWT_CLAIM_JTI "jit1234Xyz"
#define JWT_CLAIM_SCOPE "scope1"
#define JWT_CLAIM_AGE 42
#define JWT_CLAIM_VERIFIED json_true()
#define JWT_CLAIM_TYP "jwt+rhnabwy"
#define JWT_CLAIM_CTY "application/mater"

START_TEST(test_rhonabwy_init)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_alg)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jwt_set_sign_alg(NULL, R_JWA_ALG_ES256), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_ES256);
  
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS512), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_RS512);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_enc_alg)
{
  jwt_t * jwt;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jwt_set_enc_alg(NULL, R_JWA_ALG_RSA1_5), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_RSA1_5);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_ECDH_ES), RHN_OK);
  ck_assert_int_eq(r_jwt_get_enc_alg(jwt), R_JWA_ALG_ECDH_ES);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jwt_get_header_str_value(jwt, "keystr"));
  ck_assert_int_eq(42, r_jwt_get_header_int_value(jwt, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jwt_get_header_json_t_value(jwt, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_header_str_value(jwt, "error"));
  ck_assert_int_eq(0, r_jwt_get_header_int_value(jwt, "error"));
  ck_assert_ptr_eq(NULL, r_jwt_get_header_json_t_value(jwt, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_full_header)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_header = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value), * j_result;
  
  ck_assert_ptr_ne(j_header, NULL);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_header_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(json_equal(j_header, (j_result = r_jwt_get_full_header_json_t(jwt))) , 1);
  json_decref(j_value);
  json_decref(j_header);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_claim)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_claim)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  ck_assert_int_eq(42, r_jwt_get_claim_int_value(jwt, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jwt_get_claim_json_t_value(jwt, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "error"));
  ck_assert_int_eq(0, r_jwt_get_claim_int_value(jwt, "error"));
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_json_t_value(jwt, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_full_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));
  
  json_decref(j_value);
  json_decref(j_claims);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_full_claims_str)
{
  jwt_t * jwt;
  char str_value[] = "{\"str\":\"grut\",\"int\":42,\"obj\":true}";
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_str_eq("value", r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_int_eq(r_jwt_set_full_claims_json_str(jwt, str_value), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwt_get_claim_str_value(jwt, "keystr"));
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));
  
  json_decref(j_value);
  json_decref(j_claims);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_get_full_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), 
         * j_claims, 
         * j_expected = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected));
  
  json_decref(j_value);
  json_decref(j_claims);
  json_decref(j_expected);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_append_claims)
{
  jwt_t * jwt;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), 
         * j_claims, 
         * j_expected_1 = json_pack("{sssi}", "keystr", "value", "keyint", 42),
         * j_expected_2 = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "keyint", 42), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected_1));
  json_decref(j_claims);
  
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "keyjson", j_value), RHN_OK);
  
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_expected_2));
  
  json_decref(j_value);
  json_decref(j_claims);
  json_decref(j_expected_1);
  json_decref(j_expected_2);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_sign_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_sign_jwks)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
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
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_privkey_sign));
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_pubkey_sign));
  ck_assert_int_eq(r_jwt_add_sign_jwks(jwt, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_privkey_sign));
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_pubkey_sign));
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_add_sign_keys_by_content)
{
  jwt_t * jwt;
  jwk_t * jwk_priv, * jwk_pub;
  jwks_t * jwks;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_privkey_t g_privkey;
  gnutls_pubkey_t g_pubkey;
#endif
  json_t * j_privkey, * j_pubkey;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_priv, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pub, jwk_pubkey_rsa_str), RHN_OK);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_ptr_ne(g_privkey = r_jwk_export_to_gnutls_privkey(jwk_priv), NULL);
  ck_assert_ptr_ne(g_pubkey = r_jwk_export_to_gnutls_pubkey(jwk_pub, 0), NULL);
#endif
  ck_assert_ptr_ne(j_privkey = r_jwk_export_to_json_t(jwk_priv), NULL);
  ck_assert_ptr_ne(j_pubkey = r_jwk_export_to_json_t(jwk_pub), NULL);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_sign_keys_json_t(jwt, j_privkey, j_pubkey), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt, R_FORMAT_PEM, rsa_2048_priv, sizeof(rsa_2048_priv), rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_sign_key_symmetric(jwt, symmetric_key, sizeof(symmetric_key)), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwt_add_sign_keys_gnutls(jwt, g_privkey, g_pubkey), RHN_OK);
  
  jwks = r_jwt_get_sign_jwks_privkey(jwt);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_sign_jwks_pubkey(jwt);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
  
  r_jwt_free(jwt);
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

START_TEST(test_rhonabwy_set_enc_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_set_enc_jwks)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
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
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_privkey_enc));
  ck_assert_int_eq(0, r_jwks_size(jwt->jwks_pubkey_enc));
  ck_assert_int_eq(r_jwt_add_enc_jwks(jwt, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_privkey_enc));
  ck_assert_int_eq(2, r_jwks_size(jwt->jwks_pubkey_enc));
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_add_enc_keys_by_content)
{
  jwt_t * jwt;
  jwk_t * jwk_priv, * jwk_pub;
  jwks_t * jwks;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_privkey_t g_privkey;
  gnutls_pubkey_t g_pubkey;
#endif
  json_t * j_privkey, * j_pubkey;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_priv, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pub, jwk_pubkey_rsa_str), RHN_OK);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_ptr_ne(g_privkey = r_jwk_export_to_gnutls_privkey(jwk_priv), NULL);
  ck_assert_ptr_ne(g_pubkey = r_jwk_export_to_gnutls_pubkey(jwk_pub, 0), NULL);
#endif
  ck_assert_ptr_ne(j_privkey = r_jwk_export_to_json_t(jwk_priv), NULL);
  ck_assert_ptr_ne(j_pubkey = r_jwk_export_to_json_t(jwk_pub), NULL);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_enc_keys_json_str(jwt, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_enc_keys_json_t(jwt, j_privkey, j_pubkey), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_enc_keys_pem_der(jwt, R_FORMAT_PEM, rsa_2048_priv, sizeof(rsa_2048_priv), rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jwt_add_enc_key_symmetric(jwt, symmetric_key, sizeof(symmetric_key)), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwt_add_enc_keys_gnutls(jwt, g_privkey, g_pubkey), RHN_OK);
  
  jwks = r_jwt_get_enc_jwks_privkey(jwt);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jwt_get_enc_jwks_pubkey(jwt);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
  
  r_jwt_free(jwt);
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

START_TEST(test_rhonabwy_validate_claims)
{
  jwt_t * jwt;
  time_t now;

  time(&now);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, JWT_CLAIM_SUB, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, JWT_CLAIM_AUD, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, JWT_CLAIM_JTI, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_TYP, JWT_CLAIM_TYP, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_CTY, JWT_CLAIM_CTY, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_PRESENT, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_TYP, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_CTY, NULL, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", JWT_CLAIM_ISS), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sub", JWT_CLAIM_SUB), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, JWT_CLAIM_SUB, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", JWT_CLAIM_AUD), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, JWT_CLAIM_AUD, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "jti", JWT_CLAIM_JTI), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, JWT_CLAIM_JTI, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "exp", (now+JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, now+1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, (now+JWT_CLAIM_EXP+JWT_CLAIM_EXP), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "nbf", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, now-1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, (now-JWT_CLAIM_NBF-JWT_CLAIM_NBF), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iat", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, now-1, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, (now-JWT_CLAIM_IAT-JWT_CLAIM_IAT), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", JWT_CLAIM_SCOPE), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "age", JWT_CLAIM_AGE), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE-1, R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "verified", JWT_CLAIM_VERIFIED), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", json_null(), R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "typ", JWT_CLAIM_TYP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_TYP, JWT_CLAIM_TYP, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_TYP, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_set_header_str_value(jwt, "cty", JWT_CLAIM_CTY), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_CTY, JWT_CLAIM_CTY, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_CTY, "error", R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_SUB, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_AUD, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JTI, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_EXP, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_NBF, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_IAT, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_STR, "scope", NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_JSN, "verified", NULL, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_TYP, NULL, R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, JWT_CLAIM_AUD,
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, NULL,
                                              R_JWT_CLAIM_SUB, NULL,
                                              R_JWT_CLAIM_AUD, NULL,
                                              R_JWT_CLAIM_JTI, NULL,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_PRESENT,
                                              R_JWT_CLAIM_STR, "scope", NULL,
                                              R_JWT_CLAIM_JSN, "verified", NULL,
                                              R_JWT_CLAIM_NOP), RHN_OK);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, "error",
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, JWT_CLAIM_ISS,
                                              R_JWT_CLAIM_SUB, JWT_CLAIM_SUB,
                                              R_JWT_CLAIM_AUD, JWT_CLAIM_AUD,
                                              R_JWT_CLAIM_JTI, JWT_CLAIM_JTI,
                                              R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_IAT, R_JWT_CLAIM_NOW,
                                              R_JWT_CLAIM_STR, "scope", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_INT, "age", JWT_CLAIM_AGE,
                                              R_JWT_CLAIM_JSN, "verified", JWT_CLAIM_VERIFIED,
                                              R_JWT_CLAIM_STR, "error", JWT_CLAIM_SCOPE,
                                              R_JWT_CLAIM_NOP), RHN_ERROR_PARAM);
  
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_copy)
{
  jwt_t * jwt, * jwt_copy;
  char * token = NULL, * token_copy;
  time_t now;
  
  time(&now);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "iss", JWT_CLAIM_ISS), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "sub", JWT_CLAIM_SUB), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "aud", JWT_CLAIM_AUD), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "jti", JWT_CLAIM_JTI), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "exp", (now+JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "nbf", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "iat", (now-JWT_CLAIM_EXP)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_str_value(jwt, "scope", JWT_CLAIM_SCOPE), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_int_value(jwt, "age", JWT_CLAIM_AGE), RHN_OK);
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt, "verified", JWT_CLAIM_VERIFIED), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys_json_str(jwt, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_key_symmetric(jwt, (const unsigned char *)symmetric_key, sizeof(symmetric_key)), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0)), NULL);
  
  ck_assert_ptr_ne((jwt_copy = r_jwt_copy(jwt)), NULL);
  ck_assert_ptr_ne((token_copy = r_jwt_serialize_nested(jwt_copy, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwt_parse(jwt_copy, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt_copy, NULL, 0, NULL, 0), RHN_OK);
  
  o_free(token);
  o_free(token_copy);
  r_jwt_free(jwt);
  r_jwt_free(jwt_copy);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWT core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_add_test(tc_core, test_rhonabwy_sign_alg);
  tcase_add_test(tc_core, test_rhonabwy_enc_alg);
  tcase_add_test(tc_core, test_rhonabwy_set_header);
  tcase_add_test(tc_core, test_rhonabwy_get_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_header);
  tcase_add_test(tc_core, test_rhonabwy_set_claim);
  tcase_add_test(tc_core, test_rhonabwy_get_claim);
  tcase_add_test(tc_core, test_rhonabwy_set_full_claims);
  tcase_add_test(tc_core, test_rhonabwy_set_full_claims_str);
  tcase_add_test(tc_core, test_rhonabwy_get_full_claims);
  tcase_add_test(tc_core, test_rhonabwy_append_claims);
  tcase_add_test(tc_core, test_rhonabwy_set_sign_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_sign_jwks);
  tcase_add_test(tc_core, test_rhonabwy_add_sign_keys_by_content);
  tcase_add_test(tc_core, test_rhonabwy_set_enc_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_enc_jwks);
  tcase_add_test(tc_core, test_rhonabwy_add_enc_keys_by_content);
  tcase_add_test(tc_core, test_rhonabwy_validate_claims);
  tcase_add_test(tc_core, test_rhonabwy_copy);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT core tests");
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
