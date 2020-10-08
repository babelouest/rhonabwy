/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <ulfius.h>

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"grut\"}";
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
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2016-06-22\"}";

const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2012-04-29\",\"x5u\":\"https://www.example.com/x509\"}";
const char jwk_pubkey_rsa_x5c_str[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"AL64zn8_QnHYMeZ0LncoXaEde1fiLm1jHjmQsF_449IYALM9if6amFtPDy2"\
                                       "yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf_u3WG7K-IiZhtELto_A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quG"\
                                       "mFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel-W1GC8ugMhyr4_p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPp"\
                                       "njL1XyW-oyVVkaZdklLQp2Btgt9qr21m42f4wTw-Xrp6rCKNb0\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]}";
const char jwk_pubkey_rsa_str_invalid_n[] = "{\"kty\":\"RSA\",\"n\":42,\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2010-04-29\"}";

int callback_jwks_ok (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  json_t * j_jwks = json_loads(jwks_str, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, j_jwks);
  json_decref(j_jwks);
  o_free(jwks_str);
  return U_CALLBACK_CONTINUE;
}

int callback_jwks_error_content_no_jwks (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * j_jwks = json_loads(jwk_pubkey_ecdsa_str, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, j_jwks);
  json_decref(j_jwks);
  return U_CALLBACK_CONTINUE;
}

int callback_jwks_error_content_no_json (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  ulfius_set_string_body_response(response, 200, jwks_str);
  o_free(jwks_str);
  return U_CALLBACK_CONTINUE;
}

int callback_jwks_error_status (const struct _u_request * request, struct _u_response * response, void * user_data) {
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  json_t * j_jwks = json_loads(jwks_str, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 400, j_jwks);
  json_decref(j_jwks);
  o_free(jwks_str);
  return U_CALLBACK_CONTINUE;
}

int callback_jwks_redirect (const struct _u_request * request, struct _u_response * response, void * user_data) {
  u_map_put(response->map_header, "Location", "jwks_ok");
  response->status = 302;
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_rhonabwy_init_jwks)
{
  jwks_t * jwks;
  
  ck_assert_int_eq(r_jwks_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_is_valid)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_is_valid(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 0);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 1);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 2);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 3);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 4);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kty", "error"), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 5);
  ck_assert_int_eq(r_jwks_is_valid(jwks), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  r_jwks_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_export_str)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  char * out;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 2);
  r_jwk_free(jwk);
  
  ck_assert_ptr_ne((out = r_jwks_export_to_json_str(jwks, 0)), NULL);
  
  o_free(out);
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_export_json_t)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  json_t * j_out;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 2);
  r_jwk_free(jwk);
  
  ck_assert_ptr_ne((j_out = r_jwks_export_to_json_t(jwks)), NULL);
  
  json_decref(j_out);
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_export_privkey)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  gnutls_privkey_t * out = NULL;
  size_t len = 0;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 1);
  ck_assert_ptr_ne(out[0], NULL);
  gnutls_privkey_deinit(out[0]);
  o_free(out);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 2);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_eq(out[1], NULL);
  gnutls_privkey_deinit(out[0]);
  o_free(out);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 3);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_eq(out[1], NULL);
  ck_assert_ptr_ne(out[2], NULL);
  gnutls_privkey_deinit(out[0]);
  gnutls_privkey_deinit(out[2]);
  o_free(out);
  
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_export_pubkey)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  gnutls_pubkey_t * out = NULL;
  size_t len = 0;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_pubkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 1);
  ck_assert_ptr_ne(out[0], NULL);
  gnutls_pubkey_deinit(out[0]);
  o_free(out);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_pubkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 2);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_ne(out[1], NULL);
  gnutls_pubkey_deinit(out[0]);
  gnutls_pubkey_deinit(out[1]);
  o_free(out);
#else
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_pubkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 1);
  ck_assert_ptr_ne(out[0], NULL);
  gnutls_pubkey_deinit(out[0]);
  o_free(out);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_pubkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 2);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_ne(out[1], NULL);
  gnutls_pubkey_deinit(out[0]);
  gnutls_pubkey_deinit(out[1]);
  o_free(out);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_pubkey(jwks, &len, 0)), NULL);
  ck_assert_int_eq(len, 3);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_ne(out[1], NULL);
  ck_assert_ptr_ne(out[2], NULL);
  gnutls_pubkey_deinit(out[0]);
  gnutls_pubkey_deinit(out[1]);
  gnutls_pubkey_deinit(out[2]);
  o_free(out);
  
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_export_pem)
{
  jwks_t * jwks;
  jwk_t  * jwk;
  unsigned char out[4096];
  size_t len = 4096;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
#endif
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwks_export_to_pem_der(jwks, R_FORMAT_PEM, out, &len, 0), RHN_OK);
  ck_assert_int_lt(len, 4096);
  len = 42;
  ck_assert_int_eq(r_jwks_export_to_pem_der(jwks, R_FORMAT_PEM, out, &len, 0), RHN_ERROR_PARAM);
  
  r_jwk_free(jwks);
}
END_TEST

START_TEST(test_rhonabwy_jwks_import)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwks_import_from_str(NULL, jwks_str), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_str(jwks, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_str(NULL, NULL), RHN_ERROR_PARAM);
  
  ck_assert_ptr_ne(jwks_str, NULL);
  ck_assert_int_eq(r_jwks_import_from_str(jwks, "{error}"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_str(jwks, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 4);
  r_jwk_free(jwks);
  o_free(jwks_str);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_str_invalid_n);
  ck_assert_ptr_ne(jwks_str, NULL);
  ck_assert_int_eq(r_jwks_import_from_str(jwks, jwks_str), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_size(jwks), 3);
  r_jwk_free(jwks);
  o_free(jwks_str);
  
}
END_TEST

START_TEST(test_rhonabwy_jwks_import_uri)
{
  struct _u_instance instance;
  jwks_t * jwks = NULL;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_ok", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_content_no_jwks", NULL, 0, &callback_jwks_error_content_no_jwks, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_content_no_json", NULL, 0, &callback_jwks_error_content_no_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_status", NULL, 0, &callback_jwks_error_status, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_redirect", NULL, 0, &callback_jwks_redirect, NULL), U_OK);
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(NULL, "http://localhost:7462/jwks_ok", 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_uri(NULL, NULL, 0), RHN_ERROR_PARAM);
  r_jwk_free(jwks);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_ok", 0), RHN_ERROR);
  r_jwk_free(jwks);

  ck_assert_int_eq(ulfius_start_framework(&instance), U_OK);
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_error_content_no_jwks", 0), RHN_ERROR);
  r_jwk_free(jwks);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_error_content_no_json", 0), RHN_ERROR);
  r_jwk_free(jwks);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_error_status", 0), RHN_ERROR);
  r_jwk_free(jwks);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_redirect", 0), RHN_ERROR);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_redirect", R_FLAG_FOLLOW_REDIRECT), RHN_OK);
  r_jwk_free(jwks);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_ok", 0), RHN_OK);
  r_jwk_free(jwks);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_jwks_get_by_kid)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwks_import_from_str(jwks, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 4);
  
  ck_assert_ptr_eq(r_jwks_get_by_kid(jwks, ""), NULL);
  ck_assert_ptr_eq(r_jwks_get_by_kid(jwks, NULL), NULL);
  ck_assert_ptr_eq(r_jwks_get_by_kid(jwks, "error"), NULL);
  jwk = r_jwks_get_by_kid(jwks, "1");
  ck_assert_ptr_ne(jwk, NULL);
  
  r_jwk_free(jwk);
  r_jwk_free(jwks);
  o_free(jwks_str);
}
END_TEST

START_TEST(test_rhonabwy_jwks_equal)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str),
       * jwks_str2 = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks1, * jwks2;
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks1, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks2, jwks_str), RHN_OK);
  
  ck_assert_int_ne(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks1, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks2, jwks_str2), RHN_OK);
  
  ck_assert_int_eq(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks1, jwks_str), RHN_OK);
  
  ck_assert_int_eq(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  
  ck_assert_int_ne(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  o_free(jwks_str);
  o_free(jwks_str2);
}
END_TEST

START_TEST(test_rhonabwy_jwks_empty)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwks_import_from_str(jwks, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 4);
  
  ck_assert_int_eq(r_jwks_empty(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_empty(jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 0);
  
  r_jwk_free(jwks);
  o_free(jwks_str);
}
END_TEST

START_TEST(test_rhonabwy_jwks_copy)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks1, * jwks2;

  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks1, jwks_str), RHN_OK);
  ck_assert_ptr_ne((jwks2 = r_jwks_copy(jwks1)), NULL);

  ck_assert_int_ne(r_jwks_equal(jwks1, jwks2), 0);

  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  o_free(jwks_str);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWKS core function tests");
  tc_core = tcase_create("test_rhonabwy_jwks");
  tcase_add_test(tc_core, test_rhonabwy_init_jwks);
  tcase_add_test(tc_core, test_rhonabwy_jwks_is_valid);
  tcase_add_test(tc_core, test_rhonabwy_jwks_export_str);
  tcase_add_test(tc_core, test_rhonabwy_jwks_export_json_t);
  tcase_add_test(tc_core, test_rhonabwy_jwks_export_privkey);
  tcase_add_test(tc_core, test_rhonabwy_jwks_export_pubkey);
  tcase_add_test(tc_core, test_rhonabwy_jwks_export_pem);
  tcase_add_test(tc_core, test_rhonabwy_jwks_import);
  tcase_add_test(tc_core, test_rhonabwy_jwks_import_uri);
  tcase_add_test(tc_core, test_rhonabwy_jwks_get_by_kid);
  tcase_add_test(tc_core, test_rhonabwy_jwks_equal);
  tcase_add_test(tc_core, test_rhonabwy_jwks_empty);
  tcase_add_test(tc_core, test_rhonabwy_jwks_copy);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWKS jwks tests");
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
