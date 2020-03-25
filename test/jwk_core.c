/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <rhonabwy.h>

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":[\"https://www.example.com/x509\"]}";
const char jwk_pubkey_rsa_x5c_str[] = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"1b94c\",\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                       "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                       "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                       "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
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

#define KID "kid_1"

START_TEST(test_rhonabwy_init)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_get_property)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "EC");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "crv"), "P-256");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "x"), "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "y"), "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "use"), "enc");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kid"), "1");
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, ""), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, NULL), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(NULL, "kty"), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "error"), NULL);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "RSA");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "n"), "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "e"), "AQAB");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "alg"), "RS256");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kid"), "2011-04-29");
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 0), "https://www.example.com/x509");
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5u", 1), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5u"), NULL);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "RSA");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "use"), "sig");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kid"), "1b94c");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "n"), "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                                     "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                                     "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                                     "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "e"), "AQAB");
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5c", 0), "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==");
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5c", 1), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "x5c"), NULL);
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_set_property)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_set_property_str(NULL, "kid", "42"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "", "42"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, NULL, "42"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kid", ""), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kid", NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "kid", "42"), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "EC");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "crv"), "P-256");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "x"), "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "y"), "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "use"), "enc");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kid"), "42");
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, ""), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, NULL), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(NULL, "kty"), NULL);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "error"), NULL);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "x", ";error;"), RHN_OK);
  ck_assert_int_eq(r_jwk_is_valid(jwk), RHN_ERROR_PARAM);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 0), "https://www.example.com/x509");
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "x5u", NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "x5u", ""), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_array(jwk, "x5u", 1, "https://www.example.com/x509/42"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_array(jwk, "x5u", 0, "https://www.example.com/x509/42"), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 0), "https://www.example.com/x509/42");
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "x5u", "https://www.example.com/x509"), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 0), "https://www.example.com/x509/42");
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 1), "https://www.example.com/x509");
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "new1", 0), NULL);
  ck_assert_int_eq(r_jwk_set_property_array(jwk, "new1", 0, "https://www.example.com/x509/42"), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "new1", 0), "https://www.example.com/x509/42");
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "new2", 0), NULL);
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "new2", "https://www.example.com/x509/42"), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "new2", 0), "https://www.example.com/x509/42");
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5c", 0), "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==");
  ck_assert_int_eq(r_jwk_set_property_array(jwk, "x5c", 1, "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA=="), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_set_property_array(jwk, "x5c", 0, "GIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA=="), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5c", 0), "GIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==");
  ck_assert_int_eq(r_jwk_append_property_array(jwk, "x5c", "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA=="), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5c", 0), "GIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==");
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5c", 1), "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                       "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                       "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                       "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                       "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                       "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                       "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                       "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                       "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                       "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                       "MPvACWpkA6SdS4xSvdXK3IVfOWA==");
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_delete_property)
{
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "EC");
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, ""), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_str(NULL, "kty"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, "kty"), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_str(jwk, "kty"), NULL);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_array(jwk, "x5u", 0), "https://www.example.com/x509");
  ck_assert_int_eq(r_jwk_delete_property_array_at(jwk, "x5u", 1), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_array_at(jwk, "", 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_array_at(jwk, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_array_at(NULL, "x5u", 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_delete_property_array_at(jwk, "x5u", 0), RHN_OK);
  ck_assert_ptr_eq(r_jwk_get_property_array(jwk, "x5u", 0), NULL);
  r_jwk_free(jwk);
  
}
END_TEST

START_TEST(test_rhonabwy_generate_key_pair)
{
  jwk_t * jwk_privkey, * jwk_pubkey;
  unsigned int bits = 0;
  int type;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(NULL, jwk_pubkey, R_KEY_TYPE_RSA, 4096, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, NULL, R_KEY_TYPE_RSA, 4096, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, 0, 4096, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_RSA, 0, KID), RHN_ERROR_PARAM);
  
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_RSA, 4096, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_privkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_privkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 4096);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 4096);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_RSA, 4096, NULL), RHN_OK);
  ck_assert_str_ne(KID, r_jwk_get_property_str(jwk_privkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_privkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 4096);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  ck_assert_str_ne(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 4096);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  
#if GNUTLS_VERSION_NUMBER >= 0x030500
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 1, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 555, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 512, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_privkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_privkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 512);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 512);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
#endif
  
}
END_TEST

START_TEST(test_rhonabwy_equal)
{
  jwk_t * jwk1, * jwk2;
  
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk2), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk2, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_ne(r_jwk_equal(jwk1, jwk2), 0);
  r_jwk_set_property_str(jwk2, "kid", "2");
  ck_assert_int_eq(r_jwk_equal(jwk1, jwk2), 0);

  r_jwk_free(jwk1);
  r_jwk_free(jwk2);
}
END_TEST

START_TEST(test_rhonabwy_copy)
{
  jwk_t * jwk1, * jwk2 = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwk_equal(jwk1, jwk2), 0);
  ck_assert_ptr_ne((jwk2 = r_jwk_copy(jwk1)), NULL);
  ck_assert_int_ne(r_jwk_equal(jwk1, jwk2), 0);

  r_jwk_free(jwk1);
  r_jwk_free(jwk2);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWK core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_add_test(tc_core, test_rhonabwy_get_property);
  tcase_add_test(tc_core, test_rhonabwy_set_property);
  tcase_add_test(tc_core, test_rhonabwy_delete_property);
  tcase_add_test(tc_core, test_rhonabwy_generate_key_pair);
  tcase_add_test(tc_core, test_rhonabwy_equal);
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
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWK core tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
