/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":\"https://www.example.com/x509\"}";
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
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                  "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                  "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                  ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2020-03-13\"}";
const char jwk_pubkey_rsa_2_str[] = "{\"kty\":\"RSA\",\"n\":\"ANL8e2oKHmxnEErrj4iyV2abTfZ53a0Jm1xKbNmogBW1oTO_C4VseHG23wALVU_Os8LtUSu2jxRcboQ0dS-rUqHPwSRAj3m1"\
                                    "ikV4wWQohVeJ96JJ44TLLZ-uLWf9lvuSbBmOB3OZ_cgVwK8Jfd5are_0TecOgn9IeEMkOb_uuWBo0EdPxQ1tkL86mN-vEEDInALWkqs7PCiWYJ2G_XO3dM4HQ"\
                                    "GR87uqjEL0S-YWo659Z_dQmzqWyEg9PKjS8q3ZLfmxU1oQCOLzEBYelnmbtHzOJRXdjXEcK91z5LCDR2kPhv8QZ4iKm8NC7NYxeOPnLBQrq_pBIFPGsGqScyp"\
                                    "6gyoM\",\"e\":\"AQAB\",\"kid\":\"rTIyDPbFltiEsFOBulc6uo3dV0m03o9KI6efmondrrI\"}";
const char jwk_pubkey_rsa_2_pem[] = "-----BEGIN PUBLIC KEY-----"\
                                  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX"\
                                  "ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS"\
                                  "oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt"\
                                  "7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0"\
                                  "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f"\
                                  "M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK"\
                                  "gwIDAQAB"\
                                  "-----END PUBLIC KEY-----";
const char jwk_pubkey_rsa_3_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                    "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                    "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                    ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_3_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
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
#if GNUTLS_VERSION_NUMBER >= 0x030600
const char jwk_pubkey_ecdsa_2_str[] = "{\"kty\":\"EC\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"AOBLZekkVtmIi1Kzeb371R7oae8fD8ZbZllpW2zOC"\
                                      "Bcj\",\"crv\":\"P-256\",\"kid\":\"UblEzfpUTUwyc6pr81BiWn3VO7tqcXIydPU4sZogd2A\"}";
const char jwk_pubkey_ecdsa_2_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                                      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\n"\
                                      "iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n"\
                                      "-----END PUBLIC KEY-----\n";
#endif
const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0\"}";

const char jwk_from_rfc[] = "{\
\"kty\": \"RSA\",\
\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\
W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\
\"e\": \"AQAB\",\
\"alg\": \"RS256\",\
\"kid\": \"2011-04-29\"\
}";

const char jwk_from_frc_thumb[] = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

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
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "x5u"), "https://www.example.com/x509");
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kty"), "RSA");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "use"), "sig");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "kid"), "1b94c");
  ck_assert_str_eq(r_jwk_get_property_str(jwk, "n"), "AL64zn8_QnHYMeZ0LncoXaEde1fiLm1jHjmQsF_449IYALM9if6amFtPDy2"\
                                                     "yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf_u3WG7K-IiZhtELto_A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quG"\
                                                     "mFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel-W1GC8ugMhyr4_p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPp"\
                                                     "njL1XyW-oyVVkaZdklLQp2Btgt9qr21m42f4wTw-Xrp6rCKNb0");
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
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 1, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 555, KID), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDSA, 521, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_privkey, "kid"));
  ck_assert_str_eq("P-521", r_jwk_get_property_str(jwk_privkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_privkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 521);
  ck_assert_int_eq(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_str_eq("P-521", r_jwk_get_property_str(jwk_pubkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 521);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);

  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_EDDSA, 256, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_str_eq("Ed25519", r_jwk_get_property_str(jwk_pubkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);

#if GNUTLS_VERSION_NUMBER >= 0x03060e
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_EDDSA, 448, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_str_eq("Ed448", r_jwk_get_property_str(jwk_pubkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 448);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
#endif

  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDH, 256, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_str_eq("X25519", r_jwk_get_property_str(jwk_pubkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 256);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDH, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_HMAC, 0);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);

  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_privkey, jwk_pubkey, R_KEY_TYPE_ECDH, 448, KID), RHN_OK);
  ck_assert_str_eq(KID, r_jwk_get_property_str(jwk_pubkey, "kid"));
  ck_assert_str_eq("X448", r_jwk_get_property_str(jwk_pubkey, "crv"));
  ck_assert_int_ne((type = r_jwk_key_type(jwk_pubkey, &bits, 0)), R_KEY_TYPE_NONE);
  ck_assert_int_eq(bits, 448);
  ck_assert_int_ne(type & R_KEY_TYPE_PUBLIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_PRIVATE, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_SYMMETRIC, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_RSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_EDDSA, 0);
  ck_assert_int_eq(type & R_KEY_TYPE_ECDSA, 0);
  ck_assert_int_ne(type & R_KEY_TYPE_ECDH, 0);
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

START_TEST(test_rhonabwy_thumb)
{
  jwk_t * jwk1, * jwk2 = NULL;
  char * thumb1, * thumb2, * thumb3;

  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk2, jwk_pubkey_rsa_x5u_str), RHN_OK);

  ck_assert_ptr_eq(NULL, r_jwk_thumbprint(NULL, 42, 0));
  ck_assert_ptr_eq(NULL, r_jwk_thumbprint(NULL, R_JWK_THUMB_SHA256, 0));
  ck_assert_ptr_eq(NULL, r_jwk_thumbprint(jwk1, 42, 0));

  // Compare 2 equivalent keys, one with more optional properties
  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_ptr_ne(NULL, (thumb2 = r_jwk_thumbprint(jwk2, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq(thumb1, thumb2);
  r_free(thumb1);
  r_free(thumb2);
  r_jwk_free(jwk1);
  r_jwk_free(jwk2);

  // Compare 2 equivalent RSA keys, one in PEM format, one in jwk format
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_rsa_2_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk2, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)jwk_pubkey_rsa_2_pem, o_strlen(jwk_pubkey_rsa_2_pem)), RHN_OK);

  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_ptr_ne(NULL, (thumb2 = r_jwk_thumbprint(jwk2, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq(thumb1, thumb2);
  r_jwk_free(jwk1);
  r_jwk_free(jwk2);
  r_free(thumb1);
  r_free(thumb2);

#if GNUTLS_VERSION_NUMBER >= 0x030600
  // Compare 2 equivalent ecdsa keys, one in PEM format, one in jwk format
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_ecdsa_2_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_pem_der(jwk2, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)jwk_pubkey_ecdsa_2_pem, o_strlen(jwk_pubkey_ecdsa_2_pem)), RHN_OK);

  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_ptr_ne(NULL, (thumb2 = r_jwk_thumbprint(jwk2, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq(thumb1, thumb2);
  r_free(thumb1);
  r_free(thumb2);
  r_jwk_free(jwk1);
  r_jwk_free(jwk2);
#endif

  // Test SHA256, SHA384 and SHA512 thumbprints
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_str_eq("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq("R9_OfJjSjaw8Fuum86UzK5ixTdN9bo9BaqPSiseq89DWfmqCdpSgUHus-cxDUNc8", (thumb2 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA384, 0)));
  ck_assert_str_eq("DpvEwocfn3FjeWWQjcJHzWrpKTIymKwgoL1xVgQcud48-qZDSRCr1zfWZQdHAJn_ciqXqPTSARyg-L-NyNGpVA", (thumb3 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA512, 0)));
  r_free(thumb1);
  r_free(thumb2);
  r_free(thumb3);
  r_jwk_free(jwk1);

  // Test symmetric key thumb
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_key_symmetric), RHN_OK);
  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  r_free(thumb1);
  r_jwk_free(jwk1);

  // Test key thumbprint example in the RFC
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_from_rfc), RHN_OK);
  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq(thumb1, jwk_from_frc_thumb);
  r_free(thumb1);
  r_jwk_free(jwk1);

  // Compare 2 keys, one private, one public
  ck_assert_int_eq(r_jwk_init(&jwk1), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk1, jwk_pubkey_rsa_3_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk2, jwk_privkey_rsa_3_str), RHN_OK);
  ck_assert_ptr_ne(NULL, (thumb1 = r_jwk_thumbprint(jwk1, R_JWK_THUMB_SHA256, 0)));
  ck_assert_ptr_ne(NULL, (thumb2 = r_jwk_thumbprint(jwk2, R_JWK_THUMB_SHA256, 0)));
  ck_assert_str_eq(thumb1, thumb2);
  r_free(thumb1);
  r_free(thumb2);
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
  tcase_add_test(tc_core, test_rhonabwy_thumb);
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
  r_global_init();
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  r_global_close();
  y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
