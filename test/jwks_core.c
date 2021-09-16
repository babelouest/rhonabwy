/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
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

const unsigned char rsa_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIEWTCCAsGgAwIBAgIUJyAFwqkMTppNiyU8gFOK4WUC1GgwDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0xOTEyMDYxMzU1MzlaFw0yMDExMjAxMzU1MzlaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MIIBojANBgkqhkiG9w0BAQEFAAOC\n"
"AY8AMIIBigKCAYEAsUWjL3wK1B/dQbXbhSXaodF0gXMNlZg3ZecjZIJOKgXGDVOn\n"
"V0ly4evW8xkn8F2gC3TYJXik7efdhGdiaYul9kyzpPBr53ELHMmAeI/I1rnF4pgI\n"
"wfN1vBsaDwJw9w0R6FQ9fxDUIte47WdElEHhtST9V874mMehsSUG4xM2qiBvvbWw\n"
"X0KCyKk6BY/CdyljUjAPUShcVysKUTyfefew38KUVTVpk2vWLlN+a41iC/gxGvLt\n"
"H142LDiDx/s+Kh37f4paD2zsEw5McF81eiKTAfrraIC1Gj2BxyEj6n2EjqyI+NFR\n"
"sSUmqfPoFgiMzlEWj4P8AwvfE9jbjXz/E0GOISiXt4L+06U7rLoGHFri5oVI6KUk\n"
"LAOwwwTri+ikeQFx68IKvhytBiX1O+XHh51JZyyC+fcKKN+/ATgGKIiR63M5UWYx\n"
"O2JkVkPvpzORKJUivePFQbkEcxYZb9VqoVZ04sfpfGb3h2douzBrKbkDP/Jf+O0J\n"
"PKDTltrUJOpZbYhVAgMBAAGjdjB0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI\n"
"KwYBBQUHAwIwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUiZGaRSyAyraAdeo5\n"
"wJc+0Ks7IOcwHwYDVR0jBBgwFoAU0marYk/GnTVDeDbie2BY15qCu0QwDQYJKoZI\n"
"hvcNAQELBQADggGBAGINVR+lskHnxkYvPkgCQG+nGqovI28W6rtx8a5xM/6rtsVs\n"
"5jCu1nnJd32YNjDsySxsbkhXjW0WjGR7cEsnmcOITeP4kLLVzh1vm6sZa/9vX1fh\n"
"M5pTUTYTHYozl6TA85CtBd7oC/AB2Gwh5q1kJ3wmGwmCY8mqPftP+plyFTSbCwAH\n"
"BZSfCgsMpffILDzPgViU54BehfpfljZcmGJnnGKEnTRvUr84/NlmKEdhw9rKyod5\n"
"KKieGneVzpPeiyXrzUEJuGkmLtVLpvNdDdB5+6rN0hK+bFyB3NA+gASIiekuM7Q+\n"
"4RgroWwTF7fq1XUhX3aexOI2eTx0B2bBpD28TcYvqo6Y+aBKHVbo8gnbMr5IoIkI\n"
"rYz8CXrbbZFRilsHRQgzyEmTq/Wp0GVt/zakMF7suA8nl/AQcKDOWGBnEFc+okAe\n"
"K0P/4R4UnQSPU8SfsFBGxm4PXN4BZktZ10LC/xKMJBkdSD0vTLce9Sx7xR4PUIaN\n"
"n2x0D4zZG7px73kB0Q==\n"
"-----END CERTIFICATE-----";
const unsigned char ecdsa_crt[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDNjCCAZ6gAwIBAgIUDzxOEj+8WUrLa1M97arwkEo5gEwwDQYJKoZIhvcNAQEL\n"
"BQAwMjEbMBkGA1UEAwwSZ2xld2x3eWRfcGFja2VkX2NhMRMwEQYDVQQKEwpiYWJl\n"
"bG91ZXN0MB4XDTE5MTIwNjEzNTYxM1oXDTIwMTEyMDEzNTYxM1owYDEYMBYGA1UE\n"
"AwwPZ2xld2x3eWRfcGFja2VkMSIwIAYDVQQLExlBdXRoZW50aWNhdG9yIEF0dGVz\n"
"dGF0aW9uMRMwEQYDVQQKEwpiYWJlbG91ZXN0MQswCQYDVQQGEwJDQTBZMBMGByqG\n"
"SM49AgEGCCqGSM49AwEHA0IABOjeoVGraskp+jax8TTOXy92o6PGGN2Tl3XshqN/\n"
"XZnfkyxxLxKvJ0igfQ4Qy4/9w8PGjVilnY4zR3y25VJ7KLejYTBfMAwGA1UdEwEB\n"
"/wQCMAAwDwYDVR0PAQH/BAUDAweAADAdBgNVHQ4EFgQU34GPDg2bLIneLKIfjYjU\n"
"NuiU170wHwYDVR0jBBgwFoAUlOaykWFTL+EV/0PHksB2Dh1k1KAwDQYJKoZIhvcN\n"
"AQELBQADggGBAFHNuUQUkZaunXfV3qSemhlyHH1hnt6YXJLIl2IKugg/mg8hga2C\n"
"dBN7MMcVYpXtNI8AKfSIZRu3v16OMIajCIh7PYGa5asbJZgtOkbvfc58eaWhzl8U\n"
"B0j89aGlntZs3WWINYgqfzBS6Pw3SJ5iVTpS+xH2JSWxZYX3uvEDkVkw1VjmyyN3\n"
"ZX0tkFTKQB3GNFZwesxoRKizsu8r+tCIqgfqRTG7FIOa/UB3MXVClA//+TCnW2RI\n"
"48JzjY/YhO54pWVsblHAQwMOmuHlJrnfLFPvBqFx5mi8Z5jHfZipsNksIteKFdtG\n"
"3FvjQYIj2wJM9k7XHrQ3szxwvq9Ss2cyCBPArrKVpBTibypIkON9R2Peocr3HkUx\n"
"YYhu3pNumaSdGzL0r7A2iGIXy9orIAQ8f1i7iaYDBWs/PkJ340iHRZtSuez8F+GN\n"
"NUV15utv9AMvahkCI5ZS71TAv4AFjsZpsvYuCvpUUPdZpC+r9lk8H1wa4VA+mujL\n"
"2Yxh1fFV7ONNjA==\n"
"-----END CERTIFICATE-----";

const unsigned char rsa_2048_pub[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
"uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
"iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
"ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
"6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
"K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
"BwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const unsigned char rsa_2048_pub_der[] = 
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\
uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\
iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\
ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\
6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\
K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\
BwIDAQAB";

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
const unsigned char x509_cert[] = "-----BEGIN CERTIFICATE-----\n"
"MIIBejCCASGgAwIBAgIUUmwvBcKwJSWZMLC9xtUYQhh/YicwCgYIKoZIzj0EAwIw\n"
"EzERMA8GA1UEAwwIZ2xld2x3eWQwHhcNMTkwNjEyMTY0MjExWhcNMjkwNjA5MTY0\n"
"MjExWjATMREwDwYDVQQDDAhnbGV3bHd5ZDBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
"A0IABKP9Eu2Rzt15pKqriLiniryG9zsabCq+aNneB+mmIDwRkjaqpKeGwztLEHBG\n"
"TrHh9poToHkaxUuFE/wVD+9GscGjUzBRMB0GA1UdDgQWBBQQv5dX9gxGFfEDD2Zu\n"
"jZQT3FTitDAfBgNVHSMEGDAWgBQQv5dX9gxGFfEDD2ZujZQT3FTitDAPBgNVHRMB\n"
"Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIBqkd3kqcKZ/gEsnAVi5sQR3gB04\n"
"U8JNjzPwv//HmV/FAiBT45X52j1G6QGPg82twWR7CZiHbJPe26drWkkoDeT/QQ==\n"
"-----END CERTIFICATE-----\n";

const unsigned char error_pem[] = "-----BEGIN ERROR FROM OUTER SPACE-----";
const unsigned char symmetric_key[] = "secret";

#define HTTPS_CERT_KEY "cert/server.key"
#define HTTPS_CERT_PEM "cert/server.crt"

static char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
  }
  
  return buffer;
}

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

int callback_x5u_rsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)ecdsa_crt);
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
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len)), NULL);
  ck_assert_int_eq(len, 1);
  ck_assert_ptr_ne(out[0], NULL);
  gnutls_privkey_deinit(out[0]);
  o_free(out);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len)), NULL);
  ck_assert_int_eq(len, 2);
  ck_assert_ptr_ne(out[0], NULL);
  ck_assert_ptr_eq(out[1], NULL);
  gnutls_privkey_deinit(out[0]);
  o_free(out);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_ptr_ne((out = r_jwks_export_to_gnutls_privkey(jwks, &len)), NULL);
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
  
  ck_assert_int_eq(r_jwks_import_from_json_str(NULL, jwks_str), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_json_str(NULL, NULL), RHN_ERROR_PARAM);
  
  ck_assert_ptr_ne(jwks_str, NULL);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, "{error}"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwks), 4);
  r_jwk_free(jwks);
  o_free(jwks_str);

  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_str_invalid_n);
  ck_assert_ptr_ne(jwks_str, NULL);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, jwks_str), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwks_size(jwks), 3);
  r_jwk_free(jwks);
  o_free(jwks_str);
  
}
END_TEST

START_TEST(test_rhonabwy_jwks_import_uri)
{
  struct _u_instance instance;
#ifdef R_WITH_CURL
  jwks_t * jwks = NULL;
#endif
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_ok", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_content_no_jwks", NULL, 0, &callback_jwks_error_content_no_jwks, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_content_no_json", NULL, 0, &callback_jwks_error_content_no_json, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_error_status", NULL, 0, &callback_jwks_error_status, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_redirect", NULL, 0, &callback_jwks_redirect, NULL), U_OK);
  
#ifdef R_WITH_CURL
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
  ck_assert_int_eq(r_jwks_import_from_uri(jwks, "http://localhost:7462/jwks_error_content_no_jwks", 0), RHN_ERROR_PARAM);
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
#endif
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_jwks_get_by_kid)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  jwks_t * jwks;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks), RHN_OK);
  
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, jwks_str), RHN_OK);
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
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks1, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks2, jwks_str), RHN_OK);
  
  ck_assert_int_ne(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks1, jwks_str), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks2, jwks_str2), RHN_OK);
  
  ck_assert_int_eq(r_jwks_equal(jwks1, jwks2), 0);
  
  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  ck_assert_int_eq(r_jwks_init(&jwks1), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks2), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks1, jwks_str), RHN_OK);
  
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
  
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks, jwks_str), RHN_OK);
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
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks1, jwks_str), RHN_OK);
  ck_assert_ptr_ne((jwks2 = r_jwks_copy(jwks1)), NULL);

  ck_assert_int_ne(r_jwks_equal(jwks1, jwks2), 0);

  r_jwk_free(jwks1);
  r_jwk_free(jwks2);
  
  o_free(jwks_str);
}
END_TEST

START_TEST(test_rhonabwy_jwks_quick_import)
{
  char * jwks_str = msprintf("{\"keys\":[%s,%s,%s,%s]}", jwk_pubkey_ecdsa_str, jwk_pubkey_rsa_str, jwk_pubkey_rsa_x5u_str, jwk_pubkey_rsa_x5c_str);
  json_t * jwks_j = json_loads(jwks_str, JSON_DECODE_ANY, NULL), * jwk_j = json_loads(jwk_pubkey_rsa_str, JSON_DECODE_ANY, NULL);
  jwks_t * jwks;
  unsigned char der_decoded[4096];
  size_t der_dec_len = 0;
  struct _u_instance instance;
  char * http_key = get_file_content(HTTPS_CERT_KEY), * http_cert = get_file_content(HTTPS_CERT_PEM);
  gnutls_privkey_t privkey;
  gnutls_x509_privkey_t x509_key;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;
  gnutls_datum_t data;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7463, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jwks_ok", NULL, 0, &callback_jwks_ok, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwks_str, R_IMPORT_NONE));
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str, R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_T, jwks_j, R_IMPORT_NONE));
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_T, jwk_j, R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_PEM, R_X509_TYPE_PUBKEY, rsa_2048_pub, sizeof(rsa_2048_pub), R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_PEM, R_X509_TYPE_PUBKEY, error_pem, sizeof(error_pem), R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_int_eq(o_base64_decode(rsa_2048_pub_der, o_strlen((const char *)rsa_2048_pub_der), der_decoded, &der_dec_len), 1);
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_DER, R_X509_TYPE_PUBKEY, der_decoded, der_dec_len, R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_DER, R_X509_TYPE_PUBKEY, der_decoded+40, der_dec_len-40, R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_privkey_init(&privkey));
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_init(&x509_key));
  data.data = (unsigned char *)rsa_2048_priv;
  data.size = sizeof(rsa_2048_priv);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_privkey_import_x509(privkey, x509_key, 0));
  ck_assert_ptr_ne(RHN_OK, jwks = r_jwks_quick_import(R_IMPORT_G_PRIVKEY, privkey, R_IMPORT_NONE));
  gnutls_privkey_deinit(privkey);
  gnutls_x509_privkey_deinit(x509_key);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_G_PRIVKEY, NULL, R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  gnutls_pubkey_init(&pubkey);
  data.data = (unsigned char *)rsa_2048_pub;
  data.size = sizeof(rsa_2048_pub);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_G_PUBKEY, pubkey, R_IMPORT_NONE));
  gnutls_pubkey_deinit(pubkey);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_G_PUBKEY, NULL, R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  gnutls_x509_crt_init(&crt);
  data.data = (unsigned char *)x509_cert;
  data.size = sizeof(x509_cert);
  ck_assert_int_eq(GNUTLS_E_SUCCESS, gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM));
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_G_CERT, crt, R_IMPORT_NONE));
  gnutls_x509_crt_deinit(crt);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_G_CERT, NULL, R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#ifdef R_WITH_CURL

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_crt", R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/error", R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600

  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_ecdsa_crt", R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/error", R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
#endif
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_SYMKEY, symmetric_key, sizeof(symmetric_key), R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_SYMKEY, NULL, sizeof(symmetric_key), R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_PASSWORD, symmetric_key, sizeof(symmetric_key), R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_PASSWORD, NULL, sizeof(symmetric_key), R_IMPORT_NONE));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_T, jwk_j, R_IMPORT_JSON_T, jwks_j, R_IMPORT_NONE));
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_T, jwk_j, R_IMPORT_JSON_T, NULL, R_IMPORT_NONE));
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#ifdef R_WITH_CURL
  ck_assert_ptr_ne(NULL, jwks = r_jwks_quick_import(R_IMPORT_JSON_T, jwk_j, R_IMPORT_JSON_T, jwks_j, R_IMPORT_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE, "https://localhost:7463/x5u_rsa_crt", R_IMPORT_NONE));
  ck_assert_int_eq(6, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
  
  json_decref(jwks_j);
  json_decref(jwk_j);
  o_free(jwks_str);
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
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
  tcase_add_test(tc_core, test_rhonabwy_jwks_quick_import);
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
