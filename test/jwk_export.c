/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <check.h>
#include <rhonabwy.h>
#include <orcania.h>
#include <yder.h>
#include <ulfius.h>

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                                     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\n"\
                                     "iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n"\
                                     "-----END PUBLIC KEY-----\n";

const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_pem[] = "-----BEGIN EC PRIVATE KEY-----\n"\
                                      "MHgCAQEEIQDzvQwHqB+5Mnge1SdS9gzImmvl5Rk0/gGTjdtV2Pd4AaAKBggqhkjO\n"\
                                      "PQMBB6FEA0IABDCgQkzSHClEg4otdckrN+duog2fAIk6O07uijwKr+w+4Etl6SRW\n"\
                                      "2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM=\n"\
                                      "-----END EC PRIVATE KEY-----\n";

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                                   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX\n"\
                                   "ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS\n"\
                                   "oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt\n"\
                                   "7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0\n"\
                                   "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f\n"\
                                   "M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK\n"\
                                   "gwIDAQAB\n"\
                                   "-----END PUBLIC KEY-----\n";

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
const char jwk_privkey_rsa_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
                                    "MIIEowIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L\n"\
                                    "hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknj\n"\
                                    "hMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/F\n"\
                                    "DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO\n"\
                                    "pbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBni\n"\
                                    "Iqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQABAoIBAF+HE7XiWP4J+BWD\n"\
                                    "7FwfK3V4seb8LINRSzeRNxGhukSaFR/hyyyg/TO3ceaKOxlEZJ3IZ60cHlJAu4U+\n"\
                                    "XySzNFmxQCjS1mNr7+wejal0s1L8U9P2En6oo8Kd0U85QWgsVqeHaBZOTdqPBsv5\n"\
                                    "xzSq6AAyJCeOqUVKIbF8sG0XgHWGjMBbPbb/Hf3D1WN4tO2t7fDDekzcJtHUmsJv\n"\
                                    "b+O1Igpd0pOWYhu8aIzy7uLG4NVNo8eCAUzQc52yUsxRyuuo0/G4JLqrJNBo7JAy\n"\
                                    "ZNfWeKsI8G7J5+I9lgYot0S/lLNpRlZGPH5Bc5ntc9B2yJH89GOpqpzmLanNF+I3\n"\
                                    "3CqAAvECgYEA83i+7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxt\n"\
                                    "PVnwD20R+60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQy\n"\
                                    "qVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfsCgYEA3dfO\n"\
                                    "R9cuYq+0S+mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgT\n"\
                                    "nCdpYzBcOfW5r370AFXjiWft/NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ+1k\n"\
                                    "Yd/s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxkCgYAbiw9eRzphr3Lyglb38guP\n"\
                                    "jG6mm7SXOL8ftVORLzGPlJ1fdygTSiKZjDEiLZ6ZMC57RQ5rl2mAUbIEnhzy1DZU\n"\
                                    "XjTZdG6AoNM/xqRiEWjm0ADvtB782a25hlzcLebcjbgbYa9HmxIPFTIA3bOrwt+f\n"\
                                    "0RSazqtjc5vxh6IqROIGPQKBgQCz2UAf1+CAGygVHw5pzZH8TaDDbzatPaQY4CG8\n"\
                                    "iWURMTV5+sDqG5RS8x8FwymfyWp5bq/POdhjlJJAXukx0L9qAjecbwhunUFRvQlS\n"\
                                    "KtpE2pR8uFxBv930YXgOHt7vhZtGyhtGie6NNg3XEJo/pM7rWO9atf4vXy3FfDj3\n"\
                                    "hD9yCQKBgBsjP6eia18kos9baBYCm1lfiXSN40OMqbva2zFsd60CQX5rdBaGM4FC\n"\
                                    "GRFRRHDqsHpkTfNc6AwGmvgZNCljRg4yR2Q3Q5hYVtwDe5SPqbsZP5h2Ridda8ck\n"\
                                    "fDueVy0nt0j5kXysGSOslNuGcb0ChWCLXZXVChszuiGus0yoQFUV\n"\
                                    "-----END RSA PRIVATE KEY-----\n";

#define KEY_DECODED "secret"
const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0\"}";

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

const char jwk_pubkey_rsa_x5u_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\",\"x5u\":[\"https://www.example.com/x509\"]}";

const char jwk_pubkey_rsa_x5u_only_rsa_pub[] = "{\"alg\": \"RS256\",\"x5u\":[\"https://localhost:7462/x5u_rsa_crt\"]}";
const char jwk_pubkey_rsa_x5u_only_ecdsa_pub[] = "{\"alg\": \"RS256\",\"x5u\":[\"https://localhost:7462/x5u_ecdsa_crt\"]}";

const char jwk_pubkey_rsa_x5u_export[] = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsUWjL3wK1B/dQbXbhSXa\n"\
"odF0gXMNlZg3ZecjZIJOKgXGDVOnV0ly4evW8xkn8F2gC3TYJXik7efdhGdiaYul\n"\
"9kyzpPBr53ELHMmAeI/I1rnF4pgIwfN1vBsaDwJw9w0R6FQ9fxDUIte47WdElEHh\n"\
"tST9V874mMehsSUG4xM2qiBvvbWwX0KCyKk6BY/CdyljUjAPUShcVysKUTyfefew\n"\
"38KUVTVpk2vWLlN+a41iC/gxGvLtH142LDiDx/s+Kh37f4paD2zsEw5McF81eiKT\n"\
"AfrraIC1Gj2BxyEj6n2EjqyI+NFRsSUmqfPoFgiMzlEWj4P8AwvfE9jbjXz/E0GO\n"\
"ISiXt4L+06U7rLoGHFri5oVI6KUkLAOwwwTri+ikeQFx68IKvhytBiX1O+XHh51J\n"\
"ZyyC+fcKKN+/ATgGKIiR63M5UWYxO2JkVkPvpzORKJUivePFQbkEcxYZb9VqoVZ0\n"\
"4sfpfGb3h2douzBrKbkDP/Jf+O0JPKDTltrUJOpZbYhVAgMBAAE=\n"\
"-----END PUBLIC KEY-----\n";
const char jwk_pubkey_ecdsa_x5u_export[] = "-----BEGIN PUBLIC KEY-----\n"\
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6N6hUatqySn6NrHxNM5fL3ajo8YY\n"\
"3ZOXdeyGo39dmd+TLHEvEq8nSKB9DhDLj/3Dw8aNWKWdjjNHfLblUnsotw==\n"\
"-----END PUBLIC KEY-----\n";

#define HTTPS_CERT_KEY "-----BEGIN PRIVATE KEY-----\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDr90HrswgEmln/\
rXeNqYq0boIvas5wu27hmeHDdGGKtkCWIWGAo9GUy45xqsI4mDl3bOWS+pmb/3yi\
+nhe+BmYHvEqUFo1JfUcVMxaNEbdd9REytMjKdOS+kkLf++BBRoZI/g8DggIu+Ri\
dOSypk+pUECyQxROsyCrB/FgXuKbyC4QNl7fqZxMSpzw7jsWCZiwFv4pu8kMqzDG\
2wTl/r/4STyK4Pj2TVa/JVzbZbH7VfcjT8MdMsXvKhlmPywjbqo70Hnmt3cnakYF\
X+07ncx/5mjYYd3eSFgiNXr7WNw2rhFKtfTUcjrqSw9FDxmHFWUU76mwJyUo02N9\
ViakSoQpAgMBAAECggEBAJp/VBwdJpzM6yxqyaJpZbXpvTeKuQw6zMjN1nIBG3SV\
DAjAZnSxziGcffGSmoQvt0CoflAT4MuxJkwXrwSPcUKWz9Sis82kwq4AH6TYIaYU\
NVmtazzUwAC1+2maJJjXXFUlpfy8Oypsy4ZjfvIxzmrPbuzI2t0Ej9kr5DDzL3BL\
CWQ/U7w7y4KC0Pnq1ueIzM+UJIfvI0ldUcXHWsAnjyQzwgFBC35qDOfDTw0YUJv+\
ElfFFcGYCA+9wlQyhM/zhAWqKgZ2mwAS6WykgbSc7j4NDjlmZwf4ZuTxbDUV1kBX\
pPH21snqO42CFpw9hRUAA0W0XydCIfUhH8/6tH9enQECgYEA+rM9f6cUk3c7aLWs\
hnauVqJuyGhgCkMyF9sSxgfcs87OVLNuGgaTIfwcT/7oxAY8G7sY44cbk1ZRhh7y\
6kf01xqiJeXxBQei1qiJxMb2gukvpeY81s2Mg9og5d9qbEhLzp8TdiRJHxLIiGwF\
xOM69CpugKN4T0Zum7EBGeSvmBECgYEA8PRG5SRTE4JwzGtLuTbMbjYTqyEjXAkB\
zo33a92znA0EXEeLCl845EUgzUkSkeN/T/uyWRjj0hrPU99UaaXHt3bc+lrDHrc7\
WFAR3QoAfFFJPIqqwiHcBDdTeAozQ8IOqFIxspl72RukuRdeQR3EdfcF9TUZyUbU\
k8SuRioggpkCgYA2scgnA3KvwYGKlKgxJc9fQ0zcGDlrw8E4BymPXsO9zs6hGAxb\
TTfoYDJlGX361kli22zQpvdTK6/ZjQL+LfiyvTLHBeWRbVsPbfGwpp+9a9ZjYVnA\
m1OeqIYo4Jc9TICNcZMzYTM6vkRVzwtrKw//mQpGsmNbGEilWvaciZHtoQKBgQDo\
FDBQtir6SJIConm9/ETtBlLtai6Xj+lYnK6qC1DaxkLj6tjF9a9jVh3g/DfRopBW\
ZnSCkpGkJcR54Up5s35ofCkdTdxPsmaLihuaje6nztc+Y8VS1LAIs41GunRkF/5s\
KzbI8kIyfAitag+Toms+v93SLwIWNo27gh3lYOANSQKBgQDIidSO3fzB+jzJh7R0\
Yy9ADWbBsLxc8u+sBdxmZBGl+l4YZWNPlQsnsafwcpJWT3le6N7Ri3iuOZw9KiGe\
QDkc7olxUZZ3pshg+cOORK6jVE8v6FeUlLnxpeAWa4C4JDawGPTOBct6bVBl5sxi\
7GaqDcEK1TSxc4cUaiiPDNNXQA==\
-----END PRIVATE KEY-----"
#define HTTPS_CERT_PEM "-----BEGIN CERTIFICATE-----\
MIIDhTCCAm2gAwIBAgIJANrO2RnCbURLMA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV\
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\
aWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNzA0MjgxNTA0\
NDVaFw0xODA0MjgxNTA0NDVaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21l\
LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNV\
BAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOv3\
QeuzCASaWf+td42pirRugi9qznC7buGZ4cN0YYq2QJYhYYCj0ZTLjnGqwjiYOXds\
5ZL6mZv/fKL6eF74GZge8SpQWjUl9RxUzFo0Rt131ETK0yMp05L6SQt/74EFGhkj\
+DwOCAi75GJ05LKmT6lQQLJDFE6zIKsH8WBe4pvILhA2Xt+pnExKnPDuOxYJmLAW\
/im7yQyrMMbbBOX+v/hJPIrg+PZNVr8lXNtlsftV9yNPwx0yxe8qGWY/LCNuqjvQ\
eea3dydqRgVf7TudzH/maNhh3d5IWCI1evtY3DauEUq19NRyOupLD0UPGYcVZRTv\
qbAnJSjTY31WJqRKhCkCAwEAAaNQME4wHQYDVR0OBBYEFPFfmGA3jO9koBZNGNZC\
T/dZHZyHMB8GA1UdIwQYMBaAFPFfmGA3jO9koBZNGNZCT/dZHZyHMAwGA1UdEwQF\
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIc8Yuom4vz82izNEV+9bcCvuabcVwLH\
Qgpv5Nzy/W+1hDoqfMfKNwOSdUB7jZoDaNDG1WhjKGGCLTAx4Hx+q1LwUXvu4Bs1\
woocge65bl85h10l2TxxnlT5BIJezm5r3NiZSwOK2zxxIEyL4vh+b/xqQblBEkR3\
e4/A4Ugn9Egh8GdpF4klGp4MjjpRyAVI7BDaleAhvDSfPmm7ylHJ2y7CLI9ApOQY\
glwRuTmowAZQtaSiE1Ox7QtWj858HDzzTZyFWRG/MNqQptn7AMTPJv3DivNfDNPj\
fYxFAheH3CjryHqqR9DD+d9396W8mqEaUp+plMwSjpcTDSR4rEQkUJg=\
-----END CERTIFICATE-----"
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

int callback_x5u_rsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)rsa_crt);
  return U_CALLBACK_CONTINUE;
}

int callback_x5u_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, (const char *)ecdsa_crt);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_rhonabwy_export_to_str)
{
  jwk_t * jwk;
  char * export_str;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"EC\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"crv\":\"P-256\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"use\":\"enc\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kid\":\"1\""), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"EC\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"crv\":\"P-256\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"use\":\"enc\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kid\":\"1\""), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"RSA\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"e\":\"AQAB\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"alg\":\"RS256\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kid\":\"2011-04-29\""), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"oct\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"alg\":\"HS256\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"k\":\"c2VjcmV0\""), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"RSA\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"use\":\"sig\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kid\":\"1b94c\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                        "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                        "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                        "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"e\":\"AQAB\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
                                        "b3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQY"\
                                        "DVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UE"\
                                        "BxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPA"\
                                        "DCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3W"\
                                        "G7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/"\
                                        "p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCK"\
                                        "Nb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9A"\
                                        "qBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKV"\
                                        "MJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5"\
                                        "MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]"), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_ptr_ne((export_str = r_jwk_export_to_json_str(jwk, 0)), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kty\":\"RSA\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"e\":\"AQAB\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"alg\":\"RS256\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"kid\":\"2011-04-29\""), NULL);
  ck_assert_ptr_ne(o_strstr(export_str, "\"x5u\":[\"https://www.example.com/x509\"]"), NULL);
  o_free(export_str);
  r_jwk_free(jwk);

}
END_TEST

START_TEST(test_rhonabwy_export_to_json)
{
  jwk_t * jwk;
  json_t * j_export;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_ptr_eq(r_jwk_export_to_json_t(jwk), NULL);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "EC");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "crv")), "P-256");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "y")), "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "use")), "enc");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kid")), "1");
  json_decref(j_export);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "EC");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "crv")), "P-256");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "y")), "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "d")), "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "use")), "enc");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kid")), "1");
  json_decref(j_export);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "RSA");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "n")), "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "e")), "AQAB");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "alg")), "RS256");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kid")), "2011-04-29");
  json_decref(j_export);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "oct");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "alg")), "HS256");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "k")), "c2VjcmV0");
  json_decref(j_export);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5c_str), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "RSA");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "use")), "sig");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kid")), "1b94c");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "n")), "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLb"\
                                        "K_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a"\
                                        "YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-m"\
                                        "eMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "e")), "AQAB");
  ck_assert_int_eq(json_is_array(json_object_get(j_export, "x5c")), 1);
  ck_assert_int_eq(json_array_size(json_object_get(j_export, "x5c")), 1);
  ck_assert_int_eq(json_is_string(json_array_get(json_object_get(j_export, "x5c"), 0)), 1);
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_export, "x5c"), 0)), "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSI"\
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
  json_decref(j_export);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_str), RHN_OK);
  ck_assert_ptr_ne((j_export = r_jwk_export_to_json_t(jwk)), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kty")), "RSA");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "n")), "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                            "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                            "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "e")), "AQAB");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "alg")), "RS256");
  ck_assert_str_eq(json_string_value(json_object_get(j_export, "kid")), "2011-04-29");
  ck_assert_str_eq(json_string_value(json_array_get(json_object_get(j_export, "x5u"), 0)), "https://www.example.com/x509");
  json_decref(j_export);
  r_jwk_free(jwk);

}
END_TEST

START_TEST(test_rhonabwy_export_to_gnutls_privkey)
{
  jwk_t * jwk;
  gnutls_privkey_t privkey = NULL;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_eq(r_jwk_export_to_gnutls_privkey(jwk, 0), NULL);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((privkey = r_jwk_export_to_gnutls_privkey(jwk, 0)), NULL);
  gnutls_privkey_deinit(privkey);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_ptr_eq(r_jwk_export_to_gnutls_privkey(jwk, 0), NULL);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne((privkey = r_jwk_export_to_gnutls_privkey(jwk, 0)), NULL);
  gnutls_privkey_deinit(privkey);
  r_jwk_free(jwk);

}
END_TEST

START_TEST(test_rhonabwy_export_to_gnutls_pubkey)
{
  jwk_t * jwk;
  gnutls_pubkey_t pubkey = NULL;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, HTTPS_CERT_KEY, HTTPS_CERT_PEM), U_OK);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, 0)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, 0)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);
#endif

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, 0)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, 0)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE)), NULL);
  ck_assert_ptr_eq((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, R_FLAG_IGNORE_REMOTE)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_ecdsa_pub), RHN_OK);
  ck_assert_ptr_ne((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, R_FLAG_IGNORE_SERVER_CERTIFICATE)), NULL);
  ck_assert_ptr_eq((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, R_FLAG_IGNORE_REMOTE)), NULL);
  gnutls_pubkey_deinit(pubkey);
  r_jwk_free(jwk);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_export_to_pem)
{
  jwk_t * jwk;
  unsigned char data[4096];
  size_t data_len = 4096;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_instance(&instance, 7462, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_rsa_crt", NULL, 0, &callback_x5u_rsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u_ecdsa_crt", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, HTTPS_CERT_KEY, HTTPS_CERT_PEM), U_OK);

#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, 0), RHN_OK);
  ck_assert_int_eq(o_strncmp(jwk_privkey_ecdsa_pem, (const char *)data, data_len), 0);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, 0), RHN_OK);
  ck_assert_int_eq(o_strncmp(jwk_pubkey_ecdsa_pem, (const char *)data, data_len), 0);
  r_jwk_free(jwk);
#endif

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, 0), RHN_OK);
  ck_assert_int_eq(o_strncmp(jwk_privkey_rsa_pem, (const char *)data, data_len), 0);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, 0), RHN_OK);
  ck_assert_int_eq(o_strncmp(jwk_pubkey_rsa_pem, (const char *)data, data_len), 0);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_rsa_pub), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, R_FLAG_IGNORE_REMOTE), RHN_ERROR);
  ck_assert_int_eq(o_strncmp(jwk_pubkey_rsa_x5u_export, (const char *)data, data_len), 0);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_x5u_only_ecdsa_pub), RHN_OK);
  data_len = 4096;
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwk_export_to_pem_der(jwk, R_FORMAT_PEM, data, &data_len, R_FLAG_IGNORE_REMOTE), RHN_ERROR);
  ck_assert_int_eq(o_strncmp(jwk_pubkey_ecdsa_x5u_export, (const char *)data, data_len), 0);
  r_jwk_free(jwk);

  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_export_to_symmetric_key)
{
  jwk_t * jwk;
  unsigned char key[128] = {0};
  size_t key_len = 0;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_export_to_symmetric_key(jwk, key, &key_len), RHN_ERROR_PARAM);
  ck_assert_int_eq(key_len, 0);
  ck_assert_int_eq(o_strlen((const char *)key), 0);
  r_jwk_free(jwk);

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);
  ck_assert_int_eq(r_jwk_export_to_symmetric_key(jwk, key, &key_len), RHN_OK);
  ck_assert_int_eq(o_strncmp(KEY_DECODED, (const char *)key, key_len), 0);
  r_jwk_free(jwk);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWK export function tests");
  tc_core = tcase_create("test_rhonabwy_export");
  tcase_add_test(tc_core, test_rhonabwy_export_to_str);
  tcase_add_test(tc_core, test_rhonabwy_export_to_json);
  tcase_add_test(tc_core, test_rhonabwy_export_to_gnutls_privkey);
  tcase_add_test(tc_core, test_rhonabwy_export_to_gnutls_pubkey);
  tcase_add_test(tc_core, test_rhonabwy_export_to_pem);
  tcase_add_test(tc_core, test_rhonabwy_export_to_symmetric_key);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWK export tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
