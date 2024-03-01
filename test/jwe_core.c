/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include <rhonabwy.h>

#define UNUSED(x) (void)(x)

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define HUGE_PAYLOAD "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis efficitur lectus sit amet libero gravida eleifend. Nulla aliquam accumsan erat, quis tincidunt purus ultricies eu. Aenean eu dui ac diam placerat mollis. Duis eget tempor ipsum, vel ullamcorper purus. Ut eget quam vehicula, congue urna vel, dictum risus. Duis tristique est sed diam lobortis commodo. Proin et urna in odio malesuada sagittis. Donec lectus ligula, porttitor sed lorem ut, malesuada posuere neque. Nullam et nisl a felis congue mattis id non lectus.\
Quisque viverra hendrerit malesuada. Integer sollicitudin magna purus, in dignissim eros ullamcorper et. Praesent dignissim metus neque, eget tempor dolor tincidunt egestas. Nulla odio risus, tincidunt et egestas aliquet, pellentesque et eros. Etiam mattis orci a dui efficitur pharetra. Donec fermentum sem sed lacus finibus, nec luctus nisl vulputate. Donec sodales, nisi sed posuere maximus, lectus elit fermentum sapien, quis volutpat risus nisl vel dui. In vitae ante diam.\
Vivamus a nisl quam. Proin in lectus nunc. Aliquam condimentum tellus non feugiat aliquam. Nulla eu mi ligula. Proin auctor varius massa sed consectetur. Nulla et ligula pellentesque, egestas dui eu, gravida arcu. Maecenas vehicula feugiat tincidunt. Aenean sed sollicitudin ex. Cras luctus facilisis erat eu pharetra. Vestibulum interdum consequat tellus nec sagittis. Aliquam tincidunt eget lectus non bibendum. Mauris ut consectetur diam.\
Interdum et malesuada fames ac ante ipsum primis in faucibus. Sed lorem lectus, ullamcorper consectetur quam ut, pharetra consectetur diam. Suspendisse eu erat quis nunc imperdiet lacinia vitae id arcu. Fusce non euismod urna. Aenean lacinia porta tellus nec rutrum. Aliquam est magna, aliquam non hendrerit eget, scelerisque quis sapien. Quisque consectetur et lacus non dapibus. Duis diam purus, vulputate convallis faucibus in, rutrum quis mi. Sed sed magna eget tellus semper suscipit a in augue.\
Aenean vitae tortor quam. Praesent pulvinar nulla a nisi egestas, laoreet tempus mauris ullamcorper. Nam vulputate molestie velit, quis laoreet felis suscipit euismod. Pellentesque a enim dapibus, tincidunt lorem vel, suscipit turpis. Phasellus id metus vehicula, luctus sem nec, maximus purus. Duis dictum elit quam, quis rhoncus ex ullamcorper ut. Donec fringilla augue vitae vestibulum maximus. Mauris vel arcu eget arcu bibendum ornare."

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

#define CLAIM_STR "grut"
#define CLAIM_INT 42
unsigned char cypher_key[] = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207};
unsigned char iv[] = {3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101};
unsigned char aad[] = {82, 110, 74, 112, 90, 87, 53, 107, 99, 50, 104, 112, 99, 67, 66, 112, 99, 121, 66, 116, 89, 87, 100, 112, 89, 119, 111};

#define HTTPS_CERT_KEY "cert/server.key"
#define HTTPS_CERT_PEM "cert/server.crt"

const unsigned char advanced_key_1[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIAYMcQvkJcMXw5WYHEL05zOvksZ3JG6WAVc4PqupNxncoAoGCCqGSM49\n"
"AwEHoUQDQgAEKOIR+UzdL4i9/nP35uX5RIafqwsADRFiN74McMa3LVL/TDfougV5\n"
"plYuZz2/TzJbrwPDUYCB/rV8/hHku0tXnA==\n"
"-----END EC PRIVATE KEY-----";
const unsigned char advanced_cert_pem_1[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDDjCCAXagAwIBAgIUNdBXsS0f7w7zoqBV005eOeD2DMgwDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0yMTA5MTMyMTQ5MzhaFw0yMjA4MjkyMTQ5MzhaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
"AQcDQgAEKOIR+UzdL4i9/nP35uX5RIafqwsADRFiN74McMa3LVL/TDfougV5plYu\n"
"Zz2/TzJbrwPDUYCB/rV8/hHku0tXnKN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE\n"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBR/xAPVMRUg\n"
"SF2INrNsGrX9ZikSYDAfBgNVHSMEGDAWgBRZm42kTC+aL+0DVOySIDIN9SvUEjAN\n"
"BgkqhkiG9w0BAQsFAAOCAYEAHH8FtJ4CVfrSvlGxRkZH91XFK6ib110b/Nu9zIPG\n"
"2t+GaFhvCBtRfHhbzF7FG/o+NNhbUfWLnbPReNQy45QasqlrQMDkgeCAZskeadx1\n"
"MjrAN8EbFSmQxQ9dKJwZrXYxiT3IW1LFWyuHHA+avDyWyDQSoABZkVWzV3UHj6PF\n"
"GjNUhdWbU7WLF9zYX07K7u2FyV67/fJCPX9R1+cvVFpYtPQsOo5NFnELrlbRs8d1\n"
"g7JpfZX/juXBtYsiA71iOP9sVqWHM5UkWgd6xadOGFqiiSpJMn+k5LL9PVLZ6Bqd\n"
"qLOEFELIULM/mVvIvd3kbwiTiUkZTb6wtI/Z8bAPlKSQB/xHuxy8/H3cOc8COoq2\n"
"fnTtLBaQj4c4VEk+MPuLsK7smFWsQnQNRS+uHPIPW4Nv6nyUj54tqe8FaIzEioBU\n"
"D779sJ9gxiz68UPDo5ArHx3i2iS2ROkEGEUm93fYGi8y8yZtWb8MsPvqJi2Ar0tv\n"
"s3yOHp3+WqTOfToYSrrNz2rP\n"
"-----END CERTIFICATE-----";
const unsigned char advanced_cert_der_1[] =
"MIIDDjCCAXagAwIBAgIUNdBXsS0f7w7zoqBV005eOeD2DMgwDQYJKoZIhvcNAQEL"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe"
"Fw0yMTA5MTMyMTQ5MzhaFw0yMjA4MjkyMTQ5MzhaMCsxFDASBgNVBAMTC0RhdmUg"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D"
"AQcDQgAEKOIR+UzdL4i9/nP35uX5RIafqwsADRFiN74McMa3LVL/TDfougV5plYu"
"Zz2/TzJbrwPDUYCB/rV8/hHku0tXnKN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBR/xAPVMRUg"
"SF2INrNsGrX9ZikSYDAfBgNVHSMEGDAWgBRZm42kTC+aL+0DVOySIDIN9SvUEjAN"
"BgkqhkiG9w0BAQsFAAOCAYEAHH8FtJ4CVfrSvlGxRkZH91XFK6ib110b/Nu9zIPG"
"2t+GaFhvCBtRfHhbzF7FG/o+NNhbUfWLnbPReNQy45QasqlrQMDkgeCAZskeadx1"
"MjrAN8EbFSmQxQ9dKJwZrXYxiT3IW1LFWyuHHA+avDyWyDQSoABZkVWzV3UHj6PF"
"GjNUhdWbU7WLF9zYX07K7u2FyV67/fJCPX9R1+cvVFpYtPQsOo5NFnELrlbRs8d1"
"g7JpfZX/juXBtYsiA71iOP9sVqWHM5UkWgd6xadOGFqiiSpJMn+k5LL9PVLZ6Bqd"
"qLOEFELIULM/mVvIvd3kbwiTiUkZTb6wtI/Z8bAPlKSQB/xHuxy8/H3cOc8COoq2"
"fnTtLBaQj4c4VEk+MPuLsK7smFWsQnQNRS+uHPIPW4Nv6nyUj54tqe8FaIzEioBU"
"D779sJ9gxiz68UPDo5ArHx3i2iS2ROkEGEUm93fYGi8y8yZtWb8MsPvqJi2Ar0tv"
"s3yOHp3+WqTOfToYSrrNz2rP";

const unsigned char advanced_key_2[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEICXdcvJ68jTD5qOxv5a1QQLE7K6OcqSOjgNLd3pPE1z1oAoGCCqGSM49\n"
"AwEHoUQDQgAEO/I3Q8FsEFii5oHZB5HtZe46awSYxkmTtmVpWKab5T9SIfznVwL3\n"
"n5/ijLyQ54f6bWnLkxeuZxRfTdrDHNodOg==\n"
"-----END EC PRIVATE KEY-----";
const unsigned char advanced_cert_pem_2[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDDjCCAXagAwIBAgIUd1sYeALcC3nDDzlovmUm9S+IAaEwDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0yMTA5MTQxNTI0NDZaFw0yMjA4MzAxNTI0NDZaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
"AQcDQgAEO/I3Q8FsEFii5oHZB5HtZe46awSYxkmTtmVpWKab5T9SIfznVwL3n5/i\n"
"jLyQ54f6bWnLkxeuZxRfTdrDHNodOqN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE\n"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBSdjs0rqLgE\n"
"HvJoen2T0XIRRirS5TAfBgNVHSMEGDAWgBSTmEmG+THW/zrJM5ZfCPi259RA8zAN\n"
"BgkqhkiG9w0BAQsFAAOCAYEAECdRtFVERpkkAfj7mwC7Qu2nopMYcKCDagDKi16Y\n"
"JELQWDEx1djR9GFu19QERN0RGSOEgzPunifaUOGfkYsFaF9NA27KVGgpK3TgTl5A\n"
"JBIGIiKP8vSiqF6KOosbTU3WeKwT4mE3t1yWcG/ExCqXUcOUmH2BFMh74aO2yp8A\n"
"FiRAK51AlU7L3WRvdtaVL1rriiYnOh5SrSevVvebMdZxOzsl7wGhpW6gVfm0xmMP\n"
"KdCNhyjTlX6UzRDGpNxT5TNb3kYRGviZ/BsMpT1MrnIQRUUhLEz7dd4362XgRX1J\n"
"i6RvDKcQVxQNdIOTWyJIDenrbqmuA4ZeV/OI86Uf9iPkjKUGJiVhaYMWwgXSkfRy\n"
"U3uAVpelLX7/mzm3PuJV5RyBsJqNsumsdDSkA++5VhdOqi8Yr5gI0gF3ep5tggvV\n"
"BKgGmpZ2fEF6BKMTC4HyiCc9e2qeqLTIOZPiMpJm8N6fpEY37JEqqPHeY19WYxdE\n"
"TrY5XLCqtITFRVTMubJPyDnc\n"
"-----END CERTIFICATE-----";
const unsigned char advanced_cert_der_2[] =
"MIIDDjCCAXagAwIBAgIUd1sYeALcC3nDDzlovmUm9S+IAaEwDQYJKoZIhvcNAQEL"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe"
"Fw0yMTA5MTQxNTI0NDZaFw0yMjA4MzAxNTI0NDZaMCsxFDASBgNVBAMTC0RhdmUg"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D"
"AQcDQgAEO/I3Q8FsEFii5oHZB5HtZe46awSYxkmTtmVpWKab5T9SIfznVwL3n5/i"
"jLyQ54f6bWnLkxeuZxRfTdrDHNodOqN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBSdjs0rqLgE"
"HvJoen2T0XIRRirS5TAfBgNVHSMEGDAWgBSTmEmG+THW/zrJM5ZfCPi259RA8zAN"
"BgkqhkiG9w0BAQsFAAOCAYEAECdRtFVERpkkAfj7mwC7Qu2nopMYcKCDagDKi16Y"
"JELQWDEx1djR9GFu19QERN0RGSOEgzPunifaUOGfkYsFaF9NA27KVGgpK3TgTl5A"
"JBIGIiKP8vSiqF6KOosbTU3WeKwT4mE3t1yWcG/ExCqXUcOUmH2BFMh74aO2yp8A"
"FiRAK51AlU7L3WRvdtaVL1rriiYnOh5SrSevVvebMdZxOzsl7wGhpW6gVfm0xmMP"
"KdCNhyjTlX6UzRDGpNxT5TNb3kYRGviZ/BsMpT1MrnIQRUUhLEz7dd4362XgRX1J"
"i6RvDKcQVxQNdIOTWyJIDenrbqmuA4ZeV/OI86Uf9iPkjKUGJiVhaYMWwgXSkfRy"
"U3uAVpelLX7/mzm3PuJV5RyBsJqNsumsdDSkA++5VhdOqi8Yr5gI0gF3ep5tggvV"
"BKgGmpZ2fEF6BKMTC4HyiCc9e2qeqLTIOZPiMpJm8N6fpEY37JEqqPHeY19WYxdE"
"TrY5XLCqtITFRVTMubJPyDnc";

const unsigned char advanced_key_3[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIEslWGWIe3xz8KResadYE+JZEfrPNp4wV7b19He998GLoAoGCCqGSM49\n"
"AwEHoUQDQgAEB8zD2LcZJt8GFMS07Z9k0aWm4r4VFOAm7BQOJzgsIUkFbVxKfABU\n"
"Xm1qDJIFMq/Ct9//ZMw3cHcvzJSDsqOuLQ==\n"
"-----END EC PRIVATE KEY-----";
const unsigned char advanced_cert_pem_3[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDDjCCAXagAwIBAgIUF6BNJxZDAJ79e+0I4OStbeBHNB4wDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMjETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0yMTA5MTMyMTQ5NDBaFw0yMjA4MjkyMTQ5NDBaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
"AQcDQgAEB8zD2LcZJt8GFMS07Z9k0aWm4r4VFOAm7BQOJzgsIUkFbVxKfABUXm1q\n"
"DJIFMq/Ct9//ZMw3cHcvzJSDsqOuLaN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE\n"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBSdgOkpqrAK\n"
"R71zgTVIPfKcF40SAzAfBgNVHSMEGDAWgBREM51ULZjY5niamwAnB62dRTAjZDAN\n"
"BgkqhkiG9w0BAQsFAAOCAYEAHe+d5uxOBNW+6o9gyn+g2Q1x0YFJhaCvvgoVVC71\n"
"E1WkdBMO0nRYJZNxmNgd13DNvrD+Y31IFmTgGidg9urDq6HLo9Q9UkpAYdOKTsXk\n"
"NDo1QL5Kjqspuf2Aco3cDcvR2a5OUAJigftpdjOSTvG3geltDsYcd/khY0dMOl3h\n"
"25OZm6KyZAORWw3LhXxtmDfPxe31cd/lEp19Gp8aokLorHc7/yYS5h4OhL146vm/\n"
"CHYSt8pAIP65IyKoHJpHdSc4uOz0HJ92lpR10Qa9wqrFzDVcHGDX/JBvS0/H5Uyd\n"
"OY4jO7FEImq434YOtSy0yGJh/soK8RNe0frGzoQsQ/WxMBeHnprp/eBVZ8jqvYJ4\n"
"GW8kTtl8SGitehjoFdby46nAzdt3dBUcmZhm9Yka4jRVN5mwd+s13Pu2zRSvEwvq\n"
"IiKlSjZYotFffUsrfHVYqlk58PX5j7P/fohvLnHkucbu9FVrvVLlqZHK3vzafdw6\n"
"SlefNWD4/90X/5VFOpePkjZY\n"
"-----END CERTIFICATE-----";
const unsigned char advanced_cert_der_3[] =
"MIIDDjCCAXagAwIBAgIUcqJBzjg4lb0vBeFBGZ2uuY9ZoLkwDQYJKoZIhvcNAQEL"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMTETMBEGA1UEChMKYmFiZWxvdWVzdDAe"
"Fw0yMTA5MTMyMTQ5MzlaFw0yMjA4MjkyMTQ5MzlaMCsxFDASBgNVBAMTC0RhdmUg"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D"
"AQcDQgAE/TPAuX0MdUL6H1xse1VwixvR6wxmy6+GS5XS4P8H6lcczryuu+8Oqz2h"
"6sw1ChDIRt00l25j92h1SjFknnbE2qN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBScRf4VnU2d"
"71JxFeUmXa5uqaMclTAfBgNVHSMEGDAWgBRZm42kTC+aL+0DVOySIDIN9SvUEjAN"
"BgkqhkiG9w0BAQsFAAOCAYEAmhXg8uHQcAttx1gOKrLi77q1RpeGIu4dYy0UtOW1"
"ucNJuOGs8prcPROPElZEkZmfcgwDd2wwjNfs8tqPrcgSDyipLG7yMEj3uxxSZW7S"
"DN72f3qL2QavZ4joVZI5v2VplBFbCqC3Fr06Pg8xRcihfb+SnsrhQ4hVuG6GxIF+"
"n/khTXsEW6kEi6V0s79AIFBzYa/nH3sfK4gWQvcmUoBJ3Hzz2EIroB9v+P8OdJcR"
"37pfw+IDZx2Ri/W18nLwDTF0NVydT2ZGxHRFjankV2uM5q79nW1fsRCTrfoKxWGN"
"pKG9IxeXORwv87pETRxQA8W08AGqBsk62f5/lEuxfJqIw6wZKLtb2nqN912QDXLc"
"q0F6StYQHYB7WMZM2FA3AzaYeCjfI5a1/LirKm8okt96HXVo2rpqaDB3sJq5C5u+"
"yUZ3i+PlDEkUv3CTYSVYaBjKBDTgj6Z4kxKTdBE/A5rXRwIi14LyddTcPRKDrHlh"
"MQJL7ADzfeTbVYOHJx8XEE0F";

const unsigned char advanced_key_4[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIF+8UMnI9we1opth9BXqoNmsyj7bpeyMl6gnj8y4jejaoAoGCCqGSM49\n"
"AwEHoUQDQgAErXNalVG5Ylar4cutzXQVVA02QJLCo7b21E3C2nHhBLdF/27T27R6\n"
"KeiN/+ym/O780uZLwqCaFR9ix5I3/Jxpdg==\n"
"-----END EC PRIVATE KEY-----";
const unsigned char advanced_cert_pem_4[] = "-----BEGIN CERTIFICATE-----\n"
"MIIDDjCCAXagAwIBAgIUVWRCzRVkKkvSV8p5hX2em+k5NH0wDQYJKoZIhvcNAQEL\n"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMjETMBEGA1UEChMKYmFiZWxvdWVzdDAe\n"
"Fw0yMTA5MTQxNTI0NDdaFw0yMjA4MzAxNTI0NDdaMCsxFDASBgNVBAMTC0RhdmUg\n"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
"AQcDQgAErXNalVG5Ylar4cutzXQVVA02QJLCo7b21E3C2nHhBLdF/27T27R6KeiN\n"
"/+ym/O780uZLwqCaFR9ix5I3/JxpdqN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE\n"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBTLd4oWdCho\n"
"wKLuBKrx0Gq1C8W4mDAfBgNVHSMEGDAWgBRK5ldhst/tVyTQRn8g0Sc3gWnqkDAN\n"
"BgkqhkiG9w0BAQsFAAOCAYEAjq6QQM2ghdIvYkPwVV1r3oovuX9jTflslmzcZhuA\n"
"Mf41hKXjx/Y56n5YgWm6IeDWNfD7Q0u+ewe9k8sOA/6SROlrhW/1mFSVUDACd0uw\n"
"NubxeQQBLuYC+aoXOVacWX3zPXti7AcmYCHXtHnIp9ug3mYPyXg5idKRAqaaujZw\n"
"lN9DXB8L40PcujjzG/2rYhUx0xasyZZsbUotwn8YxvqPtEFls/3KWNTguu64VE3a\n"
"ha+NYJHcyyK8anNSTGV2snHNyCQagvb/lu+hsLYx3QkfknqWnbLHaA5Be86jZNQ8\n"
"EfAKsVN2N1NsIZfeRJ7jkeoFztI+sEuJjXEKJfQ69KoDAiIVfNuooMlYH9r2ldCJ\n"
"WZp5QzZ+cMXLrf3quKudH6QvdD0uKkHX9vQ9pfMDhMNgAbrUyI4dMgWJcW788N1N\n"
"Yj7MxshEtderX2xwlf0atGNyj/MQjhiuBzYCuvbzLxD8CkZMMjPwEHbwGkVaSdTa\n"
"Cggnp64OVIyU5OqLa4BVmWQl\n"
"-----END CERTIFICATE-----";
const unsigned char advanced_cert_der_4[] =
"MIIDDjCCAXagAwIBAgIUVWRCzRVkKkvSV8p5hX2em+k5NH0wDQYJKoZIhvcNAQEL"
"BQAwKjETMBEGA1UEAwwKZ2xld2x3eWRfMjETMBEGA1UEChMKYmFiZWxvdWVzdDAe"
"Fw0yMTA5MTQxNTI0NDdaFw0yMjA4MzAxNTI0NDdaMCsxFDASBgNVBAMTC0RhdmUg"
"TG9wcGVyMRMwEQYDVQQKEwpiYWJlbG91ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D"
"AQcDQgAErXNalVG5Ylar4cutzXQVVA02QJLCo7b21E3C2nHhBLdF/27T27R6KeiN"
"/+ym/O780uZLwqCaFR9ix5I3/JxpdqN2MHQwDAYDVR0TAQH/BAIwADATBgNVHSUE"
"DDAKBggrBgEFBQcDAjAPBgNVHQ8BAf8EBQMDB4AAMB0GA1UdDgQWBBTLd4oWdCho"
"wKLuBKrx0Gq1C8W4mDAfBgNVHSMEGDAWgBRK5ldhst/tVyTQRn8g0Sc3gWnqkDAN"
"BgkqhkiG9w0BAQsFAAOCAYEAjq6QQM2ghdIvYkPwVV1r3oovuX9jTflslmzcZhuA"
"Mf41hKXjx/Y56n5YgWm6IeDWNfD7Q0u+ewe9k8sOA/6SROlrhW/1mFSVUDACd0uw"
"NubxeQQBLuYC+aoXOVacWX3zPXti7AcmYCHXtHnIp9ug3mYPyXg5idKRAqaaujZw"
"lN9DXB8L40PcujjzG/2rYhUx0xasyZZsbUotwn8YxvqPtEFls/3KWNTguu64VE3a"
"ha+NYJHcyyK8anNSTGV2snHNyCQagvb/lu+hsLYx3QkfknqWnbLHaA5Be86jZNQ8"
"EfAKsVN2N1NsIZfeRJ7jkeoFztI+sEuJjXEKJfQ69KoDAiIVfNuooMlYH9r2ldCJ"
"WZp5QzZ+cMXLrf3quKudH6QvdD0uKkHX9vQ9pfMDhMNgAbrUyI4dMgWJcW788N1N"
"Yj7MxshEtderX2xwlf0atGNyj/MQjhiuBzYCuvbzLxD8CkZMMjPwEHbwGkVaSdTa"
"Cggnp64OVIyU5OqLa4BVmWQl";
const char advanced_jku_4[] = "{\"keys\":[{\"kty\":\"EC\",\"x\":\"rXNalVG5Ylar4cutzXQVVA02QJLCo7b21E3C2nHhBLc\",\"y\":\"Rf9u09u0einojf_spvzu_NLmS8KgmhUfYseSN_ycaXY\",\"crv\":\"P-256\",\"kid\":\"OsipzlLJ1CAOU_WnT2zuB4u31IlgFPsZfT4j4r5qZUA\"}]}";
const char jwk_key_128_1[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"Zd3bPKCfbPc2A6sh3M7dIbzgD6PS-qIwsbN79VgN5PY\"}";

#define ADVANCED_TOKEN "eyJraWQiOiJkZjVTckx2SlgzWEI3OHhHa25QZVZDemdXOTZhT2pYSTlfQnFtYkUzV0ljIiwiandrIjp7Imt0eSI6IkVDIiwieCI6IktPSVItVXpkTDRpOV9uUDM1dVg1UklhZnF3c0FEUkZpTjc0TWNNYTNMVkkiLCJ5IjoiXzB3MzZMb0ZlYVpXTG1jOXYwOHlXNjhEdzFHQWdmNjFmUDRSNUx0TFY1dyIsImNydiI6IlAtMjU2Iiwia2lkIjoiMSIsIng1YyI6WyJNSUlERGpDQ0FYYWdBd0lCQWdJVU5kQlhzUzBmN3c3em9xQlYwMDVlT2VEMkRNZ3dEUVlKS29aSWh2Y05BUUVMQlFBd0tqRVRNQkVHQTFVRUF3d0taMnhsZDJ4M2VXUmZNVEVUTUJFR0ExVUVDaE1LWW1GaVpXeHZkV1Z6ZERBZUZ3MHlNVEE1TVRNeU1UUTVNemhhRncweU1qQTRNamt5TVRRNU16aGFNQ3N4RkRBU0JnTlZCQU1UQzBSaGRtVWdURzl3Y0dWeU1STXdFUVlEVlFRS0V3cGlZV0psYkc5MVpYTjBNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVLT0lSK1V6ZEw0aTkvblAzNXVYNVJJYWZxd3NBRFJGaU43NE1jTWEzTFZML1REZm91Z1Y1cGxZdVp6Mi9UekpicndQRFVZQ0IvclY4L2hIa3UwdFhuS04yTUhRd0RBWURWUjBUQVFIL0JBSXdBREFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQWpBUEJnTlZIUThCQWY4RUJRTURCNEFBTUIwR0ExVWREZ1FXQkJSL3hBUFZNUlVnU0YySU5yTnNHclg5WmlrU1lEQWZCZ05WSFNNRUdEQVdnQlJabTQya1RDK2FMKzBEVk95U0lESU45U3ZVRWpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVlFQUhIOEZ0SjRDVmZyU3ZsR3hSa1pIOTFYRks2aWIxMTBiL051OXpJUEcydCtHYUZodkNCdFJmSGhiekY3RkcvbytOTmhiVWZXTG5iUFJlTlF5NDVRYXNxbHJRTURrZ2VDQVpza2VhZHgxTWpyQU44RWJGU21ReFE5ZEtKd1pyWFl4aVQzSVcxTEZXeXVISEErYXZEeVd5RFFTb0FCWmtWV3pWM1VIajZQRkdqTlVoZFdiVTdXTEY5ellYMDdLN3UyRnlWNjcvZkpDUFg5UjErY3ZWRnBZdFBRc09vNU5GbkVMcmxiUnM4ZDFnN0pwZlpYL2p1WEJ0WXNpQTcxaU9QOXNWcVdITTVVa1dnZDZ4YWRPR0ZxaWlTcEpNbitrNUxMOVBWTFo2QnFkcUxPRUZFTElVTE0vbVZ2SXZkM2tid2lUaVVrWlRiNnd0SS9aOGJBUGxLU1FCL3hIdXh5OC9IM2NPYzhDT29xMmZuVHRMQmFRajRjNFZFaytNUHVMc0s3c21GV3NRblFOUlMrdUhQSVBXNE52Nm55VWo1NHRxZThGYUl6RWlvQlVENzc5c0o5Z3hpejY4VVBEbzVBckh4M2kyaVMyUk9rRUdFVW05M2ZZR2k4eTh5WnRXYjhNc1B2cUppMkFyMHR2czN5T0hwMytXcVRPZlRvWVNyck56MnJQIl19LCJ4NWMiOlsiTUlJRERqQ0NBWGFnQXdJQkFnSVVkMXNZZUFMY0MzbkREemxvdm1VbTlTK0lBYUV3RFFZSktvWklodmNOQVFFTEJRQXdLakVUTUJFR0ExVUVBd3dLWjJ4bGQyeDNlV1JmTVRFVE1CRUdBMVVFQ2hNS1ltRmlaV3h2ZFdWemREQWVGdzB5TVRBNU1UUXhOVEkwTkRaYUZ3MHlNakE0TXpBeE5USTBORFphTUNzeEZEQVNCZ05WQkFNVEMwUmhkbVVnVEc5d2NHVnlNUk13RVFZRFZRUUtFd3BpWVdKbGJHOTFaWE4wTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTy9JM1E4RnNFRmlpNW9IWkI1SHRaZTQ2YXdTWXhrbVR0bVZwV0thYjVUOVNJZnpuVndMM241L2lqTHlRNTRmNmJXbkxreGV1WnhSZlRkckRITm9kT3FOMk1IUXdEQVlEVlIwVEFRSC9CQUl3QURBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFqQVBCZ05WSFE4QkFmOEVCUU1EQjRBQU1CMEdBMVVkRGdRV0JCU2RqczBycUxnRUh2Sm9lbjJUMFhJUlJpclM1VEFmQmdOVkhTTUVHREFXZ0JTVG1FbUcrVEhXL3pySk01WmZDUGkyNTlSQTh6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FZRUFFQ2RSdEZWRVJwa2tBZmo3bXdDN1F1Mm5vcE1ZY0tDRGFnREtpMTZZSkVMUVdERXgxZGpSOUdGdTE5UUVSTjBSR1NPRWd6UHVuaWZhVU9HZmtZc0ZhRjlOQTI3S1ZHZ3BLM1RnVGw1QUpCSUdJaUtQOHZTaXFGNktPb3NiVFUzV2VLd1Q0bUUzdDF5V2NHL0V4Q3FYVWNPVW1IMkJGTWg3NGFPMnlwOEFGaVJBSzUxQWxVN0wzV1J2ZHRhVkwxcnJpaVluT2g1U3JTZXZWdmViTWRaeE96c2w3d0docFc2Z1ZmbTB4bU1QS2RDTmh5alRsWDZVelJER3BOeFQ1VE5iM2tZUkd2aVovQnNNcFQxTXJuSVFSVVVoTEV6N2RkNDM2MlhnUlgxSmk2UnZES2NRVnhRTmRJT1RXeUpJRGVucmJxbXVBNFplVi9PSTg2VWY5aVBraktVR0ppVmhhWU1Xd2dYU2tmUnlVM3VBVnBlbExYNy9tem0zUHVKVjVSeUJzSnFOc3Vtc2REU2tBKys1VmhkT3FpOFlyNWdJMGdGM2VwNXRnZ3ZWQktnR21wWjJmRUY2QktNVEM0SHlpQ2M5ZTJxZXFMVElPWlBpTXBKbThONmZwRVkzN0pFcXFQSGVZMTlXWXhkRVRyWTVYTENxdElURlJWVE11YkpQeURuYyJdLCJ4NXUiOiJodHRwczovL2xvY2FsaG9zdDo3NDY4L3g1dSIsImprdSI6Imh0dHBzOi8vbG9jYWxob3N0Ojc0Njgvamt1IiwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoicDBRRHpqVU5HVTJ0UmM4QlNPbFpzRzBONTQwazNmTzBPT082bTJjbDlJSSIsInkiOiItTEkwRjdwbC1yNklYZjlXMVpMVFRDZXV3M05JemZRLW1OamVJS2RJc1RVIiwiY3J2IjoiUC0yNTYifSwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9.jJY1hvX8J0f8T-8piAS_9zVejfTVV-oUaflrY7WV0ErmiNlYc7aHRg.bToigkLnPUDJb_P4cHt0hA.lLYVB2ajc0KNPt2iAvP2LFxDAjI1ujqKkjgZ1--8seq63WF0jZD9CxKRUUseIAmEjiPpaOG1co8DdqUXMEvw2g.MnoGVwEN_PG2i_joWhxTUA"

#define TOKEN "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_HEADER_B64 ";error;iOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.;error;nK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.;error;czZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INVALID_CIPHER_LEN "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..-cNn1XCsgQJ4LUqRynkFYg.10CSSm6dThI4bPCQjzSrEupjI-sTLk52MEGEf06vxJDabMOAdfcyIlLa4CMJyOmFMpVvI9-eWRfLmoIM8R.r76qF3OECfzhDMxZ7yTGFg"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.;error;Z3gDEpAMD_79pOw"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_EMPTY_HEADER ".S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_EMPTY_IV "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q..BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_EMPTY_CIPHERTEXT "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ..p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_EMPTY_TAG "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g."
#define TOKEN_OVERSIZE_IV "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yCg.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_OVERSIZE_TAG "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.ZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yZXJyb3JlcnJvcmVycm9yCg"
#define TOKEN_INVALID_ENC "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INV_0 "    .S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INV_1 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.    .29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INV_2 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.    .BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INV_3 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.    -tuQjCzWfZkrE3g.p28K0cxZ3gDEpAMD_79pOw"
#define TOKEN_INV_4 "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.S7OUaa-1ekDy8cPPo1Rzq81vwaEfk3yBL5Xw9FnfRtGikBSwH0OC6Q.29q9_PdnK2jXwG4gJvgDoQ.BuhbHPZczZ_XqNm8JwoW_B8rczVdVYO4o7pflVAcT0ojJg_m8Eo79F2W7FgLUEKVxrOoOz6-tuQjCzWfZkrE3g.    "
#define TOKEN_VALID_CIPHER_LEN_1 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_1 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_1_2 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2IcBE6yb.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_1_3 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5V.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_1_4 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2IcBE6y.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_VALID_CIPHER_LEN_2 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.W5WH8adpm8Rmgz5X8MNkG3MUH3-Pdjr7F3nJ2L0CHDupVFGRuoMWBmYFrIIK6Po23LTK7Xo0QtxgoemzYpclIHZ8WLEh3FD-Ku0bq5Vm2Ic.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_2 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0F.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_2_2 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZFBE6y.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_2_3 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0.xrblYm4FGTv2j59L7xQgAA"
#define TOKEN_INVALID_CIPHER_LEN_2_4 "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..BE6ybfu_NcwhkB01q7svMw.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZFBE6ybs.xrblYm4FGTv2j59L7xQgAA"

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

START_TEST(test_rhonabwy_set_full_header_error)
{
  jwe_t * jwe;
  json_t * j_header;

  j_header = json_pack("{ssss}", "alg", r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP_256), "enc", "error");
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_header_json_t(jwe, j_header), RHN_ERROR_PARAM);
  r_jwe_free(jwe);
  json_decref(j_header);

  j_header = json_pack("{ssss}", "alg", "error", "enc", r_jwa_enc_to_str(R_JWA_ENC_A256GCM));
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_header_json_t(jwe, j_header), RHN_ERROR_PARAM);
  r_jwe_free(jwe);
  json_decref(j_header);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_header_json_t(jwe, NULL), RHN_ERROR_PARAM);
  r_jwe_free(jwe);

  j_header = json_pack("{ssss}", "alg", r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP_256), "enc", r_jwa_enc_to_str(R_JWA_ENC_A256GCM));
  ck_assert_int_eq(r_jwe_set_full_header_json_t(NULL, j_header), RHN_ERROR_PARAM);
  json_decref(j_header);

}
END_TEST

START_TEST(test_rhonabwy_set_full_header)
{
  jwe_t * jwe;
  json_t * j_header = json_pack("{sssisossss}", "str", CLAIM_STR, "int", CLAIM_INT, "obj", json_true(), "alg", r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP_256), "enc", r_jwa_enc_to_str(R_JWA_ENC_A256GCM));
  char * str_header = json_dumps(j_header, JSON_COMPACT);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_header_json_t(jwe, j_header), RHN_OK);
  ck_assert_str_eq(r_jwe_get_header_str_value(jwe, "str"), CLAIM_STR);
  ck_assert_int_eq(r_jwe_get_header_int_value(jwe, "int"), CLAIM_INT);
  ck_assert_ptr_eq(r_jwe_get_header_json_t_value(jwe, "obj"), json_true());
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_RSA_OAEP_256);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A256GCM);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_header_json_str(jwe, str_header), RHN_OK);
  ck_assert_str_eq(r_jwe_get_header_str_value(jwe, "str"), CLAIM_STR);
  ck_assert_int_eq(r_jwe_get_header_int_value(jwe, "int"), CLAIM_INT);
  ck_assert_ptr_eq(r_jwe_get_header_json_t_value(jwe, "obj"), json_true());
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_RSA_OAEP_256);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A256GCM);
  r_jwe_free(jwe);

  o_free(str_header);
  json_decref(j_header);
}
END_TEST

START_TEST(test_rhonabwy_get_full_header)
{
  jwe_t * jwe;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_header = json_pack("{sssisO}", "keystr", "value", "keyint", 42, "keyjson", j_value), * j_result;

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

START_TEST(test_rhonabwy_set_full_unprotected_header)
{
  jwe_t * jwe;
  json_t * j_header = json_pack("{sssiso}", "str", CLAIM_STR, "int", CLAIM_INT, "obj", json_true());
  char * str_header = json_dumps(j_header, JSON_COMPACT);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, json_null()), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe,  NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(NULL,  j_header), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_header), RHN_OK);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_str(jwe, "[4, 8, 15, 16, 23, 42]"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_str(jwe, NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_str(NULL, str_header), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_str(jwe, str_header), RHN_OK);
  r_jwe_free(jwe);

  o_free(str_header);
  json_decref(j_header);
}
END_TEST

START_TEST(test_rhonabwy_get_full_unprotected_header)
{
  jwe_t * jwe;
  json_t * j_header = json_pack("{sssiso}", "str", CLAIM_STR, "int", CLAIM_INT, "obj", json_true()), * j_header_get;
  char * str_header_get;

  ck_assert_ptr_ne(j_header, NULL);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);

  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_header), RHN_OK);
  ck_assert_ptr_ne(NULL, j_header_get = r_jwe_get_full_unprotected_header_json_t(jwe));
  ck_assert_int_eq(1, json_equal(j_header_get, j_header));
  json_decref(j_header_get);
  ck_assert_ptr_ne(NULL, str_header_get = r_jwe_get_full_unprotected_header_str(jwe));
  ck_assert_ptr_ne(NULL, j_header_get = json_loads(str_header_get, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(1, json_equal(j_header_get, j_header));

  o_free(str_header_get);
  json_decref(j_header);
  json_decref(j_header_get);
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
  ck_assert_ptr_ne(g_privkey = r_jwk_export_to_gnutls_privkey(jwk_priv), NULL);
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

START_TEST(test_rhonabwy_set_properties_error)
{
  jwe_t * jwe;
  jwk_t * jwk;

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);

  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_FULL_JSON_STR, json_true(),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_FULL_JSON_STR, "{}",
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_INT_VALUE, "key", CLAIM_INT,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_RHN_INT_VALUE, "key", CLAIM_INT,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_JSON_T_VALUE, "key", json_true(),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_CLAIM_STR_VALUE, "key", CLAIM_STR,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_SIG_ALG, R_JWA_ALG_RS256,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_SIGN_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_VERIFY_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);

  r_jwe_free(jwe);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_set_properties)
{
  jwe_t * jwe;
  jwk_t * jwk;
  const unsigned char * key_iv_aad;
  size_t key_iv_aad_len;
  json_t * j_un_header = json_pack("{ss ss ss ss ss ss}", "Twilight Sparkle", "six-pointed star", "Applejack", "trio of apples", "Rainbow Dash", "rainbow-colored lightning bolt with a cloud", "Pinkie Pie", "trio of balloons", "Rarity", "trio of diamonds", "Fluttershy", "trio of butterflies"), * j_un_header_resp;

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);

  ck_assert_int_eq(r_jwe_set_properties(jwe, RHN_OPT_HEADER_INT_VALUE, "int", CLAIM_INT,
                                             RHN_OPT_HEADER_RHN_INT_VALUE, "rhn_int", (rhn_int_t)CLAIM_INT,
                                             RHN_OPT_HEADER_STR_VALUE, "str", CLAIM_STR,
                                             RHN_OPT_HEADER_JSON_T_VALUE, "json", json_true(),
                                             RHN_OPT_UN_HEADER_FULL_JSON_T, j_un_header,
                                             RHN_OPT_PAYLOAD, PAYLOAD, o_strlen(PAYLOAD),
                                             RHN_OPT_ENC_ALG, R_JWA_ALG_RSA1_5,
                                             RHN_OPT_ENC, R_JWA_ENC_A256GCM,
                                             RHN_OPT_CIPHER_KEY, cypher_key, sizeof(cypher_key),
                                             RHN_OPT_IV, iv, sizeof(iv),
                                             RHN_OPT_AAD, aad, sizeof(aad),
                                             RHN_OPT_ENCRYPT_KEY_JWK, jwk,
                                             RHN_OPT_DECRYPT_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_OK);

  ck_assert_int_eq(CLAIM_INT, r_jwe_get_header_int_value(jwe, "int"));
  ck_assert_int_eq(CLAIM_INT, r_jwe_get_header_int_value(jwe, "rhn_int"));
  ck_assert_str_eq(CLAIM_STR, r_jwe_get_header_str_value(jwe, "str"));
  ck_assert_ptr_eq(json_true(), r_jwe_get_header_json_t_value(jwe, "json"));
  ck_assert_ptr_ne(NULL, j_un_header_resp = r_jwe_get_full_unprotected_header_json_t(jwe));
  ck_assert_int_eq(1, json_equal(j_un_header_resp, j_un_header));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_payload(jwe, &key_iv_aad_len));
  ck_assert_int_eq(o_strlen(PAYLOAD), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, PAYLOAD, key_iv_aad_len));
  ck_assert_int_eq(R_JWA_ALG_RSA1_5, r_jwe_get_alg(jwe));
  ck_assert_int_eq(R_JWA_ENC_A256GCM, r_jwe_get_enc(jwe));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_cypher_key(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(cypher_key), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, cypher_key, key_iv_aad_len));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_iv(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(iv), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, iv, key_iv_aad_len));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_aad(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(aad), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, aad, key_iv_aad_len));
  ck_assert_int_eq(1, r_jwks_size(jwe->jwks_privkey));
  ck_assert_int_eq(1, r_jwks_size(jwe->jwks_pubkey));

  json_decref(j_un_header);
  json_decref(j_un_header_resp);
  r_jwe_free(jwe);
  r_jwk_free(jwk);
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

START_TEST(test_rhonabwy_get_set_key_iv_aad)
{
  jwe_t * jwe;
  const unsigned char * key_iv_aad;
  size_t key_iv_aad_len;
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_cypher_key(jwe, cypher_key, sizeof(cypher_key)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_iv(jwe, iv, sizeof(iv)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_aad(jwe, aad, sizeof(aad)), RHN_OK);
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_cypher_key(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(cypher_key), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, cypher_key, key_iv_aad_len));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_iv(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(iv), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, iv, key_iv_aad_len));
  ck_assert_ptr_ne(NULL, key_iv_aad = r_jwe_get_aad(jwe, &key_iv_aad_len));
  ck_assert_int_eq(sizeof(aad), key_iv_aad_len);
  ck_assert_int_eq(0, memcmp(key_iv_aad, aad, key_iv_aad_len));
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
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(PAYLOAD)));
  r_jwe_free(jwe);

  // R_JWA_ENC_A192GCM not supported by GnuTLS until 3.6.14
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A192GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  r_jwe_free(jwe);
#endif

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
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

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_cypher_key(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_generate_iv(jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)HUGE_PAYLOAD, o_strlen(HUGE_PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(jwe->ciphertext_b64url, NULL);

  r_jwe_set_header_str_value(jwe, "zip", "DEF");
  ck_assert_int_eq(r_jwe_encrypt_payload(jwe), RHN_OK);
  ck_assert_ptr_ne(jwe->ciphertext_b64url, NULL);
  ck_assert_int_eq(r_jwe_decrypt_payload(jwe), RHN_OK);
  ck_assert_int_eq(0, o_strncmp(HUGE_PAYLOAD, (const char *)r_jwe_get_payload(jwe, NULL), o_strlen(HUGE_PAYLOAD)));

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
  ck_assert_int_eq(r_jwe_decrypt_key(jwe, jwk_pubkey_rsa, 0), RHN_ERROR_INVALID);
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

START_TEST(test_rhonabwy_jwk_in_header_invalid)
{
  jwe_t * jwe, * jwe_parsed;
  jwk_t * jwk_pubkey_rsa;
  json_t * j_jwk;
  char * str_jwe;

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_parsed), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_ptr_ne(NULL, j_jwk = json_loads(jwk_privkey_rsa_str, JSON_DECODE_ANY, 0));
  ck_assert_int_eq(r_jwe_set_header_json_t_value(jwe, "jwk", j_jwk), RHN_OK);
  ck_assert_ptr_ne(NULL, str_jwe = r_jwe_serialize(jwe, jwk_pubkey_rsa, 0));

  ck_assert_int_eq(r_jwe_parse(jwe_parsed, str_jwe, 0), RHN_ERROR_PARAM);

  r_jwe_free(jwe);
  r_jwe_free(jwe_parsed);
  r_jwk_free(jwk_pubkey_rsa);
  json_decref(j_jwk);
  o_free(str_jwe);
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

START_TEST(test_rhonabwy_decrypt_updated_header_cbc)
{
  jwe_t * jwe, * jwe_dec;
  jwk_t * jwk_pubkey_rsa, * jwk_privkey_rsa;
  char * token, header_b64[128] = {0}, * header_re, * token_updated;
  unsigned char header[256] = {0}, header_reb64[256] = {0};
  size_t header_len = 0, header_reb64_len = 0;
  json_t * j_header = NULL;

  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_dec), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_ne(NULL, token = r_jwe_serialize(jwe, jwk_pubkey_rsa, 0));
  o_strncpy(header_b64, token, o_strchr(token, '.')-token);
  ck_assert_int_ne(o_strlen(header_b64), 0);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)header_b64, o_strlen(header_b64), header, &header_len), 1);
  header[header_len] = '\0';
  ck_assert_ptr_ne(NULL, j_header = json_loads((const char *)header, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(1, json_is_object(j_header));
  ck_assert_int_eq(0, json_object_set_new(j_header, "plop", json_string("grut")));
  ck_assert_ptr_ne(NULL, header_re = json_dumps(j_header, JSON_COMPACT));
  ck_assert_int_eq(1, o_base64url_encode((const unsigned char *)header_re, o_strlen(header_re), header_reb64, &header_reb64_len));
  token_updated = o_strndup((const char *)header_reb64, header_reb64_len);
  token_updated = mstrcatf(token_updated, "%s", o_strchr(token, '.'));
  ck_assert_int_eq(r_jwe_parse(jwe_dec, token_updated, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  o_free(token_updated);
  o_free(token);
  o_free(header_re);
  r_jwe_free(jwe);
  r_jwe_free(jwe_dec);
  json_decref(j_header);

  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_updated_header_gcm)
{
  jwe_t * jwe, * jwe_dec;
  jwk_t * jwk_pubkey_rsa, * jwk_privkey_rsa;
  char * token, header_b64[128] = {0}, * header_re, * token_updated;
  unsigned char header[256] = {0}, header_reb64[256] = {0};
  size_t header_len = 0, header_reb64_len = 0;
  json_t * j_header = NULL;

  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_dec), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128GCM), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_ne(NULL, token = r_jwe_serialize(jwe, jwk_pubkey_rsa, 0));
  o_strncpy(header_b64, token, o_strchr(token, '.')-token);
  ck_assert_int_ne(o_strlen(header_b64), 0);
  ck_assert_int_eq(o_base64url_decode((const unsigned char *)header_b64, o_strlen(header_b64), header, &header_len), 1);
  header[header_len] = '\0';
  ck_assert_ptr_ne(NULL, j_header = json_loads((const char *)header, JSON_DECODE_ANY, NULL));
  ck_assert_int_eq(1, json_is_object(j_header));
  ck_assert_int_eq(0, json_object_set_new(j_header, "plop", json_string("grut")));
  ck_assert_ptr_ne(NULL, header_re = json_dumps(j_header, JSON_COMPACT));
  ck_assert_int_eq(1, o_base64url_encode((const unsigned char *)header_re, o_strlen(header_re), header_reb64, &header_reb64_len));
  token_updated = o_strndup((const char *)header_reb64, header_reb64_len);
  token_updated = mstrcatf(token_updated, "%s", o_strchr(token, '.'));
  ck_assert_int_eq(r_jwe_parse(jwe_dec, token_updated, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  o_free(token_updated);
  o_free(token);
  o_free(header_re);
  r_jwe_free(jwe);
  r_jwe_free(jwe_dec);
  json_decref(j_header);

  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

#if GNUTLS_VERSION_NUMBER >= 0x030600 && defined(R_WITH_CURL)
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

int callback_x5u_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  ulfius_set_string_body_response(response, 200, (const char *)advanced_cert_pem_3);
  return U_CALLBACK_CONTINUE;
}

int callback_jku_ecdsa_crt (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  ulfius_set_response_properties(response, U_OPT_STATUS, 200,
                                           U_OPT_HEADER_PARAMETER, "Content-Type", "application/json",
                                           U_OPT_STRING_BODY, advanced_jku_4,
                                           U_OPT_NONE);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_rhonabwy_advanced_parse)
{
  jwk_t * jwk_pub;
  jwe_t * jwe;
  struct _u_instance instance;
  char * http_key, * http_cert;

  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));

  ck_assert_int_eq(ulfius_init_instance(&instance, 7468, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jku", NULL, 0, &callback_jku_ecdsa_crt, NULL), U_OK);

  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);

  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pub, jwk_pubkey_ecdsa_str), RHN_OK);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe, ADVANCED_TOKEN, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 4);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 0);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_JKU, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 1);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_JWK, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 1);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_X5C, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 1);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_X5U, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 1);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_X5U|R_PARSE_HEADER_X5C, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 2);
  r_jwe_free(jwe);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_advanced_parse(jwe, ADVANCED_TOKEN, R_PARSE_HEADER_ALL, R_FLAG_IGNORE_SERVER_CERTIFICATE), RHN_OK);
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 4);
  r_jwe_free(jwe);

  r_jwk_free(jwk_pub);
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_quick_parse)
{
  jwk_t * jwk_pub;
  jwe_t * jwe;
  jwk_t * jwk;
  struct _u_instance instance;
  char * http_key, * http_cert;

  ck_assert_ptr_ne(NULL, http_key = get_file_content(HTTPS_CERT_KEY));
  ck_assert_ptr_ne(NULL, http_cert = get_file_content(HTTPS_CERT_PEM));

  ck_assert_int_eq(ulfius_init_instance(&instance, 7468, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/x5u", NULL, 0, &callback_x5u_ecdsa_crt, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "GET", "/jku", NULL, 0, &callback_jku_ecdsa_crt, NULL), U_OK);

  ck_assert_int_eq(ulfius_start_secure_framework(&instance, http_key, http_cert), U_OK);

  ck_assert_int_eq(r_jwk_init(&jwk_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pub, jwk_pubkey_ecdsa_str), RHN_OK);

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  r_jwe_free(jwe);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_symmetric_str));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_OVERSIZE_IV, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_OVERSIZE_TAG, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_ENC, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_HEADER, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_HEADER_B64, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_IV_B64, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_B64, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_TAG_B64, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_DOTS, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_EMPTY_HEADER, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_EMPTY_IV, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_EMPTY_CIPHERTEXT, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_EMPTY_TAG, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INV_0, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INV_1, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INV_2, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INV_3, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_ptr_eq(NULL, jwe = r_jwe_quick_parse(TOKEN_INV_4, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(ADVANCED_TOKEN, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 0);
  r_jwe_free(jwe);

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(ADVANCED_TOKEN, R_PARSE_HEADER_ALL, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 4);
  r_jwe_free(jwe);

  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(ADVANCED_TOKEN, R_PARSE_HEADER_JWK|R_PARSE_HEADER_X5C, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), 2);
  r_jwe_free(jwe);

  r_jwk_free(jwk_pub);
  o_free(http_key);
  o_free(http_cert);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_rhonabwy_cipher_length)
{
  jwe_t * jwe;
  jwk_t * jwk;

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_VALID_CIPHER_LEN_1, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_1, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_1_2, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_1_3, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_1_4, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_VALID_CIPHER_LEN_2, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_2, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_2_2, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_2_3, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_JSON_STR, jwk_key_128_1));
  ck_assert_ptr_ne(NULL, jwe = r_jwe_quick_parse(TOKEN_INVALID_CIPHER_LEN_2_4, R_PARSE_NONE, R_FLAG_IGNORE_SERVER_CERTIFICATE));
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe);
  r_jwk_free(jwk);

}
END_TEST
#endif

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
  tcase_add_test(tc_core, test_rhonabwy_set_full_header_error);
  tcase_add_test(tc_core, test_rhonabwy_set_full_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_header);
  tcase_add_test(tc_core, test_rhonabwy_set_full_unprotected_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_unprotected_header);
  tcase_add_test(tc_core, test_rhonabwy_set_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_jwks);
  tcase_add_test(tc_core, test_rhonabwy_add_keys_by_content);
  tcase_add_test(tc_core, test_rhonabwy_set_properties_error);
  tcase_add_test(tc_core, test_rhonabwy_set_properties);
  tcase_add_test(tc_core, test_rhonabwy_copy);
  tcase_add_test(tc_core, test_rhonabwy_generate_cypher_key);
  tcase_add_test(tc_core, test_rhonabwy_generate_iv);
  tcase_add_test(tc_core, test_rhonabwy_get_set_key_iv_aad);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_all_format);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_payload_invalid_key_no_tag);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_payload_zip);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_key_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_key_valid);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_rhonabwy_decrypt_key_invalid_encrypted_key);
  tcase_add_test(tc_core, test_rhonabwy_jwk_in_header_invalid);
#endif
  tcase_add_test(tc_core, test_rhonabwy_decrypt_key_valid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_updated_header_cbc);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_updated_header_gcm);
#if GNUTLS_VERSION_NUMBER >= 0x030600 && defined(R_WITH_CURL)
  tcase_add_test(tc_core, test_rhonabwy_advanced_parse);
  tcase_add_test(tc_core, test_rhonabwy_quick_parse);
  tcase_add_test(tc_core, test_rhonabwy_cipher_length);
#endif
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE core tests");
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
