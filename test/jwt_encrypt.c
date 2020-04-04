/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define TOKEN "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.TGaK3fCgsGxLNuGbWR2j4Fi_hetyBLSRyadtdG0MAsXTnXlXsFb_wwFahZQASsLxwEEekZQ5EEkJb9gwu3uWaf3Oq58lOETa4Fb_Z1-WN1jvzF4DBEQLVl0azU62LbPsFHl8vWuuE7NF5oFX2V3CboQnFoWB1yyqWBJXkdEvFyIrHnNmQw9goPs2kjACnYdsNzMnP6SOYsYvguIJcvKnoBAbQYp0DA8OHXI6fW4P_zgZ7TQVCJLwpB0QoD_4Raaya3OABxQ7LJqhpYvk7iHGHnC-Ws23dmLCdv5WG_w6NEQwQLkuED8SXhUbirLeq4LRVxXdf8I1XTKesS6_NVJBNg.GMeHp_DOIg9h8sfGYE8fYg.XcRXOh492A8SPw8EEQ6mRe1kt7BNFqOgG8GqHR2g6CI4a_RI3JA2taxi3wc4eRWJ.94p-hjUgcWGiJsQ8TnnKtQ"
#define TOKEN_INVALID_HEADER_B64 ";error;.TGaK3fCgsGxLNuGbWR2j4Fi_hetyBLSRyadtdG0MAsXTnXlXsFb_wwFahZQASsLxwEEekZQ5EEkJb9gwu3uWaf3Oq58lOETa4Fb_Z1-WN1jvzF4DBEQLVl0azU62LbPsFHl8vWuuE7NF5oFX2V3CboQnFoWB1yyqWBJXkdEvFyIrHnNmQw9goPs2kjACnYdsNzMnP6SOYsYvguIJcvKnoBAbQYp0DA8OHXI6fW4P_zgZ7TQVCJLwpB0QoD_4Raaya3OABxQ7LJqhpYvk7iHGHnC-Ws23dmLCdv5WG_w6NEQwQLkuED8SXhUbirLeq4LRVxXdf8I1XTKesS6_NVJBNg.GMeHp_DOIg9h8sfGYE8fYg.XcRXOh492A8SPw8EEQ6mRe1kt7BNFqOgG8GqHR2g6CI4a_RI3JA2taxi3wc4eRWJ.94p-hjUgcWGiJsQ8TnnKtQ"
#define TOKEN_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.TGaK3fCgsGxLNuGbWR2j4Fi_hetyBLSRyadtdG0MAsXTnXlXsFb_wwFahZQASsLxwEEekZQ5EEkJb9gwu3uWaf3Oq58lOETa4Fb_Z1-WN1jvzF4DBEQLVl0azU62LbPsFHl8vWuuE7NF5oFX2V3CboQnFoWB1yyqWBJXkdEvFyIrHnNmQw9goPs2kjACnYdsNzMnP6SOYsYvguIJcvKnoBAbQYp0DA8OHXI6fW4P_zgZ7TQVCJLwpB0QoD_4Raaya3OABxQ7LJqhpYvk7iHGHnC-Ws23dmLCdv5WG_w6NEQwQLkuED8SXhUbirLeq4LRVxXdf8I1XTKesS6_NVJBNg.GMeHp_DOIg9h8sfGYE8fYg.;error;.94p-hjUgcWGiJsQ8TnnKtQ"
#define TOKEN_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0TGaK3fCgsGxLNuGbWR2j4Fi_hetyBLSRyadtdG0MAsXTnXlXsFb_wwFahZQASsLxwEEekZQ5EEkJb9gwu3uWaf3Oq58lOETa4Fb_Z1-WN1jvzF4DBEQLVl0azU62LbPsFHl8vWuuE7NF5oFX2V3CboQnFoWB1yyqWBJXkdEvFyIrHnNmQw9goPs2kjACnYdsNzMnP6SOYsYvguIJcvKnoBAbQYp0DA8OHXI6fW4P_zgZ7TQVCJLwpB0QoD_4Raaya3OABxQ7LJqhpYvk7iHGHnC-Ws23dmLCdv5WG_w6NEQwQLkuED8SXhUbirLeq4LRVxXdf8I1XTKesS6_NVJBNg.GMeHp_DOIg9h8sfGYE8fYg.XcRXOh492A8SPw8EEQ6mRe1kt7BNFqOgG8GqHR2g6CI4a_RI3JA2taxi3wc4eRWJ.94p-hjUgcWGiJsQ8TnnKtQ"
#define TOKEN_INVALID_SIGNATURE "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.TGaK3fCgsGxLNuGbWR2j4Fi_hetyBLSRyadtdG0MAsXTnXlXsFb_wwFahZQASsLxwEEekZQ5EEkJb9gwu3uWaf3Oq58lOETa4Fb_Z1-WN1jvzF4DBEQLVl0azU62LbPsFHl8vWuuE7NF5oFX2V3CboQnFoWB1yyqWBJXkdEvFyIrHnNmQw9goPs2kjACnYdsNzMnP6SOYsYvguIJcvKnoBAbQYp0DA8OHXI6fW4P_zgZ7TQVCJLwpB0QoD_4Raaya3OABxQ7LJqhpYvk7iHGHnC-Ws23dmLCdv5WG_w6NEQwQLkuED8SXhUbirLeq4LRVxXdf8I1XTKesS6_NVJBNg.GMeHp_DOIg9h8sfGYE8fYg.XcRXOh492A8SPw8EEQ6mRe1kt7BNFqOgG8GqHR2g6CI4a_RI3JA2taxi3wc4wRWJ.94p-hjUgcWGiJsQ8TnnKtQ"

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"}";
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
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD8"
                                    "2B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW3b"
                                    "bsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9hNl5"
                                    "szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK4OPm"
                                    "N6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4GwyfF"
                                    "-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"kid\":\"2\"}";
const char jwk_privkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD"
                                     "82B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW"
                                     "3bbsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9h"
                                     "Nl5szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK"
                                     "4OPmN6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4"
                                     "GwyfF-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"d\":\"cf9SlRkzf5G1-4nRhlfmMBuVzPF4V87WD"
                                     "NOm0FGS1TkwxigUSIp0ALR0J6tZzKEQ0sqwz4ZipwbHsHHC7WDjsbu5l8mppNqP3ov5lu6VjejUt_9_2aTZrbBynLgUCPLK6VO90v_k7778Nq4lXARI5iQqgZCVyRa6L"
                                     "d2xVTBznBeDs3PprV2x4Sk1p7FHBaYW4mdURE6bWrsBXiJ_qiS8uMTG9fW_0JSAo0jH6obRNRqGvrAzDw3m4-ht-Bicndpq-dhi3tJdsE6wAp8u9X-SSehuTydJxN77-"
                                     "WdguV0DQJcK9Okz7bearhO_Ek8D_8XKPqH-mtYt6nid47APoT3kLNp1v5qiXQ8hLN4N1YM_s7LG44Gtns32Vzs7nwwBnBHAdhUxm5q40twVGXraw6SrTZC1hMpVCgJvp"
                                     "Ta-Ebz8RM7b7Qw142_4BRfi4p2QuOxoxY5ahmKD7xF8MH5307hPCC2-MO8FNe8c5sr4soEj93eFEf9V0UV5YHekopAKHDaS15sSbCIrDk78vFVmO2R6RCa3JKWLhg5Lk"
                                     "V5SeT5u3_TYdQ_3tgpZusuV534DbUV-Ztan2Emu4ds4-icL-SqkXzA_1TvDYtwnMxIWlG07gqTw-BshL2JuY18_8FjVzy4MWB7J8s2GVzJqKT8iY-L4JTJY5cvYsaQkF"
                                     "xRFEc2oE4E\",\"p\":\"AOLIjerOJBuW-Odoq2WSGSRzD5M5i4wwHV88wsNhzLsarB_ebyKwQwEKyalhOAUFTXjUQzg2G8FB9FLPmdgnUukWNCmd4c0pRBKCLNXHQwK"
                                     "uYTHf8lkfn2WchyGGIVQUFbgSdJtN6PGZbRa-26sz4xQgtyiFLerA8shwGl6Q07Sjd6CvRi-NvGqEW2LCz10iNPCqzQYfS0cPWhYXDrIqL_BFTo6A3bU0ifg_NukCvcR"
                                     "KZtlD2FaMCMF5xxfoCMtfXF1Owf_QwCAI5GebTbmLf3BmaCNjlmFm6nR1Vo-17Tk0nq3_rPYGiqLr2ANk8NHeMs6xe1GcWuO_nD1gE6o5QtM\",\"q\":\"APTlzxeo8"
                                     "IINCZulhQyOr3-zBTAtyaHgHQk2-AQYK98Ev6pfBvxwwMzAkSoVpCm1pxyp3JCSyjRSYFd4ibnZDjwd5p8RBfLr_zEnfx-IdUIrY7SyCGaFcKt2jS__4DUZQZu0-3Ysi"
                                     "dK8AECtVr0pa4XifZQnkqWnOeqkZqW1lT1yI8w4NbpCJVAT3ohhhRbTcCLFMhZjmWt5ZGgPz9r251PE-7i-04UvShSevhwdS6YJ3ma4gWhYbDMoADOXFfc5Qr1LxHd1w"
                                     "8LUk20bYTW_yZM8tDZxOQqkGivFW53kcgifzmKYjADNgQQojKO4KhG7xGxqvNrzNJQjM3SPdmUM4ME\",\"qi\":\"DwIv9lrwRP5ptwss0aNKgE1wRaaT8upXvzzlZA"
                                     "uNwolrVhmft_ELSNFuMRv-FCL1BK7YQgBwqux0_iRljvMcRogpeCs7w9DwLpivWyVcJf4PKZZWWlm7_kjIoVxRmNBzZUPpadCTQpAc8uGDtlz6OVgnvnb8FWtYDmHJMy"
                                     "UUdOb5Yxyg98P69pQ9ubPkkRwisDNnujjU3FCdiKZM1W1-l-qGJSHx0L8FEV3pckdOqzejw4jvb0mQroS5_UyeeY5nD93dwyI2faoD6K8xdh_Q1l6yW-7S3z7Z9qTkcP"
                                     "Ikb_BnWE59bAJniLDFx9KCSLMXv-_AhtY8AoGmSwT2rzAFpw\",\"dp\":\"ALDkPIZNOq7miMl_xElatw_OS_TLawTzNsXlkAl0jIvZFy9YghltoSX78yaSNW79HtvD"
                                     "vZbn5ahNuLSrR9XpfmtfLVrU0p8DtBw3u58YaTV7LUcI5nEMEHniqSjGBdMeQ36rrpbBI5Tn1sZqItAcjeBSUGtjzlgRHo6nmnnuv6Nj6ljEvpszFCeFi_6x86syllau"
                                     "83L2D_Kij-MxIv5nl7LzbH4NGGJSU9f1_u-rerfUTPrlR6biXaYERf5ouAtiG5qQZxQSEPor1XTXF75FiCb1Sf9om5DoBLLIH7fC8QGxAKC6EIBqw9Km4XxsTMd2aOz-"
                                     "VTFoIyEIgWcCPPSG648\",\"dq\":\"GW-xJdz3NhrSj6cOfbJoShQ3Cr0Gv1h-y5E5C3vTOrPMkI6UNC4l6F5r9XoP9gEXHWQLM7z7YZnYxd0QOQxxbQ8SAB2Nh6C5f"
                                     "cqDaqwKude14HPJaZSckkKbAYxLJli8NscCg1C28_tw70bRxo4BzAMtVfESS0BmRJfUzYtht-MeEr0X34O1Sm714yZ141wMvp_KxwaLTd1q72AND8orVskT-Clh4Oh7g"
                                     "k7Gojbsv48w2Wx6jHL6sgmKk9Eyh94br3uqKVpC_f6EXYXFgAaukitw8GKsMQ3AZiF2lZy_t2OZ1SXRDNhLeToY-XxMalEdYsFnYjp2kJhjZMzt2CsRQQ\",\"kid\":\"2\"}";

START_TEST(test_rhonabwy_encrypt_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_encrypted(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_encrypted(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_rsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_encrypted(jwt, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_encrypted(jwt, NULL, 0), NULL);
  
  r_jwk_free(jwk_pubkey_rsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_encrypted(jwt, jwk_pubkey_rsa, 0), NULL);
  
  r_jwk_free(jwk_pubkey_rsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_without_set_encrypt_alg)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_encrypted(jwt, NULL, 0), NULL);

  r_jwk_free(jwk_pubkey_rsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt(jwt, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt(jwt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_error_encryption_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt(jwt, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_encryption_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt(jwt, jwk_privkey_rsa, 0), RHN_OK);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_encryption_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt(jwt, jwk_privkey_rsa, 0), RHN_OK);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWT encrypt function tests");
  tc_core = tcase_create("test_rhonabwy_encrypt");
  tcase_add_test(tc_core, test_rhonabwy_encrypt_error);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_with_key_in_serialize);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_without_set_encrypt_alg);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_error_key);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_error_key_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_error_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_error_encryption_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_encryption_ok);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_encryption_with_add_keys_ok);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT encrypt tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
