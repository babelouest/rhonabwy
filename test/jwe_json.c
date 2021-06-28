/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."
#define KID_1 "Raoul"
#define KID_2 "Ernie"
#define KID_3 "Sammy"

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                  "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                  "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                  ",\"e\":\"AQAB\",\"kid\":\""KID_1"\",\"alg\":\"RSA1_5\"}";
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
                                   "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"kid\":\""KID_1"\"}";
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
                                     "k7Gojbsv48w2Wx6jHL6sgmKk9Eyh94br3uqKVpC_f6EXYXFgAaukitw8GKsMQ3AZiF2lZy_t2OZ1SXRDNhLeToY-XxMalEdYsFnYjp2kJhjZMzt2CsRQQ\",\"kid\":"
                                     "\""KID_2"\"}";
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\",\"kid\":\""KID_2"\"}";
const char jwk_key_aesgcm[] = "{\"kty\":\"oct\",\"alg\":\"A128GCMKW\",\"k\":\"ELG-YDhuRKg-6zH2QTR7Tg\",\"kid\":\""KID_3"\"}";
const char jwks_all_privkeys[] = "{\"keys\": ["
"{\"kty\": \"RSA\", \"n\": \"AL9GIadpvuz-_1Xr2xAaZJwhxPqQ_xfanlYta3rg2cgBAryHUtWXlFP_FCGpYoX3kOlnDFpeczdc19Kt5K6YSaC9pTpBa_hT7iAzj8sx-YIx7JbAHXCnjM1LbsTA4_0T--Fv3xC4RtBktH4gjUwe3FDwyr87DyDt6d13wFBLvKKkggO70StGFRQucLY_ZXnSJIzJLdIpZ6H-0FFpaOw2kyS6zT1zxw71i1UtQodauFZvWuGIj6eDRakMJBaIkf59ZMXdgzcGuWea38JjpP6jU26q3PHXXUfdrL7QY0rzOROuoEDkeSyVdxAwFd3VdKhzWMJCLBDWg_yOuqr7fW3dzcU\", \"e\": \"AQAB\", \"d\": \"AKCnAftAGSmrn8CGAg_LazesMWsXP_rEF3tgWMbzdlfDaY35xzw5PU8zjrAbOfI1llRDxh9c9z7Hz0pX3hw7MpQ81TtR2aLQs8_-HsdXKS8OSZ3wrImDYQLJWbcOIC_fig62TNAZRvkfrG3HX4ZQ4VFmfZQSwckxqtzmCPQoOL8NI5x1LolCH9j5FCFLhyePoI6K0fR8OzLmD6CMvFFW-IfrxwdtJn2IlioWIhDUs_OtDIKzSoducYGziPA45OEloT_TcLiseeP_JycOn0aoQTsjpNWBaEtqq8KKHdx3JX4kWLEIE5h8jXaRttwCvdca0FlggfkppUQeWpSQSHdAQaE\", \"p\": \"ANrbmia58Rf3KNyl76GafjR9LFJhdJJFGSwPiRhW0NdPoAuJvklj2rBJu33XKYZ-slZQfZwDswXl1XSzC06IVuCn7znAiEy42m0UKJOZxqx7rDICzCzoYTdAsL29iC4zmXg6zJbYYEaWhdkYVsIanRbDxPGsNsPgqFJ1BGi_vJiN\", \"q\": \"AN-8IgrjQOIRoLjRGH0uQuIHZwSVfPvzEEb0u5MVjBWWa5-7ZoMtI6WeV1_pWdC10zz7MTP3L_ruUQTve2Xp_R0EZlHtOyFe-QYGPNyQn3evwUX-T5tflrFl20wr-c1Czy6ctWbZYrv6cXMpxEhU9JG3WPNgtusdj-Zp5o57CIgZ\", \"qi\": \"AKmHBufGZQ8oarF0w7MwXpBdg9PSIevH9ONrUkWc1ljdSTKRJD2nMqrZqPW32XKnK7bVX6aVV8T3DFLo7BbEmcUnY7inkcNjL_WMU6Zwm1MXsFbjc0yE4rbOLca24YQ4awCXzKOxYjeGcayq7B6BZ23NWVWuEC_ha22YgchfyfMH\", \"dp\": \"PFShD9_eGC8n8ntDrZa7B5kh6Ku4yMGHiN_XeQAlndTzV3rnG7ANDt-kcbIoXkz6uFSD68gRR6TtzLe2fDWVTWS9y3vJluy2Oa9-6AFSBSYqd7bRtedxNRv-HK_spF_RBJWg5ExNbef8ibXt5KAVgbsBxWUly6VYgTKEvqNsR9k\", \"dq\": \"FLVjKULTlJkxGSoxbBTGGAm7XU9A3EkpLogkfH64Ep9zortDx8x7yi6Xw8bji0_pF3HgogC1LjK0yRIph8tapD7uAZNFr9cMkaQuKfQw7nEUIJhjYew9FHprC-feHUObzaKvn69rVh7eNVyeUFucr4ga8Zv4ElcQJLGUp4d3yLE\", \"kid\": \"RSA1_5\", \"alg\": \"RSA1_5\"}"
#if NETTLE_VERSION_NUMBER >= 0x030400
",{\"kty\": \"RSA\", \"n\": \"ALup-Z784fSG10vOGotny1I5G79Mw-MI8eXZmE1sR6d-1APlI3xDY6RBzjYHsmwyKL_Dxp6mkLkyzoom2c2flNwIDGyxXS9zMpBG84kE8jKiMP_N7tG0NkqZ45zJTDBg7VG1kxtcBZj5wuThPPy8SkbcQay9dH7-9u-6n-5suqMWG88YEbPugHbsiAhJ6hopKKX2-8VLJ7w0IMLXAlGXdaLz_6wh5S0KwwpMe0xEyiNCkWWFu9uNyuuR0UZPCZTQSTJssUUgCovnCKV_oS399G7M1k7qzOx0Y7EINvrcuxmpcLm9buAiDSlcn2DHRQNjAt3C3X7agLuquKl-NrG0-OU\", \"e\": \"AQAB\", \"d\": \"WenOl8ZB3I7eiItvXGuWlwaVrMpy8ExQ2fevaSkAC9hQbK1Umy0OiJye2HRHoF9H9tkuSMU1ggY9vyNuJ37WK7YPfeRc6WcgStAzzup3wJrFL0rTqdXWTVf-Hhi0UFmgWw3MNceZRvojztW8CruMOvc84C7FqjMuzR11kx61LX2QD-O3BhrFO7Efqhns3h-5qpCXYklJ0ToCQGatsQYNbXOfU9zTkmTeMmWRLmU0_wV6gLwsG6sjRfEYDwLiLUYnuvB834uqsDnlrecgLdK9DQ1n5IAGmRzp4B0A54PJhc9zw34lUlGcqHOnmkOLbPXP-nyurfQ2CwXTWmot3MD94Q\", \"p\": \"ANJs_no_UeTaA5gVBkj4fl5iSu0Kx7tM39bbelCChlKkB89AoMTm9nd3uZjnY1O6Z00MOcgaWj2cM9tWAmA4fpWcEqY6NeooeQNB1_l0Cp_k7Tn_Ig6IyVXAO12tDWhSzumVQNJI6qJQy-vGcQXMMZ_XTUxhCmCrsCb8ziVKAdhb\", \"q\": \"AORO9XeL8mn9ph8lNkRiVLKR2yHyJJ8HAbAnVpRD6njdpn35ZUfOIXclwFDIwApuYVpX8BQr-jrLUfnZ520HM1UBUMhzIurftRDewbHcXUtHU3ivNLpFYEjcdbPk9VcA1DA918llIkshe1-MKGn_as7WF09qXHPQnaO9RkYt2ze_\", \"qi\": \"HVi7B53n44UC0ny-NFDfRGvM6EyMAZTw4YjWzzQq0WvC25mpWLHsr-fuzijONFO745jh_gMtAU4xofjWL3BmYToQHymzLAJN6QnrgHWXd8a3d3zUoPMVEsIM5YDr_V_Cmg5-kxRQIpmK85LjtLinex0H4_3A8Gt0LpXE9elIHpg\", \"dp\": \"AI8MGVLxiLKSoq7YXBVvGDkBiP3rvivN7r0ZJuVkVfwIFmcGAETa3eIJOdqAMj3REjiGfyFRCNepQHdy2NqgjS0XlHX8THqKWPml4TRrdm2MKtiqYHSQ-I2ayMC9y8eHw7F3DUHm39rIIlh95oeScInAy4OI1I0zKeTXJyyiSu7R\", \"dq\": \"ANfNVrLgQowzKOIJr4jmFT8RJTuqATmcStkx5eGRbMFAac5rfXNpATL5KRZzGysA-N6HfrPiec03QE5VzS2-f6Pa8Xv3cMroF-NRW27-Z-TvD5RksAdd6kwUruETC2BotSjAXAbOpKK1jENdXRoMRu4pabE0TR1f1JHgJ9vQHoVL\", \"kid\": \"RSA-OAEP\", \"alg\": \"RSA-OAEP\"}"
",{\"kty\": \"RSA\", \"n\": \"ANZKK6hNe1e9TwmRuT5Espfu7fslRrE1UmtSv1Xka1u9D75Wqt1flKqCThPaiqPpjbG8LX2zPk_f74vPFK6RvetgOVZOH3hJ3b5du051Dbcdiv_AVM3iWJSCqZyViVOb02Kh7EpXEAnvn2dfQW4ev23QoFx40rBwCW-quO139zoOEDc6WlJdn_DwmrpN0SadZmiMKyJvZlIo6p0BDbWAfj_PG7bGE_CwMmaxIg3rF_zUI2U4K1SQh45Fv2Dtgl_WZlJCEK0qOx2lmzN1wZLZk7M6bt9zW8OGYwHNY1gLSrdBkC_FN7ecbzApJ4QLkSJG1vKvpxLbqSXxPS1DXdGuNrs\", \"e\": \"AQAB\", \"d\": \"GAeHL79IhoU2-La7lAz2De2ACDqc28BD9r73r7UGiOoBevGTBXHzZM9p2_YUt963wed9HmxcH27YGNBm3FCBgIRwyYnHI6D82Zz_JQQhPph0fstddxzbnAOu610lYhfGM3g-2_M5XDPfpyLaXnPaOYE8ikIONjTKChiV1iMuuPaoMZFuaatSaInIDOkhRJfgsFbE3l_z2Z5QwxkWFMWC14a8zRRfElTEGmyWXmoWEMI9xea7Zqtl1XS99PBvJUdNdaPc74lUgh1TDncBU1R6CjoOs5DdzUfRYHN1F2BqfKh7YlnxDKNVPssNsbBFZNsLHVeakYjGws4G6FcRVCudQQ\", \"p\": \"APJdeDaLUa0A-rbr2gtMevJcU7biLHT_77NtsE7VlruMVDovoY7KCoIaB4CyGTP_Y1GwQBc-aHs9OGhIYG2VZWK3ImILIvHbTQ4orvMz3eFlq428kaO4tQ0w_zjmgxegb2efP6a7yML5_MXtpZLT4rtOUASvZyq1im57lJHQVLHb\", \"q\": \"AOJYXFGU5Nyc-ksaG1syreL9FhmSRL8I7PL_vI176r_X5Zpd9koMAR1TSr90rQ26MvgW-eoG8NFP0BYj7ay_5-ENTPJ6GUJhmTK5HzlNQlz35XIzcXgC0akhfPtsJlqN4w1CjOcKPC5HpmPcWP9G9L4Y-ZtP74UJk7gkrEP3s9Sh\", \"qi\": \"AKnu_rJQcJ7vWC1vkzbxeXYva94KQj8Pay58XBABtTK-zuXKwVlwuYltSNaw_PAUvBL-hqx2KTF4z7ktGKCiMcQoCHtDYfQTTcm76Fu3id2i7ymReIu7o4FG_Eau2eYJwVU_Z73JfxPIEM-3ncqQz520R4JFNoW_ewUdIRteSVdd\", \"dp\": \"AOYcBnnK9uYKKwAnl6Lon0aikDzwKoN_SAcUmrOOqQkyJ_oCpSJcA3QY4Iy5C6LJ1HOHoqIu96Yirv6b0SnaESOTesqZhjkZHOTXjZuM4BoTnLj6k1Bdm1CF95v_h_GTupIoqZdVbTxpeyw1AOIR2JA7v09jddEgAen53UpAAVnH\", \"dq\": \"HomhWvhlsEYVltBc5H7_6uIOe0C6ubNwlJBgVg5j66IrPhpzQiZAeD5mlVIejv2SJtqiuSpaj0LfZj1OscHqfPiYaxaCFeypCKjlR4ve6kAf2rqKEpD-zHzSKfG7cvg1q_JQpFNDL1NHZa2y7C4ckxE3i_bK7_4MyglYnIrs3kE\", \"kid\": \"RSA-OAEP-256\", \"alg\": \"RSA-OAEP-256\"}"
",{\"kty\": \"oct\", \"k\": \"wihT-v_265OXyGpOIe62hg\", \"alg\": \"A128KW\", \"kid\": \"A128KW\"}"
",{\"kty\": \"oct\", \"k\": \"OI_6XYApCCn_9R-8GPxOubBPkMNbt3Vd\", \"alg\": \"A192KW\", \"kid\": \"A192KW\"}"
",{\"kty\": \"oct\", \"k\": \"IZ2ifICT03pMCZfqHCtO1vPU1_yhGwZUu3Lt3NPiiow\", \"alg\": \"A256KW\", \"kid\": \"A256KW\"}"
#endif
#if defined(R_ECDH_ENABLED) && GNUTLS_VERSION_NUMBER >= 0x030600
",{\"kty\": \"EC\", \"x\": \"AOJ9FiyptD67tbjYKAXr7sn7TzT5SAtcke5YcZjXbdLy\", \"y\": \"AMSB2nGzT4mCbai0hY_qODr4DaHVD9Gk_oJ9lXGb-TRw\", \"d\": \"esY6_Xtac52F88CHCIAs-b8kG7VYBvN8GV5vTVeUB6Y\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A128KW\", \"alg\": \"ECDH-ES+A128KW\"}"
",{\"kty\": \"EC\", \"x\": \"dQQcQ_TdYVScUzDaMdHUHvGZtfc_piecctF-q4Mz8PQ\", \"y\": \"AND5hLGPJKeEFDl_AQ9JsR5cE-uFUgvLQgPW9BgrluZJ\", \"d\": \"FEmyk5hggKjbm-KAAutCvy4Wp4zOYaux8u5Jt6hks-k\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A192KW\", \"alg\": \"ECDH-ES+A192KW\"}"
",{\"kty\": \"EC\", \"x\": \"AP4C-BLKoo98wrpMSuovvkhV2A7eyXwAw4DSa-Bs724I\", \"y\": \"djnAg_Fqjf9C23WsAI_c7ktV3XweOrfBA5lKzHjV4tw\", \"d\": \"c6-ZFaSrXFhxi0GVjD1DNagk_hwsg7x8BEoh0eT6LmU\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A256KW\", \"alg\": \"ECDH-ES+A256KW\"}"
",{\"kty\": \"OKP\", \"x\": \"AuQ7nbIvxilE4nzzRoS_C_cmpqMx-kcXNkcAyy46fWM\", \"d\": \"-NOCJItqI-R-AFsq1cLNLAIpfIf-otm7x2psH5EXJoo\", \"crv\": \"X25519\", \"kid\": \"ECDH-ES+A256KW-X25519\", \"alg\": \"ECDH-ES+A256KW\"}"
",{\"kty\":\"OKP\",\"d\":\"DFFZ-8-3Q7xEBHV0VVC1JmBL4oMrRo9zDKqLIJF1GEJgNGgrBYY5CrsoZbgs6NOurHTp73o6jhM\",\"crv\":\"X448\",\"x\":\"W46m2SwV-XgAWMqvPQe0KLy_-0CsHhb5r6y11aj7bJBK1F2fvWg02iEsGd5JyA5A3qllofTJwoQ\", \"kid\": \"ECDH-ES+A128KW-X448\", \"alg\": \"ECDH-ES+A128KW\"}"
#endif
",{\"kty\": \"oct\", \"k\": \"r8hh3G0zJct-DF_NAaR5yw\", \"alg\": \"A128GCMKW\", \"kid\": \"A128GCMKW\"}"
#if GNUTLS_VERSION_NUMBER >= 0x03060e
",{\"kty\": \"oct\", \"k\": \"y_x8eBUnma_IgqFEorIaJwCsCdnhQx1Z\", \"alg\": \"A192GCMKW\", \"kid\": \"A192GCMKW\"}"
#endif
",{\"kty\": \"oct\", \"k\": \"LRt4ClEqexrcCTUgywVUlgVnlpXZpKUEhmr9kjVI6mI\", \"alg\": \"A256GCMKW\", \"kid\": \"A256GCMKW\"}"
#if GNUTLS_VERSION_NUMBER >= 0x03060e
",{\"kty\": \"oct\", \"k\": \"4_24kl8FjgZAzoMPp57jLlMCWzegXVJVo1cooIo2cE0\", \"alg\": \"PBES2-HS256+A128KW\", \"kid\": \"PBES2-HS256+A128KW\"}"
",{\"kty\": \"oct\", \"k\": \"Vf0u-vnszx1mVBwscPLgHsaVOpeg47xJseZIIsoxJ80\", \"alg\": \"PBES2-HS384+A192KW\", \"kid\": \"PBES2-HS384+A192KW\"}"
",{\"kty\": \"oct\", \"k\": \"Ckym3KqZnG-VhBPBwffRQGshX4ZldrG9BVDBA4DAPw0\", \"alg\": \"PBES2-HS512+A256KW\", \"kid\": \"PBES2-HS512+A256KW\"}"
#endif
"]}";
const char jwks_all_pubkeys[] = "{\"keys\": ["
"{\"kty\": \"RSA\", \"n\": \"AL9GIadpvuz-_1Xr2xAaZJwhxPqQ_xfanlYta3rg2cgBAryHUtWXlFP_FCGpYoX3kOlnDFpeczdc19Kt5K6YSaC9pTpBa_hT7iAzj8sx-YIx7JbAHXCnjM1LbsTA4_0T--Fv3xC4RtBktH4gjUwe3FDwyr87DyDt6d13wFBLvKKkggO70StGFRQucLY_ZXnSJIzJLdIpZ6H-0FFpaOw2kyS6zT1zxw71i1UtQodauFZvWuGIj6eDRakMJBaIkf59ZMXdgzcGuWea38JjpP6jU26q3PHXXUfdrL7QY0rzOROuoEDkeSyVdxAwFd3VdKhzWMJCLBDWg_yOuqr7fW3dzcU\", \"e\": \"AQAB\", \"kid\": \"RSA1_5\", \"alg\": \"RSA1_5\"}"
#if NETTLE_VERSION_NUMBER >= 0x030400
",{\"kty\": \"RSA\", \"n\": \"ALup-Z784fSG10vOGotny1I5G79Mw-MI8eXZmE1sR6d-1APlI3xDY6RBzjYHsmwyKL_Dxp6mkLkyzoom2c2flNwIDGyxXS9zMpBG84kE8jKiMP_N7tG0NkqZ45zJTDBg7VG1kxtcBZj5wuThPPy8SkbcQay9dH7-9u-6n-5suqMWG88YEbPugHbsiAhJ6hopKKX2-8VLJ7w0IMLXAlGXdaLz_6wh5S0KwwpMe0xEyiNCkWWFu9uNyuuR0UZPCZTQSTJssUUgCovnCKV_oS399G7M1k7qzOx0Y7EINvrcuxmpcLm9buAiDSlcn2DHRQNjAt3C3X7agLuquKl-NrG0-OU\", \"e\": \"AQAB\", \"kid\": \"RSA-OAEP\", \"alg\": \"RSA-OAEP\"}"
",{\"kty\": \"RSA\", \"n\": \"ANZKK6hNe1e9TwmRuT5Espfu7fslRrE1UmtSv1Xka1u9D75Wqt1flKqCThPaiqPpjbG8LX2zPk_f74vPFK6RvetgOVZOH3hJ3b5du051Dbcdiv_AVM3iWJSCqZyViVOb02Kh7EpXEAnvn2dfQW4ev23QoFx40rBwCW-quO139zoOEDc6WlJdn_DwmrpN0SadZmiMKyJvZlIo6p0BDbWAfj_PG7bGE_CwMmaxIg3rF_zUI2U4K1SQh45Fv2Dtgl_WZlJCEK0qOx2lmzN1wZLZk7M6bt9zW8OGYwHNY1gLSrdBkC_FN7ecbzApJ4QLkSJG1vKvpxLbqSXxPS1DXdGuNrs\", \"e\": \"AQAB\", \"kid\": \"RSA-OAEP-256\", \"alg\": \"RSA-OAEP-256\"}"
",{\"kty\": \"oct\", \"k\": \"wihT-v_265OXyGpOIe62hg\", \"alg\": \"A128KW\", \"kid\": \"A128KW\"}"
",{\"kty\": \"oct\", \"k\": \"OI_6XYApCCn_9R-8GPxOubBPkMNbt3Vd\", \"alg\": \"A192KW\", \"kid\": \"A192KW\"}"
",{\"kty\": \"oct\", \"k\": \"IZ2ifICT03pMCZfqHCtO1vPU1_yhGwZUu3Lt3NPiiow\", \"alg\": \"A256KW\", \"kid\": \"A256KW\"}"
#endif
#if defined(R_ECDH_ENABLED) && GNUTLS_VERSION_NUMBER >= 0x030600
",{\"kty\": \"EC\", \"x\": \"AOJ9FiyptD67tbjYKAXr7sn7TzT5SAtcke5YcZjXbdLy\", \"y\": \"AMSB2nGzT4mCbai0hY_qODr4DaHVD9Gk_oJ9lXGb-TRw\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A128KW\", \"alg\": \"ECDH-ES+A128KW\"}"
",{\"kty\": \"EC\", \"x\": \"dQQcQ_TdYVScUzDaMdHUHvGZtfc_piecctF-q4Mz8PQ\", \"y\": \"AND5hLGPJKeEFDl_AQ9JsR5cE-uFUgvLQgPW9BgrluZJ\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A192KW\", \"alg\": \"ECDH-ES+A192KW\"}"
",{\"kty\": \"EC\", \"x\": \"AP4C-BLKoo98wrpMSuovvkhV2A7eyXwAw4DSa-Bs724I\", \"y\": \"djnAg_Fqjf9C23WsAI_c7ktV3XweOrfBA5lKzHjV4tw\", \"crv\": \"P-256\", \"kid\": \"ECDH-ES+A256KW\", \"alg\": \"ECDH-ES+A256KW\"}"
",{\"kty\": \"OKP\", \"x\": \"AuQ7nbIvxilE4nzzRoS_C_cmpqMx-kcXNkcAyy46fWM\", \"crv\": \"X25519\", \"kid\": \"ECDH-ES+A256KW-X25519\", \"alg\": \"ECDH-ES+A256KW\"}"
",{\"kty\":\"OKP\",\"crv\":\"X448\",\"x\":\"W46m2SwV-XgAWMqvPQe0KLy_-0CsHhb5r6y11aj7bJBK1F2fvWg02iEsGd5JyA5A3qllofTJwoQ\", \"kid\": \"ECDH-ES+A128KW-X448\", \"alg\": \"ECDH-ES+A128KW\"}"
#endif
",{\"kty\": \"oct\", \"k\": \"r8hh3G0zJct-DF_NAaR5yw\", \"alg\": \"A128GCMKW\", \"kid\": \"A128GCMKW\"}"
#if GNUTLS_VERSION_NUMBER >= 0x03060e
",{\"kty\": \"oct\", \"k\": \"y_x8eBUnma_IgqFEorIaJwCsCdnhQx1Z\", \"alg\": \"A192GCMKW\", \"kid\": \"A192GCMKW\"}"
#endif
",{\"kty\": \"oct\", \"k\": \"LRt4ClEqexrcCTUgywVUlgVnlpXZpKUEhmr9kjVI6mI\", \"alg\": \"A256GCMKW\", \"kid\": \"A256GCMKW\"}"
#if GNUTLS_VERSION_NUMBER >= 0x03060e
",{\"kty\": \"oct\", \"k\": \"4_24kl8FjgZAzoMPp57jLlMCWzegXVJVo1cooIo2cE0\", \"alg\": \"PBES2-HS256+A128KW\", \"kid\": \"PBES2-HS256+A128KW\"}"
",{\"kty\": \"oct\", \"k\": \"Vf0u-vnszx1mVBwscPLgHsaVOpeg47xJseZIIsoxJ80\", \"alg\": \"PBES2-HS384+A192KW\", \"kid\": \"PBES2-HS384+A192KW\"}"
",{\"kty\": \"oct\", \"k\": \"Ckym3KqZnG-VhBPBwffRQGshX4ZldrG9BVDBA4DAPw0\", \"alg\": \"PBES2-HS512+A256KW\", \"kid\": \"PBES2-HS512+A256KW\"}"
#endif
"]}";

#define JWE_FLATTENED "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_INVALID_JSON "error\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_PROTECTED "{\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_ENCRYPTED_KEY "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_IV "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_TAG "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_HEADER "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_ALG "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_MISSING_UNPROTECTED "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\"}"
#define JWE_FLATTENED_MISSING_AAD "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_INVALID_ENC_KEY "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_INVALID_CIPHERTEXT "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7xAqonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpcCBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_FLATTENED_INVALID_AAD "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"encrypted_key\":\"63FSVQ9eI9WjN_8j9T0cd6irn_lX0_gO_2bLKmHc61Za8S3QW9VwYA\",\"iv\":\"deU9T1k-_6ohC0sGnnNLlA\",\"ciphertext\":\"ejhwuqZ9JMdTTWAv7x0qonqICYsgAFOgtB6CAt-xy5frcW0AGZ2UUlLqO6KXdNOHpL6ldakzEB-Luxpb8UAZvw\",\"tag\":\"Qojttvz7NaOc1Rvnv6w4Rg\",\"header\":{\"alg\":\"A128KW\",\"kid\":\"Ernie\"},\"aad\":\"RnJpZW5kc2hpACBpcyBtYWdpYwo\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"

#define JWE_GENERAL "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_INVALID_JSON "error\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_MISSING_PROTECTED "{,\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_MISSING_IV "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_MISSING_CIPERTEXT "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_MISSING_TAG "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_MISSING_RECIPIENTS "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_EMPTY_RECIPIENTS "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_INVALID_CIPHERTEXT "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoaxAfnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_INVALID_TAG "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"KEeKAKbyG5_pHY0fon9a_A\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFpXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"
#define JWE_GENERAL_INVALID_AAD "{\"protected\":\"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0\",\"iv\":\"7faJWH0jrt1UcLMOPqCdcw\",\"ciphertext\":\"_9g8VmWcBlFEoax1fnLnNn2qgEsA15mBdIhwUS3biplvZjhJg1VRS6vCMib9E_Plrxi6G0PpnuvXfLeyuS2UOg\",\"tag\":\"YPFqTge_86Z3H-LU4AiccQ\",\"recipients\":[{\"encrypted_key\":\"3LuKb2XteFqe7oUlO5pmhsBLEOEH7RO5O1nLAWB6QpzycTW0ZD8A-g\",\"header\":{\"alg\":\"A128KW\"}},{\"encrypted_key\":\"VNBaXwpcZJEo1rgJ2_ZjGvIDbtJHggbILhgpJGyugF4gV584yhdQAXlOXV45VYcnPDrKOlVORS6S_xtw9JyuPoW8a09fHpkSqLzJKEBoKOpci99DZ4DUtpDMNqbR8YITpJhl5OY5fY8HLunlOlqR4JkItEZgBmN5Fzj_R_JBWTtZetd2ABeRKi_sofe2RxzQ7rx462g3YKHq7kU-murXw6CMqMtEx8SEwyyOAFOJ73SaAvalANSv2B_vcx5pXzariZRewZt79iJPKRPrdlm4vTc6bRJPKeniuBQJhEFMjNI-CzWambqrsihR_8JR82gBA0VFL-z2cWZhfXMpwX6vfw\",\"header\":{\"alg\":\"RSA1_5\"}},{\"encrypted_key\":\"1CpSZufVImvW5dl2gDBJS1VTjiBjE8RdEUQDhalEd58\",\"header\":{\"iv\":\"rGr-JToZe-Wpawrs\",\"tag\":\"_7pHIdTPXbG4ZZzdE6O_tw\",\"alg\":\"A128GCMKW\"}}],\"aad\":\"Um5KcFAXNWtjMmhwY0NCcGN5QnRZV2RwWXdv\",\"unprotected\":{\"jku\":\"https://equestria.tld/magic-keys.jwks\"}}"

unsigned char aad[] = {70, 114, 105, 101, 110, 100, 115, 104, 105, 112, 32, 105, 115, 32, 109, 97, 103, 105, 99, 10};

void test_rhonabwy_json_flattened_all_algs(jwa_enc enc) {
  jwe_t * jwe, * jwe_decrypt;
  jwks_t * jwks_pub, * jwks_priv, * jwks_cur;
  jwk_t * jwk, * jwk_decrypt;
  json_t * j_result, * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  size_t i;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_priv), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks_priv, jwks_all_privkeys), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks_pub, jwks_all_pubkeys), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_aad(jwe, aad, sizeof(aad)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, enc), RHN_OK);

  for (i=0; i<r_jwks_size(jwks_pub); i++) {
    ck_assert_int_eq(r_jwks_init(&jwks_cur), RHN_OK);
    jwk = r_jwks_get_at(jwks_pub, i);
    y_log_message(Y_LOG_LEVEL_DEBUG, "Test flattened, key %s", r_jwk_get_property_str(jwk, "kid"));
    ck_assert_int_eq(r_jwks_append_jwk(jwks_cur, jwk), RHN_OK);
    ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, jwks_cur, 0, R_JSON_MODE_FLATTENED));
    ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
    ck_assert_int_eq(r_jwe_add_jwks(jwe_decrypt, jwks_priv, NULL), RHN_OK);
    ck_assert_int_eq(r_jwe_parse_json_t(jwe_decrypt, j_result, 0), RHN_OK);
    ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
    ck_assert_ptr_ne(NULL, jwk_decrypt = r_jwks_get_by_kid(jwks_priv, r_jwk_get_property_str(jwk, "kid")));
    ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_decrypt, 0), RHN_OK);
    
    json_decref(j_result);
    r_jwe_free(jwe_decrypt);
    r_jwk_free(jwk_decrypt);
    r_jwk_free(jwk);
    r_jwks_free(jwks_cur);
  }

  r_jwks_free(jwks_priv);
  r_jwks_free(jwks_pub);
  r_jwe_free(jwe);
  json_decref(j_un_header);
}

void test_rhonabwy_json_general_all_algs(jwa_enc enc)
{
  jwe_t * jwe, * jwe_decrypt;
  jwks_t * jwks_pub, * jwks_priv;
  jwk_t * jwk;
  json_t * j_result, * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  size_t i;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_priv), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks_priv, jwks_all_privkeys), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_str(jwks_pub, jwks_all_pubkeys), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_aad(jwe, aad, sizeof(aad)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, enc), RHN_OK);

  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, jwks_pub, 0, R_JSON_MODE_GENERAL));
  ck_assert_int_eq(json_array_size(json_object_get(j_result, "recipients")), r_jwks_size(jwks_pub));
  ck_assert_int_eq(r_jwe_parse_json_t(jwe_decrypt, j_result, 0), RHN_OK);
  
  for (i=0; i<r_jwks_size(jwks_priv); i++) {
    jwk = r_jwks_get_at(jwks_priv, i);
    y_log_message(Y_LOG_LEVEL_DEBUG, "Test general, key %s", r_jwk_get_property_str(jwk, "kid"));
    ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
    ck_assert_int_eq(r_jwk_delete_property_str(jwk, "kid"), RHN_OK);
    ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk, 0), RHN_OK);
    r_jwk_free(jwk);
  }

  r_jwks_free(jwks_priv);
  r_jwks_free(jwks_pub);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
  json_decref(j_un_header);
  json_decref(j_result);
}

START_TEST(test_rhonabwy_json_flattened_error)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_key_symmetric_str), RHN_OK);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_ok)
{
  jwe_t * jwe;
  json_t * j_result, * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_key_symmetric_str), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "encrypted_key"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  //ck_assert_ptr_ne(NULL, json_object_get(j_result, "header"));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  ck_assert_int_eq(r_jwe_set_aad(jwe, aad, sizeof(aad)), RHN_OK);
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "encrypted_key"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  //ck_assert_ptr_ne(NULL, json_object_get(j_result, "header"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "encrypted_key"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  //ck_assert_ptr_ne(NULL, json_object_get(j_result, "header"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  r_jwe_free(jwe);
  json_decref(j_un_header);
}
END_TEST

START_TEST(test_rhonabwy_json_parse_flattened_error)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_INVALID_JSON, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_PROTECTED, 0), RHN_ERROR_PARAM);
  //ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_ENCRYPTED_KEY, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_TAG, 0), RHN_ERROR_PARAM);
  //ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_HEADER, 0), RHN_ERROR_PARAM);
  //ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_ALG, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_parse_flattened_ok)
{
  jwe_t * jwe;
  size_t len = 0;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A128CBC);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_A128KW);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_UNPROTECTED, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A128CBC);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_A128KW);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_MISSING_AAD, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A128CBC);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_A128KW);
  ck_assert_ptr_ne(NULL, r_jwe_get_iv(jwe, &len));
  ck_assert_int_eq(16, len);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_flattened_invalid_key)
{
  jwe_t * jwe;
  const char jwk_invalid_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"AAECAwQABgcICQoLDA0ODw\",\"kid\":\""KID_2"\"}";
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_invalid_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_flattened_invalid_key_specified)
{
  jwe_t * jwe;
  const char jwk_invalid_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"A128KW\",\"k\":\"AAECAwQABgcICQoLDA0ODw\",\"kid\":\""KID_2"\"}";
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_invalid_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);
  
  r_jwe_free(jwe);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_flattened_invalid_decryption)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_INVALID_ENC_KEY, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_INVALID_CIPHERTEXT, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED_INVALID_AAD, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_flattened_ok)
{
  jwe_t * jwe;
  const unsigned char * payload;
  size_t payload_len;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_FLATTENED, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jwe_get_payload(jwe, &payload_len));
  ck_assert_int_eq(o_strlen(PAYLOAD), payload_len);
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, payload_len));
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_general_error)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(NULL, r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_key_symmetric_str), RHN_OK);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_general_ok)
{
  jwe_t * jwe;
  json_t * j_result, * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, NULL, jwk_key_aesgcm), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "recipients"));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), json_array_size(json_object_get(j_result, "recipients")));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  ck_assert_int_eq(r_jwe_set_aad(jwe, aad, sizeof(aad)), RHN_OK);
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "recipients"));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), json_array_size(json_object_get(j_result, "recipients")));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_eq(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_ptr_ne(NULL, j_result = r_jwe_serialize_json_t(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "protected"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "iv"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "ciphertext"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "tag"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "recipients"));
  ck_assert_int_eq(r_jwks_size(jwe->jwks_pubkey), json_array_size(json_object_get(j_result, "recipients")));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "aad"));
  ck_assert_ptr_ne(NULL, json_object_get(j_result, "unprotected"));
  json_decref(j_result);
  
  r_jwe_free(jwe);
  json_decref(j_un_header);
}
END_TEST

START_TEST(test_rhonabwy_json_parse_general_error)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_INVALID_JSON, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_MISSING_PROTECTED, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_MISSING_IV, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_MISSING_CIPERTEXT, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_MISSING_TAG, 0), RHN_ERROR_PARAM);
  //ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_MISSING_RECIPIENTS, 0), RHN_ERROR_PARAM);
  //ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_EMPTY_RECIPIENTS, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_parse_general_ok)
{
  jwe_t * jwe;
  size_t len = 0;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_UNKNOWN);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_UNKNOWN);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_get_enc(jwe), R_JWA_ENC_A128CBC);
  ck_assert_int_eq(r_jwe_get_alg(jwe), R_JWA_ALG_UNKNOWN);
  ck_assert_ptr_ne(NULL, r_jwe_get_iv(jwe, &len));
  ck_assert_int_eq(16, len);
  
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_general_invalid_key)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_privkey_rsa_str_2, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);

  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_general_invalid_key_specified)
{
  jwe_t * jwe;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_ERROR_INVALID);

  r_jwk_free(jwk);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_general_invalid_decryption)
{
  jwe_t * jwe;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_INVALID_CIPHERTEXT, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_INVALID_TAG, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL_INVALID_AAD, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_ERROR_INVALID);

  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_general_ok)
{
  jwe_t * jwe;
  const unsigned char * payload;
  size_t payload_len;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jwe_get_payload(jwe, &payload_len));
  ck_assert_int_eq(o_strlen(PAYLOAD), payload_len);
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, payload_len));

  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_decrypt_general_without_kid_ok)
{
  jwe_t * jwe;
  jwk_t * jwk;
  const unsigned char * payload;
  size_t payload_len;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, "kid"), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, JWE_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jwe_get_payload(jwe, &payload_len));
  ck_assert_int_eq(o_strlen(PAYLOAD), payload_len);
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, payload_len));

  r_jwk_free(jwk);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_flood)
{
  jwe_t * jwe;
  json_t * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  char * str_result;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, jwk_key_symmetric_str), RHN_OK);
  
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  o_free(str_result);
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_FLATTENED));
  o_free(str_result);
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_FLATTENED));

  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  
  json_decref(j_un_header);
  o_free(str_result);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_general_flood)
{
  jwe_t * jwe;
  json_t * j_un_header = json_pack("{ss}", "jku", "https://equestria.tld/magic-keys.jwks");
  char * str_result;
  
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_full_unprotected_header_json_t(jwe, j_un_header), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_symmetric_str, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys_json_str(jwe, jwk_key_aesgcm, jwk_key_aesgcm), RHN_OK);
  
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  o_free(str_result);
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_GENERAL));
  o_free(str_result);
  ck_assert_ptr_ne(NULL, str_result = r_jwe_serialize_json_str(jwe, NULL, 0, R_JSON_MODE_GENERAL));

  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_parse_json_str(jwe, str_result, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  
  json_decref(j_un_header);
  o_free(str_result);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_all_algs_cbc)
{
  test_rhonabwy_json_flattened_all_algs(R_JWA_ENC_A128CBC);
}
END_TEST

START_TEST(test_rhonabwy_json_general_all_algs_cbc)
{
  test_rhonabwy_json_general_all_algs(R_JWA_ENC_A128CBC);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_all_algs_gcm)
{
  test_rhonabwy_json_flattened_all_algs(R_JWA_ENC_A128GCM);
}
END_TEST

START_TEST(test_rhonabwy_json_general_all_algs_gcm)
{
  test_rhonabwy_json_general_all_algs(R_JWA_ENC_A128GCM);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE JSON function tests");
  tc_core = tcase_create("test_rhonabwy_json");
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_error);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_parse_flattened_error);
  tcase_add_test(tc_core, test_rhonabwy_json_parse_flattened_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_flattened_invalid_key);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_flattened_invalid_key_specified);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_flattened_invalid_decryption);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_flattened_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_general_error);
  tcase_add_test(tc_core, test_rhonabwy_json_general_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_parse_general_error);
  tcase_add_test(tc_core, test_rhonabwy_json_parse_general_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_general_invalid_key);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_general_invalid_key_specified);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_general_invalid_decryption);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_general_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_decrypt_general_without_kid_ok);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_flood);
  tcase_add_test(tc_core, test_rhonabwy_json_general_flood);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_all_algs_cbc);
  tcase_add_test(tc_core, test_rhonabwy_json_general_all_algs_cbc);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_all_algs_gcm);
  tcase_add_test(tc_core, test_rhonabwy_json_general_all_algs_gcm);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE JSON tests");
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
