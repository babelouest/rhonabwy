/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define TOKEN_SE "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0fxe50Bk7-aDFHa-VUl2XX-drlp-Uhl8e3k6HYR_nhSo8CwsNzqJV_LQON2NomLlLFWz4EBSAYONuFjMxe_xWS2zZ3V7EEdHAcwsfbWiT0vope5MQyYYVRMnxbuO7y0ItaCJQ1Q8oSk7NRkugQlE7eP-DVTUVsFg8w-v9ujy6cMLDSwvjMog_PmjPDbmKRgVwWzi5vkRN8MUmkwthIJg6wnNACt6wpWusoeiSIuJErCqDdULxbI1GvQTNXSFoikieyv8wA1iJi2hg103hHj9X6lBNSV8EHvuhPMDfvg4bwl_dVU-7GXCnssHtMZ6VgcY_BF_GRg15pBhBn8ZPyia8Q.Zc27WaSxQA9dtV1PwB_KHQ.Le464stBKFU5w2GYyFEMVPZkearSVCjEJZkHnNP81h3sQpt3_eVXZnGjcTs95N4HzU5B_ww7Lz80FOQ3YgEnHCmkZoxlk6v6ft7JXrxc62D4Q0W1EgBKnwvERslxSaPEm8jMa_5UEREt1ZIybTEJTKxrv4BOxm89RLLqygb43YLShCkl0F-ovsJIEqURHXvtQRfAQFeZ5OCIDhiqk_na75cHBuTlX_E0rWKSuPa2gr7KbsO5F_AZNP8sUAvsJ9WF.bhS9EYK23TsV1EpdOvLT2w"
#define TOKEN_SE_INVALID_HEADER_B64 ";error;.0fxe50Bk7-aDFHa-VUl2XX-drlp-Uhl8e3k6HYR_nhSo8CwsNzqJV_LQON2NomLlLFWz4EBSAYONuFjMxe_xWS2zZ3V7EEdHAcwsfbWiT0vope5MQyYYVRMnxbuO7y0ItaCJQ1Q8oSk7NRkugQlE7eP-DVTUVsFg8w-v9ujy6cMLDSwvjMog_PmjPDbmKRgVwWzi5vkRN8MUmkwthIJg6wnNACt6wpWusoeiSIuJErCqDdULxbI1GvQTNXSFoikieyv8wA1iJi2hg103hHj9X6lBNSV8EHvuhPMDfvg4bwl_dVU-7GXCnssHtMZ6VgcY_BF_GRg15pBhBn8ZPyia8Q.Zc27WaSxQA9dtV1PwB_KHQ.Le464stBKFU5w2GYyFEMVPZkearSVCjEJZkHnNP81h3sQpt3_eVXZnGjcTs95N4HzU5B_ww7Lz80FOQ3YgEnHCmkZoxlk6v6ft7JXrxc62D4Q0W1EgBKnwvERslxSaPEm8jMa_5UEREt1ZIybTEJTKxrv4BOxm89RLLqygb43YLShCkl0F-ovsJIEqURHXvtQRfAQFeZ5OCIDhiqk_na75cHBuTlX_E0rWKSuPa2gr7KbsO5F_AZNP8sUAvsJ9WF.bhS9EYK23TsV1EpdOvLT2w"
#define TOKEN_SE_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0fxe50Bk7-aDFHa-VUl2XX-drlp-Uhl8e3k6HYR_nhSo8CwsNzqJV_LQON2NomLlLFWz4EBSAYONuFjMxe_xWS2zZ3V7EEdHAcwsfbWiT0vope5MQyYYVRMnxbuO7y0ItaCJQ1Q8oSk7NRkugQlE7eP-DVTUVsFg8w-v9ujy6cMLDSwvjMog_PmjPDbmKRgVwWzi5vkRN8MUmkwthIJg6wnNACt6wpWusoeiSIuJErCqDdULxbI1GvQTNXSFoikieyv8wA1iJi2hg103hHj9X6lBNSV8EHvuhPMDfvg4bwl_dVU-7GXCnssHtMZ6VgcY_BF_GRg15pBhBn8ZPyia8Q.Zc27WaSxQA9dtV1PwB_KHQ.;error;.bhS9EYK23TsV1EpdOvLT2w"
#define TOKEN_SE_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In00fxe50Bk7-aDFHa-VUl2XX-drlp-Uhl8e3k6HYR_nhSo8CwsNzqJV_LQON2NomLlLFWz4EBSAYONuFjMxe_xWS2zZ3V7EEdHAcwsfbWiT0vope5MQyYYVRMnxbuO7y0ItaCJQ1Q8oSk7NRkugQlE7eP-DVTUVsFg8w-v9ujy6cMLDSwvjMog_PmjPDbmKRgVwWzi5vkRN8MUmkwthIJg6wnNACt6wpWusoeiSIuJErCqDdULxbI1GvQTNXSFoikieyv8wA1iJi2hg103hHj9X6lBNSV8EHvuhPMDfvg4bwl_dVU-7GXCnssHtMZ6VgcY_BF_GRg15pBhBn8ZPyia8Q.Zc27WaSxQA9dtV1PwB_KHQ.Le464stBKFU5w2GYyFEMVPZkearSVCjEJZkHnNP81h3sQpt3_eVXZnGjcTs95N4HzU5B_ww7Lz80FOQ3YgEnHCmkZoxlk6v6ft7JXrxc62D4Q0W1EgBKnwvERslxSaPEm8jMa_5UEREt1ZIybTEJTKxrv4BOxm89RLLqygb43YLShCkl0F-ovsJIEqURHXvtQRfAQFeZ5OCIDhiqk_na75cHBuTlX_E0rWKSuPa2gr7KbsO5F_AZNP8sUAvsJ9WF.bhS9EYK23TsV1EpdOvLT2w"
#define TOKEN_SE_INVALID_ENCRYPTION "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0fxe50Bk7-aDFHa-VUl2XX-drlp-Uhl8e3k6HYR_nhSo8CwsNzqJV_LQON2NomLlLFWz4EBSAYONuFjMxe_xWS2zZ3V7EEdHAcwsfbWiT0vope5MQyYYVRMnxbuO7y0ItaCJQ1Q8oSk7NRkugQlE7eP-DVTUVsFg8w-v9ujy6cMLDSwvjMog_PmjPDbmKRgVwWzi5vkRN8MUmkwthIJg6wnNACt6wpWusoeiSIuJErCqDdULxbI1GvQTNXSFoikieyv8wA1iJi2hg103hHj9X6lBNSV8EHvuhPMDfvg4bwl_dVU-7GXCnssHtMZ6VgcY_BF_GRg15pBhBn8ZPyia8Q.Zc27WaSxQA9dtV1PwB_KHQ.Le464stBKFU5w2GYyFEMVPZkearSVCjEJZkHnNP81h3sQpt3_eVXZnGjcTs95N4HzU5B_ww7Lz80FOQ3YgEnHCmkZoxlk6v6ft7JXrxc62D4Q0W1EgBKnwvERslxSaPEm8jMa_5UEREt1ZIybTEJTKxrv4BOxm89RLLqygb43YLShCkl0F-ovsJIEqURHXvtQRfAQFeZ5OCIDhiqk_na75cHBuTlX_E0rWKSuPa2gr7KbsO5F_AZNP8sUAv4J9WF.bhS9EYK23TsV1EpdOvLT2w"
#define TOKEN_ES "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4wSVFVY2Jva2tRVF9wTnJOR3lSRzdCSnBxdzh2UW8yZTJTcnFxaEh5anlDekVQdDBvU3VUeVFYODVUM1RLc1R1SXVqTHJCU2s3Xy0zc0VKU0o3VjFHUjU3M25oRHRrdk5PS2lDbEZYQnJZQmhuTmdldjBOTHBSRGNrdXprZ1pROEJqVTRVOXpIbmE0emx2ejJ5S2hpSjEtQzVnLW54WmVXYjJBalV1Rmc3VEpyclRnNmQ0OHM2WDMtem1NVjk1ZC1pcU11aUE3eURablAzNl9MT0UzYnhIbmg0cWg3QnNBMHIxOTJEdklEZGdCcUlVT2ZTREIzejgyQmFoTXdsOF9Hcks0ZDBySjZseG1JdFZ5WDhHZmMzSXFwOEdVWmVJTGRkN0x6LUJESmVzdzhyaTRUMXpjWVVKOE1WUXpuVjE1LVhhemFKOGRHbHVhdFpXbm52MERpT1EuU3FwQ1lSbFBjOWY4cEdhU2p3cDhhUS5WX2h2MWlMMV9KeHFnTXlKNkdVZmZjUHpaVnJCb0t3Vmc2WTZveldqbnlTU0J6V3pJWjlYQkVRTGpudEdzbEdVLkMxSk9pNklpbmMxalJCT1ZGbnYtNHc.Qjd4J4094NIpZLTfD2tlp4QEpvUTolUXreu14AsvizTBUTEx2bIF4FMlhMVfJ285PwLG-NST3pzq9CAwLxXy-g"
#define TOKEN_ES_INVALID_HEADER_B64 ";error;.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4wSVFVY2Jva2tRVF9wTnJOR3lSRzdCSnBxdzh2UW8yZTJTcnFxaEh5anlDekVQdDBvU3VUeVFYODVUM1RLc1R1SXVqTHJCU2s3Xy0zc0VKU0o3VjFHUjU3M25oRHRrdk5PS2lDbEZYQnJZQmhuTmdldjBOTHBSRGNrdXprZ1pROEJqVTRVOXpIbmE0emx2ejJ5S2hpSjEtQzVnLW54WmVXYjJBalV1Rmc3VEpyclRnNmQ0OHM2WDMtem1NVjk1ZC1pcU11aUE3eURablAzNl9MT0UzYnhIbmg0cWg3QnNBMHIxOTJEdklEZGdCcUlVT2ZTREIzejgyQmFoTXdsOF9Hcks0ZDBySjZseG1JdFZ5WDhHZmMzSXFwOEdVWmVJTGRkN0x6LUJESmVzdzhyaTRUMXpjWVVKOE1WUXpuVjE1LVhhemFKOGRHbHVhdFpXbm52MERpT1EuU3FwQ1lSbFBjOWY4cEdhU2p3cDhhUS5WX2h2MWlMMV9KeHFnTXlKNkdVZmZjUHpaVnJCb0t3Vmc2WTZveldqbnlTU0J6V3pJWjlYQkVRTGpudEdzbEdVLkMxSk9pNklpbmMxalJCT1ZGbnYtNHc.Qjd4J4094NIpZLTfD2tlp4QEpvUTolUXreu14AsvizTBUTEx2bIF4FMlhMVfJ285PwLG-NST3pzq9CAwLxXy-g"
#define TOKEN_ES_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.;error;.Qjd4J4094NIpZLTfD2tlp4QEpvUTolUXreu14AsvizTBUTEx2bIF4FMlhMVfJ285PwLG-NST3pzq9CAwLxXy-g"
#define TOKEN_ES_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4wSVFVY2Jva2tRVF9wTnJOR3lSRzdCSnBxdzh2UW8yZTJTcnFxaEh5anlDekVQdDBvU3VUeVFYODVUM1RLc1R1SXVqTHJCU2s3Xy0zc0VKU0o3VjFHUjU3M25oRHRrdk5PS2lDbEZYQnJZQmhuTmdldjBOTHBSRGNrdXprZ1pROEJqVTRVOXpIbmE0emx2ejJ5S2hpSjEtQzVnLW54WmVXYjJBalV1Rmc3VEpyclRnNmQ0OHM2WDMtem1NVjk1ZC1pcU11aUE3eURablAzNl9MT0UzYnhIbmg0cWg3QnNBMHIxOTJEdklEZGdCcUlVT2ZTREIzejgyQmFoTXdsOF9Hcks0ZDBySjZseG1JdFZ5WDhHZmMzSXFwOEdVWmVJTGRkN0x6LUJESmVzdzhyaTRUMXpjWVVKOE1WUXpuVjE1LVhhemFKOGRHbHVhdFpXbm52MERpT1EuU3FwQ1lSbFBjOWY4cEdhU2p3cDhhUS5WX2h2MWlMMV9KeHFnTXlKNkdVZmZjUHpaVnJCb0t3Vmc2WTZveldqbnlTU0J6V3pJWjlYQkVRTGpudEdzbEdVLkMxSk9pNklpbmMxalJCT1ZGbnYtNHc.Qjd4J4094NIpZLTfD2tlp4QEpvUTolUXreu14AsvizTBUTEx2bIF4FMlhMVfJ285PwLG-NST3pzq9CAwLxXy-g"
#define TOKEN_ES_INVALID_SIGNATURE "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC4wSVFVY2Jva2tRVF9wTnJOR3lSRzdCSnBxdzh2UW8yZTJTcnFxaEh5anlDekVQdDBvU3VUeVFYODVUM1RLc1R1SXVqTHJCU2s3Xy0zc0VKU0o3VjFHUjU3M25oRHRrdk5PS2lDbEZYQnJZQmhuTmdldjBOTHBSRGNrdXprZ1pROEJqVTRVOXpIbmE0emx2ejJ5S2hpSjEtQzVnLW54WmVXYjJBalV1Rmc3VEpyclRnNmQ0OHM2WDMtem1NVjk1ZC1pcU11aUE3eURablAzNl9MT0UzYnhIbmg0cWg3QnNBMHIxOTJEdklEZGdCcUlVT2ZTREIzejgyQmFoTXdsOF9Hcks0ZDBySjZseG1JdFZ5WDhHZmMzSXFwOEdVWmVJTGRkN0x6LUJESmVzdzhyaTRUMXpjWVVKOE1WUXpuVjE1LVhhemFKOGRHbHVhdFpXbm52MERpT1EuU3FwQ1lSbFBjOWY4cEdhU2p3cDhhUS5WX2h2MWlMMV9KeHFnTXlKNkdVZmZjUHpaVnJCb0t3Vmc2WTZveldqbnlTU0J6V3pJWjlYQkVRTGpudEdzbEdVLkMxSk9pNklpbmMxalJCT1ZGbnYtNHc.Qjd4J4094NIpZLTfD2tlp4QEpvUTolUXreu14AsvizTBUTEx2bIF4FMlhMVfJ285PwLG-NST3pzq9C4wLxXy-g"

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
const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\"1\"}";
const char jwk_pubkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\""\
                                      ",\"d\":\"KMRJaGpxVer0w9lMjIY_UrjC067tZdEJkL5eaiBVWi8\",\"crv\":\"P-256\",\"kid\":\"3\",\"alg\":\"ES256\"}";
const char jwk_privkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\","\
                                       "\"crv\":\"P-256\",\"kid\":\"3\",\"alg\":\"ES256\"}";

START_TEST(test_rhonabwy_serialize_se_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_se_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_se_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_NESTED_SIGN_THEN_ENCRYPT, jwk_privkey_ecdsa, 0, jwk_pubkey_rsa, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_NESTED_ENCRYPT_THEN_SIGN, jwk_privkey_ecdsa, 0, jwk_pubkey_rsa, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_decryption_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_ENCRYPTION, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_decryption_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_decryption_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_signature_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_decryption_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_decryption_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_nested;

  s = suite_create("Rhonabwy JWT nested function tests");
  tc_nested = tcase_create("test_rhonabwy_nested");
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_error);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_with_key_in_serialize);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_error);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_with_key_in_serialize);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_key);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_key_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_token_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_decryption_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_decryption_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_decryption_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_key);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_key_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_token_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_signature_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_decryption_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_decryption_verify_with_add_keys_ok);
  tcase_set_timeout(tc_nested, 30);
  suite_add_tcase(s, tc_nested);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT nested tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
