/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define TOKEN "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_HEADER "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ij.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_HEADER_B64 ";error;.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_CLAIMS "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cn.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.;error;.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQeyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfpjqCsg"
#define TOKEN_INVALID_SIGNATURE "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9IEOR0hA-1f5AYmvsE5NUepLfp6qCsg"
#define TOKEN_WITH_WHITESPACES "           \v\n\teyJ0eXAiOiJKV1QiLCJhbGciOi\n\n\n   \tJSUzI1NiIsImtpZCI6IjMifQ.eyJz\t\t \v\rdHIiOiJncnV0IiwiaW50I\n\t\vjo0Miwib2JqIjp0cnVlfQ.SgopnfP3vEE7HbuvfyYqZQZZsbu49GBR5w2YCesW7J0i_s5pVYPMIjl6xU4vOs-nV1lEwn7Z_OaQiyEhVftlOUkM5n7w57YViBZkus5C64S6LuQli150oXWNnis4La6qpg_12EocKffvmG940gL2dWg3dnQYenC-fgtX-CNcaIDZUL-NKq3iaQrwvdbuzNADlSBQUfHh80b7uyKgqcT4tboRyAnJXhcjZ-0NWxCIEusnbskmQEqdxEiq28xL8b_F2hDYe5ZuuHw8tmXcXNHUplswEefTCm0phbvi5D490nVBav6ri6zLTkC9\t\n   \vIEOR0hA-1f5AYmvsE5NUepLfpjqCsg     \t\n"

#define TOKEN_UNSECURE "eyJhbGciOiJub25lIn0.eyJzdHIiOiJncnV0IiwiaW50Ijo0Miwib2JqIjp0cnVlfQ."

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
const char jwk_pubkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9"\
                                    "EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MC"\
                                    "N0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_"\
                                    "U\",\"e\":\"AQAB\",\"kid\":\"3\"}";
const char jwk_privkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH"\
                                    "9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9M"\
                                    "CN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0"\
                                    "_U\",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZj"\
                                    "TnoeKbOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rC"\
                                    "iNSfKMgoM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_"\
                                    "Ww64E\",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rN"\
                                    "af8q1L4kvaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD"\
                                    "9HPRV0dAUmDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_"\
                                    "X4fcl\",\"qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzL"\
                                    "hpIUB_cFBAgI7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_J"\
                                    "BJbM6oIb7IUPjLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9"\
                                    "jtpXE\",\"dq\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA"\
                                    "6YBAzdMNjHL6hnwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"3\"}";
const char jwk_pubkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE6"\
                                    "8Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v3"\
                                    "FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-VfqG"\
                                    "MVM\",\"e\":\"AQAB\",\"kid\":\"4\"}";
const char jwk_privkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE"\
                                    "68Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v"\
                                    "3FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-Vfq"\
                                    "GMVM\",\"e\":\"AQAB\",\"d\":\"HyIUlkT0-vDr8t7W3vmG9xJpItVMuCDfzNtP9lvaTnfvLBhGl154clY0_GAuywUxOS_r5GIYq6xJNxX0XX9vPOgPVMKC"\
                                    "5IWfcwiM1O0fx19boWuArcc69fWNnuZ6kl5GFkk4cevbbCVdkcAgoG8Vd7tZWgDcMnWmGnZ35GV-f7Rw3kQTxge4V7T5-I5preMxRAV2YZ1zafIDpYXaOXWL9b"\
                                    "X0vAApb5Vie1btPiOj7lZ_J0ChkkdIW-ZTiQZ0sTRo6c6qLVNHQLKAJ_I6QLMfiHAT8xFir3fgiUxNwxxifYOts_akh3-wJEs4r4G92hohmIiIKp2TABDc3Wrm"\
                                    "FDafYQ\",\"p\":\"ANVUDxAxNuR8Ds5W_3xpGgOKzypYGfimDrU_kRzXsdXOz4EkSYXG2SR7V854vvcgJDzFIihmaI_65LN_pk_6ZE1ddd8Qrud9nMtd5n9ne"\
                                    "EkOGTCsTO-TM4gLjyZQ3FCo_oCsJ6MiQRlOTw5pf1yH69q3QUd5e_5c75MYr4G0fPwn\",\"q\":\"ANrZ0K-ZdBt9uP1Bt0G7YmW3j41wFt1JnmOkX86YX6Q3"\
                                    "wrI4YqiRfolVexAtQ1a1iRVY7ZGXhy_q0rDLPIpfYAy9LSS1NZHb_vu7C-p8hCALxKa6bTGLeT4Z5LABHPBoMVCyKhlANMHhcUeNY76p4JwT1zwT7FIHamKgVK"\
                                    "zv_CD1\",\"qi\":\"GUmL7fbgnNa2IQ13i3Xi3A5dXzgqBeVHb2HjAzCJhNCcg8jslpU4rmMoGAq_WagT-U3_NuUVnGWnHTPWHjFe9MkwxPpSIISbMRorOhsZ"\
                                    "Mrlzg4vdyZ2Kt_zs3yNTb_KOYx6YxU3_93IdFU2XjlnUf4mDThVoTSRfNh-NMJgwLUw\",\"dp\":\"ALBi7IGK78RD_0oFDQIlNOkw4NI2PmMliou6n5Wlktk"\
                                    "iQtiY1GHUZL6Rbay-kcdrwAqvROr6ogJKhMcWCMGgW0bMvCVQeg3WAsr0PR2ixAZDrfhcvtBoefdG93nK6h-XW7ewoKV2MTVnVl6oRDKSACW72DHs9OUAmuaZR"\
                                    "qSMQ7uJ\",\"dq\":\"AIgWpDddtB6YOl157Ov6CwD3eVPZXM50RgLuJwmAJREn_3D1sRvjhYz-08zGaLZVoo3cw7YiRNVeL2_yoY3mKwMg7B6EdHBkHhYJRSq"\
                                    "mDT8kMj__c4E4mscsMNHlj0pLcEce0yDqlSPu_ZMh7-GTH3HOwKvCM9T6eYQk8SKtBNq1\",\"kid\":\"4\"}";

const unsigned char rsa_2048_pub[] = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\n"
"uqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\n"
"iBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\n"
"ZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n"
"6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\n"
"K49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\n"
"BwIDAQAB\n"
"-----END PUBLIC KEY-----\n";

START_TEST(test_rhonabwy_sign_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  r_jwk_free(jwk_privkey_ecdsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, jwk_privkey_ecdsa, 0), NULL);
  
  r_jwk_free(jwk_privkey_ecdsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_sign_without_set_sign_alg)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);

  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  o_free(token);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_rsa, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_error_token_invalid)
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

START_TEST(test_rhonabwy_verify_error_signature_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_signature_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_signature_with_whitespaces)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_WITH_WHITESPACES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_verify_signature_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_SIGN);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

/**
 * 
 * This test validates that the vulnerability described in
 * https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 * doesn't concern Rhonabwy
 * Basically, the attacker signs a JWT with the public key and the signature verification
 * doesn't check that the algorithm used is different from the expected one.
 * 
 */
START_TEST(test_rhonabwy_verify_vulnerabilty_ok)
{
  jwt_t * jwt_sign, * jwt_verify;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt_sign), RHN_OK);
  ck_assert_int_eq(r_jwt_init(&jwt_verify), RHN_OK);
  
  ck_assert_int_eq(r_jwt_add_sign_key_symmetric(jwt_sign, rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt_sign, j_claims), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_sign, R_JWA_ALG_HS256), RHN_OK);

  ck_assert_ptr_ne(token = r_jwt_serialize_signed(jwt_sign, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt_verify, R_FORMAT_PEM, NULL, 0, rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt_verify, NULL, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  json_decref(j_claims);
  r_jwt_free(jwt_sign);
  r_jwt_free(jwt_verify);
}
END_TEST

START_TEST(test_rhonabwy_jwt_unsecure)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;
  json_t * j_claims = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_UNSECURE, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_parse_unsecure(jwt, TOKEN_UNSECURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_NONE);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, jwk_pubkey_ecdsa, 0), RHN_ERROR_INVALID);
  
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_claims), RHN_OK);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_NONE), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, NULL, 0), NULL);
  ck_assert_ptr_eq(r_jwt_serialize_signed(jwt, jwk_pubkey_ecdsa, 0), NULL);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed_unsecure(jwt, jwk_pubkey_ecdsa, 0), NULL);
  o_free(token);
  ck_assert_ptr_ne(token = r_jwt_serialize_signed_unsecure(jwt, NULL, 0), NULL);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, token, 0), RHN_ERROR_INVALID);
  ck_assert_int_eq(r_jwt_parse_unsecure(jwt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_sign_alg(jwt), R_JWA_ALG_NONE);
  o_free(token);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  json_decref(j_claims);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWT sign function tests");
  tc_core = tcase_create("test_rhonabwy_sign");
  tcase_add_test(tc_core, test_rhonabwy_sign_error);
  tcase_add_test(tc_core, test_rhonabwy_sign_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_sign_with_key_in_serialize);
  tcase_add_test(tc_core, test_rhonabwy_sign_without_set_sign_alg);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_key);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_key_with_add_keys);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_error_signature_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_signature_ok);
  tcase_add_test(tc_core, test_rhonabwy_verify_signature_with_whitespaces);
  tcase_add_test(tc_core, test_rhonabwy_verify_signature_with_add_keys_ok);
  tcase_add_test(tc_core, test_rhonabwy_verify_vulnerabilty_ok);
  tcase_add_test(tc_core, test_rhonabwy_jwt_unsecure);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT sign tests");
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
