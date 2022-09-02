/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define TOKEN "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_HEADER "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_ENCRYPTED_KEY "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYA6-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_IV "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcEgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_CIPHER "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTY666JtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_TAG "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iweEOgQ"
#define TOKEN_INVALID_TAG_LEN "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwe"
#define TOKEN_INVALID_HEADER_B64 ";error;iOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_IV_B64 "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.;error;JEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_CIPHER_B64 "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.;error;ImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_TAG_B64 "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.;error;8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_DOTS "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"
#define TOKEN_INVALID_ENC "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQiLCJraWQiOiIyMDExLTA0LTI5In0.hTdKQoNUPNyaiJrY2w08F7AMfgQqPlJU_OhiBMpbc4qpEyqN9H_rmT1qWbyihrZdYAA-erClptOnX2jJZJit83iIykfPyHsWpOENGfN6S8U8oopVgOJWRW2C1TP9hpn1zVmAnvAXlVjAie2frs_zE7S2Rx2IFpFCbu5G1bcc0ERbAhLLxInqUlRl2wblefWUrd22kalO5ozQny1BnKkRnLJ80eD98RFrvV2ie1DO5bZBFRQzypKmXzjpLTsfT0BvX2-ReYodMC07-5feH_d5nFNcqerf2FLUcuItQLShZENzmW9gqlvaiggppPbax9A5UlCMQ2TQX64IXX5GvNSViA.jcPgqVtJEEf237zYfmGFvg.4FyxKUqImoKN_9VnKu9BVCA_vRL6A3gjFb_TSqlD43oLsBw9vJaWVpc5v6ZFHRrpdyxScMQTYKUQJtmLZeFiPw.hpofnoY8vjDLxu9iwepOgQ"

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
const char jwk_privkey_rsa_3015_str[] = "{\"kty\":\"RSA\",\"n\":\"UkE5utIP_jhZm_HxNa4ITmjhIYSYCctVQF9R8gmwj2WMdq0sV8IonqnjmJkrx1w0X5qUI7LMD6seMbZYyN41VRhbHm7Nq8sJ1Eyi"\
                                        "7JhF0nQsiTpYeopAHbDIJvGh7lAtOSSLzyz-jIaRFGgIymFCLrlVM3Jehn87N19IDNX2VizHw8JnAL5ZAEbAoFCm1NhkAQT3P-cUTCg5YBxCy_zF1Cjqn0tzk4bVE"\
                                        "Y7001VCeSk8dwmj_5HU62T_TECyQwlKTDdaJaC7ni6gxA-p0UC9oloHCuvVm4Li0PcJILVCtSSUoO7kNDWb2RKpl6fURKNz9a_in02jOOeH46v2vaBU_XfRDwbEcZ"\
                                        "3FFbLAw42VRv5C0YCuuGhNERZpWhPqC3fzf6VC7RJ6ZW5XtcfvCrOc3qjPGZsDxMFxAKFgJBSlQ57IIattYbsmkIA3rk_aQBZrxNGVFvrpwaQ3I7OZXA6MQWuNwBM"\
                                        "onk1rmrKoXcpxzf-y7NNXTfauDP8\",\"e\":\"AQAB\",\"d\":\"HRaD29U9YqF6zvMYYetRdKkSNFA3k_8b_s-2oulaTtuSeMV00PQQeUuK-QPxv2aT_tsjWBx"\
                                        "6nW_eFaZub1plcdpTHsgAY6hBqZoQY6rVxj7fIQhJEcyiL928akk5ApXH6FVMO8-llPxhgd3ofek3Bl70CmV_mACWaFaBnEht_LuJSWkOE-08fCSJKihbVxnPA61F"\
                                        "4otNWkE_SQW1eX3CV-zAS-Ta0mj0IGl1muajw0UZ5N676D0iFrx4q_aORDSZR5r9ce0DAIGoYrrPi3w22yZIFOTIKrTs-4AqaQSum6n6m_NAVibMIYQl81jVxxQ9M"\
                                        "hFOoIGAUFNBiD-5u_xbeB0ne6nwWR8L7TFT4nl5yORMvu8nbzi41MofrXMyBQJO9ccGKMfu6RhQVPQGFI-ctFpIKysvGAlMarQvAR3RA65w01ShqWyWBGGCPTq-of"\
                                        "2WtxnZQmNJnlctZlU9drq7TTIrs99KHjYEl5-wYE2PLd_2-WnNlOl2JgE\",\"p\":\"DN1pM-wKkTMpacxQOY8RHuS9ls1GqBNoFvzRo6-FW_Aj49Y1uPov8DeG2"\
                                        "b1NyPqXMv8xbyjONpMtc1TTby_6Kp4dr_r79XoEgGC0WnXJSLk_cUb5YHB5N_yDeKvlqa9vRBZPiX0PVAI97_4R9x-89fd4TRJ-ot-M1308HMhKoGvmqus5ZkLgni"\
                                        "EH89np_cZnJcHaXNZpQkua2xT0FH3WVkiElQ2PpkbcxpWoSacu6IhRVQTqN1bSkghRHy2h\",\"q\":\"BmTMYx7TCVAFGDtT6_l84fwF_21z1RQuJjEmKPIcVjkm"\
                                        "RgkqhmZZjGe0ehXvCNODOtrDiNb40Q2gZiDV9CrjWXhAjUcjaBO2OcgalNFAUnExo6olsdRkzDP7t1mU6GiZ35IjgpND4oxMXr0sjgl9o-Hyv4nP5ls-kr_2CVQq_"\
                                        "PzgR4_O7nFr77R7AK_Jq9NDrkFNjBiNbwZxVUMUkU-tUzQk8HzKOIckM5SHaQZKIkZt5UC-H1C26BpbePaf\",\"qi\":\"C-WQU2YoqY_ux_FLXvldlbbiHiisP9"\
                                        "xLdL0NsiCEgN2karv6uWXdNih9e7rAr0zTFotOLgysRkU7jzK1dCRfq7hroHmA0q_ljsxuyB_GlAhFi219aoKchS4nDsHr70x2eLDJnLkVKTQg2TaGjGUbgV892tu"\
                                        "J05vwmKBIYWngRnzB1nRWKk9sz4AskXALW8JWNMm1-Hp3ZrkqxnwZ7c_hDkKPErIy26mfcIfKccsASTxmVLijA9NNuUPUUifN\",\"dp\":\"iPBH5WenE-6D5Kft"\
                                        "TMKUe0Ra0dw_PtdUJVz-Jl0wLnL_lTeUomp93YEw6osicTD6QNwoWBUC9ems4vkLpX4MaZioaZIyacloIR0-qakd6f32UtIprWOM7WX2DYe2H4JL3XWfLOEHSDSVF"\
                                        "wZeNSahP5Hz-nHjidIMX7uxIq7frrzfnHo9g0hdqtfuzr_I-oftbPsMYynrRMOCmoNvmq_f1JIWtIKlkkq5wx1FOrtblddz5olqlaSZx9i_qCE\",\"dq\":\"BSg"\
                                        "Jxe64GAyW70H5npfo5YARfjxRbIkH5vlAY0lPHSKeAWGnEBk_IwMIBGXoD2A1t6NyisuEg2TP9U2J_48PJ7rZpJa4sVkkX1lIRrizfUmY1PuFxvMaD63k1avDcePa"\
                                        "JPqA9O-7kdvAQ6-hXTO-RgsVcO-94XO49TUnQcLFoJ54an5KTvbeK8WMZbNfm9mX_dLgrZmnhuDVSgP9dGujxzSIjgK2O_yRb5_bzRGrfBT80CT0r-CygmGvX9DV\""\
                                        ",\"kid\":\"3015\"}";
const char jwk_pubkey_rsa_3015_str[] = "{\"kty\":\"RSA\",\"n\":\"UkE5utIP_jhZm_HxNa4ITmjhIYSYCctVQF9R8gmwj2WMdq0sV8IonqnjmJkrx1w0X5qUI7LMD6seMbZYyN41VRhbHm7Nq8sJ1Eyi7"\
                                       "JhF0nQsiTpYeopAHbDIJvGh7lAtOSSLzyz-jIaRFGgIymFCLrlVM3Jehn87N19IDNX2VizHw8JnAL5ZAEbAoFCm1NhkAQT3P-cUTCg5YBxCy_zF1Cjqn0tzk4bVEY7"\
                                       "001VCeSk8dwmj_5HU62T_TECyQwlKTDdaJaC7ni6gxA-p0UC9oloHCuvVm4Li0PcJILVCtSSUoO7kNDWb2RKpl6fURKNz9a_in02jOOeH46v2vaBU_XfRDwbEcZ3FF"\
                                       "bLAw42VRv5C0YCuuGhNERZpWhPqC3fzf6VC7RJ6ZW5XtcfvCrOc3qjPGZsDxMFxAKFgJBSlQ57IIattYbsmkIA3rk_aQBZrxNGVFvrpwaQ3I7OZXA6MQWuNwBMonk1"\
                                       "rmrKoXcpxzf-y7NNXTfauDP8\",\"e\":\"AQAB\",\"kid\":\"3015\"}";
const char jwk_privkey_rsa_4109_str[] = "{\"kty\":\"RSA\",\"n\":\"GBCMlNgIVKgDhxhYog5r-Qt7KD2GsLRQmQvTImLeqf8VOZzK5cF4vF-N9apBW8MksV29g1vUljCFz1EXrz6EaO30LbC8wa0g-gXa"\
                                        "m9pT0QPXOBr2knOHWSCpxVk6ZlVpClOecuy5dvTorZTxNbTtkh4YWlSo5nieAKkZgFR4kQl1DXxpdfGdcXaVfc-QL5npPvwv3Q15aVmiilcAY_-tMw-MACPm6zG6W"\
                                        "7PeilGaH-Y24_E6PMZNA3bxdFQ1do56V1i7DdlH_CZpa2sbv4e5q3mlcg6G0nNN3HqGqIBwkT_Y8Q5vNs2bhzXRDWQjRdouRMs1VZkKJrMX-yZHgKI1xr_LlwnmxL"\
                                        "Gq1zWTf6_beiZxmeGRu7tkXKgEaQ8yffokv2o0nI5dKn7U8SWKlRNP-ansyuouaxCWOrIrfjo0ABA6pV_PsBJJ_wOqX0WucYGJANM89LDMC_FPjjqg7Fze8cjMyMF"\
                                        "SHBJgbWTGD_951iBZhnf69PgfC-AoKNnM4xkib1Xp3_i0o7Al3vJSmBuY5qSn0iLoUcn5SbpEuqZOCwZ6grSzwbyWljSSr_w7vg8mB-RZLvEehR4GQ6lCY17gDB4Z"\
                                        "e4trE4YIvYxDJNde1XIwcaZCVWrtoyC_sbr_OtrDcxetCbnDkmawBX-8idEwZgE8O99s-D2wGH7c2A4iDUFh2w\",\"e\":\"AQAB\",\"d\":\"B25k2znzKKFRp"\
                                        "ZBBHpoxgZCoEX8ebsbf9MMQChhaBkj9NvNSPK0IKbOgVPKkiD-0vwjhkwTymwaU67ZxB-7YWMbSlqFzSKO8ATl5jpNXOr5i4bKB3ivK6h0KECVDwYIyk7vKvFaZ10"\
                                        "A98gyCiEE889hTUOG_3pv0vuN5OoXbTX6MJQP8VS2tnvItq9JDBlATFR4vcaXNjljdtrazKi40QAZXB1wO3SZYFCVxXWlhnOQsoytE_quF8MH0QiYW9Gt_ICYIbXh"\
                                        "hoF4EQ-WphfXVwjwoeRY_UBHHQ4SavMIdAN2kkpwQf-3yT0ixK992fQWpMBlIeQxvdA_uIeJqRjDRRnSUw85b0JJGYg5QvE3w9tF0he4cR7RJV5I3St1ivqxMdPnp"\
                                        "xcCVkGrM8nXT8HMZbL3G6c4BfNhwFrtWeowu0YX3cJX6fYAcoHWt4uuBxxZJi60LrJC8W1uaoDF0t3xIH0NK_Lym7SKpdd7vNGzOwV5f39wErXGwGFz_jXd-x-H6T"\
                                        "qgt_eXz-y2xX5cWavEXsH7cf8v4Mt7WTps_CO1sEl5IBPAgR-Y-Oiu_f3XT87kznaHEfc8glzJqOKTpNJdVVLw8oBhwu_kxpQ7V9GBobT1TCiKRVhTBtvKWpANxcJ"\
                                        "XP6t6bbb3N-EckCubSS7LhZG4TeNWbxHgVncyTGqkc4f9w8Q\",\"p\":\"bOB6_y6_syB3efXtxMa0Ln1MqHcNMw7UaMjWVGlrHvSdjADvAmARZm6IZ7lnjiDHGD"\
                                        "ucyIgo71HRh_NRUuYaLT8EX27kEpQRXpat89Fo7DoZ8xPbytuCgCWBX0VYiNL_eZVlg6hAjF56SXRaAdAMwa29SkzIVpKGfW5-Gca45d9yCdRjRV5bNWlr0v7Xaem"\
                                        "lu2sa3ZOzlvik7f03baBSKxlLSp_V2N0dQCEb7pf73JGOQzcfbMwG1-ysYIuC776IpFhh713n9LYVnzna6MRPotv4j6oIDHO6S63u0P-uOhAW30Tq06y8hxIiVOuv"\
                                        "7p9BuCH1551G50Yhf4sqlDEs8Ec\",\"q\":\"OJUsuWdEew_PsqO00OQ-IR4d7XhiYjvlLgRlujsgWcs5j6RfFCS2-9bmbBHZHqvJw3AL6HGEFr3TcVnYvyDvCEh"\
                                        "PNJs2PBDG9F4-XUPHi-15ar8adsCPuW1GxGkl_SzIvW41YbHokIdVfNgCbXJRANWReKbkTACpFNNqjAgnCIOdLoWGfAhQmy93fv28ETd0Zi7plQQTlhXdOvWkPqh0"\
                                        "X_eXCNgl9ijjL4D4ZLUtRv9p6yrnCp6QhaiJi9VFloqiuOi1P9jPKbuCixWVwzuw4aJ1neqH_upHl_t5IY5XT5HtERwzWi1MGC1J29wY8fEN_pzLlawTBFoD5V4j2"\
                                        "DMAv80\",\"qi\":\"VFdf8Hg-4ZE9x6AsS9n8YmYvigx2r042LYWLhd3uXHKliAa5DW__jiaqgCmVtwDO3aq97B40SpHZAaVmzUUboFV1Fs8HIcvdtc9yBgWxfOI"\
                                        "-7w-jnskS4o3dZZmw1KVBH_3a_80RUginGr7bUliKdwU_YL15qW4JlQScdQJld9hxEDTKOMHlLvqieRiJpmtLT1-QA_kw2CwbhgVYurAFT-VBpKx6Yn8_85exSWjp"\
                                        "-ciUfR9zqCs6uU-Q5wVdQT6-e8d13KON6L0y5T4p8v6NnN8mKer_uYDHcVnD0SqcDzOkm3FmvBH_3OUx9w71er1p5Ek80UAwRIouE6PXTMiABkA\",\"dp\":\"Xh"\
                                        "1R1QJJLYNUI_XlWaLWIBWpzTpUC523GPj65K7XrUOQaHRqJqh6ggvsF5VaIa7Ny3HEXkfs8qrML_OxibJkUFZX5lLKDhE2Toh7x_Zt9z1mLwwsg1dqoHFLOtqL5IJ"\
                                        "X2na88KjhWzVUCejs4QJB9K3FodNrngI9BXIcyRVRwUt8nWidg1pEB5CgZxxpgyE4ZSD5cS37IPbAQwUPA9GBFcZgoho2VacVYNj99yojyg98ZTfiDz7yb3Yjr7UJ"\
                                        "M0qFfWL1DWAkYRGA8UmmpG0F1ebGHxHAsVrcYAzzEnDh30kHLGq7fsyjjzKqwLOXOfMqcQvSMCtxHfwuer0GymET0oM\",\"dq\":\"HkyTdHy-CQAAgnJzYuC1_F"\
                                        "n6QK2UUXItWST1rHH48tyGaErmtwyqB9Wd8gTktS3cjxEy7zfKObtQvIQWMtLZ7R97enoa4rNBNp442wxukJmLyQOokiqvS-YeXRLJSvduTzHy1-vC05IEzyOEuUL"\
                                        "b6Yxzp54G5kP8RrCnf3DmJgMEamMKDuUM9OzIGnKZAMcnR4ibgDZ8noP6wZXEa-Ec4D7e29eTDGv8q_VuDc-O_VPMTifdLKyYS1pivURpTSHT3RyP4i6hUIGeeAgI"\
                                        "-FDAeTLbtMJgLLsbt2DsDnIAgxVrUxw8y28yLkgiIt-LZBNnIQ6pXe6VCGGDcJGmtCErp4k\",\"kid\":\"4109\"}";
const char jwk_pubkey_rsa_4109_str[] = "{\"kty\":\"RSA\",\"n\":\"GBCMlNgIVKgDhxhYog5r-Qt7KD2GsLRQmQvTImLeqf8VOZzK5cF4vF-N9apBW8MksV29g1vUljCFz1EXrz6EaO30LbC8wa0g-gXam"\
                                       "9pT0QPXOBr2knOHWSCpxVk6ZlVpClOecuy5dvTorZTxNbTtkh4YWlSo5nieAKkZgFR4kQl1DXxpdfGdcXaVfc-QL5npPvwv3Q15aVmiilcAY_-tMw-MACPm6zG6W7P"\
                                       "eilGaH-Y24_E6PMZNA3bxdFQ1do56V1i7DdlH_CZpa2sbv4e5q3mlcg6G0nNN3HqGqIBwkT_Y8Q5vNs2bhzXRDWQjRdouRMs1VZkKJrMX-yZHgKI1xr_LlwnmxLGq1"\
                                       "zWTf6_beiZxmeGRu7tkXKgEaQ8yffokv2o0nI5dKn7U8SWKlRNP-ansyuouaxCWOrIrfjo0ABA6pV_PsBJJ_wOqX0WucYGJANM89LDMC_FPjjqg7Fze8cjMyMFSHBJ"\
                                       "gbWTGD_951iBZhnf69PgfC-AoKNnM4xkib1Xp3_i0o7Al3vJSmBuY5qSn0iLoUcn5SbpEuqZOCwZ6grSzwbyWljSSr_w7vg8mB-RZLvEehR4GQ6lCY17gDB4Ze4trE"\
                                       "4YIvYxDJNde1XIwcaZCVWrtoyC_sbr_OtrDcxetCbnDkmawBX-8idEwZgE8O99s-D2wGH7c2A4iDUFh2w\",\"e\":\"AQAB\",\"kid\":\"4109\"}";
const char jwk_privkey_rsa_1024_str[] = "{\"kty\":\"RSA\",\"n\":\"wXI38cl3dtYLPsV7XC5fEUnV77979stmzsb4ADJiflUZGAppdnJYEDQK3Z5nqtpKP1aPLN0n9rrqWFbQqIMhFMdwSOf10uHy2i0M"\
                                        "jw3oblVZsLG57qYT2T1139XqNFU_nGELfur81ta4dTEPZ_fIa7V9woqX_eqm8GVeW6lDfwE\",\"e\":\"AQAB\",\"d\":\"Y2YYPwIhg4uKba-1qnEdYlnJNw7y"\
                                        "WKa9ZeSxDBDXsUhyw3qeJEGu5GyJZMT_SbguzIriuM_OuCXlQo0hXGU8unUajlIkHqA-OiJb9Jgh1ZTBhD0-pcFnorDNCqPuP9c07EZFlaAFt9xxrC6Ol0_x_ekRP"\
                                        "nGOxEApd85-G_XVH5E\",\"p\":\"xDxOdvrcmknxfBnh-06sCO9iKO6652yhHN3bKjLNQuUFlp_L0g-RCyn4YSZgddXTcnlltgeqmrBqAHOEoR1JvQ\",\"q\":\""\
                                        "_Fxu7icd3mj-0vGawjKhoLydUQaY3_KEYWVerfmeU-aZt01zo2GCYen_IgHAlW_ivxrG-ssD01gg2I-Q400klQ\",\"qi\":\"PG34Ixvyg-V7p4PM-FchaQxmUVU"\
                                        "bpfr4KoSy35a4hmk3Kfcxkrfx_lbhAxdE46u-IBDHBBMH5OXFStNx4xTOXg\",\"dp\":\"TmGMMcf3z4TTeO9ZrSh6XMNJIPJiI0fnfoE7JjrOc_bIaaaAIfJny9"\
                                        "7CwAM1KjvzTlkhADlFsq3eWTnK8xOgvQ\",\"dq\":\"T4oSrJ1HnMIbDwF3dZ3fs3m_W7polK0rbEc3AD6c2HTmHhAbUnN5VMMb1uwWdwM8xF78OC-klQhB0f_t-"\
                                        "rZlwQ\",\"kid\":\"1024\"}";
const char jwk_pubkey_rsa_1024_str[] = "{\"kty\":\"RSA\",\"n\":\"wXI38cl3dtYLPsV7XC5fEUnV77979stmzsb4ADJiflUZGAppdnJYEDQK3Z5nqtpKP1aPLN0n9rrqWFbQqIMhFMdwSOf10uHy2i0Mj"\
                                       "w3oblVZsLG57qYT2T1139XqNFU_nGELfur81ta4dTEPZ_fIa7V9woqX_eqm8GVeW6lDfwE\",\"e\":\"AQAB\",\"kid\":\"1024\"}";

#if NETTLE_VERSION_NUMBER >= 0x030400
START_TEST(test_rhonabwy_parse_token_invalid)
{
  jwe_t * jwe_decrypt;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_IV_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);
  
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_decrypt_token_invalid)
{
  jwe_t * jwe_decrypt;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_ENCRYPTED_KEY, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_IV, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_CIPHER, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_TAG_LEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_INVALID);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, TOKEN_INVALID_ENC, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_privkey);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_invalid_privkey)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_ERROR_INVALID);
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_small_privkey)
{
  jwe_t * jwe;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_1024_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwe_serialize(jwe, jwk_pubkey, 0), NULL);
  
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_rsa1_aescbc_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_rsa1_aesgcm_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk_pubkey, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_rsa256_aescbc_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_encrypt_decrypt_rsa256_aesgcm_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A256GCM), RHN_OK);
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, jwk_pubkey, 0)), NULL);
  
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, jwk_privkey, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  
  o_free(token);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_flood_ok)
{
  jwe_t * jwe, * jwe_decrypt;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_decrypt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwe_set_payload(jwe, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, NULL, jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe_decrypt, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwe_set_alg(jwe, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  ck_assert_ptr_ne((token = r_jwe_serialize(jwe, NULL, 0)), NULL);
  ck_assert_int_eq(r_jwe_parse(jwe_decrypt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe_decrypt, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe_decrypt->payload, PAYLOAD, jwe_decrypt->payload_len));
  o_free(token);
  
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
  r_jwe_free(jwe);
  r_jwe_free(jwe_decrypt);
}
END_TEST

START_TEST(test_rhonabwy_check_key_length_rsa1)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_rsa2048_pub, * jwk_rsa2048_priv, * jwk_rsa4096_pub, * jwk_rsa4096_priv;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2048_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2048_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa4096_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa4096_priv), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2048_pub, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2048_priv, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa4096_pub, jwk_pubkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa4096_priv, jwk_privkey_rsa_str_2), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_rsa2048_pub, 0)), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_rsa4096_pub, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa2048_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa4096_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa4096_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa2048_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_rsa2048_pub);
  r_jwk_free(jwk_rsa2048_priv);
  r_jwk_free(jwk_rsa4096_pub);
  r_jwk_free(jwk_rsa4096_priv);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

START_TEST(test_rhonabwy_variable_key_length_rsa1)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_rsa1_pub, * jwk_rsa1_priv, * jwk_rsa2_pub, * jwk_rsa2_priv;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_rsa1_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa1_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2_priv), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa1_pub, jwk_pubkey_rsa_3015_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa1_priv, jwk_privkey_rsa_3015_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2_pub, jwk_pubkey_rsa_4109_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2_priv, jwk_privkey_rsa_4109_str), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_rsa1_pub, 0)), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_RSA_OAEP), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_rsa2_pub, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa1_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa2_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa2_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa1_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_rsa1_pub);
  r_jwk_free(jwk_rsa1_priv);
  r_jwk_free(jwk_rsa2_pub);
  r_jwk_free(jwk_rsa2_priv);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

START_TEST(test_rhonabwy_variable_key_length_rsa256)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_rsa1_pub, * jwk_rsa1_priv, * jwk_rsa2_pub, * jwk_rsa2_priv;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_rsa1_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa1_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2_priv), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_rsa1_priv, jwk_rsa1_pub, R_KEY_TYPE_RSA, 3015, NULL), RHN_OK);
  ck_assert_int_eq(r_jwk_generate_key_pair(jwk_rsa2_priv, jwk_rsa2_pub, R_KEY_TYPE_RSA, 4109, NULL), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_rsa1_pub, 0)), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_rsa2_pub, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa1_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa2_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa2_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa1_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_rsa1_pub);
  r_jwk_free(jwk_rsa1_priv);
  r_jwk_free(jwk_rsa2_pub);
  r_jwk_free(jwk_rsa2_priv);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

START_TEST(test_rhonabwy_check_key_length_rsa256)
{
  jwe_t * jwe_enc_1, * jwe_enc_2, * jwe_dec_1, * jwe_dec_2;
  jwk_t * jwk_rsa2048_pub, * jwk_rsa2048_priv, * jwk_rsa4096_pub, * jwk_rsa4096_priv;
  char * token_1, * token_2;
  
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2048_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa2048_priv), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa4096_pub), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_rsa4096_priv), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_1), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe_enc_2), RHN_OK);

  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2048_pub, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa2048_priv, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa4096_pub, jwk_pubkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_rsa4096_priv, jwk_privkey_rsa_str_2), RHN_OK);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_1, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_1, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_1, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_1 = r_jwe_serialize(jwe_enc_1, jwk_rsa2048_pub, 0)), NULL);

  ck_assert_int_eq(r_jwe_set_payload(jwe_enc_2, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwe_set_alg(jwe_enc_2, R_JWA_ALG_RSA_OAEP_256), RHN_OK);
  ck_assert_int_eq(r_jwe_set_enc(jwe_enc_2, R_JWA_ENC_A256CBC), RHN_OK);
  ck_assert_ptr_ne((token_2 = r_jwe_serialize(jwe_enc_2, jwk_rsa4096_pub, 0)), NULL);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa2048_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa4096_priv, 0), RHN_OK);
  r_jwe_free(jwe_dec_2);
  
  ck_assert_ptr_ne((jwe_dec_1 = r_jwe_quick_parse(token_1, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_1, jwk_rsa4096_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_1);

  ck_assert_ptr_ne((jwe_dec_2 = r_jwe_quick_parse(token_2, R_PARSE_NONE, 0)), NULL);
  ck_assert_int_eq(r_jwe_decrypt(jwe_dec_2, jwk_rsa2048_priv, 0), RHN_ERROR_INVALID);
  r_jwe_free(jwe_dec_2);
  
  r_jwk_free(jwk_rsa2048_pub);
  r_jwk_free(jwk_rsa2048_priv);
  r_jwk_free(jwk_rsa4096_pub);
  r_jwk_free(jwk_rsa4096_priv);
  r_jwe_free(jwe_enc_1);
  r_jwe_free(jwe_enc_2);
  r_free(token_1);
  r_free(token_2);
}
END_TEST

/**
 * Test decrypting the JWE in the RFC 7516
 * A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
 * https://tools.ietf.org/html/rfc7516#page-36
 */
START_TEST(test_rhonabwy_decrypt_rfc_ok)
{
  const char token[] = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.\
OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe\
ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb\
Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV\
mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8\
1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi\
6UklfCpIMfIjf7iGdXKHzg.\
48V1_ALb6US04U3b.\
5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji\
SdiwkIr3ajwQzaBtQD_A.\
XFBoMYUZodetZdvTiFvSkQ",
  privkey[] = "{\"kty\":\"RSA\",\
\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW\
cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S\
psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a\
sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS\
tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj\
YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\",\
\"e\":\"AQAB\",\
\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N\
WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9\
3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk\
qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl\
t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd\
VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\",\
\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-\
SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf\
fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\",\
\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm\
UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX\
IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\",\
\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL\
hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827\
rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\",\
\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj\
ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB\
UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\",\
\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7\
AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3\
eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\"}",
  plaintext[] = "The true sign of intelligence is not knowledge but imagination.";
  jwe_t * jwe;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, privkey), RHN_OK);
  ck_assert_int_eq(r_jwe_add_keys(jwe, jwk_privkey, NULL), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwe_decrypt(jwe, NULL, 0), RHN_OK);
  ck_assert_int_eq(0, memcmp(jwe->payload, plaintext, jwe->payload_len));
  r_jwk_free(jwk_privkey);
  r_jwe_free(jwe);
}
END_TEST
#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWE RSA OAEP key encryption tests");
  tc_core = tcase_create("test_rhonabwy_rsa_oaep");
#if NETTLE_VERSION_NUMBER >= 0x030400
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_small_privkey);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_invalid_privkey);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_rsa1_aescbc_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_rsa1_aesgcm_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_rsa256_aescbc_ok);
  tcase_add_test(tc_core, test_rhonabwy_encrypt_decrypt_rsa256_aesgcm_ok);
  tcase_add_test(tc_core, test_rhonabwy_flood_ok);
  tcase_add_test(tc_core, test_rhonabwy_check_key_length_rsa1);
  tcase_add_test(tc_core, test_rhonabwy_check_key_length_rsa256);
  tcase_add_test(tc_core, test_rhonabwy_variable_key_length_rsa1);
  tcase_add_test(tc_core, test_rhonabwy_variable_key_length_rsa256);
  tcase_add_test(tc_core, test_rhonabwy_decrypt_rfc_ok);
#endif
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWE RSA OAEP key encryption tests");
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
