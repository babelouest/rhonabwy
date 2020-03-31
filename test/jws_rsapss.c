/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <gnutls/gnutls.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define PS256_TOKEN "eyJhbGciOiJQUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.t2G7YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"
#define PS256_TOKEN_INVALID_HEADER "eyJhbGciOiJQUzI1NiIsImtpZCI6Ij.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.t2G7YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"
#define PS256_TOKEN_INVALID_HEADER_B64 ";error;.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.t2G7YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"
#define PS256_TOKEN_INVALID_PAYLOAD_B64 "eyJhbGciOiJQUzI1NiIsImtpZCI6IjEifQ.;error;.t2G7YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"
#define PS256_TOKEN_INVALID_SIGNATURE "eyJhbGciOiJQUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.t2G6YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"
#define PS256_TOKEN_INVALID_DOTS "eyJhbGciOiJQUzI1NiIsImtpZCI6IjEifQVGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.t2G7YMKJVZe0U1_ZM7efsGWhSAGia5JN-K4lAk3IX7NsMSrWHwZufBXMYZW6S7t_N8xkWEuAgHOY1etwxXuUdhw8uotA-E66M-fErP8MH-N5yUR2G60g3DkcVD-GwbBCsA-Jzum_psaXMA08-3zBjrvGbldqyM51rcdt2qSDxjZ7yxRVhbFbKD0qPOUH49WZx6Mld9oMMSUoIarJitY9LwIC0cR2lXULIh5E-xia42TsNIw9F7VwPXGdHc7_VBqT7R4soxQjWDmfk5QXSMDw2WTIfEXdI3VJiUQ5qnIAe5WWW-wPsK8ughxHLabKXEQ4j7op8EvhZziLOgntGmqQzDq2vEFqoAWYcChijQvg3Ae-3h3F-oFYo8Wh-lcrNZMxta8Ts7AYrdb7cvE2DAO8Oxl0yWJj7vTBJ1YAlO9Kwlba0EydgGY_Xyrl__amALw8p9hSqdVCrJBjYYza8oq_m6B9P1Q3AuVOSdj15yjURa5Hv_ipM9k76Fi0OobHbzfglXCNmw_qDHGhx7aiud9ZPAM-_9xgiWFuIvorltsFDznSimU3va7qorms4AMJ20moG2nmG6ov79cN5Lebj-vupWkUbZ87nd28jOSAJCtDvR2GN0mwYVdrP5jfaIHDpgOKsNTcvigq_srDUyjU-X79LDPtNKUqAwCV3fS2hiwrwlc"

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184YismuCS5PYe0"
                                  "Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvRYvM4Tb5yvvRM7Iz3"
                                  "Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2opKHLFZlL5BTmPWnGIwmmioxI"
                                  "RaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpftn_GgWUk17ti2-xAtYG8XEFsv4hzCWip"
                                  "x0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYulkDynavFJK_13NpJ7d-44ns_F2r2Bl9K6bYxK8W4"
                                  "d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"kid\":\"1\",\"alg\":\"PS256\"}";
const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184YismuCS5PYe"
                                   "0Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvRYvM4Tb5yvvRM7I"
                                   "z3Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2opKHLFZlL5BTmPWnGIwmmi"
                                   "oxIRaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpftn_GgWUk17ti2-xAtYG8XEFsv4hz"
                                   "CWipx0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYulkDynavFJK_13NpJ7d-44ns_F2r2Bl9K6bY"
                                   "xK8W4d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"d\":\"MZrdaw5ETXEnZyXWx5jCW8ZuJUD4MExh8dEwsTGl5d_Nw"
                                   "7pW0QqiaK8c4cMdtMnjxSG7gA8_JujcBF8GXraGtlhJnek5JI2AbvbqlXgvu__kI_DiKIyoZLxsFoRV4Nvw7uLj5qlqhIa_x2bRvR5bW15ic738mcQu8eAPSjhKZLEiOpw"
                                   "T21IkdI6dmpx2tDGTqJSi9sn5UQL-M8lrnfswdtWsWcjCoo8l3NDYLKpxnUkSxOgjEkpeU6txE5O2540MlzBvIi6Belp2ZxqXxijDIXPS5w7n5A-UvUtR5DZzpa_lz84b5"
                                   "9bwtUzfPEPHUSoJjvjRq9BQlw4k2uM7uLzOOmbrIQRbH8byc7Z9DUDK6zRaEW85xVKaXuM7bqcolUuNsHHGGzPGf5pkPYvMV7qACipy9Ksuo8iAGtoZPRan6dO_TfrP0oe"
                                   "eowtmg-6S2--lRPjKAHfhPRwqxKp9WKUdEKu1T9TxHOLkWoOJERRBaE7U7RI8kHO3BIaDxPkBzR47llNPr7ufJ0XZQsKx5kSfdNwJfJ_2kNErEe2neKswaIQ9UwTebYYAk"
                                   "glvaAs85AdP7-g0VLhF51fipK8Y-9g-hY4VITsEvmxQtS7tRKOgzKOY4PqHRpeB2CTJ4Dvj8JPAfbgWBnXpgh-nrq-37HVr1FLCDkFPqyDIzMur_NxRwSk\",\"p\":\"A"
                                   "NXj3t1HDn8OEo_QECNUm1Ie1-xl482FDYvca74igmfVyj017jNwlyl-HlOYYFp9O-hxXF6XLCKtUDk0h_acVOnFeKhYRZCSRlZzGrVjtIX8UtrVkosMxPfqIywl-V5TMLG"
                                   "JhdihNhYm02mdXsGk_ksiPXzmjKUxjwPc--kNgZ1rECeFSNCVQDMLHZ0V-W3MVwpxJKU1bc-BpU5hxvANqIfEzgUNpGLet80FAZaHKyWtYzXhRiIggHkJi7K8UjDhraZGH"
                                   "wPnfhyAIOAplPfA7zYuB0DIYHshKIQgDWTZ7IVTgzs9B_9OS31FUhXTrcSlNqL-RsE_dxMpPEZLUqOgl08\",\"q\":\"AN-OYtTrB8qNhC80CQV7jJD4pMsFwHmOCihl6"
                                   "QBjEj3NfhMP3DtGVhIcX84ZG91QA4NSj9iXswJa9KWpbSNBEzS9bA1AitM0P54_4_jbM9nIX3gXMMwzIbBYrcGuzsvuoz1p4nvWuGHFQhsA9mXiumQ1jj1_7pLopCbl_w9"
                                   "eVCafMB2vC55ZloIe5V5L6Ot6I2PenmVEZ4Kgf6DzexHyCXlgYNWP1nKgpE0aRjHAtL3xiBqct-a2HF-kwMH2tbLKmWW3pvNsPWgrsy3h4f2unk5kLCKxn_15gSm8xV4Nr"
                                   "54ai-ShQc_QYVr8tXXl_Y2nU9ubUQaA4khhU77G_KOsRj0\",\"qi\":\"ALp3wGNfSv7Ns-S3NlqZB68b4AeykPL59CybNKuaUQkAHkuEfpCaG2lAjeVPrA9UFSio2wKu"
                                   "255cwDOTcOkBPhuFeLlegchpWW4tTTyUu1sUYrqUIwhIGxoms4at9sXo3jbtUMe8R4iakfKaGk84ANL_s50uQoCHLevzKalTfItOT5J_7oQYtSZFCxFcZ8w4wDnBLhP4J8"
                                   "aFw_wHJZuH9dGGiOeAiJnr4wWWkRuuhHmfsgXxev27NI-dK11-vDaxxgLsCTbltN1_1EuU5bOwO-IUpYOqV3AqfBMfYr8cNgPGAP5dUxWkMV5VCR2efsIBHBmjvVuJv8aZ"
                                   "rKsLvqrmRx4\",\"dp\":\"PaCpfzJRD_S7DmrRq4xeMFwotLlq2LWkgI7jEGabElX8LoTSfEnNlCv9ivKVmJ0K3N-E0NBX7CnpuoHTRxAmOzElocPFT3GGCLSjlm4C_rQ"
                                   "EH393-M6WFiSFO9w5LJ9loVHRmehhUCKhuYWZXswuZPGZq9o13gcYgPF0N-MnXHcTsX9qyoamd86VGsTRGHzO-3g8KcnqOObO_XWYv2QAEhZ3kecrXT100gLGQVvy56k8s"
                                   "7KT5ZNd0QIaGUa_m8v6n7UGjLZvlMCqOExi2rvhcMf0WQsjGXclWGRv14Ye6w9z-WaNXldt0stdamKSZ91-j5oaQuYJZiD0eACN8A1-aw\",\"dq\":\"BKxbUIwhO5C9x"
                                   "KbX0W-FvroT59KU9XWMrM-EkWeAyB31lrxsJCkSP4qsTgikVnoHuMUPEL4LFe-E0bm6-FOx7RZQne5NeKDM-6fmQhuC9_iCVmZVtM8U0zTnXPckh4rTisMd4uzYKeMPwLT"
                                   "CcdrNfq7H7G0yNYv7cny4Wj_kjnIhdV1lZsgEp2-x58i6c8G336yVrxRA_bAROvIcDoH6xLjJDW3WU8sb5Ci6cuvOW3IjIDtKdN41taIiDWv03GnzzvaJ3OjUV8siEcF5E"
                                   "e6GjKj3azo_V_MkShUSIycyFqIDbqIYWBnJDzfdKzvFkyJ-VEbo6LPlBxJRx9ktCtbdGQ\",\"kid\":\"1\",\"alg\":\"PS256\"}";
const char jwk_pubkey_rsa_no_alg_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184Yismu"
                                         "CS5PYe0Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvRYv"
                                         "M4Tb5yvvRM7Iz3Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2opKH"
                                         "LFZlL5BTmPWnGIwmmioxIRaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpftn_G"
                                         "gWUk17ti2-xAtYG8XEFsv4hzCWipx0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYulkDyn"
                                         "avFJK_13NpJ7d-44ns_F2r2Bl9K6bYxK8W4d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"kid\":\"1\"}";
const char jwk_privkey_rsa_no_alg_str[] = "{\"kty\":\"RSA\",\"n\":\"ALrIdhuABv82Y7K1-LJCXRy1LVdmK9IAHwmmlI-HnOrFeEsSwuCeblUgEpqz_mj7lLtZN0Gnlz-7U0hOpGCeOYXRMn8184Yism"
                                          "uCS5PYe0Jfot0kMumF2IOBV94AGBSeWQcK8J-Ed3X-rkR9vovv8gXhKyRDQH4mon_cPwtdCi2PScnRlkvlOjYkib9m0QQqpvjmcd02s8BYtakRVRva2mQT_dCvR"
                                          "YvM4Tb5yvvRM7Iz3Ni6Jj-IOUZvaZtRW_2HPvhho6Pj_XuYDVHHWyi8SWXtvMQehOtiv9cNecOcvtvEN7YLf2sTM9nIBxOmkRF6k2wvmxwMeoqQZ-pZuvVQkn2o"
                                          "pKHLFZlL5BTmPWnGIwmmioxIRaDmc1KApufOw2voHqCSJR99UMwIyJpIulFqBw_F2y2vS-uXDODA3PmG1u1qpN2mqjvbHz1PwKYucPQH1GoMMRKeEPsjKamLLpf"
                                          "tn_GgWUk17ti2-xAtYG8XEFsv4hzCWipx0zh4S0aVRLoomN9AisHTCWpOgdg1kFj3ECrKxhYMETWGUTKrItAOhE1VuyOenIPMN8ZEeWfqPdUnrRYtRN0ce7WCYu"
                                          "lkDynavFJK_13NpJ7d-44ns_F2r2Bl9K6bYxK8W4d2Q9soCtfsb6eOabtuP-5yWuvPxn9gt6xgbIMEc643k__Lx2_ct6fT\",\"e\":\"AQAB\",\"d\":\"MZr"
                                          "daw5ETXEnZyXWx5jCW8ZuJUD4MExh8dEwsTGl5d_Nw7pW0QqiaK8c4cMdtMnjxSG7gA8_JujcBF8GXraGtlhJnek5JI2AbvbqlXgvu__kI_DiKIyoZLxsFoRV4N"
                                          "vw7uLj5qlqhIa_x2bRvR5bW15ic738mcQu8eAPSjhKZLEiOpwT21IkdI6dmpx2tDGTqJSi9sn5UQL-M8lrnfswdtWsWcjCoo8l3NDYLKpxnUkSxOgjEkpeU6txE"
                                          "5O2540MlzBvIi6Belp2ZxqXxijDIXPS5w7n5A-UvUtR5DZzpa_lz84b59bwtUzfPEPHUSoJjvjRq9BQlw4k2uM7uLzOOmbrIQRbH8byc7Z9DUDK6zRaEW85xVKa"
                                          "XuM7bqcolUuNsHHGGzPGf5pkPYvMV7qACipy9Ksuo8iAGtoZPRan6dO_TfrP0oeeowtmg-6S2--lRPjKAHfhPRwqxKp9WKUdEKu1T9TxHOLkWoOJERRBaE7U7RI"
                                          "8kHO3BIaDxPkBzR47llNPr7ufJ0XZQsKx5kSfdNwJfJ_2kNErEe2neKswaIQ9UwTebYYAkglvaAs85AdP7-g0VLhF51fipK8Y-9g-hY4VITsEvmxQtS7tRKOgzK"
                                          "OY4PqHRpeB2CTJ4Dvj8JPAfbgWBnXpgh-nrq-37HVr1FLCDkFPqyDIzMur_NxRwSk\",\"p\":\"ANXj3t1HDn8OEo_QECNUm1Ie1-xl482FDYvca74igmfVyj0"
                                          "17jNwlyl-HlOYYFp9O-hxXF6XLCKtUDk0h_acVOnFeKhYRZCSRlZzGrVjtIX8UtrVkosMxPfqIywl-V5TMLGJhdihNhYm02mdXsGk_ksiPXzmjKUxjwPc--kNgZ"
                                          "1rECeFSNCVQDMLHZ0V-W3MVwpxJKU1bc-BpU5hxvANqIfEzgUNpGLet80FAZaHKyWtYzXhRiIggHkJi7K8UjDhraZGHwPnfhyAIOAplPfA7zYuB0DIYHshKIQgD"
                                          "WTZ7IVTgzs9B_9OS31FUhXTrcSlNqL-RsE_dxMpPEZLUqOgl08\",\"q\":\"AN-OYtTrB8qNhC80CQV7jJD4pMsFwHmOCihl6QBjEj3NfhMP3DtGVhIcX84ZG9"
                                          "1QA4NSj9iXswJa9KWpbSNBEzS9bA1AitM0P54_4_jbM9nIX3gXMMwzIbBYrcGuzsvuoz1p4nvWuGHFQhsA9mXiumQ1jj1_7pLopCbl_w9eVCafMB2vC55ZloIe5"
                                          "V5L6Ot6I2PenmVEZ4Kgf6DzexHyCXlgYNWP1nKgpE0aRjHAtL3xiBqct-a2HF-kwMH2tbLKmWW3pvNsPWgrsy3h4f2unk5kLCKxn_15gSm8xV4Nr54ai-ShQc_Q"
                                          "YVr8tXXl_Y2nU9ubUQaA4khhU77G_KOsRj0\",\"qi\":\"ALp3wGNfSv7Ns-S3NlqZB68b4AeykPL59CybNKuaUQkAHkuEfpCaG2lAjeVPrA9UFSio2wKu255c"
                                          "wDOTcOkBPhuFeLlegchpWW4tTTyUu1sUYrqUIwhIGxoms4at9sXo3jbtUMe8R4iakfKaGk84ANL_s50uQoCHLevzKalTfItOT5J_7oQYtSZFCxFcZ8w4wDnBLhP"
                                          "4J8aFw_wHJZuH9dGGiOeAiJnr4wWWkRuuhHmfsgXxev27NI-dK11-vDaxxgLsCTbltN1_1EuU5bOwO-IUpYOqV3AqfBMfYr8cNgPGAP5dUxWkMV5VCR2efsIBHB"
                                          "mjvVuJv8aZrKsLvqrmRx4\",\"dp\":\"PaCpfzJRD_S7DmrRq4xeMFwotLlq2LWkgI7jEGabElX8LoTSfEnNlCv9ivKVmJ0K3N-E0NBX7CnpuoHTRxAmOzEloc"
                                          "PFT3GGCLSjlm4C_rQEH393-M6WFiSFO9w5LJ9loVHRmehhUCKhuYWZXswuZPGZq9o13gcYgPF0N-MnXHcTsX9qyoamd86VGsTRGHzO-3g8KcnqOObO_XWYv2QAE"
                                          "hZ3kecrXT100gLGQVvy56k8s7KT5ZNd0QIaGUa_m8v6n7UGjLZvlMCqOExi2rvhcMf0WQsjGXclWGRv14Ye6w9z-WaNXldt0stdamKSZ91-j5oaQuYJZiD0eACN"
                                          "8A1-aw\",\"dq\":\"BKxbUIwhO5C9xKbX0W-FvroT59KU9XWMrM-EkWeAyB31lrxsJCkSP4qsTgikVnoHuMUPEL4LFe-E0bm6-FOx7RZQne5NeKDM-6fmQhuC9"
                                          "_iCVmZVtM8U0zTnXPckh4rTisMd4uzYKeMPwLTCcdrNfq7H7G0yNYv7cny4Wj_kjnIhdV1lZsgEp2-x58i6c8G336yVrxRA_bAROvIcDoH6xLjJDW3WU8sb5Ci6"
                                          "cuvOW3IjIDtKdN41taIiDWv03GnzzvaJ3OjUV8siEcF5Ee6GjKj3azo_V_MkShUSIycyFqIDbqIYWBnJDzfdKzvFkyJ-VEbo6LPlBxJRx9ktCtbdGQ\",\"kid\":\"1\"}";

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
#if GNUTLS_VERSION_NUMBER >= 0x030600
START_TEST(test_rhonabwy_serialize_error_header)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_eq(r_jws_serialize(jws, NULL, 0), NULL);
  ck_assert_ptr_eq(r_jws_serialize(NULL, jwk_privkey, 0), NULL);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_serialize_error_payload)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_PS256), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_eq(r_jws_serialize(jws, NULL, 0), NULL);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_set_alg_serialize_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_PS256), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key", "value"), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key2", "value2"), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  o_free(token);
  
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_no_set_alg_serialize_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  
  o_free(token);
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_serialize_with_key_ok)
{
  jws_t * jws;
  jwk_t * jwk_privkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_PS256), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, jwk_privkey, 0)), NULL);
  
  o_free(token);
  r_jws_free(jws);
  r_jwk_free(jwk_privkey);
}
END_TEST

START_TEST(test_rhonabwy_parse_token_invalid_content)
{
  jws_t * jws;
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN_INVALID_PAYLOAD_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse(jws, "error", 0), RHN_ERROR_PARAM);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_token)
{
  jws_t * jws;
  size_t payload_len = 0;
  const unsigned char * payload = NULL;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN, 0), RHN_OK);
  ck_assert_ptr_ne((payload = r_jws_get_payload(jws, &payload_len)), NULL);
  ck_assert_int_eq(R_JWA_ALG_PS256, r_jws_get_alg(jws));
  ck_assert_int_gt(payload_len, 0);
  ck_assert_int_eq(0, o_strncmp(PAYLOAD, (const char *)payload, payload_len));
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_verify_token_invalid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(R_JWA_ALG_PS256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_verify_token_invalid_kid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWA_ALG_PS256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  r_jwk_set_property_str(jwk_pubkey, "kid", "42");
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_ERROR_INVALID);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_verify_token_valid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWA_ALG_PS256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk_pubkey, 0), RHN_OK);
  r_jws_free(jws);
  r_jwk_free(jwk_pubkey);
  
}
END_TEST

START_TEST(test_rhonabwy_verify_token_multiple_keys_valid)
{
  jws_t * jws;
  jwk_t * jwk_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, PS256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(R_JWA_ALG_PS256, r_jws_get_alg(jws));
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str_2), RHN_OK);
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  r_jwk_free(jwk_pubkey);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  r_jws_add_keys(jws, NULL, jwk_pubkey);
  r_jwk_free(jwk_pubkey);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  r_jws_free(jws);
  
}
END_TEST

START_TEST(test_rhonabwy_set_alg_serialize_verify_ok)
{
  jws_t * jws_sign, * jws_verify;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_sign), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_verify), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_no_alg_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws_sign, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws_sign, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWA_ALG_PS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWA_ALG_PS384), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  
  /*
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWA_ALG_PS512), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, jwk_pubkey, 0), RHN_OK);
  o_free(token);
  */
  
  r_jws_free(jws_sign);
  r_jws_free(jws_verify);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
}
END_TEST
#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWS RSA PSS function tests");
  tc_core = tcase_create("test_rhonabwy_rsapss");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_rhonabwy_serialize_error_header);
  tcase_add_test(tc_core, test_rhonabwy_serialize_error_payload);
  tcase_add_test(tc_core, test_rhonabwy_set_alg_serialize_ok);
  tcase_add_test(tc_core, test_rhonabwy_no_set_alg_serialize_ok);
  tcase_add_test(tc_core, test_rhonabwy_serialize_with_key_ok);
  tcase_add_test(tc_core, test_rhonabwy_parse_token_invalid_content);
  tcase_add_test(tc_core, test_rhonabwy_parse_token);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_invalid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_invalid_kid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_valid);
  tcase_add_test(tc_core, test_rhonabwy_verify_token_multiple_keys_valid);
  tcase_add_test(tc_core, test_rhonabwy_set_alg_serialize_verify_ok);
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
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWS RSA PSS tests");
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
