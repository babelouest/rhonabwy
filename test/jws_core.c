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

#define HUGE_PAYLOAD "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis efficitur lectus sit amet libero gravida eleifend. Nulla aliquam accumsan erat, quis tincidunt purus ultricies eu. Aenean eu dui ac diam placerat mollis. Duis eget tempor ipsum, vel ullamcorper purus. Ut eget quam vehicula, congue urna vel, dictum risus. Duis tristique est sed diam lobortis commodo. Proin et urna in odio malesuada sagittis. Donec lectus ligula, porttitor sed lorem ut, malesuada posuere neque. Nullam et nisl a felis congue mattis id non lectus.\
Quisque viverra hendrerit malesuada. Integer sollicitudin magna purus, in dignissim eros ullamcorper et. Praesent dignissim metus neque, eget tempor dolor tincidunt egestas. Nulla odio risus, tincidunt et egestas aliquet, pellentesque et eros. Etiam mattis orci a dui efficitur pharetra. Donec fermentum sem sed lacus finibus, nec luctus nisl vulputate. Donec sodales, nisi sed posuere maximus, lectus elit fermentum sapien, quis volutpat risus nisl vel dui. In vitae ante diam.\
Vivamus a nisl quam. Proin in lectus nunc. Aliquam condimentum tellus non feugiat aliquam. Nulla eu mi ligula. Proin auctor varius massa sed consectetur. Nulla et ligula pellentesque, egestas dui eu, gravida arcu. Maecenas vehicula feugiat tincidunt. Aenean sed sollicitudin ex. Cras luctus facilisis erat eu pharetra. Vestibulum interdum consequat tellus nec sagittis. Aliquam tincidunt eget lectus non bibendum. Mauris ut consectetur diam.\
Interdum et malesuada fames ac ante ipsum primis in faucibus. Sed lorem lectus, ullamcorper consectetur quam ut, pharetra consectetur diam. Suspendisse eu erat quis nunc imperdiet lacinia vitae id arcu. Fusce non euismod urna. Aenean lacinia porta tellus nec rutrum. Aliquam est magna, aliquam non hendrerit eget, scelerisque quis sapien. Quisque consectetur et lacus non dapibus. Duis diam purus, vulputate convallis faucibus in, rutrum quis mi. Sed sed magna eget tellus semper suscipit a in augue.\
Aenean vitae tortor quam. Praesent pulvinar nulla a nisi egestas, laoreet tempus mauris ullamcorper. Nam vulputate molestie velit, quis laoreet felis suscipit euismod. Pellentesque a enim dapibus, tincidunt lorem vel, suscipit turpis. Phasellus id metus vehicula, luctus sem nec, maximus purus. Duis dictum elit quam, quis rhoncus ex ullamcorper ut. Donec fringilla augue vitae vestibulum maximus. Mauris vel arcu eget arcu bibendum ornare."

#define HS256_TOKEN "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.PdtqfpescIy_55JZ4PbRKp_nTbbVJik1Bs7S3nr99vQ"
#define HS256_TOKEN_UNSECURE "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u."
#define HS256_TOKEN_INVALID_HEADER "eyJhbGciOiJIUzI1NiIsImtpZCI6Ij.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.PdtqfpescIy_55JZ4PbRKp_nTbbVJik1Bs7S3nr99vQ"
#define HS256_TOKEN_INVALID_HEADER_B64 ";error;.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.PdtqfpescIy_55JZ4PbRKp_nTbbVJik1Bs7S3nr99vQ"
#define HS256_TOKEN_INVALID_PAYLOAD_B64 "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.;error;.PdtqfpescIy_55JZ4PbRKp_nTbbVJik1Bs7S3nr99vQ"
#define HS256_TOKEN_INVALID_DOTS "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQVGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.PdtqfpescIy_55JZ4PbRKp_nTbbVJik1Bs7S3nr99vQ"

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

#define ANDROID_SAFETYNET_JWT "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGa2pDQ0JIcWdBd0lCQWdJUVJYcm9OMFpPZFJrQkFBQUFBQVB1bnpBTkJna3Foa2lHOXcwQkFRc0ZBREJDTVFz"\
"d0NRWURWUVFHRXdKVlV6RWVNQndHQTFVRUNoTVZSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6TVJNd0VRWURWUVFERXdwSFZGTWdRMEVnTVU4eE1CNFhE"\
"VEU0TVRBeE1EQTNNVGswTlZvWERURTVNVEF3T1RBM01UazBOVm93YkRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpB"\
"VUJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hFekFSQmdOVkJBb1RDa2R2YjJkc1pTQk1URU14R3pBWkJnTlZCQU1URW1GMGRHVnpkQzVoYm1SeWIybGtM"\
"bU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTmpYa3owZUsxU0U0bSsvRzV3T28rWEdTRUNycWRuODhzQ3BSN2ZzMTRm"\
"SzBSaDNaQ1laTEZIcUJrNkFtWlZ3Mks5RkcwTzlyUlBlUURJVlJ5RTMwUXVuUzl1Z0hDNGVnOW92dk9tK1FkWjJwOTNYaHp1blFFaFVXWEN4QURJRUdKSzNT"\
"MmFBZnplOTlQTFMyOWhMY1F1WVhIRGFDN09acU5ub3NpT0dpZnM4djFqaTZIL3hobHRDWmUybEorN0d1dHpleEtweHZwRS90WlNmYlk5MDVxU2xCaDlmcGow"\
"MTVjam5RRmtVc0FVd21LVkFVdWVVejR0S2NGSzRwZXZOTGF4RUFsK09raWxNdElZRGFjRDVuZWw0eEppeXM0MTNoYWdxVzBXaGg1RlAzOWhHazlFL0J3UVRq"\
"YXpTeEdkdlgwbTZ4RlloaC8yVk15WmpUNEt6UEpFQ0F3RUFBYU9DQWxnd2dnSlVNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdF"\
"RkJRY0RBVEFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUXFCUXdHV29KQmExb1RLcXVwbzRXNnhUNmoyREFmQmdOVkhTTUVHREFXZ0JTWTBmaHVF"\
"T3ZQbSt4Z254aVFHNkRyZlFuOUt6QmtCZ2dyQmdFRkJRY0JBUVJZTUZZd0p3WUlLd1lCQlFVSE1BR0dHMmgwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJk"\
"MGN6RnZNVEFyQmdnckJnRUZCUWN3QW9ZZmFIUjBjRG92TDNCcmFTNW5iMjluTDJkemNqSXZSMVJUTVU4eExtTnlkREFkQmdOVkhSRUVGakFVZ2hKaGRIUmxj"\
"M1F1WVc1a2NtOXBaQzVqYjIwd0lRWURWUjBnQkJvd0dEQUlCZ1puZ1F3QkFnSXdEQVlLS3dZQkJBSFdlUUlGQXpBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1"\
"b2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwwZFVVekZQTVM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWR3Q2t1UW1RdEJoWUZJZTdF"\
"NkxNWjNBS1BEV1lCUGtiMzdqamQ4ME95QTNjRUFBQUFXWmREM1BMQUFBRUF3QklNRVlDSVFDU1pDV2VMSnZzaVZXNkNnK2dqLzl3WVRKUnp1NEhpcWU0ZVk0"\
"Yy9teXpqZ0loQUxTYmkvVGh6Y3pxdGlqM2RrM3ZiTGNJVzNMbDJCMG83NUdRZGhNaWdiQmdBSFVBVmhRR21pL1h3dXpUOWVHOVJMSSt4MFoydWJ5WkVWekE3"\
"NVNZVmRhSjBOMEFBQUZtWFE5ejVBQUFCQU1BUmpCRUFpQmNDd0E5ajdOVEdYUDI3OHo0aHIvdUNIaUFGTHlvQ3EySzAreUxSd0pVYmdJZ2Y4Z0hqdnB3Mm1C"\
"MUVTanEyT2YzQTBBRUF3Q2tuQ2FFS0ZVeVo3Zi9RdEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUk5blRmUktJV2d0bFdsM3dCTDU1RVRWNmthenNwaFcx"\
"eUFjNUR1bTZYTzQxa1p6d0o2MXdKbWRSUlQvVXNDSXkxS0V0MmMwRWpnbG5KQ0YyZWF3Y0VXbExRWTJYUEx5RmprV1FOYlNoQjFpNFcyTlJHelBodDNtMWI0"\
"OWhic3R1WE02dFg1Q3lFSG5UaDhCb200L1dsRmloemhnbjgxRGxkb2d6L0syVXdNNlM2Q0IvU0V4a2lWZnYremJKMHJqdmc5NEFsZGpVZlV3a0k5Vk5NakVQ"\
"NWU4eWRCM29MbDZnbHBDZUY1ZGdmU1g0VTl4MzVvai9JSWQzVUUvZFBwYi9xZ0d2c2tmZGV6dG1VdGUvS1Ntcml3Y2dVV1dlWGZUYkkzenNpa3daYmtwbVJZ"\
"S21qUG1odjRybGl6R0NHdDhQbjhwcThNMktEZi9QM2tWb3QzZTE4UT0iLCJNSUlFU2pDQ0F6S2dBd0lCQWdJTkFlTzBtcUdOaXFtQkpXbFF1REFOQmdrcWhr"\
"aUc5dzBCQVFzRkFEQk1NU0F3SGdZRFZRUUxFeGRIYkc5aVlXeFRhV2R1SUZKdmIzUWdRMEVnTFNCU01qRVRNQkVHQTFVRUNoTUtSMnh2WW1Gc1UybG5iakVU"\
"TUJFR0ExVUVBeE1LUjJ4dlltRnNVMmxuYmpBZUZ3MHhOekEyTVRVd01EQXdOREphRncweU1URXlNVFV3TURBd05ESmFNRUl4Q3pBSkJnTlZCQVlUQWxWVE1S"\
"NHdIQVlEVlFRS0V4VkhiMjluYkdVZ1ZISjFjM1FnVTJWeWRtbGpaWE14RXpBUkJnTlZCQU1UQ2tkVVV5QkRRU0F4VHpFd2dnRWlNQTBHQ1NxR1NJYjNEUUVC"\
"QVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURRR005RjFJdk4wNXprUU85K3ROMXBJUnZKenp5T1RIVzVEekVaaEQyZVBDbnZVQTBRazI4RmdJQ2ZLcUM5RWtzQzRU"\
"MmZXQllrL2pDZkMzUjNWWk1kUy9kTjRaS0NFUFpSckF6RHNpS1VEelJybUJCSjV3dWRnem5kSU1ZY0xlL1JHR0ZsNXlPRElLZ2pFdi9TSkgvVUwrZEVhbHRO"\
"MTFCbXNLK2VRbU1GKytBY3hHTmhyNTlxTS85aWw3MUkyZE44RkdmY2Rkd3VhZWo0YlhocDBMY1FCYmp4TWNJN0pQMGFNM1Q0SStEc2F4bUtGc2JqemFUTkM5"\
"dXpwRmxnT0lnN3JSMjV4b3luVXh2OHZObWtxN3pkUEdIWGt4V1k3b0c5aitKa1J5QkFCazdYckpmb3VjQlpFcUZKSlNQazdYQTBMS1cwWTN6NW96MkQwYzF0"\
"Skt3SEFnTUJBQUdqZ2dFek1JSUJMekFPQmdOVkhROEJBZjhFQkFNQ0FZWXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUJJR0Ex"\
"VWRFd0VCL3dRSU1BWUJBZjhDQVFBd0hRWURWUjBPQkJZRUZKalIrRzRRNjgrYjdHQ2ZHSkFib090OUNmMHJNQjhHQTFVZEl3UVlNQmFBRkp2aUIxZG5IQjdB"\
"YWdiZVdiU2FMZC9jR1lZdU1EVUdDQ3NHQVFVRkJ3RUJCQ2t3SnpBbEJnZ3JCZ0VGQlFjd0FZWVphSFIwY0RvdkwyOWpjM0F1Y0d0cExtZHZiMmN2WjNOeU1q"\
"QXlCZ05WSFI4RUt6QXBNQ2VnSmFBamhpRm9kSFJ3T2k4dlkzSnNMbkJyYVM1bmIyOW5MMmR6Y2pJdlozTnlNaTVqY213d1B3WURWUjBnQkRnd05qQTBCZ1pu"\
"Z1F3QkFnSXdLakFvQmdnckJnRUZCUWNDQVJZY2FIUjBjSE02THk5d2Eya3VaMjl2Wnk5eVpYQnZjMmwwYjNKNUx6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FR"\
"RUFHb0ErTm5uNzh5NnBSamQ5WGxRV05hN0hUZ2laL3IzUk5Ha21VbVlIUFFxNlNjdGk5UEVhanZ3UlQyaVdUSFFyMDJmZXNxT3FCWTJFVFV3Z1pRK2xsdG9O"\
"RnZoc085dHZCQ09JYXpwc3dXQzlhSjl4anU0dFdEUUg4TlZVNllaWi9YdGVEU0dVOVl6SnFQalk4cTNNRHhyem1xZXBCQ2Y1bzhtdy93SjRhMkc2eHpVcjZG"\
"YjZUOE1jRE8yMlBMUkw2dTNNNFR6czNBMk0xajZieWtKWWk4d1dJUmRBdktMV1p1L2F4QlZielltcW13a201ekxTRFc1bklBSmJFTENRQ1p3TUg1NnQyRHZx"\
"b2Z4czZCQmNDRklaVVNweHU2eDZ0ZDBWN1N2SkNDb3NpclNtSWF0ai85ZFNTVkRRaWJldDhxLzdVSzR2NFpVTjgwYXRuWnoxeWc9PSJdfQ."\
"eyJub25jZSI6IlhQQjdWVGRSWGJEM01mMENvTFF5ZVJQclA5ZjIzYW9mVHBtVWd6cmlrbzA9IiwidGltZXN0YW1wTXMiOjE1NDA2NTE2ODQwOTMsImFwa1Bh"\
"Y2thZ2VOYW1lIjoiY29tLmdvb2dsZS5hbmRyb2lkLmdtcyIsImFwa0RpZ2VzdFNoYTI1NiI6ImVRYyt2elVjZHgwRlZOTHZYSHVHcEQwK1I4MDdzVUV2cCtK"\
"ZWxlWVpzaUE9IiwiY3RzUHJvZmlsZU1hdGNoIjp0cnVlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyI4UDFzVzBFUEpjc2x3N1V6UnNpWEw2NHcr"\
"TzUwRWQrUkJJQ3RheTFnMjRNPSJdLCJiYXNpY0ludGVncml0eSI6dHJ1ZX0."\
"emYayEmcZR5nGyQ0yayZIwSa8zDC4zCWdzvh9seR3hXYBcmV9lL6PmWp-H58FMnuEahH2HgMAyHo0xPjB0xr1QzFzsbNmEsC-_LotaviM3VIuWahejkx_Rob"\
"-0q3vhCqCYyraMiTcFkzN-bXgauBO0Md9eAGFBR5P0pLnui8_6hpo6wRNA74lGKAs0kOi4A9jUs7Na-A4OaeyYs8Q3q425S7fu6Pzadk4rkZclfEvPIjMqFF"\
"CCO-_llXvHTap4S09_W6tFpR_cw9JXL7g5dUcca5iWoDZxXztsKRz3p1cA1M2gkZsmMWCYD6Kv4BIsHtiitwhL2SNC8QZiYc1Wxj3A"

#define TOKEN_WITH_JWK_IN_HEADER "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR"\
"0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI"\
"6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIi"\
"wiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"

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

START_TEST(test_rhonabwy_init)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(NULL), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_payload)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_payload(NULL, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, 0), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, NULL, o_strlen(PAYLOAD)), RHN_OK);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_alg)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_UNKNOWN);

  ck_assert_int_eq(r_jws_set_alg(NULL, R_JWA_ALG_ES256), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_ES256), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_ES256);
  
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_RS512), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_RS512);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_set_header)
{
  jws_t * jws;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_header_str_value(NULL, "key", "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_str_value(jws, NULL, "value"), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "key", "value"), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_header_int_value(NULL, "key", 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_int_value(jws, NULL, 42), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_int_value(jws, "key", 42), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_header_json_t_value(NULL, "key", j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_json_t_value(jws, NULL, j_value), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_header_json_t_value(jws, "key", NULL), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_json_t_value(jws, "key", j_value), RHN_OK);
  
  json_decref(j_value);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_get_header)
{
  jws_t * jws;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_int_value(jws, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_json_t_value(jws, "keyjson", j_value), RHN_OK);
  
  ck_assert_str_eq("value", r_jws_get_header_str_value(jws, "keystr"));
  ck_assert_int_eq(42, r_jws_get_header_int_value(jws, "keyint"));
  ck_assert_int_eq(json_equal(j_value, (j_result = r_jws_get_header_json_t_value(jws, "keyjson"))) , 1);
  
  ck_assert_ptr_eq(NULL, r_jws_get_header_str_value(jws, "error"));
  ck_assert_int_eq(0, r_jws_get_header_int_value(jws, "error"));
  ck_assert_ptr_eq(NULL, r_jws_get_header_json_t_value(jws, "error"));
  
  json_decref(j_value);
  json_decref(j_result);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_set_full_header_error)
{
  jws_t * jws;
  json_t * j_header;
  
  j_header = json_pack("{ss}", "alg", "error");
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_full_header_json_t(jws, j_header), RHN_ERROR_PARAM);
  r_jws_free(jws);
  json_decref(j_header);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_full_header_json_t(jws, NULL), RHN_ERROR_PARAM);
  r_jws_free(jws);
  
  j_header = json_pack("{ss}", "alg", r_jwa_alg_to_str(R_JWA_ALG_RS256));
  ck_assert_int_eq(r_jws_set_full_header_json_t(NULL, j_header), RHN_ERROR_PARAM);
  json_decref(j_header);
  
}
END_TEST

START_TEST(test_rhonabwy_set_full_header)
{
  jws_t * jws;
  json_t * j_header = json_pack("{sssisoss}", "str", CLAIM_STR, "int", CLAIM_INT, "obj", json_true(), "alg", r_jwa_alg_to_str(R_JWA_ALG_RS256));
  char * str_header = json_dumps(j_header, JSON_COMPACT);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_full_header_json_t(jws, j_header), RHN_OK);
  ck_assert_str_eq(r_jws_get_header_str_value(jws, "str"), CLAIM_STR);
  ck_assert_int_eq(r_jws_get_header_int_value(jws, "int"), CLAIM_INT);
  ck_assert_ptr_eq(r_jws_get_header_json_t_value(jws, "obj"), json_true());
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_RS256);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_set_full_header_json_str(jws, str_header), RHN_OK);
  ck_assert_str_eq(r_jws_get_header_str_value(jws, "str"), CLAIM_STR);
  ck_assert_int_eq(r_jws_get_header_int_value(jws, "int"), CLAIM_INT);
  ck_assert_ptr_eq(r_jws_get_header_json_t_value(jws, "obj"), json_true());
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_RS256);
  r_jws_free(jws);
  
  o_free(str_header);
  json_decref(j_header);
}
END_TEST

START_TEST(test_rhonabwy_get_full_header)
{
  jws_t * jws;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_header = json_pack("{sssssisO}", "alg", "RS256", "keystr", "value", "keyint", 42, "keyjson", j_value), * j_result;
  
  ck_assert_ptr_ne(j_header, NULL);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_header_str_value(jws, "keystr", "value"), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_int_value(jws, "keyint", 42), RHN_OK);
  ck_assert_int_eq(r_jws_set_header_json_t_value(jws, "keyjson", j_value), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(json_equal(j_header, (j_result = r_jws_get_full_header_json_t(jws))) , 1);
  json_decref(j_value);
  json_decref(j_header);
  json_decref(j_result);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_set_keys)
{
  jws_t * jws;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa, * jwk_key_symmetric;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_key_symmetric), RHN_OK);
  
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_pubkey_rsa, jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_key_symmetric, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_key_symmetric, NULL), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(NULL, jwk_pubkey_ecdsa, jwk_privkey_ecdsa), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_add_keys(jws, NULL, NULL), RHN_ERROR_PARAM);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_key_symmetric);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_set_jwks)
{
  jws_t * jws;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_ecdsa, * jwk_pubkey_rsa, * jwk_privkey_rsa;
  jwks_t * jwks_pubkey, * jwks_privkey, * jwks;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
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
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(0, r_jwks_size(jws->jwks_privkey));
  ck_assert_int_eq(0, r_jwks_size(jws->jwks_pubkey));
  ck_assert_int_eq(r_jws_add_jwks(jws, jwks_privkey, jwks_pubkey), RHN_OK);
  ck_assert_int_eq(2, r_jwks_size(jws->jwks_privkey));
  ck_assert_int_eq(2, r_jwks_size(jws->jwks_pubkey));
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwk_free(jwk_privkey_rsa);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_add_keys_by_content)
{
  jws_t * jws;
  jwk_t * jwk_priv, * jwk_pub;
  jwks_t * jwks;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_privkey_t g_privkey;
  gnutls_pubkey_t g_pubkey;
#endif
  json_t * j_privkey, * j_pubkey;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
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
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(0, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, jwk_privkey_rsa_str, jwk_pubkey_rsa_str), RHN_OK);
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(1, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jws_add_keys_json_t(jws, j_privkey, j_pubkey), RHN_OK);
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(2, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jws_add_keys_pem_der(jws, R_FORMAT_PEM, rsa_2048_priv, sizeof(rsa_2048_priv), rsa_2048_pub, sizeof(rsa_2048_pub)), RHN_OK);
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(3, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  ck_assert_int_eq(r_jws_add_key_symmetric(jws, symmetric_key, sizeof(symmetric_key)), RHN_OK);
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(4, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_int_eq(r_jws_add_keys_gnutls(jws, g_privkey, g_pubkey), RHN_OK);
  
  jwks = r_jws_get_jwks_privkey(jws);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
  
  jwks = r_jws_get_jwks_pubkey(jws);
  ck_assert_int_eq(5, r_jwks_size(jwks));
  r_jwks_free(jwks);
#endif
  
  r_jws_free(jws);
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

START_TEST(test_rhonabwy_parse)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_INVALID_HEADER, 0), RHN_ERROR_PARAM);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_INVALID_PAYLOAD_B64, 0), RHN_ERROR_PARAM);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_INVALID_DOTS, 0), RHN_ERROR_PARAM);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_UNSECURE, 0), RHN_OK);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN, 0), RHN_OK);
  r_jws_free(jws);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN_UNSECURE, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, HS256_TOKEN, 0), RHN_OK);
  r_jws_free(jws);
  
}
END_TEST

START_TEST(test_rhonabwy_parse_android_safetynet_jwt)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, ANDROID_SAFETYNET_JWT, 0), RHN_OK);
  ck_assert_int_gt(r_jwks_size(jws->jwks_pubkey), 0);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_token_unsecure)
{
  jws_t * jws_sign, * jws_verify;
  char * token;
  
  ck_assert_int_eq(r_jws_init(&jws_sign), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_verify), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws_sign, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_set_alg(jws_sign, R_JWA_ALG_NONE), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws_sign, NULL, 0)), NULL);
  
  ck_assert_int_eq(r_jws_parse(jws_verify, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_verify, NULL, 0), RHN_ERROR_INVALID);
  o_free(token);
  
  r_jws_free(jws_sign);
  r_jws_free(jws_verify);
}
END_TEST

START_TEST(test_rhonabwy_copy)
{
  jws_t * jws, * jws_copy;
  jwk_t * jwk_privkey, * jwk_pubkey;
  char * token = NULL, * token_copy;
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_privkey, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_alg(jws, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);
  
  ck_assert_ptr_ne((jws_copy = r_jws_copy(jws)), NULL);
  ck_assert_ptr_ne((token_copy = r_jws_serialize(jws_copy, NULL, 0)), NULL);
  
#if GNUTLS_VERSION_NUMBER >= 0x030600
  ck_assert_str_eq(token, token_copy);
#endif
  
  o_free(token);
  o_free(token_copy);
  r_jws_free(jws);
  r_jws_free(jws_copy);
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_pubkey);
}
END_TEST

START_TEST(test_rhonabwy_set_properties_error)
{
  jws_t * jws;
  jwk_t * jwk;

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CLAIM_FULL_JSON_STR, json_true(),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CLAIM_FULL_JSON_STR, "{}",
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CLAIM_INT_VALUE, "key", CLAIM_INT,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CLAIM_JSON_T_VALUE, "key", json_true(),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CLAIM_STR_VALUE, "key", CLAIM_STR,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_ENC_ALG, R_JWA_ALG_RSA1_5,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_ENC, R_JWA_ENC_A256GCM,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_ENCRYPT_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_DECRYPT_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_CIPHER_KEY, cypher_key, sizeof(cypher_key),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_IV, iv, sizeof(iv),
                                             RHN_OPT_NONE), RHN_ERROR_PARAM);

  r_jws_free(jws);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_set_properties)
{
  jws_t * jws;
  jwk_t * jwk;
  const unsigned char * key_iv;
  size_t key_iv_len;

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_properties(jws, RHN_OPT_HEADER_INT_VALUE, "int", CLAIM_INT,
                                             RHN_OPT_HEADER_STR_VALUE, "str", CLAIM_STR,
                                             RHN_OPT_HEADER_JSON_T_VALUE, "json", json_true(),
                                             RHN_OPT_PAYLOAD, PAYLOAD, o_strlen(PAYLOAD),
                                             RHN_OPT_SIG_ALG, R_JWA_ALG_RS256,
                                             RHN_OPT_SIGN_KEY_JWK, jwk,
                                             RHN_OPT_VERIFY_KEY_JWK, jwk,
                                             RHN_OPT_NONE), RHN_OK);

  ck_assert_int_eq(CLAIM_INT, r_jws_get_header_int_value(jws, "int"));
  ck_assert_str_eq(CLAIM_STR, r_jws_get_header_str_value(jws, "str"));
  ck_assert_ptr_eq(json_true(), r_jws_get_header_json_t_value(jws, "json"));
  ck_assert_ptr_ne(NULL, key_iv = r_jws_get_payload(jws, &key_iv_len));
  ck_assert_int_eq(o_strlen(PAYLOAD), key_iv_len);
  ck_assert_int_eq(0, memcmp(key_iv, PAYLOAD, key_iv_len));
  ck_assert_int_eq(R_JWA_ALG_RS256, r_jws_get_alg(jws));
  ck_assert_int_eq(1, r_jwks_size(jws->jwks_privkey));
  ck_assert_int_eq(1, r_jwks_size(jws->jwks_pubkey));
  
  r_jws_free(jws);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_zip_payload)
{
  jws_t * jws, * jws_parse, * jws_parse_def;
  jwk_t * jwk_key_symmetric;
  char * token = NULL, * token_def = NULL;
  const unsigned char * payload, * payload_def;
  size_t payload_len = 0, payload_def_len = 0;
  
  ck_assert_int_eq(r_jwk_init(&jwk_key_symmetric), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_key_symmetric, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)HUGE_PAYLOAD, o_strlen(HUGE_PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys(jws, jwk_key_symmetric, NULL), RHN_OK);

  ck_assert_ptr_ne((token = r_jws_serialize(jws, NULL, 0)), NULL);

  ck_assert_int_eq(r_jws_set_header_str_value(jws, "zip", "DEF"), RHN_OK);
  ck_assert_ptr_ne((token_def = r_jws_serialize(jws, NULL, 0)), NULL);
  
  ck_assert_int_gt(o_strlen(token), o_strlen(token_def));
  
  ck_assert_int_eq(r_jws_init(&jws_parse), RHN_OK);
  ck_assert_int_eq(r_jws_init(&jws_parse_def), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse(jws_parse, token, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_parse, jwk_key_symmetric, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jws_get_payload(jws_parse, &payload_len));
  
  ck_assert_int_eq(r_jws_parse(jws_parse_def, token_def, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws_parse_def, jwk_key_symmetric, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload_def = r_jws_get_payload(jws_parse_def, &payload_def_len));
  
  ck_assert_int_eq(payload_len, payload_def_len);
  ck_assert_int_eq(0, memcmp(payload, payload_def, payload_def_len));
  
  r_jws_free(jws_parse);
  r_jws_free(jws_parse_def);
  
  o_free(token);
  o_free(token_def);
  r_jws_free(jws);
  r_jwk_free(jwk_key_symmetric);
}
END_TEST

#if GNUTLS_VERSION_NUMBER >= 0x030600
START_TEST(test_rhonabwy_jwk_in_header)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse(jws, TOKEN_WITH_JWK_IN_HEADER, 0), RHN_OK);
  ck_assert_int_gt(r_jwks_size(jws->jwks_pubkey), 0);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  r_jws_free(jws);
}
END_TEST
#endif

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWS core function tests");
  tc_core = tcase_create("test_rhonabwy_core");
  tcase_add_test(tc_core, test_rhonabwy_init);
  tcase_add_test(tc_core, test_rhonabwy_payload);
  tcase_add_test(tc_core, test_rhonabwy_alg);
  tcase_add_test(tc_core, test_rhonabwy_set_header);
  tcase_add_test(tc_core, test_rhonabwy_get_header);
  tcase_add_test(tc_core, test_rhonabwy_set_full_header_error);
  tcase_add_test(tc_core, test_rhonabwy_set_full_header);
  tcase_add_test(tc_core, test_rhonabwy_get_full_header);
  tcase_add_test(tc_core, test_rhonabwy_set_keys);
  tcase_add_test(tc_core, test_rhonabwy_set_jwks);
  tcase_add_test(tc_core, test_rhonabwy_add_keys_by_content);
  tcase_add_test(tc_core, test_rhonabwy_parse);
  tcase_add_test(tc_core, test_rhonabwy_parse_android_safetynet_jwt);
  tcase_add_test(tc_core, test_rhonabwy_token_unsecure);
  tcase_add_test(tc_core, test_rhonabwy_copy);
  tcase_add_test(tc_core, test_rhonabwy_set_properties_error);
  tcase_add_test(tc_core, test_rhonabwy_set_properties);
  tcase_add_test(tc_core, test_rhonabwy_zip_payload);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_rhonabwy_jwk_in_header);
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
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWS core tests");
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
