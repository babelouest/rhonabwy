/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

int _r_deflate_payload(const unsigned char * uncompressed, size_t uncompressed_len, unsigned char ** compressed, size_t * compressed_len);

int _r_inflate_payload(const unsigned char * compressed, size_t compressed_len, unsigned char ** uncompressed, size_t * uncompressed_len);

#define PAYLOAD "The true sign of intelligence is not knowledge but imagination."

#define HUGE_PAYLOAD "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis efficitur lectus sit amet libero gravida eleifend. Nulla aliquam accumsan erat, quis tincidunt purus ultricies eu. Aenean eu dui ac diam placerat mollis. Duis eget tempor ipsum, vel ullamcorper purus. Ut eget quam vehicula, congue urna vel, dictum risus. Duis tristique est sed diam lobortis commodo. Proin et urna in odio malesuada sagittis. Donec lectus ligula, porttitor sed lorem ut, malesuada posuere neque. Nullam et nisl a felis congue mattis id non lectus.\
Quisque viverra hendrerit malesuada. Integer sollicitudin magna purus, in dignissim eros ullamcorper et. Praesent dignissim metus neque, eget tempor dolor tincidunt egestas. Nulla odio risus, tincidunt et egestas aliquet, pellentesque et eros. Etiam mattis orci a dui efficitur pharetra. Donec fermentum sem sed lacus finibus, nec luctus nisl vulputate. Donec sodales, nisi sed posuere maximus, lectus elit fermentum sapien, quis volutpat risus nisl vel dui. In vitae ante diam.\
Vivamus a nisl quam. Proin in lectus nunc. Aliquam condimentum tellus non feugiat aliquam. Nulla eu mi ligula. Proin auctor varius massa sed consectetur. Nulla et ligula pellentesque, egestas dui eu, gravida arcu. Maecenas vehicula feugiat tincidunt. Aenean sed sollicitudin ex. Cras luctus facilisis erat eu pharetra. Vestibulum interdum consequat tellus nec sagittis. Aliquam tincidunt eget lectus non bibendum. Mauris ut consectetur diam.\
Interdum et malesuada fames ac ante ipsum primis in faucibus. Sed lorem lectus, ullamcorper consectetur quam ut, pharetra consectetur diam. Suspendisse eu erat quis nunc imperdiet lacinia vitae id arcu. Fusce non euismod urna. Aenean lacinia porta tellus nec rutrum. Aliquam est magna, aliquam non hendrerit eget, scelerisque quis sapien. Quisque consectetur et lacus non dapibus. Duis diam purus, vulputate convallis faucibus in, rutrum quis mi. Sed sed magna eget tellus semper suscipit a in augue.\
Aenean vitae tortor quam. Praesent pulvinar nulla a nisi egestas, laoreet tempus mauris ullamcorper. Nam vulputate molestie velit, quis laoreet felis suscipit euismod. Pellentesque a enim dapibus, tincidunt lorem vel, suscipit turpis. Phasellus id metus vehicula, luctus sem nec, maximus purus. Duis dictum elit quam, quis rhoncus ex ullamcorper ut. Donec fringilla augue vitae vestibulum maximus. Mauris vel arcu eget arcu bibendum ornare."

#define TOKEN_SIGNED_INVALID_ZIP "eyJ6aXAiOiJERUYiLCJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gRHVpcyBlZmZpY2l0dXIgbGVjdHVzIHNpdCBhbWV0IGxpYmVybyBncmF2aWRhIGVsZWlmZW5kLiBOdWxsYSBhbGlxdWFtIGFjY3Vtc2FuIGVyYXQsIHF1aXMgdGluY2lkdW50IHB1cnVzIHVsdHJpY2llcyBldS4gQWVuZWFuIGV1IGR1aSBhYyBkaWFtIHBsYWNlcmF0IG1vbGxpcy4gRHVpcyBlZ2V0IHRlbXBvciBpcHN1bSwgdmVsIHVsbGFtY29ycGVyIHB1cnVzLiBVdCBlZ2V0IHF1YW0gdmVoaWN1bGEsIGNvbmd1ZSB1cm5hIHZlbCwgZGljdHVtIHJpc3VzLiBEdWlzIHRyaXN0aXF1ZSBlc3Qgc2VkIGRpYW0gbG9ib3J0aXMgY29tbW9kby4gUHJvaW4gZXQgdXJuYSBpbiBvZGlvIG1hbGVzdWFkYSBzYWdpdHRpcy4gRG9uZWMgbGVjdHVzIGxpZ3VsYSwgcG9ydHRpdG9yIHNlZCBsb3JlbSB1dCwgbWFsZXN1YWRhIHBvc3VlcmUgbmVxdWUuIE51bGxhbSBldCBuaXNsIGEgZmVsaXMgY29uZ3VlIG1hdHRpcyBpZCBub24gbGVjdHVzLlF1aXNxdWUgdml2ZXJyYSBoZW5kcmVyaXQgbWFsZXN1YWRhLiBJbnRlZ2VyIHNvbGxpY2l0dWRpbiBtYWduYSBwdXJ1cywgaW4gZGlnbmlzc2ltIGVyb3MgdWxsYW1jb3JwZXIgZXQuIFByYWVzZW50IGRpZ25pc3NpbSBtZXR1cyBuZXF1ZSwgZWdldCB0ZW1wb3IgZG9sb3IgdGluY2lkdW50IGVnZXN0YXMuIE51bGxhIG9kaW8gcmlzdXMsIHRpbmNpZHVudCBldCBlZ2VzdGFzIGFsaXF1ZXQsIHBlbGxlbnRlc3F1ZSBldCBlcm9zLiBFdGlhbSBtYXR0aXMgb3JjaSBhIGR1aSBlZmZpY2l0dXIgcGhhcmV0cmEuIERvbmVjIGZlcm1lbnR1bSBzZW0gc2VkIGxhY3VzIGZpbmlidXMsIG5lYyBsdWN0dXMgbmlzbCB2dWxwdXRhdGUuIERvbmVjIHNvZGFsZXMsIG5pc2kgc2VkIHBvc3VlcmUgbWF4aW11cywgbGVjdHVzIGVsaXQgZmVybWVudHVtIHNhcGllbiwgcXVpcyB2b2x1dHBhdCByaXN1cyBuaXNsIHZlbCBkdWkuIEluIHZpdGFlIGFudGUgZGlhbS5WaXZhbXVzIGEgbmlzbCBxdWFtLiBQcm9pbiBpbiBsZWN0dXMgbnVuYy4gQWxpcXVhbSBjb25kaW1lbnR1bSB0ZWxsdXMgbm9uIGZldWdpYXQgYWxpcXVhbS4gTnVsbGEgZXUgbWkgbGlndWxhLiBQcm9pbiBhdWN0b3IgdmFyaXVzIG1hc3NhIHNlZCBjb25zZWN0ZXR1ci4gTnVsbGEgZXQgbGlndWxhIHBlbGxlbnRlc3F1ZSwgZWdlc3RhcyBkdWkgZXUsIGdyYXZpZGEgYXJjdS4gTWFlY2VuYXMgdmVoaWN1bGEgZmV1Z2lhdCB0aW5jaWR1bnQuIEFlbmVhbiBzZWQgc29sbGljaXR1ZGluIGV4LiBDcmFzIGx1Y3R1cyBmYWNpbGlzaXMgZXJhdCBldSBwaGFyZXRyYS4gVmVzdGlidWx1bSBpbnRlcmR1bSBjb25zZXF1YXQgdGVsbHVzIG5lYyBzYWdpdHRpcy4gQWxpcXVhbSB0aW5jaWR1bnQgZWdldCBsZWN0dXMgbm9uIGJpYmVuZHVtLiBNYXVyaXMgdXQgY29uc2VjdGV0dXIgZGlhbS5JbnRlcmR1bSBldCBtYWxlc3VhZGEgZmFtZXMgYWMgYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMuIFNlZCBsb3JlbSBsZWN0dXMsIHVsbGFtY29ycGVyIGNvbnNlY3RldHVyIHF1YW0gdXQsIHBoYXJldHJhIGNvbnNlY3RldHVyIGRpYW0uIFN1c3BlbmRpc3NlIGV1IGVyYXQgcXVpcyBudW5jIGltcGVyZGlldCBsYWNpbmlhIHZpdGFlIGlkIGFyY3UuIEZ1c2NlIG5vbiBldWlzbW9kIHVybmEuIEFlbmVhbiBsYWNpbmlhIHBvcnRhIHRlbGx1cyBuZWMgcnV0cnVtLiBBbGlxdWFtIGVzdCBtYWduYSwgYWxpcXVhbSBub24gaGVuZHJlcml0IGVnZXQsIHNjZWxlcmlzcXVlIHF1aXMgc2FwaWVuLiBRdWlzcXVlIGNvbnNlY3RldHVyIGV0IGxhY3VzIG5vbiBkYXBpYnVzLiBEdWlzIGRpYW0gcHVydXMsIHZ1bHB1dGF0ZSBjb252YWxsaXMgZmF1Y2lidXMgaW4sIHJ1dHJ1bSBxdWlzIG1pLiBTZWQgc2VkIG1hZ25hIGVnZXQgdGVsbHVzIHNlbXBlciBzdXNjaXBpdCBhIGluIGF1Z3VlLkFlbmVhbiB2aXRhZSB0b3J0b3IgcXVhbS4gUHJhZXNlbnQgcHVsdmluYXIgbnVsbGEgYSBuaXNpIGVnZXN0YXMsIGxhb3JlZXQgdGVtcHVzIG1hdXJpcyB1bGxhbWNvcnBlci4gTmFtIHZ1bHB1dGF0ZSBtb2xlc3RpZSB2ZWxpdCwgcXVpcyBsYW9yZWV0IGZlbGlzIHN1c2NpcGl0IGV1aXNtb2QuIFBlbGxlbnRlc3F1ZSBhIGVuaW0gZGFwaWJ1cywgdGluY2lkdW50IGxvcmVtIHZlbCwgc3VzY2lwaXQgdHVycGlzLiBQaGFzZWxsdXMgaWQgbWV0dXMgdmVoaWN1bGEsIGx1Y3R1cyBzZW0gbmVjLCBtYXhpbXVzIHB1cnVzLiBEdWlzIGRpY3R1bSBlbGl0IHF1YW0sIHF1aXMgcmhvbmN1cyBleCB1bGxhbWNvcnBlciB1dC4gRG9uZWMgZnJpbmdpbGxhIGF1Z3VlIHZpdGFlIHZlc3RpYnVsdW0gbWF4aW11cy4gTWF1cmlzIHZlbCBhcmN1IGVnZXQgYXJjdSBiaWJlbmR1bSBvcm5hcmUu.HoVfiZqrwC-QQF_etLZcMYEPEOY5_I8seUjgCb46qP4"

#define TOKEN_ENCRYPTED_INVALID_ZIP "eyJ6aXAiOiJERUYiLCJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.jcPWiKo22JIJpKB3bOl0bOCvF9aO5iZ8Ud8rU6RhCBludm1Zh5Nh6g.dGHvIuHMMc0dr8x0szYRVA.Va2TwbAhiSLVFGsfevD4lb5u2GiSROfysv4AO-uPOD9tE5O2IW3nFkMis5edghtVf3wvkMtjpAb73KWMDC1E-TEs5OVKJ8y4_lQaKgKsiyunuUb8J8h-R5XNXIi8G4yilnrM5tS5n8A-pFd34wL1vqPkdeCd8LVkfBl17DzLLO8sXvIRRdSr0H-t2H5UXyZykEckV5K3zwv7OuJ1iK3iAvwa_Pku0T-4RHvHU13QCjwULkTh3nyo9dpH35DDIjP_M77gG3HTa-u6wyMfNC-sXoPC7B4e_i5Um4itCIyXPXnEVJfuovcuUWDgh4QiaeIWuvA_Yh0XIlq93ZZuC7z3nonfOLftoeT6kq-82Sbd39wBtHxCCPN9XwOO6QCO-POXOuAWSKPr9HF0bYiCvE6W83imTeR0EI_oq7-pmGflo077jPW8H-gz4Vphp2jNwT0jIid_Um8q1eS0ApbbrA6MTgwKVDf7fchgyyLZp6rzREEfoBkf1c8bImwaiCO0otuwrrvghcPg5TiQCKvN3m1KWGlDdBV2076DE0nFGjEUH-1vfVrN7Y5T3i_ZyCZBNTxVHLXIiejcvaaghTqErLeXXUbxMGKEKe3nbEdSnrGeyDVKkEKKcsYVn2wDAU-WkMaFjoCbnJUjAbsm4hvscEFs-bTLebYNX6eCC-9ZzoZlOLUJ_5GvtQ7lWd59emQjrw0Xd2DhxfWyuKlPDPFue7nyTBqIxZ1rVlcGXQXuRKxy-y13ji2NG3O_5Ml6ntvgbEasp5x04mFON3f1z-SfYye86CHiQPQFVWhpuBUB4mAiGFarq3Al6rg1lwqhS-AR2HUVJvDuUgAxqtDPUmWRZZEjZKd-RYMPZ5lzle8mnZOUanRF4HBi6fMR11dPfldRXGzAOVwFyQhK3HKeWCVrZ2pLE3hzoURuiodA3ubx6zQ6MX2pdjIt1-Sl8jRDbCJi-VIqPuGwxvgHwTX2b0jxdtnnH93_mz3QgjxKYpNBFF4rDBKnWcrHFiwLbhx7sudaDByUV8cQyisRPuZEo2f2Z0epcU672xRl_eX3fZS03VEKIr78TOK7HQc_XnR3l18bnjP3JRAaMHLW7VXIS-0qL-d7IxNzbm_BYsECeDIKFNlyxrf9FJnJJlfUQWNKJKu3A4Q3uCg0wBCT2xi7klU9lnXNfFHiNe74dCvB14CIAzyoKR-BAyAjnEmnttSp7iNBTN9h-NCfvbPCh9JmAF4l92-wvfBeWvybpaSwBT4oVU0MWNyAzvRs66b0SdyDhJgDzjKhkCraBig6X5ZsvgPRmgLSZ49QSn828tLXn0fSfB78wrn0DIuB4rJyuei4UWADdXnu1i8XuOMNKKwIhgQDTNP1ELhhFimsuBFKqLRGlwH4luuq7ANjTrlmKWSF8kxoAWpsv0TBRRDHWpx-KW7YS-wM99sSEkWg4NfNE4w5KvVYy6mY4uNCcVYLLbZuqhWbRvoOtUwl_spwOyevK0DCN0iGZFti1tzwlMq01dNnjZTiCqOcJBCL1hxfQ9YIZSrFbCwxWwf-aa6ZpbLTj8uGaRFEpb6alXmJaitbQmzN-l7RxAKXb69abERyenxPE-jA2nvSO80RlH3DhDIutRsvG69-C_woDjjqGSzH03qpKTiwljGFkUqOelcyqi9_10yWIGR5KskbSKTczRrcnd8p9xlYqFoIB1duo-nvlBMpNUDLDosf_xBta7iJnFFBRm1b0HBSeXS538ZkIGAqw1LKRBI0jBn7LvQxMyxCSbofvSdFapfYPMOx7ITzUwOXY-9tJ2tTviMAcQUxcuvq8zdGEXydlToVg-6dBTMUo4ih-WKG48e4sNsCMZ6kC1J_I55jDRH7Tnbx0Fda3_tddm34VUTqmdzzrSQ9mq1_7evTrE15R4au0OJcsxJMZIAbm0Ki92n9AesUE__wfvCBam0AeB77wM8BX3YW6ukybCKBxpWL6jZFV7oP-dskXe1D7XSO1s-PAduhfqEGvgW_h06tQ8DxkIINc3vnNhwdBLFZWCszknQVS2fq-LFOHExsSx6zBSHR0O6jI_gDbyU40OzY21fLT-COp8qfmsHqa8SCjyjXsWXInqYUO8A9LExMSboWY1iByWVVeDeYglPM9GtkmBzQbLy_pKe5iEs71YfPOixXUtVvQqDmJRDAluxCW1ho0LXepvNPYppwvhTzg3iEbiGMlhzxEunyvEjjYOpbXAohnNL41LI4X_xKldim0Rzx0_jO84cqVbVzZUReSms4-l7ZJDWqA8WECRkgPgLMZAySWy0PEFLKRInpQ21RCq7NotsWeE8SY7R76cOreUCJVmsDWln5kEjBf8vGnacwv2oR5edF-BuVaIiryKvU2K-PJPGTX6dhIwVVWS1V3uDoelEQdA_SdLkye2uBDvn91fcvO7nG1MDLG_98GptECUGFk7soM2TgsQhlyqY92VaoQvKUwWM81PWkjMI7B-6ZquoxJJzyPdj6ZO1dyw-mkZheCpUlTU2mkmUC77rzlBCYQKwS66pcKSAeSP9TXaa-lbYrz1g0QaR1h3cpBvahxk71YGwqv-T8DPlsZw5T2X5l-W4Bg76FYVVp6JWjnpMQCYZMgQ5dQzDPDkPOarTotO0ZUEF0o1VchRMW6FgRIccgqnsa8sSPF2miIswfsoMkOQHuszsl94RBw61pu4t_N7PIo3ipZ7OHblm3PGJelEEAzO9F4qDiZG7Bpj0WLmEAh5h6aQdYh1kNtDlPH0pKmBWjyIjijV1amjWGSl9ZPqTGhh3upXpDnhgC65sGIcYkthwPrwvqhZqbppef6mG1jkhkisz0hVG3nV9FuLjcLtSTsL8harweziFhiPRkiaGDUebqKQVanyo-TrkZOosvx8FM6ugANIU2hYgS6NPGW_HoBznXei1nVLeDdy7_e3KRdPmksQAgt0FxTjg5OvxdsZkPDLE60NnDkAMQOJP8A13rBg36YgGiqAKs1MiuiEU5kP2nQFtSzZjzTWEFRDCAfM0Z-K_ZfYEAnSbbyZ_Y3VT59jHPLUhewv6lWZaJLgAxXk1vG_Je-q711sMamFGbeczW2LZQY3IzyYmTYJ_6hgI67TMjTBDvnB2m4R7VkTBHJAzPVKXPeFUhPFPCSe_J6mwwIU0fs9_JkyMMgtQ-T-MCGg1kZi5lAGBrCBxMSXoQclZLUdaHaGSq-GpoYt3vHlon-BXC.644LPTwW_DyY7p2TvrJUqg"

const char jwk_key_symmetric[] = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODw\"}";

START_TEST(test_rhonabwy_info_json_t)
{
  json_t * j_info_control = r_library_info_json_t();
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[ssss]s[sssss]}}",
                            "version", RHONABWY_VERSION_STR,
                            "jws",
                              "alg",
                                "none",
                                "HS256",
                                "HS384",
                                "HS512",
                                "RS256",
                                "RS384",
                                "RS512",
                            "jwe",
                              "alg",
                                "RSA1_5",
                                "dir",
                                "A128GCMKW",
                                "A256GCMKW",
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512",
                                "A128GCM",
                                "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
//  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256K"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192GCMKW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "enc"), json_string("A192GCM"));
#endif
#if NETTLE_VERSION_NUMBER >= 0x030400
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP-256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A256KW"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060d
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS256+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS384+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS512+A256KW"));
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A256KW"));
#endif

  ck_assert_ptr_ne(j_info, NULL);
  ck_assert_ptr_ne(j_info_control, NULL);
  ck_assert_int_eq(json_equal(j_info, j_info_control), 1);
  json_decref(j_info);
  json_decref(j_info_control);
}
END_TEST

START_TEST(test_rhonabwy_info_str)
{
  char * j_info_control_str = r_library_info_json_str();
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[ssss]s[sssss]}}",
                            "version", RHONABWY_VERSION_STR,
                            "jws",
                              "alg",
                                "none",
                                "HS256",
                                "HS384",
                                "HS512",
                                "RS256",
                                "RS384",
                                "RS512",
                            "jwe",
                              "alg",
                                "RSA1_5",
                                "dir",
                                "A128GCMKW",
                                "A256GCMKW",
                              "enc",
                                "A128CBC-HS256",
                                "A192CBC-HS384",
                                "A256CBC-HS512",
                                "A128GCM",
                                "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
//  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256K"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192GCMKW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "enc"), json_string("A192GCM"));
#endif
#if NETTLE_VERSION_NUMBER >= 0x030400
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP-256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A256KW"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060d
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS256+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS384+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS512+A256KW"));
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A256KW"));
#endif
  json_t * j_info_control_parsed = json_loads(j_info_control_str, JSON_DECODE_ANY, NULL);

  ck_assert_ptr_ne(j_info, NULL);
  ck_assert_ptr_ne(j_info_control_str, NULL);
  ck_assert_ptr_ne(j_info_control_parsed, NULL);
  ck_assert_int_eq(json_equal(j_info, j_info_control_parsed), 1);
  json_decref(j_info);
  json_decref(j_info_control_parsed);
  r_free(j_info_control_str);
}
END_TEST

START_TEST(test_rhonabwy_alg_conversion)
{
  ck_assert_int_eq(r_str_to_jwa_alg("none"), R_JWA_ALG_NONE);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_NONE), "none");
  ck_assert_int_eq(r_str_to_jwa_alg("HS256"), R_JWA_ALG_HS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS256), "HS256");
  ck_assert_int_eq(r_str_to_jwa_alg("HS384"), R_JWA_ALG_HS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS384), "HS384");
  ck_assert_int_eq(r_str_to_jwa_alg("HS512"), R_JWA_ALG_HS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_HS512), "HS512");
  ck_assert_int_eq(r_str_to_jwa_alg("ES256"), R_JWA_ALG_ES256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES256), "ES256");
  ck_assert_int_eq(r_str_to_jwa_alg("ES384"), R_JWA_ALG_ES384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES384), "ES384");
  ck_assert_int_eq(r_str_to_jwa_alg("ES512"), R_JWA_ALG_ES512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES512), "ES512");
  ck_assert_int_eq(r_str_to_jwa_alg("EdDSA"), R_JWA_ALG_EDDSA);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_EDDSA), "EdDSA");
  ck_assert_int_eq(r_str_to_jwa_alg("ES256K"), R_JWA_ALG_ES256K);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ES256K), "ES256K");
  ck_assert_int_eq(r_str_to_jwa_alg("RS256"), R_JWA_ALG_RS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS256), "RS256");
  ck_assert_int_eq(r_str_to_jwa_alg("RS384"), R_JWA_ALG_RS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS384), "RS384");
  ck_assert_int_eq(r_str_to_jwa_alg("RS512"), R_JWA_ALG_RS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RS512), "RS512");
  ck_assert_int_eq(r_str_to_jwa_alg("PS256"), R_JWA_ALG_PS256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS256), "PS256");
  ck_assert_int_eq(r_str_to_jwa_alg("PS384"), R_JWA_ALG_PS384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS384), "PS384");
  ck_assert_int_eq(r_str_to_jwa_alg("PS512"), R_JWA_ALG_PS512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PS512), "PS512");
  ck_assert_int_eq(r_str_to_jwa_alg("EdDSA"), R_JWA_ALG_EDDSA);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_EDDSA), "EdDSA");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA1_5"), R_JWA_ALG_RSA1_5);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA1_5), "RSA1_5");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA-OAEP"), R_JWA_ALG_RSA_OAEP);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP), "RSA-OAEP");
  ck_assert_int_eq(r_str_to_jwa_alg("RSA-OAEP-256"), R_JWA_ALG_RSA_OAEP_256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_RSA_OAEP_256), "RSA-OAEP-256");
  ck_assert_int_eq(r_str_to_jwa_alg("A128KW"), R_JWA_ALG_A128KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A128KW), "A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A192KW"), R_JWA_ALG_A192KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A192KW), "A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A256KW"), R_JWA_ALG_A256KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A256KW), "A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("dir"), R_JWA_ALG_DIR);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_DIR), "dir");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES"), R_JWA_ALG_ECDH_ES);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES), "ECDH-ES");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A128KW"), R_JWA_ALG_ECDH_ES_A128KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A128KW), "ECDH-ES+A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A192KW"), R_JWA_ALG_ECDH_ES_A192KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A192KW), "ECDH-ES+A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("ECDH-ES+A256KW"), R_JWA_ALG_ECDH_ES_A256KW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_ECDH_ES_A256KW), "ECDH-ES+A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("A128GCMKW"), R_JWA_ALG_A128GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A128GCMKW), "A128GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("A192GCMKW"), R_JWA_ALG_A192GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A192GCMKW), "A192GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("A256GCMKW"), R_JWA_ALG_A256GCMKW);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_A256GCMKW), "A256GCMKW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS256+A128KW"), R_JWA_ALG_PBES2_H256);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H256), "PBES2-HS256+A128KW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS384+A192KW"), R_JWA_ALG_PBES2_H384);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H384), "PBES2-HS384+A192KW");
  ck_assert_int_eq(r_str_to_jwa_alg("PBES2-HS512+A256KW"), R_JWA_ALG_PBES2_H512);
  ck_assert_str_eq(r_jwa_alg_to_str(R_JWA_ALG_PBES2_H512), "PBES2-HS512+A256KW");
  ck_assert_int_eq(r_str_to_jwa_alg("error"), R_JWA_ALG_UNKNOWN);
  ck_assert_ptr_eq(r_jwa_alg_to_str(R_JWA_ALG_UNKNOWN), NULL);
}
END_TEST

START_TEST(test_rhonabwy_enc_conversion)
{
  ck_assert_int_eq(r_str_to_jwa_enc("A128CBC-HS256"), R_JWA_ENC_A128CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A128CBC), "A128CBC-HS256");
  ck_assert_int_eq(r_str_to_jwa_enc("A192CBC-HS384"), R_JWA_ENC_A192CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A192CBC), "A192CBC-HS384");
  ck_assert_int_eq(r_str_to_jwa_enc("A256CBC-HS512"), R_JWA_ENC_A256CBC);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A256CBC), "A256CBC-HS512");
  ck_assert_int_eq(r_str_to_jwa_enc("A128GCM"), R_JWA_ENC_A128GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A128GCM), "A128GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("A192GCM"), R_JWA_ENC_A192GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A192GCM), "A192GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("A256GCM"), R_JWA_ENC_A256GCM);
  ck_assert_str_eq(r_jwa_enc_to_str(R_JWA_ENC_A256GCM), "A256GCM");
  ck_assert_int_eq(r_str_to_jwa_enc("error"), R_JWA_ENC_UNKNOWN);
  ck_assert_ptr_eq(r_jwa_enc_to_str(R_JWA_ENC_UNKNOWN), NULL);
}
END_TEST

START_TEST(test_rhonabwy_inflate)
{
  unsigned char in_1[] = PAYLOAD, in_2[] = HUGE_PAYLOAD, * out_1 = NULL, * out_2 = NULL;
  size_t out_1_len = 0, out_2_len = 0;

  ck_assert_int_eq(_r_deflate_payload(in_1, sizeof(in_1), &out_1, &out_1_len), RHN_OK);
  ck_assert_int_eq(_r_inflate_payload(out_1, out_1_len, &out_2, &out_2_len), RHN_OK);
  ck_assert_int_eq(sizeof(in_1), out_2_len);
  ck_assert_int_eq(0, memcmp(in_1, out_2, out_2_len));
  r_free(out_1);
  r_free(out_2);

  ck_assert_int_eq(_r_deflate_payload(in_2, sizeof(in_2), &out_1, &out_1_len), RHN_OK);
  ck_assert_int_eq(_r_inflate_payload(out_1, out_1_len, &out_2, &out_2_len), RHN_OK);
  ck_assert_int_eq(sizeof(in_2), out_2_len);
  ck_assert_int_eq(0, memcmp(in_2, out_2, out_2_len));
  r_free(out_1);
  r_free(out_2);

  ck_assert_int_ne(_r_inflate_payload(in_1, sizeof(in_1), &out_1, &out_1_len), RHN_OK);
  r_free(out_1);
  ck_assert_int_ne(_r_inflate_payload(in_2, sizeof(in_2), &out_1, &out_1_len), RHN_OK);
  r_free(out_1);
}
END_TEST

START_TEST(test_rhonabwy_invalid_deflate_payload)
{
  jws_t * jws;
  jwe_t * jwe;
  jwk_t * jwk;

  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric), RHN_OK);

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_ne(r_jws_parse(jws, TOKEN_SIGNED_INVALID_ZIP, 0), RHN_OK);

  ck_assert_int_eq(r_jwe_init(&jwe), RHN_OK);
  ck_assert_int_eq(r_jwe_parse(jwe, TOKEN_ENCRYPTED_INVALID_ZIP, 0), RHN_OK);
  ck_assert_int_ne(r_jwe_decrypt(jwe, jwk, 0), RHN_OK);
  
  r_jwk_free(jwk);
  r_jws_free(jws);
  r_jwe_free(jwe);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy misc tests");
  tc_core = tcase_create("test_rhonabwy_misc");
  tcase_add_test(tc_core, test_rhonabwy_info_json_t);
  tcase_add_test(tc_core, test_rhonabwy_info_str);
  tcase_add_test(tc_core, test_rhonabwy_alg_conversion);
  tcase_add_test(tc_core, test_rhonabwy_enc_conversion);
  tcase_add_test(tc_core, test_rhonabwy_inflate);
  tcase_add_test(tc_core, test_rhonabwy_invalid_deflate_payload);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy misc tests");
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
