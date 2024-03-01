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

const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"enc\",\"kid\":\""KID_1"\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                      "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                      "\"use\":\"enc\",\"kid\":\""KID_1"\",\"alg\":\"ES256\"}";
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"kid\":\""KID_2"\"}";
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
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\""KID_2"\"}";
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0Cg\",\"kid\":\""KID_3"\"}";

#define JWS_FLATTENED "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_INVALID_JSON "error\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_MISSING_PAYLOAD "{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_MISSING_PROTECTED "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_INVALID_SIGNATURE "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2NAwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_INVALID_PAYLOAD_B64 "{\"payload\":\"VGhlIHRydWUgc2ln;error;xpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_INVALID_HEADER_B64 "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJh;error;I1NiJ9\",\"signature\":\"V0O2NqwDK3Ovq4ATITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"
#define JWS_FLATTENED_INVALID_SIGNATURE_B64 "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"V0O2Nqw;error;TITgR1GRFEQ8nj_SMvcuhIRWUZMJ2thkNm8jivmc0KzF-iE3aaqy_vyPEvS6544Z6LzCpJw\",\"header\":{\"kid\":\""KID_1"\"}}"

#define JWS_GENERAL "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_INVALID_JSON "error\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_MISSING_PAYLOAD "{\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_INVALID_SIGNATURE "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKAuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_INVALID_SIGNATURE_NO_KID "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\"},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\"},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKAuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\"}]}"
#define JWS_GENERAL_MISSING_PROTECTED "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_MISSING_SIGNATURE "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_INVALID_PAYLOAD_B64 "{\"payload\":\"VGhlIHRydWUgc2ln;error;xpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_INVALID_HEADER_B64 "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJh;error;I1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_SIGNATURE_B64 "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\",\"header\":{\"kid\":\""KID_1"\"}},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\",\"header\":{\"kid\":\""KID_2"\"}},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcw;error;VqS39pNNPC736AaWOyzpTwf0I\",\"header\":{\"kid\":\""KID_3"\"}}]}"
#define JWS_GENERAL_MISSING_KID "{\"payload\":\"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u\",\"signatures\":[{\"protected\":\"eyJhbGciOiJFUzI1NiJ9\",\"signature\":\"M-23B3n2CvCTSOo4QjKuHmchAW0uonm-Tzv99Eb4btt-0CLVU-h_6Kt5mL6OtgIt8YKnUoXQGZcLWUVAcI6HeA\"},{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"rHVAWhXPsq1QYmP9S0R01poEH7d-Y6cN-KUAhFFDQRXqjPeNFL54OrGQKrTCpL_MremwLk3gOLy7L2HlNeawsoD4cLo6_qNDxOQ34S3gB4ti4FW7mFbbiLvwTcZmj88OZoub00Q8mRBWcE1uZOYo3InBNaxNGmK1Bu5l68nFIX04U8-eol_2VlA8Qy6GJ7DTfZEMncn_iBHKSy0Vb19rdFFY2wcrPKYksg8jw4q6i_uGCH0lZ6dY3v0j99AyO2cKPgTDibcTRreYQdYQag1vNrWoVafJkQo8v3sJNtHHjjCfEG6iUQPEJLBBp52o1ID5g8KhwGVuipvwS0_YdlYwnQ\"},{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"GV6JkVcwKSuz2uTOJwVqS39pNNPC736AaWOyzpTwf0I\"}]}"

START_TEST(test_rhonabwy_json_no_key)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_eq(NULL, r_jws_serialize_json_t(jws, NULL, 0, R_JSON_MODE_GENERAL));
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_no_jws)
{
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_ptr_eq(NULL, r_jws_serialize_json_t(NULL, jwks_privkey, 0, R_JSON_MODE_GENERAL));

  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_with_jwks_with_missing_kid)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, "kid"), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, jwks_privkey, 0, R_JSON_MODE_GENERAL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_eq(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_ptr_eq(NULL, json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 2), "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_with_jwks_with_missing_alg)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_delete_property_str(jwk, "alg"), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, jwks_privkey, 0, R_JSON_MODE_GENERAL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_gt(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_with_jwks_with_invalid_alg)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwk_set_property_str(jwk, "alg", "error"), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, jwks_privkey, 0, R_JSON_MODE_GENERAL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_gt(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_with_jwks)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, jwks_privkey, 0, R_JSON_MODE_GENERAL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_eq(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_str_eq(KID_1, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"), "kid")));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 2), "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_without_jwks)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_jwks(jws, jwks_privkey, NULL), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_eq(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_str_eq(KID_1, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"), "kid")));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 2), "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_general_str)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  char * str_result;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_jwks(jws, jwks_privkey, NULL), RHN_OK);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_GENERAL));
  ck_assert_ptr_ne(NULL, j_result = json_loads(str_result, JSON_DECODE_ANY, NULL));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_eq(r_jwks_size(jwks_privkey), json_array_size(json_object_get(j_result, "signatures")));
  ck_assert_str_eq(KID_1, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 0), "header"), "kid")));
  ck_assert_str_eq(KID_2, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 1), "header"), "kid")));
  ck_assert_str_eq(KID_3, json_string_value(json_object_get(json_object_get(json_array_get(json_object_get(j_result, "signatures"), 2), "header"), "kid")));
  
  o_free(str_result);
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_with_jwks)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey;
  json_t * j_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  
  ck_assert_ptr_ne(NULL, j_result = r_jws_serialize_json_t(jws, jwks_privkey, 0, R_JSON_MODE_FLATTENED));
  ck_assert_str_eq("VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u", json_string_value(json_object_get(j_result, "payload")));
  ck_assert_int_gt(json_string_length(json_object_get(j_result, "signature")), 0);
  ck_assert_str_eq(KID_1, json_string_value(json_object_get(json_object_get(j_result, "header"), "kid")));
  
  json_decref(j_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_flattened_error)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_INVALID_JSON, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_MISSING_PAYLOAD, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_MISSING_PROTECTED, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_INVALID_PAYLOAD_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_INVALID_SIGNATURE_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(NULL, JWS_FLATTENED, 0), RHN_ERROR_PARAM);

  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_flattened_str)
{
  jws_t * jws;
  const unsigned char * payload;
  size_t payload_len;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jws_get_payload(jws, &payload_len));
  ck_assert_int_eq(payload_len, o_strlen(PAYLOAD));
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, o_strlen(PAYLOAD)));
  ck_assert_int_eq(R_JWA_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_str_eq(KID_1, r_jws_get_kid(jws));
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_flattened_json_t)
{
  jws_t * jws;
  const unsigned char * payload;
  size_t payload_len;
  json_t * j_jws = json_loads(JWS_FLATTENED, JSON_DECODE_ANY, NULL);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_t(jws, j_jws, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jws_get_payload(jws, &payload_len));
  ck_assert_int_eq(payload_len, o_strlen(PAYLOAD));
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, o_strlen(PAYLOAD)));
  ck_assert_int_eq(R_JWA_ALG_ES256, r_jws_get_alg(jws));
  ck_assert_str_eq(KID_1, r_jws_get_kid(jws));
  r_jws_free(jws);
  json_decref(j_jws);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_verify_signature)
{
  jws_t * jws;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_OK);
  
  r_jwk_free(jwk);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_invalid_signature)
{
  jws_t * jws;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_FLATTENED_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk);
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_general_error)
{
  jws_t * jws;

  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_INVALID_JSON, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_MISSING_PAYLOAD, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_MISSING_PROTECTED, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_INVALID_PAYLOAD_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_MISSING_SIGNATURE, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_SIGNATURE_B64, 0), RHN_ERROR_PARAM);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_general_str)
{
  jws_t * jws;
  const unsigned char * payload;
  size_t payload_len;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jws_get_payload(jws, &payload_len));
  ck_assert_int_eq(payload_len, o_strlen(PAYLOAD));
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, o_strlen(PAYLOAD)));
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_parse_json_general_t)
{
  jws_t * jws;
  const unsigned char * payload;
  size_t payload_len;
  json_t * j_jws = json_loads(JWS_GENERAL, JSON_DECODE_ANY, NULL);
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_t(jws, j_jws, 0), RHN_OK);
  ck_assert_ptr_ne(NULL, payload = r_jws_get_payload(jws, &payload_len));
  ck_assert_int_eq(payload_len, o_strlen(PAYLOAD));
  ck_assert_int_eq(0, memcmp(PAYLOAD, payload, o_strlen(PAYLOAD)));
  r_jws_free(jws);
  json_decref(j_jws);
}
END_TEST

START_TEST(test_rhonabwy_json_general_verify_signature_with_all_public_jwks)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, NULL, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, NULL, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, NULL, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_general_verify_signature_with_one_public_jwks)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, NULL, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_general_verify_signature_with_jwk)
{
  jws_t * jws;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL, 0), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_RS256);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_ES256);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_OK);
  ck_assert_int_eq(r_jws_get_alg(jws), R_JWA_ALG_HS256);
  r_jwk_free(jwk);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_general_invalid_signature)
{
  jws_t * jws;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jws_add_keys_json_str(jws, NULL, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_ERROR_INVALID);
  
  r_jws_free(jws);
}
END_TEST

START_TEST(test_rhonabwy_json_general_verify_signature_with_no_kid)
{
  jws_t * jws;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_MISSING_KID, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_OK);
  
  r_jws_free(jws);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_json_general_invalid_signature_with_no_kid)
{
  jws_t * jws;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, JWS_GENERAL_INVALID_SIGNATURE_NO_KID, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, jwk, 0), RHN_ERROR_INVALID);
  
  r_jws_free(jws);
  r_jwk_free(jwk);
}
END_TEST

START_TEST(test_rhonabwy_json_general_flood)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey, * jwks_pubkey;
  char * str_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_jwks(jws, jwks_privkey, jwks_pubkey), RHN_OK);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_GENERAL));
  o_free(str_result);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_GENERAL));
  o_free(str_result);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_GENERAL));
  
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);

  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  
  o_free(str_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
  r_jwks_free(jwks_pubkey);
}
END_TEST

START_TEST(test_rhonabwy_json_flattened_flood)
{
  jws_t * jws;
  jwk_t * jwk;
  jwks_t * jwks_privkey, * jwks_pubkey;
  char * str_result;
  
  ck_assert_int_eq(r_jws_init(&jws), RHN_OK);
  
  ck_assert_int_eq(r_jwks_init(&jwks_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_privkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_privkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pubkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_ecdsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  ck_assert_int_eq(r_jwk_init(&jwk), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk, jwk_key_symmetric_str), RHN_OK);
  ck_assert_int_eq(r_jwks_append_jwk(jwks_pubkey, jwk), RHN_OK);
  r_jwk_free(jwk);
  
  ck_assert_int_eq(r_jws_set_payload(jws, (const unsigned char *)PAYLOAD, o_strlen(PAYLOAD)), RHN_OK);
  ck_assert_int_eq(r_jws_add_jwks(jws, jwks_privkey, jwks_pubkey), RHN_OK);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_FLATTENED));
  o_free(str_result);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_FLATTENED));
  o_free(str_result);
  
  ck_assert_ptr_ne(NULL, str_result = r_jws_serialize_json_str(jws, NULL, 0, R_JSON_MODE_FLATTENED));
  
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);
  ck_assert_int_eq(r_jws_parse_json_str(jws, str_result, 0), RHN_OK);

  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jws_verify_signature(jws, NULL, 0), RHN_OK);
  
  o_free(str_result);
  r_jws_free(jws);
  r_jwks_free(jwks_privkey);
  r_jwks_free(jwks_pubkey);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Rhonabwy JWS JSON function tests");
  tc_core = tcase_create("test_rhonabwy_json");
  tcase_add_test(tc_core, test_rhonabwy_json_no_key);
  tcase_add_test(tc_core, test_rhonabwy_json_no_jws);
  tcase_add_test(tc_core, test_rhonabwy_json_general_with_jwks_with_missing_kid);
  tcase_add_test(tc_core, test_rhonabwy_json_general_with_jwks_with_missing_alg);
  tcase_add_test(tc_core, test_rhonabwy_json_general_with_jwks_with_invalid_alg);
  tcase_add_test(tc_core, test_rhonabwy_json_general_with_jwks);
  tcase_add_test(tc_core, test_rhonabwy_json_general_without_jwks);
  tcase_add_test(tc_core, test_rhonabwy_json_general_str);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_with_jwks);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_flattened_error);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_flattened_str);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_flattened_json_t);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_verify_signature);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_invalid_signature);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_general_error);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_general_str);
  tcase_add_test(tc_core, test_rhonabwy_parse_json_general_t);
  tcase_add_test(tc_core, test_rhonabwy_json_general_verify_signature_with_all_public_jwks);
  tcase_add_test(tc_core, test_rhonabwy_json_general_verify_signature_with_one_public_jwks);
  tcase_add_test(tc_core, test_rhonabwy_json_general_verify_signature_with_jwk);
  tcase_add_test(tc_core, test_rhonabwy_json_general_invalid_signature);
  tcase_add_test(tc_core, test_rhonabwy_json_general_verify_signature_with_no_kid);
  tcase_add_test(tc_core, test_rhonabwy_json_general_invalid_signature_with_no_kid);
  tcase_add_test(tc_core, test_rhonabwy_json_general_flood);
  tcase_add_test(tc_core, test_rhonabwy_json_flattened_flood);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWS JSON tests");
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
