/**
 * 
 * @file rhonabwy.h
 * @brief Rhonabwy JSON Web Key (JWK) library
 * 
 * rhonabwy.h: structures and functions declarations
 * 
 * Copyright 2020 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifndef __RHONABWY_H_
#define __RHONABWY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "rhonabwy-cfg.h"

#include <jansson.h>
#include <gnutls/gnutls.h>

/**
 * @defgroup const Constants and properties
 * Constant values used as input or output
 * @{
 */

#define RHN_OK                 0
#define RHN_ERROR              1
#define RHN_ERROR_MEMORY       2
#define RHN_ERROR_PARAM        3
#define RHN_ERROR_UNSUPPORTED  4
#define RHN_ERROR_INVALID      5

#define R_X509_TYPE_PUBKEY      1
#define R_X509_TYPE_PRIVKEY     2
#define R_X509_TYPE_CERTIFICATE 3

#define R_FORMAT_PEM 0
#define R_FORMAT_DER 1

#define R_KEY_TYPE_NONE      0x00000000
#define R_KEY_TYPE_PUBLIC    0x00000001
#define R_KEY_TYPE_PRIVATE   0x00000010
#define R_KEY_TYPE_SYMMETRIC 0x00000100
#define R_KEY_TYPE_RSA       0x00001000
#define R_KEY_TYPE_ECDSA     0x00010000
#define R_KEY_TYPE_HMAC      0x00100000
#define R_KEY_TYPE_EDDSA     0x01000000

#define R_FLAG_IGNORE_SERVER_CERTIFICATE 0x00000001
#define R_FLAG_FOLLOW_REDIRECT           0x00000010

#define R_JWT_NESTED_SIGN_THEN_ENCRYPT 0
#define R_JWT_NESTED_ENCRYPT_THEN_SIGN 1

/**
 * @}
 */

/**
 * @defgroup type JWK, JWKS, JWS, JWE type
 * Definition of the types jwk_t, jwks_t, jws_t and jwe_t
 * @{
 */

typedef json_t jwk_t;
typedef json_t jwks_t;

typedef enum {
  R_JWA_ALG_UNKNOWN        = 0,
  R_JWA_ALG_NONE           = 1,
  R_JWA_ALG_HS256          = 2,
  R_JWA_ALG_HS384          = 3,
  R_JWA_ALG_HS512          = 4,
  R_JWA_ALG_RS256          = 5,
  R_JWA_ALG_RS384          = 6,
  R_JWA_ALG_RS512          = 7,
  R_JWA_ALG_ES256          = 8,
  R_JWA_ALG_ES384          = 9,
  R_JWA_ALG_ES512          = 10,
  R_JWA_ALG_EDDSA          = 11,
  R_JWA_ALG_PS256          = 12,
  R_JWA_ALG_PS384          = 13,
  R_JWA_ALG_PS512          = 14,
  R_JWA_ALG_RSA1_5         = 15,
  R_JWA_ALG_RSA_OAEP       = 16,
  R_JWA_ALG_RSA_OAEP_256   = 17,
  R_JWA_ALG_A128KW         = 18,
  R_JWA_ALG_A192KW         = 19,
  R_JWA_ALG_A256KW         = 20,
  R_JWA_ALG_DIR            = 21,
  R_JWA_ALG_ECDH_ES        = 22,
  R_JWA_ALG_ECDH_ES_A128KW = 23,
  R_JWA_ALG_ECDH_ES_A192KW = 24,
  R_JWA_ALG_ECDH_ES_A256KW = 25,
  R_JWA_ALG_A128GCMKW      = 26,
  R_JWA_ALG_A192GCMKW      = 27,
  R_JWA_ALG_A256GCMKW      = 28,
  R_JWA_ALG_PBES2_H256     = 29,
  R_JWA_ALG_PBES2_H384     = 30,
  R_JWA_ALG_PBES2_H512     = 31
} jwa_alg;

typedef enum {
  R_JWA_ENC_UNKNOWN = 0,
  R_JWA_ENC_A128CBC = 1,
  R_JWA_ENC_A192CBC = 2,
  R_JWA_ENC_A256CBC = 3,
  R_JWA_ENC_A128GCM = 4,
  R_JWA_ENC_A192GCM = 5,
  R_JWA_ENC_A256GCM = 6
} jwa_enc;

typedef struct {
  unsigned char * header_b64url;
  unsigned char * payload_b64url;
  unsigned char * signature_b64url;
  json_t        * j_header;
  jwa_alg         alg;
  jwks_t        * jwks_privkey;
  jwks_t        * jwks_pubkey;
  unsigned char * payload;
  size_t          payload_len;
} jws_t;

typedef struct {
  unsigned char * header_b64url;
  unsigned char * encrypted_key_b64url;
  unsigned char * iv_b64url;
  unsigned char * ciphertext_b64url;
  unsigned char * auth_tag_b64url;
  json_t        * j_header;
  jwa_alg         alg;
  jwa_enc         enc;
  jwks_t        * jwks_privkey;
  jwks_t        * jwks_pubkey;
  unsigned char * key;
  size_t          key_len;
  unsigned char * iv;
  size_t          iv_len;
  unsigned char * payload;
  size_t          payload_len;
} jwe_t;

typedef struct {
  json_t * j_header;
  json_t * j_claims;
  jws_t  * jws;
  jwe_t  * jwe;
  jwa_alg  sign_alg;
  jwa_alg  enc_alg;
  jwa_enc  enc;
  jwks_t * jwks_privkey_sign;
  jwks_t * jwks_pubkey_sign;
  jwks_t * jwks_privkey_enc;
  jwks_t * jwks_pubkey_enc;
} jwt_t;

/**
 * @}
 */

/**
 * @defgroup core Core functions
 * Core functions used to initialize or free jwk_t
 * and check if a jwk is valid and its type
 * @{
 */

/**
 * Get the library information as a json_t * object
 * - library version
 * - supported JWS algorithms
 * - supported JWE algorithms
 * @return the library information
 */
json_t * r_library_info_json_t();

/**
 * Get the library information as a JSON object in string format
 * - library version
 * - supported JWS algorithms
 * - supported JWE algorithms
 * @return the library information, must be r_free'd after use
 */
char * r_library_info_json_str();

/**
 * Free a heap allocated variable
 * previously returned by a rhonabwy function
 * @param data: the data to free
 */
void r_free(void * data);

/**
 * Initialize a jwk_t
 * @param jwk: a reference to a jwk_t * to initialize
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_init(jwk_t ** jwk);

/**
 * Free a jwk_t
 * @param jwk: the jwk_t * to free
 */
void r_jwk_free(jwk_t * jwk);

/**
 * Initialize a jwks_t
 * @param jwks: a reference to a jwks_t * to initialize
 * @return RHN_OK on success, an error value on error
 */
int r_jwks_init(jwks_t ** jwks);

/**
 * Free a jwks_t
 * @param jwks: the jwks_t * to free
 */
void r_jwks_free(jwks_t * jwks);

/**
 * Initialize a jws_t
 * @param jws: a reference to a jws_t * to initialize
 * @return RHN_OK on success, an error value on error
 */
int r_jws_init(jws_t ** jws);

/**
 * Free a jws_t
 * @param jws: the jws_t * to free
 */
void r_jws_free(jws_t * jws);

/**
 * Initialize a jwe_t
 * @param jwe: a reference to a jwe_t * to initialize
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_init(jwe_t ** jwe);

/**
 * Free a jwe_t
 * @param jwe: the jwe_t * to free
 */
void r_jwe_free(jwe_t * jwe);

/**
 * Initialize a jwt_t
 * @param jwt: a reference to a jwt_t * to initialize
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_init(jwt_t ** jwt);

/**
 * Free a jwt_t
 * @param jwt: the jwt_t * to free
 */
void r_jwt_free(jwt_t * jwt);

/**
 * Get the type and algorithm of a jwk_t
 * @param jwk: the jwk_t * to test
 * @param bits: set the key size in bits (may be NULL)
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return an integer containing 
 * - R_KEY_TYPE_NONE if the jwk is invalid
 * * the type:
 * - R_KEY_TYPE_PUBLIC: for a public key
 * - R_KEY_TYPE_PRIVATE: for a private key
 * - R_KEY_TYPE_SYMMETRIC: for a symmetrick key
 * * the algorithm used
 * - R_KEY_TYPE_RSA: for a RSA key
 * - R_KEY_TYPE_ECDSA: for a EC key
 * - R_KEY_TYPE_HMAC: for a HMAC key
 * You must test the result value with bitwise operator
 * Ex: if (r_jwk_key_type(jwk) & R_KEY_TYPE_PUBLIC) {
 *     if (r_jwk_key_type(jwk) & R_KEY_TYPE_RSA) {
 * You can combine type and algorithm values in the bitwise operator
 * Ex: if (r_jwk_key_type(jwk) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE)) {
 */
int r_jwk_key_type(jwk_t * jwk, unsigned int * bits, int x5u_flags);

/**
 * Check if the jwk is valid
 * @param jwk: the jwk_t * to test
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_is_valid(jwk_t * jwk);

/**
 * Check if the jwks is valid
 * @param jwks: the jwks_t * to test
 * @return RHN_OK on success, an error value on error
 * Stops at the first error in the array
 * Logs error message with yder on error
 */
int r_jwks_is_valid(jwks_t * jwks);

/**
 * Generates a pair of private and public key using given parameters
 * @param jwk_privkey: the private key to set, must be initialized
 * @param jwk_pubkey: the public key to set, must be initialized
 * @param type: the type of key, values available are
 * R_KEY_TYPE_RSA or R_KEY_TYPE_ECDSA
 * @param bits: the key size to generate, if the key type is R_KEY_TYPE_ECDSA,
 * the key size is the curve length: 256, 384 or 512
 * @param kid: the key ID to set to the JWKs, if NULL or empty, will be set automatically
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_generate_key_pair(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int type, unsigned int bits, const char * kid);

/**
 * Get the jwa_alg corresponding to the string algorithm specified
 * @param alg: the algorithm to convert
 * @return the converted jwa_alg, R_JWA_ALG_NONE if alg is unknown
 */
jwa_alg str_to_jwa_alg(const char * alg);

/**
 * Get the jwa_enc corresponding to the string algorithm specified
 * @param enc: the algorithm to convert
 * @return the converted jwa_enc, R_JWA_ENC_NONE if enc is unknown
 */
jwa_enc str_to_jwa_enc(const char * enc);

/**
 * @}
 */

/**
 * @defgroup properties Properties
 * read/write/delete jwk properties
 * @{
 */

/**
 * Get a property value from a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to retrieve
 * @return the property value on success, NULL on error
 */
const char * r_jwk_get_property_str(jwk_t * jwk, const char * key);

/**
 * Get a property value of an array from a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to retrieve
 * @param index: the index of the value to retrieve in the array
 * @return the property value on success, NULL on error
 */
const char * r_jwk_get_property_array(jwk_t * jwk, const char * key, size_t index);

/**
 * Set a property value into a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to set
 * @param value: the value of the property to set
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_set_property_str(jwk_t * jwk, const char * key, const char * value);

/**
 * Set a property value on an array into a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to set
 * @param index: the index of the value to set in the array
 * @param value: the value of the property to set
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_set_property_array(jwk_t * jwk, const char * key, size_t index, const char * value);

/**
 * Append a property value on an array into a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to set
 * @param value: the value of the property to set
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_append_property_array(jwk_t * jwk, const char * key, const char * value);

/**
 * Delete a property from a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to delete
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_delete_property_str(jwk_t * jwk, const char * key);

/**
 * Delete an array property from a jwk_t
 * @param jwk: the jwk_t * to get
 * @param key: the key of the property to delete
 * @param index: the index of the value to set in the array
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_delete_property_array_at(jwk_t * jwk, const char * key, size_t index);

/**
 * @}
 */

/**
 * @defgroup import Import functions
 * Import a jwk from JSON data, gnutls inner types or PEM/DER
 * @{
 */

/**
 * Import a JSON in string format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param input: a JWK in JSON stringified format
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_json_str(jwk_t * jwk, const char * input);

/**
 * Import a JSON in json_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param j_input: a JWK in json_t * format
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_json_t(jwk_t * jwk, json_t * j_input);

/**
 * Import a public or private key or a X509 certificate in PEM or DER format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param type: the type of the input, values available are R_X509_TYPE_PUBKEY, R_X509_TYPE_PRIVKEY or R_X509_TYPE_CERTIFICATE
 * @param format: the format of the input, values available are R_FORMAT_PEM or R_FORMAT_DER
 * @param input: the input value, must contain the key or the certificate in PEM or DER format
 * @param input_len: the length of the data contained in input
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_pem_der(jwk_t * jwk, int type, int format, const unsigned char * input, size_t input_len);

/**
 * Import a GnuTLS private key in gnutls_privkey_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param key: the private key to be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_gnutls_privkey(jwk_t * jwk, gnutls_privkey_t key);

/**
 * Import a GnuTLS public key in gnutls_pubkey_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param pub: the public key to be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_gnutls_pubkey(jwk_t * jwk, gnutls_pubkey_t pub);

/**
 * Import a GnuTLS X509 certificate in gnutls_x509_crt_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param crt: the X509 certificate whose public key will be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_gnutls_x509_crt(jwk_t * jwk, gnutls_x509_crt_t crt);

/**
 * Import a certificate from an URL
 * @param jwk: the jwk_t * to import to
 * @param type: the type of the input, values available are R_X509_TYPE_PUBKEY, R_X509_TYPE_PRIVKEY or R_X509_TYPE_CERTIFICATE
 * @param x5u_flags: Flags to retrieve certificates
 * @param x5u: the url to retreive the certificate
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_x5u(jwk_t * jwk, int type, int x5u_flags, const char * x5u);

/**
 * Import a symmetric key into a jwk
 * The key will be converted to base64url format
 * @param jwk: the jwk_t * to import to
 * @param key: the key to import
 * @param key_len: the size of the key
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_import_from_symmetric_key(jwk_t * jwk, const unsigned char * key, size_t key_len);

/**
 * Extract the public key from the private key jwk_privkey and set it into jwk_pubkey
 * @param jwk_privkey: the jwt containing a private key
 * @param jwk_pubkey: the jwt that will be set with the public key data
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwk_extract_pubkey(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int x5u_flags);

/**
 * Return a copy of the JWK
 * @param jwk: the jwk to copy
 * @return a copy of the jwk
 */
jwk_t * r_jwk_copy(jwk_t * jwk);

/**
 * Compare 2 jwk
 * @param jwk1: the first JWK to compare
 * @param jwk2: the second JWK to compare
 * @return 1 if both jwk1 and jwk2 are equal, 0 otherwise
 */
int r_jwk_equal(jwk_t * jwk1, jwk_t * jwk2);

/**
 * @}
 */

/**
 * @defgroup export Export functions
 * Export a jwk to JSON data, gnutls inner types or PEM/DER
 * @{
 */

/**
 * Export a jwk_t into a stringified JSON format
 * @param jwk: the jwk_t * to export
 * @param pretty: indent or compact JSON output
 * @return a char * on success, NULL on error, must be r_free'd after use
 */
char * r_jwk_export_to_json_str(jwk_t * jwk, int pretty);

/**
 * Export a jwk_t into a json_t format
 * @param jwk: the jwk_t * to export
 * @return a json_t * on success, NULL on error
 */
json_t * r_jwk_export_to_json_t(jwk_t * jwk);

/**
 * Export a jwk_t into a gnutls_privkey_t format
 * @param jwk: the jwk_t * to export
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a gnutls_privkey_t on success, NULL on error
 */
gnutls_privkey_t r_jwk_export_to_gnutls_privkey(jwk_t * jwk, int x5u_flags);

/**
 * Export a jwk_t into a gnutls_pubkey_t format
 * @param jwk: the jwk_t * to export
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a gnutls_pubkey_t on success, NULL on error
 */
gnutls_pubkey_t r_jwk_export_to_gnutls_pubkey(jwk_t * jwk, int x5u_flags);

/**
 * Export a jwk_t into a DER or PEM format
 * @param jwk: the jwk_t * to export
 * @param format: the format of the outpu, values available are R_FORMAT_PEM or R_FORMAT_DER
 * @param output: an unsigned char * that will contain the output
 * @param output_len: the size of output and will be set to the data size that has been written to output
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 * @return RHN_ERROR_PARAM if output_len isn't large enough to hold the output, then output_len will be set to the required size
 */
int r_jwk_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len, int x5u_flags);

/**
 * Export a jwk_t into a symmetric key in binary format
 * @param jwk: the jwk_t * to export
 * @param key: an unsigned char * that will contain the key
 * @param key_len: the size of key and will be set to the data size that has been written to output
 * @return RHN_OK on success, an error value on error
 * @return RHN_ERROR_PARAM if output_len isn't large enough to hold the output, then output_len will be set to the required size
 */
int r_jwk_export_to_symmetric_key(jwk_t * jwk, unsigned char * key, size_t * key_len);

/**
 * @}
 */

/**
 * @defgroup jwks JWKS functions
 * Manage JWK sets
 * @{
 */

/**
 * Import a JWKS in string format into a jwks_t
 * @param jwks: the jwk_t * to import to
 * @param input: a JWKS in JSON stringified format
 * If jwks is set, JWK will be appended
 * @return RHN_OK on success, an error value on error
 * may return RHN_ERROR_PARAM if at least one JWK 
 * is invalid, but the will import the others
 */
int r_jwks_import_from_str(jwks_t * jwks, const char * input);

/**
 * Import a JWKS in json_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param j_input: a JWK in json_t * format
 * If jwks is set, JWK will be appended
 * @return RHN_OK on success, an error value on error
 * may return RHN_ERROR_PARAM if at least one JWK 
 * is invalid, but the will import the others
 */
int r_jwks_import_from_json_t(jwks_t * jwks, json_t * j_input);

/**
 * Import a JWKS from an uri
 * @param jwk: the jwk_t * to import to
 * @param uri: an uri pointing to a JWKS
 * If jwks is set, JWK will be appended
 * @param flags: Flags to retrieve certificates
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 * may return RHN_ERROR_PARAM if at least one JWK 
 * is invalid, but the will import the others
 */
int r_jwks_import_from_uri(jwks_t * jwks, const char * uri, int flags);

/**
 * Return a copy of the JWKS
 * @param jwks: the jwks to copy
 * @return a copy of the jwks
 */
jwks_t * r_jwks_copy(jwks_t * jwks);

/**
 * Get the number of jwk_t in a jwks_t
 * @param jwk: the jwks_t * to evaluate
 * @return the number of jwk_t in a jwks_t
 */
size_t r_jwks_size(jwks_t * jwks);

/**
 * Get the jwk_t at the specified index of the jwks_t *
 * @param jwks: the jwks_t * to evaluate
 * @param index: the index of the array to retrieve
 * @return a jwk_t * on success, NULL on error
 * The returned jwk must be r_jwk_free after use
 */
jwk_t * r_jwks_get_at(jwks_t * jwks, size_t index);

/**
 * Get the jwk_t at the specified index of the jwks_t *
 * @param jwks: the jwks_t * to evaluate
 * @param kid: the key id of the jwk to retreive
 * @return a jwk_t * on success, NULL on error
 * The returned jwk must be r_jwk_free after use
 */
jwk_t * r_jwks_get_by_kid(jwks_t * jwks, const char * kid);

/**
 * Append a jwk_t at the end of the array of jwk_t in the jwks_t
 * @param jwks: the jwks_t * to append the jwk_t
 * @param jwk: the jwk_t * to be appended
 * @return RHN_OK on success, an error value on error
 */
int r_jwks_append_jwk(jwks_t * jwks, jwk_t * jwk);

/**
 * Update a jwk_t at the specified index of the jwks_t *
 * @param jwks: the jwks_t * to evaluate
 * @param jwk: the jwk_t * to set
 * @param index: the index of the array to update
 * @return RHN_OK on success, an error value on error
 */
int r_jwks_set_at(jwks_t * jwks, size_t index, jwk_t * jwk);

/**
 * Remove a jwk_t at the specified index of the jwks_t *
 * @param jwks: the jwks_t * to evaluate
 * @param index: the index of the array to remove
 * @return RHN_OK on success, an error value on error
 */
int r_jwks_remove_at(jwks_t * jwks, size_t index);

/**
 * Empty a JWKS
 * @param jwks: the jwks_t * to update
 * @return RHN_OK on success, an error value on error
 */
int r_jwks_empty(jwks_t * jwks);

/**
 * Compare 2 jwks
 * The key content and order are compared
 * @param jwks1: the first JWKS to compare
 * @param jwks2: the second JWKS to compare
 * @return 1 if both jwks1 and jwks2 are equal, 0 otherwise
 */
int r_jwks_equal(jwks_t * jwks1, jwks_t * jwks2);

/**
 * Export a jwks_t into a stringified JSON format
 * @param jwk: the jwks_t * to export
 * @param pretty: indent or compact JSON output
 * @return a char * on success, NULL on error, must be r_free'd after use
 */
char * r_jwks_export_to_json_str(jwks_t * jwks, int pretty);

/**
 * Export a jwk_t into a json_t format
 * @param jwk: the jwk_t * to export
 * @return a json_t * on success, NULL on error
 */
json_t * r_jwks_export_to_json_t(jwks_t * jwks);

/**
 * Export a jwks_t into a gnutls_privkey_t format
 * @param jwk: the jwks_t * to export
 * @param len: set the length of the output array
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a heap-allocated gnutls_privkey_t * on success, NULL on error
 * an index of the returned array may be NULL if the corresponding jwk isn't a private key
 */
gnutls_privkey_t * r_jwks_export_to_gnutls_privkey(jwks_t * jwks, size_t * len, int x5u_flags);

/**
 * Export a jwks_t into a gnutls_pubkey_t format
 * @param jwk: the jwks_t * to export
 * @param len: set the length of the output array
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a heap-allocated gnutls_pubkey_t * on success, NULL on error
 */
gnutls_pubkey_t * r_jwks_export_to_gnutls_pubkey(jwks_t * jwks, size_t * len, int x5u_flags);

/**
 * Export a jwks_t into a DER or PEM format
 * @param jwk: the jwks_t * to export
 * @param format: the format of the outpu, values available are R_FORMAT_PEM or R_FORMAT_DER
 * @param output: an unsigned char * that will contain the output
 * @param output_len: the size of output and will be set to the data size that has been written to output
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 * @return RHN_ERROR_PARAM if output_len isn't large enough to hold the output, then output_len will be set to the required size
 */
int r_jwks_export_to_pem_der(jwks_t * jwks, int format, unsigned char * output, size_t * output_len, int x5u_flags);

/**
 * @}
 */

/**
 * @defgroup jws JWS functions
 * Manage JSON Web Signatures
 * @{
 */

/**
 * Return a copy of the JWS
 * @param jws: the jws_t to duplicate
 * @return a copy of jws
 */
jws_t * r_jws_copy(jws_t * jws);

/**
 * Set the payload of the jws
 * @param jws: the jws_t to update
 * @param payload: the payload to set
 * @param payload_len: the size of the payload
 * @return RHN_OK on success, an error value on error
 */
int r_jws_set_payload(jws_t * jws, const unsigned char * payload, size_t payload_len);

/**
 * Get the JWS payload
 * @param jws: the jws_t to get the payload from
 * @param payload_len: the length of the JWS payload, may be NULL
 * @return a pointer to the JWS payload
 */
const unsigned char * r_jws_get_payload(jws_t * jws, size_t * payload_len);

/**
 * Set the JWS alg to use for signature
 * @param jws: the jws_t to update
 * @param alg: the algorithm to use
 * @return RHN_OK on success, an error value on error
 */
int r_jws_set_alg(jws_t * jws, jwa_alg alg);

/**
 * Get the JWS alg used for signature
 * @param jws: the jws_t to update
 * @return the algorithm used
 */
jwa_alg r_jws_get_alg(jws_t * jws);

/**
 * Adds a string value to the JWS header
 * @param jws: the jws_t to update
 * @param key: the key to set to the JWS header
 * @param str_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jws_set_header_str_value(jws_t * jws, const char * key, const char * str_value);

/**
 * Adds an integer value to the JWS header
 * @param jws: the jws_t to update
 * @param key: the key to set to the JWS header
 * @param i_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jws_set_header_int_value(jws_t * jws, const char * key, int i_value);

/**
 * Adds a JSON value to the JWS header
 * @param jws: the jws_t to update
 * @param key: the key to set to the JWS header
 * @param j_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jws_set_header_json_t_value(jws_t * jws, const char * key, json_t * j_value);

/**
 * Gets a string value from the JWS header
 * @param jws: the jws_t to get the value
 * @param key: the key to retreive the value
 * @return a string value, NULL if not present
 */
const char * r_jws_get_header_str_value(jws_t * jws, const char * key);

/**
 * Gets an integer value from the JWS header
 * @param jws: the jws_t to get the value
 * @param key: the key to retreive the value
 * @return an int value, 0 if not present
 */
int r_jws_get_header_int_value(jws_t * jws, const char * key);

/**
 * Gets a JSON value from the JWS header
 * @param jws: the jws_t to get the value
 * @param key: the key to retreive the value
 * @return a json_t * value, NULL if not present
 */
json_t * r_jws_get_header_json_t_value(jws_t * jws, const char * key);

/**
 * Return the full JWS header in JSON format
 * @param jws: the jws_t to get the value
 * @return a json_t * value
 */
json_t * r_jws_get_full_header_json_t(jws_t * jws);

/**
 * Sets the private and public keys for the signature and verification
 * @param jws: the jws_t to update
 * @param jwk_privkey: the private key in jwk_t * format, can be NULL
 * @param jwk_pubkey: the public key in jwk_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jws_add_keys(jws_t * jws, jwk_t * jwk_privkey, jwk_t * jwk_pubkey);

/**
 * Adds private and/or public keys sets for the signature and verification
 * @param jws: the jws_t to update
 * @param jwks_privkey: the private key set in jwk_t * format, can be NULL
 * @param jwks_pubkey: the public key set in jwk_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jws_add_jwks(jws_t * jws, jwks_t * jwks_privkey, jwks_t * jwks_pubkey);

/**
 * Get private keys set for the signature
 * @param jws: the jws_t to get the value
 * @return the private key set in jwks_t * format
 */
jwks_t * r_jws_get_jwks_privkey(jws_t * jws);

/**
 * Get public keys set for the verification
 * @param jws: the jws_t to get the value
 * @return the public key set in jwks_t * format
 */
jwks_t * r_jws_get_jwks_pubkey(jws_t * jws);

/**
 * Parses the JWS, verify the signature if the JWS header contains the public key
 * @param jws: the jws_t to update
 * @param jws_str: the jws serialized to parse
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jws_parse(jws_t * jws, const char * jws_str, int x5u_flags);

/**
 * Verifies the signature of the JWS
 * The JWS must contain a signature
 * or the JWS must have alg: none
 * @param jws: the jws_t to update
 * @param jwk_pubkey: the public key to check the signature,
 * can be NULL if jws already contains a public key
 * @return RHN_OK on success, an error value on error
 */
int r_jws_verify_signature(jws_t * jws, jwk_t * jwk_pubkey, int x5u_flags);

/**
 * Serialize a JWS into its string format (xxx.yyy.zzz)
 * @param jws: the JWS to serialize
 * @param jwk_privkey: the private key to use to sign the JWS
 * can be NULL if jws already contains a private key
 * @return the JWS in serialized format, returned value must be r_free'd after use
 */
char * r_jws_serialize(jws_t * jws, jwk_t * jwk_privkey, int x5u_flags);

/**
 * @}
 */

/**
 * @defgroup jwe JWE functions
 * Manage JSON Web Encryption
 * @{
 */

/**
 * Return a copy of the JWE
 * @param jwe: the jwe_t to duplicate
 * @return a copy of jwe
 */
jwe_t * r_jwe_copy(jwe_t * jwe);

/**
 * Set the payload of the jwe
 * @param jwe: the jwe_t to update
 * @param payload: the payload to set
 * @param payload_len: the size of the payload
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_payload(jwe_t * jwe, const unsigned char * payload, size_t payload_len);

/**
 * Get the JWE payload
 * @param jwe: the jwe_t to get the payload from
 * @param payload_len: the length of the JWE payload, may be NULL
 * @return a pointer to the JWE payload
 */
const unsigned char * r_jwe_get_payload(jwe_t * jwe, size_t * payload_len);

/**
 * Set the JWE alg to use for key encryption
 * @param jwe: the jwe_t to update
 * @param alg: the algorithm to use
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_alg(jwe_t * jwe, jwa_alg alg);

/**
 * Get the JWE alg used for key encryption
 * @param jwe: the jwe_t to update
 * @return the algorithm used
 */
jwa_alg r_jwe_get_alg(jwe_t * jwe);

/**
 * Set the JWE enc to use for payload encryption
 * @param jwe: the jwe_t to update
 * @param enc: the encorithm to use
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_enc(jwe_t * jwe, jwa_enc enc);

/**
 * Get the JWE enc used for payload encryption
 * @param jwe: the jwe_t to update
 * @return the encorithm used
 */
jwa_enc r_jwe_get_enc(jwe_t * jwe);

/**
 * Adds a string value to the JWE header
 * @param jwe: the jwe_t to update
 * @param key: the key to set to the JWE header
 * @param str_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_header_str_value(jwe_t * jwe, const char * key, const char * str_value);

/**
 * Adds an integer value to the JWE header
 * @param jwe: the jwe_t to update
 * @param key: the key to set to the JWE header
 * @param i_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_header_int_value(jwe_t * jwe, const char * key, int i_value);

/**
 * Adds a JSON value to the JWE header
 * @param jwe: the jwe_t to update
 * @param key: the key to set to the JWE header
 * @param j_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_header_json_t_value(jwe_t * jwe, const char * key, json_t * j_value);

/**
 * Gets a string value from the JWE header
 * @param jwe: the jwe_t to get the value
 * @param key: the key to retreive the value
 * @return a string value, NULL if not present
 */
const char * r_jwe_get_header_str_value(jwe_t * jwe, const char * key);

/**
 * Gets an integer value from the JWE header
 * @param jwe: the jwe_t to get the value
 * @param key: the key to retreive the value
 * @return an int value, 0 if not present
 */
int r_jwe_get_header_int_value(jwe_t * jwe, const char * key);

/**
 * Gets a JSON value from the JWE header
 * @param jwe: the jwe_t to get the value
 * @param key: the key to retreive the value
 * @return a json_t * value, NULL if not present
 */
json_t * r_jwe_get_header_json_t_value(jwe_t * jwe, const char * key);

/**
 * Return the full JWE header in JSON format
 * @param jwe: the jwe_t to get the value
 * @return a json_t * value
 */
json_t * r_jwe_get_full_header_json_t(jwe_t * jwe);

/**
 * Adds private and/or public keys for the cypher key encryption and decryption
 * @param jwe: the jwe_t to update
 * @param jwk_privkey: the private key in jwk_t * format, can be NULL
 * @param jwk_pubkey: the public key in jwk_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_add_keys(jwe_t * jwe, jwk_t * jwk_privkey, jwk_t * jwk_pubkey);

/**
 * Adds private and/or public keys sets for the cypher key encryption and decryption
 * @param jwe: the jwe_t to update
 * @param jwks_privkey: the private key set in jwks_t * format, can be NULL
 * @param jwks_pubkey: the public key set in jwks_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_add_jwks(jwe_t * jwe, jwks_t * jwks_privkey, jwks_t * jwks_pubkey);

/**
 * Get private keys set for the cypher key decryption
 * @param jwe: the jwe_t to get the value
 * @return the private key set in jwks_t * format
 */
jwks_t * r_jwe_get_jwks_privkey(jwe_t * jwe);

/**
 * Get public keys set for the cypher key encryption
 * @param jwe: the jwe_t to get the value
 * @return the public key set in jwks_t * format
 */
jwks_t * r_jwe_get_jwks_pubkey(jwe_t * jwe);

/**
 * Sets the cypher key to encrypt or decrypt the payload
 * @param jwe: the jwe_t to update
 * @param key: the key to encrypt or decrypt the payload
 * @param key_len: the size of the key
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_cypher_key(jwe_t * jwe, const unsigned char * key, size_t key_len);

/**
 * Gets the cypher key to encrypt or decrypt the payload
 * @param jwe: the jwe_t to get the value
 * @param key_len: set the size of the key, may be NULL
 * @param enc: the enc type to use
 * @return the key to encrypt or decrypt the payload
 */
const unsigned char * r_jwe_get_cypher_key(jwe_t * jwe, size_t * key_len);

/**
 * Generates a random cypher key
 * @param jwe: the jwe_t to update
 * @param bits: the size of the key
 * @param enc: the enc type
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_generate_cypher_key(jwe_t * jwe);

/**
 * Sets the Initialization Vector (iv)
 * @param jwe: the jwe_t to update
 * @param iv: the iv to set
 * @param iv_len: the size of the iv
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_set_iv(jwe_t * jwe, const unsigned char * iv, size_t iv_len);

/**
 * Gets the Initialization Vector (iv)
 * @param jwe: the jwe_t to get the value
 * @param iv_len: set the size of the iv, may be NULL
 * @return the iv
 */
const unsigned char * r_jwe_get_iv(jwe_t * jwe, size_t * iv_len);

/**
 * Generates a random Initialization Vector (iv)
 * @param jwe: the jwe_t to update
 * @param length: the size of the iv
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_generate_iv(jwe_t * jwe);

/**
 * Encrypts the payload using its key and iv
 * @param jwe: the jwe_t to update
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_encrypt_payload(jwe_t * jwe);

/**
 * Decrypts the payload using its key and iv
 * @param jwe: the jwe_t to update
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_decrypt_payload(jwe_t * jwe);

/**
 * Encrypts the key
 * @param jwe: the jwe_t to update
 * @param jwk_pubkey: the jwk to encrypt the key, may be NULL
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_encrypt_key(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags);

/**
 * Decrypts the key
 * @param jwe: the jwe_t to update
 * @param jwk_privkey: the jwk to decrypt the key, may be NULL
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_decrypt_key(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags);

/**
 * Parses the JWE
 * @param jwe: the jwe_t to update
 * @param jwe_str: the jwe serialized to parse
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_parse(jwe_t * jwe, const char * jwe_str, int x5u_flags);

/**
 * Decrypts the payload of the JWE
 * @param jwe: the jwe_t to update
 * @param jwk_privkey: the private key to decrypt cypher key,
 * can be NULL if jwe already contains a private key
 * @return RHN_OK on success, an error value on error
 */
int r_jwe_decrypt(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags);

/**
 * Serialize a JWE into its string format (aaa.bbb.ccc.xxx.yyy.zzz)
 * @param jwe: the JWE to serialize
 * @param jwk_pubkey: the public key to encrypt the cypher key,
 * can be NULL if jwe already contains a public key
 * @return the JWE in serialized format, returned value must be r_free'd after use
 */
char * r_jwe_serialize(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags);

/**
 * @}
 */

/**
 * @defgroup jwt JWT functions
 * Manage JSON Web Token
 * @{
 */

/**
 * Return a copy of the JWT
 * @param jwt: the jwt_t to duplicate
 * @return a copy of jwt
 */
jwt_t * r_jwt_copy(jwt_t * jwt);

/**
 * Adds a string value to the JWT header
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT header
 * @param str_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_header_str_value(jwt_t * jwt, const char * key, const char * str_value);

/**
 * Adds an integer value to the JWT header
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT header
 * @param i_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_header_int_value(jwt_t * jwt, const char * key, int i_value);

/**
 * Adds a JSON value to the JWT header
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT header
 * @param j_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_header_json_t_value(jwt_t * jwt, const char * key, json_t * j_value);

/**
 * Gets a string value from the JWT header
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return a string value, NULL if not present
 */
const char * r_jwt_get_header_str_value(jwt_t * jwt, const char * key);

/**
 * Gets an integer value from the JWT header
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return an int value, 0 if not present
 */
int r_jwt_get_header_int_value(jwt_t * jwt, const char * key);

/**
 * Gets a JSON value from the JWT header
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return a json_t * value, NULL if not present
 */
json_t * r_jwt_get_header_json_t_value(jwt_t * jwt, const char * key);

/**
 * Return the full JWT header in JSON format
 * @param jwt: the jwt_t to get the value
 * @return a json_t * value
 */
json_t * r_jwt_get_full_header_json_t(jwt_t * jwt);

/**
 * Return the full JWT header in char * 
 * @param jwt: the jwt_t to get the value
 * @return a char * value, must be r_free'd after use
 */
char * r_jwt_get_full_header_str(jwt_t * jwt);

/**
 * Adds a string value to the JWT claim
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT claim
 * @param str_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_claim_str_value(jwt_t * jwt, const char * key, const char * str_value);

/**
 * Adds an integer value to the JWT claim
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT claim
 * @param i_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_claim_int_value(jwt_t * jwt, const char * key, int i_value);

/**
 * Adds a JSON value to the JWT claim
 * @param jwt: the jwt_t to update
 * @param key: the key to set to the JWT claim
 * @param j_value: the value to set
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_claim_json_t_value(jwt_t * jwt, const char * key, json_t * j_value);

/**
 * Gets a string value from the JWT claim
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return a string value, NULL if not present
 */
const char * r_jwt_get_claim_str_value(jwt_t * jwt, const char * key);

/**
 * Gets an integer value from the JWT claim
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return an int value, 0 if not present
 */
int r_jwt_get_claim_int_value(jwt_t * jwt, const char * key);

/**
 * Gets a JSON value from the JWT claim
 * @param jwt: the jwt_t to get the value
 * @param key: the key to retreive the value
 * @return a json_t * value, NULL if not present
 */
json_t * r_jwt_get_claim_json_t_value(jwt_t * jwt, const char * key);

/**
 * Return the full JWT claim in JSON format
 * @param jwt: the jwt_t to get the value
 * @return a json_t * value
 */
json_t * r_jwt_get_full_claims_json_t(jwt_t * jwt);

/**
 * Return the full JWT claims in char *
 * @param jwt: the jwt_t to get the value
 * @return a char * value, must be r_free'd after use
 */
char * r_jwt_get_full_claims_str(jwt_t * jwt);

/**
 * Set the full JWT claim in JSON format
 * delete all existing value
 * @param jwt: the jwt_t to get the value
 * @param j_claim: the claim to set, must be JSON object
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_full_claims_json_t(jwt_t * jwt, json_t * j_claim);

/**
 * Append the given JSON object in the JWT payload
 * Replace existing claim if already set
 * @param jwt: the jwt_t to get the value
 * @param j_claim: the payload to set, must be JSON object
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_append_claims_json_t(jwt_t * jwt, json_t * j_claim);

/**
 * Add keys to perform signature or signature verification to the JWT
 * @param jwt: the jwt_t to update
 * @param privkey: the private key to sign the JWT
 * @param pubkey: the public key to verify the JWT signature
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_add_sign_keys(jwt_t * jwt, jwk_t * privkey, jwk_t * pubkey);

/**
 * Adds private and/or public keys sets for the signature and verification
 * @param jwt: the jwt_t to update
 * @param jwks_privkey: the private key set in jwk_t * format, can be NULL
 * @param jwks_pubkey: the public key set in jwk_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_add_sign_jwks(jwt_t * jwt, jwks_t * jwks_privkey, jwks_t * jwks_pubkey);

/**
 * Get private keys set for the signature
 * @param jwt: the jwt_t to get the value
 * @return the private key set in jwks_t * format
 */
jwks_t * r_jwt_get_sign_jwks_privkey(jwt_t * jwt);

/**
 * Get public keys set for the verification
 * @param jwt: the jwt_t to get the value
 * @return the public key set in jwks_t * format
 */
jwks_t * r_jwt_get_sign_jwks_pubkey(jwt_t * jwt);

/**
 * Add keys to perform encryption ot decryption to the JWT
 * @param jwt: the jwt_t to update
 * @param privkey: the private key to decrypt the JWT
 * @param pubkey: the public key to encrypt the JWT
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_add_enc_keys(jwt_t * jwt, jwk_t * privkey, jwk_t * pubkey);

/**
 * Adds private and/or public keys sets for the cypher key encryption and decryption
 * @param jwt: the jwt_t to update
 * @param jwks_privkey: the private key set in jwks_t * format, can be NULL
 * @param jwks_pubkey: the public key set in jwks_t * format, can be NULL
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_add_enc_jwks(jwt_t * jwt, jwks_t * jwks_privkey, jwks_t * jwks_pubkey);

/**
 * Get private keys set for the cypher key decryption
 * @param jwt: the jwt_t to get the value
 * @return the private key set in jwks_t * format
 */
jwks_t * r_jwt_get_enc_jwks_privkey(jwt_t * jwt);

/**
 * Get public keys set for the cypher key encryption
 * @param jwt: the jwt_t to get the value
 * @return the public key set in jwks_t * format
 */
jwks_t * r_jwt_get_enc_jwks_pubkey(jwt_t * jwt);

/**
 * Set the JWT alg to use for signature
 * @param jwt: the jwt_t to update
 * @param alg: the algorithm to use for signature
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_sign_alg(jwt_t * jwt, jwa_alg alg);

/**
 * Get the JWT alg used for signature
 * @param jwt: the jwt_t to update
 * @return the algorithm used for signature
 */
jwa_alg r_jwt_get_sign_alg(jwt_t * jwt);

/**
 * Set the JWT alg to use for key encryption
 * @param jwt: the jwt_t to update
 * @param alg: the algorithm to use for key encryption
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_enc_alg(jwt_t * jwt, jwa_alg alg);

/**
 * Get the JWT alg used for key encryption
 * @param jwt: the jwt_t to update
 * @return the algorithm used for key encryption
 */
jwa_alg r_jwt_get_enc_alg(jwt_t * jwt);

/**
 * Set the JWT enc to use for payload encryption
 * @param jwt: the jwt_t to update
 * @param enc: the encorithm to use for payload encryption
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_set_enc(jwt_t * jwt, jwa_enc enc);

/**
 * Get the JWT enc used for payload encryption
 * @param jwt: the jwt_t to update
 * @return the encorithm used for payload encryption
 */
jwa_enc r_jwt_get_enc(jwt_t * jwt);

/**
 * Return a signed JWT in serialized format (xxx.yyy.zzz)
 * @param jwt: the jwt_t to sign
 * @param privkey: the private key to sign the JWT, may be NULL
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
char * r_jwt_serialize_signed(jwt_t * jwt, jwk_t * privkey, int x5u_flags);

/**
 * Return an encrypted JWT in serialized format (xxx.yyy.zzz.aaa.bbb)
 * @param jwt: the jwt_t to encrypt
 * @param pubkey: the public key to encrypt the JWT, may be NULL
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
char * r_jwt_serialize_encrypted(jwt_t * jwt, jwk_t * pubkey, int x5u_flags);

/**
 * Return a nested JWT in serialized format
 * A nested JWT can be signed, then encrypted, or encrypted, then signed
 * @param jwt: the jwt_t to serialize
 * @param type: the nesting type
 * Values available are
 * - R_JWT_NESTED_SIGN_THEN_ENCRYPT: the JWT will be signed, then the token will be encrypted in a JWE
 * - R_JWT_NESTED_ENCRYPT_THEN_SIGN: The JWT will be encrypted, then the token will be signed in a JWS
 * @param sign_key: the key to sign the JWT, may be NULL
 * @param sign_key_x5u_flags: Flags to retrieve certificates in sign_key
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @param encrypt_key: the key to encrypt the JWT, may be NULL
 * @param encrypt_key_x5u_flags: Flags to retrieve certificates in encrypt_key
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
char * r_jwt_serialize_nested(jwt_t * jwt, unsigned int type, jwk_t * sign_key, int sign_key_x5u_flags, jwk_t * encrypt_key, int encrypt_key_x5u_flags);

/**
 * Parse a serialized JWT
 * If the JWT is signed only, the payload will be available
 * If the JWT is encrypted, the payload will not be accessible until
 * r_jwt_decrypt or r_jwt_decrypt_verify_signature_nested is succesfull
 * @param jwt: the jwt that will contain the parsed token
 * @param token: the token to parse into a JWT
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_parse(jwt_t * jwt, const char * token, int x5u_flags);

/**
 * Verifies the signature of the JWT
 * The JWT must contain a signature
 * or the JWT must have alg: none
 * @param jwt: the jwt_t to update
 * @param pubkey: the public key to check the signature,
 * can be NULL if jws already contains a public key
 * @param x5u_flags: Flags to retrieve certificates in pubkey
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_verify_signature(jwt_t * jwt, jwk_t * pubkey, int x5u_flags);

/**
 * Decrypts the payload of the JWT
 * @param jwt: the jwt_t to decrypt
 * @param privkey: the private key to decrypt cypher key,
 * can be NULL if jwt already contains a private key
 * @param x5u_flags: Flags to retrieve certificates in privkey
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_decrypt(jwt_t * jwt, jwk_t * privkey, int x5u_flags);

/**
 * Decrypts and verify the signature of a nested JWT
 * @param jwt: the jwt_t to decrypt and verify signature
 * @param verify_key: the public key to check the signature,
 * can be NULL if jws already contains a public key
 * @param verify_key_x5u_flags: Flags to retrieve certificates in verify_key
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @param decrypt_key: the private key to decrypt cypher key,
 * can be NULL if jwt already contains a private key
 * @param decrypt_key_x5u_flags: Flags to retrieve certificates in decrypt_key
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 */
int r_jwt_decrypt_verify_signature_nested(jwt_t * jwt, jwk_t * verify_key, int verify_key_x5u_flags, jwk_t * decrypt_key, int decrypt_key_x5u_flags);

/**
 * @}
 */

#ifndef DOXYGEN_SHOULD_SKIP_THIS

/**
 * Internal functions
 */
int _r_json_set_str_value(json_t * j_json, const char * key, const char * str_value);

int _r_json_set_int_value(json_t * j_json, const char * key, int i_value);

int _r_json_set_json_t_value(json_t * j_json, const char * key, json_t * j_value);

const char * _r_json_get_str_value(json_t * j_json, const char * key);

int _r_json_get_int_value(json_t * j_json, const char * key);

json_t * _r_json_get_json_t_value(json_t * j_json, const char * key);

json_t * _r_json_get_full_json_t(json_t * j_json);

#endif

#ifdef __cplusplus
}
#endif

#endif // __RHONABWY_H_
