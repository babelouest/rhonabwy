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

#define R_FLAG_IGNORE_SERVER_CERTIFICATE 0x00000001
#define R_FLAG_FOLLOW_REDIRECT           0x00000010

/**
 * @}
 */

/**
 * @defgroup type JWK, JWKS, JWS type
 * Definition of the types jwk_t, jwks_t and jws_t
 * @{
 */

typedef json_t jwk_t;
typedef json_t jwks_t;

typedef enum {
  R_JWS_ALG_UNSET = 0,
  R_JWS_ALG_NONE  = 1,
  R_JWS_ALG_HS256 = 2,
  R_JWS_ALG_HS384 = 3,
  R_JWS_ALG_HS512 = 4,
  R_JWS_ALG_RS256 = 5,
  R_JWS_ALG_RS384 = 6,
  R_JWS_ALG_RS512 = 7,
  R_JWS_ALG_ES256 = 8,
  R_JWS_ALG_ES384 = 9,
  R_JWS_ALG_ES512 = 10,
  R_JWS_ALG_PS256 = 11,
  R_JWS_ALG_PS384 = 12,
  R_JWS_ALG_PS512 = 13
} jws_alg;

typedef struct _jws_t {
  unsigned char * header_b64url;
  unsigned char * payload_b64url;
  unsigned char * signature_b64url;
  jws_alg alg;
  jwks_t * jwks_privkey;
  jwks_t * jwks_pubkey;
  json_t * j_header;
  unsigned char * payload;
  size_t payload_len;
} jws_t;

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
 * Return a copy of the jwk
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
 * @return a char * on success, NULL on error
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
 * Return a copy of the jwks
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
 * @return a char * on success, NULL on error
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
int r_jws_set_alg(jws_t * jws, jws_alg alg);

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
 * Get the JWS alg used for signature
 * @param jws: the jws_t to update
 * @return the algorithm used
 */
jws_alg r_jws_get_alg(jws_t * jws);

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
 * @return the JWS in serialized format, returned value must be o_free'd after use
 */
char * r_jws_serialize(jws_t * jws, jwk_t * jwk_privkey, int x5u_flags);

/**
 * Get the jws_alg corresponding to the string algorithm specified
 * @param alg: the algorithm to convert
 * @return the converted jws_alg, R_JWS_ALG_NONE if alg is unknown
 */
jws_alg str_to_js_alg(const char * alg);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif // __RHONABWY_H_
