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
#define RHN_ERROR_JWK_INVALID  5

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

#define R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE 0x00000001
#define R_X5U_FLAG_FOLLOW_REDIRECT           0x00000001

/**
 * @}
 */

/**
 * @defgroup type JWK type
 * Definition of the type jwk_t
 * @{
 */

typedef json_t jwk_t;

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
int r_init_jwk(jwk_t ** jwk);

/**
 * Free a jwk_t
 * @param jwk: the jwk_t * to free
 */
void r_free_jwk(jwk_t * jwk);

/**
 * Get the type and algorithm of a jwk_t
 * @param jwk: the jwk_t * to test
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_X5U_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
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
int r_jwk_key_type(jwk_t * jwk, int x5u_flags);

/**
 * Check if the jwk is valid
 * @param jwk: the jwk_t * to test
 * @return RHN_OK on success, an error value on error
 * Logs error message with yder on error
 */
int r_jwk_is_valid(jwk_t * jwk);

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
int r_import_from_json_str(jwk_t * jwk, const char * input);

/**
 * Import a JSON in json_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param j_input: a JWK in json_t * format
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_import_from_json_t(jwk_t * jwk, json_t * j_input);

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
int r_import_from_pem_der(jwk_t * jwk, int type, int format, const unsigned char * input, size_t input_len);

/**
 * Import a GnuTLS private key in gnutls_privkey_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param key: the private key to be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_import_from_gnutls_privkey(jwk_t * jwk, gnutls_privkey_t key);

/**
 * Import a GnuTLS public key in gnutls_pubkey_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param pub: the public key to be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_import_from_gnutls_pubkey(jwk_t * jwk, gnutls_pubkey_t pub);

/**
 * Import a GnuTLS X509 certificate in gnutls_x509_crt_t format into a jwk_t
 * @param jwk: the jwk_t * to import to
 * @param crt: the X509 certificate whose public key will be imported to jwk
 * If jwk is set, values will be overwritten
 * @return RHN_OK on success, an error value on error
 */
int r_import_from_gnutls_x509_crt(jwk_t * jwk, gnutls_x509_crt_t crt);

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
char * r_export_to_json_str(jwk_t * jwk, int pretty);

/**
 * Export a jwk_t into a json_t format
 * @param jwk: the jwk_t * to export
 * @return a json_t * on success, NULL on error
 */
json_t * r_export_to_json_t(jwk_t * jwk);

/**
 * Export a jwk_t into a gnutls_privkey_t format
 * @param jwk: the jwk_t * to export
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_X5U_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a gnutls_privkey_t on success, NULL on error
 */
gnutls_privkey_t r_export_to_gnutls_privkey(jwk_t * jwk, int x5u_flags);

/**
 * Export a jwk_t into a gnutls_pubkey_t format
 * @param jwk: the jwk_t * to export
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_X5U_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return a gnutls_pubkey_t on success, NULL on error
 */
gnutls_pubkey_t r_export_to_gnutls_pubkey(jwk_t * jwk, int x5u_flags);

/**
 * Export a jwk_t into a DER or PEM format
 * @param jwk: the jwk_t * to export
 * @param format: the format of the outpu, values available are R_FORMAT_PEM or R_FORMAT_DER
 * @param output: an unsigned char * that will contain the output
 * @param output_len: the size of output and will be set to the data size that has been written to output
 * @param x5u_flags: Flags to retrieve certificates
 * pointed by x5u if necessary, could be 0 if not needed
 * Flags available are 
 * - R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE: ignrore if web server certificate is invalid
 * - R_X5U_FLAG_FOLLOW_REDIRECT: follow redirections if necessary
 * @return RHN_OK on success, an error value on error
 * @return RHN_ERROR_PARAM if output_len isn't large enough to hold the output, then output_len will be set to the required size
 */
int r_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len, int x5u_flags);

/**
 * @}
 */
