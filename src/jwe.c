/**
 * 
 * Rhonabwy JSON Web Encryption (JWE) library
 * 
 * jwe.c: functions definitions
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

#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define UNUSED(x) (void)(x)

int r_jwe_init(jwe_t ** jwe) {
  UNUSED(jwe);
  return RHN_ERROR;
}

void r_jwe_free(jwe_t * jwe) {
  UNUSED(jwe);
}

jwe_t * r_jwe_copy(jwe_t * jwe) {
  UNUSED(jwe);
  return NULL;
}

int r_jwe_set_payload(jwe_t * jwe, const unsigned char * payload, size_t payload_len) {
  UNUSED(jwe);
  UNUSED(payload);
  UNUSED(payload_len);
  return RHN_ERROR;
}

const unsigned char * r_jwe_get_payload(jwe_t * jwe, size_t * payload_len) {
  UNUSED(jwe);
  UNUSED(payload_len);
  return NULL;
}

int r_jwe_set_alg(jwe_t * jwe, jwa_alg alg) {
  UNUSED(jwe);
  UNUSED(alg);
  return RHN_ERROR;
}

jwa_alg r_jwe_get_alg(jwe_t * jwe) {
  UNUSED(jwe);
  return R_JWA_ALG_UNKNOWN;
}

int r_jwe_set_enc(jwe_t * jwe, jwa_enc enc) {
  UNUSED(jwe);
  UNUSED(enc);
  return RHN_ERROR;
}

jwa_enc r_jwe_get_enc(jwe_t * jwe) {
  UNUSED(jwe);
  return R_JWA_ENC_UNKNOWN;
}

int r_jwe_set_header_str_value(jwe_t * jwe, const char * key, const char * str_value) {
  UNUSED(jwe);
  UNUSED(key);
  UNUSED(str_value);
  return RHN_ERROR;
}

int r_jwe_set_header_int_value(jwe_t * jwe, const char * key, int i_value) {
  UNUSED(jwe);
  UNUSED(key);
  UNUSED(i_value);
  return RHN_ERROR;
}

int r_jwe_set_header_json_t_value(jwe_t * jwe, const char * key, json_t * j_value) {
  UNUSED(jwe);
  UNUSED(key);
  UNUSED(j_value);
  return RHN_ERROR;
}

const char * r_jwe_get_header_str_value(jwe_t * jwe, const char * key) {
  UNUSED(jwe);
  UNUSED(key);
  return NULL;
}

int r_jwe_get_header_int_value(jwe_t * jwe, const char * key) {
  UNUSED(jwe);
  UNUSED(key);
  return RHN_ERROR;
}

json_t * r_jwe_get_header_json_t_value(jwe_t * jwe, const char * key) {
  UNUSED(jwe);
  UNUSED(key);
  return NULL;
}

json_t * r_jwe_get_full_header_json_t(jwe_t * jwe) {
  UNUSED(jwe);
  return NULL;
}

int r_jwe_add_keys(jwe_t * jwe, jwk_t * jwk_privkey, jwk_t * jwk_pubkey) {
  UNUSED(jwe);
  UNUSED(jwk_pubkey);
  UNUSED(jwk_privkey);
  return RHN_ERROR;
}

int r_jwe_set_cypher_key(jwe_t * jwe, const unsigned char * key, size_t key_len, jwa_enc enc) {
  UNUSED(jwe);
  UNUSED(key);
  UNUSED(key_len);
  UNUSED(enc);
  return RHN_ERROR;
}

const unsigned char * r_jwe_get_cypher_key(jwe_t * jwe, size_t * key_len) {
  UNUSED(jwe);
  UNUSED(key_len);
  return NULL;
}

int r_jwe_generate_cypher_key(jwe_t * jwe, unsigned int bits, jwa_enc enc) {
  UNUSED(jwe);
  UNUSED(bits);
  UNUSED(enc);
  return RHN_ERROR;
}

int r_jwe_set_iv(jwe_t * jwe, const unsigned char * iv, size_t iv_len) {
  UNUSED(jwe);
  UNUSED(iv);
  UNUSED(iv_len);
  return RHN_ERROR;
}

const unsigned char * r_jwe_get_iv(jwe_t * jwe, size_t * iv_len) {
  UNUSED(jwe);
  UNUSED(iv_len);
  return NULL;
}

int r_jwe_generate_iv(jwe_t * jwe, size_t length) {
  UNUSED(jwe);
  UNUSED(length);
  return RHN_ERROR;
}

int r_jwe_encrypt_payload(jwe_t * jwe) {
  UNUSED(jwe);
  return RHN_ERROR;
}

int r_jwe_decrypt_payload(jwe_t * jwe, const unsigned char * key, size_t key_len) {
  UNUSED(jwe);
  UNUSED(key);
  UNUSED(key_len);
  return RHN_ERROR;
}

int r_jwe_encrypt_key(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags) {
  UNUSED(jwe);
  UNUSED(jwk_pubkey);
  UNUSED(x5u_flags);
  return RHN_ERROR;
}

int r_jwe_decrypt_key(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags) {
  UNUSED(jwe);
  UNUSED(jwk_privkey);
  UNUSED(x5u_flags);
  return RHN_ERROR;
}

int r_jwe_parse(jwe_t * jwe, const char * jwe_str, int x5u_flags) {
  UNUSED(jwe);
  UNUSED(jwe_str);
  UNUSED(x5u_flags);
  return RHN_ERROR;
}

int r_jwe_decrypt(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags) {
  UNUSED(jwe);
  UNUSED(jwk_privkey);
  UNUSED(x5u_flags);
  return RHN_ERROR;
}

char * r_jwe_serialize(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags) {
  UNUSED(jwe);
  UNUSED(jwk_pubkey);
  UNUSED(x5u_flags);
  return NULL;
}
