/**
 *
 * Rhonabwy JSON Web Encryption (JWE) library
 *
 * jwe.c: functions definitions
 *
 * Copyright 2020-2022 Nicolas Mora <mail@babelouest.org>
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
#include <ctype.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define R_TAG_MAX_SIZE 16

#define _R_BLOCK_SIZE 256

#define _R_PBES_DEFAULT_ITERATION 4096
#define _R_PBES_DEFAULT_SALT_LENGTH 8
#define _R_CURVE_MAX_SIZE 64

#if NETTLE_VERSION_NUMBER >= 0x030400
#include <nettle/hmac.h>
#include <nettle/aes.h>
#include <nettle/memops.h>
#include <nettle/bignum.h>
#endif

#if NETTLE_VERSION_NUMBER >= 0x030400
#include <nettle/pss-mgf1.h>
#include <nettle/rsa.h>
#endif

#if NETTLE_VERSION_NUMBER >= 0x030600
#include <nettle/curve25519.h>
#include <nettle/curve448.h>
#include <nettle/eddsa.h>
#include <nettle/ecdsa.h>
#include <nettle/ecc.h>
#include <nettle/ecc-curve.h>
#endif

#if NETTLE_VERSION_NUMBER >= 0x030600

static int _r_concat_kdf(jwe_t * jwe, jwa_alg alg, const gnutls_datum_t * Z, gnutls_datum_t * kdf) {
  int ret = RHN_OK;
  unsigned char * apu_dec = NULL, * apv_dec = NULL;
  const char * alg_id = alg==R_JWA_ALG_ECDH_ES?r_jwa_enc_to_str(jwe->enc):r_jwa_alg_to_str(alg),
             * apu = r_jwe_get_header_str_value(jwe, "apu"),
             * apv = r_jwe_get_header_str_value(jwe, "apv");
  size_t apu_dec_len = 0, apv_dec_len = 0, alg_id_len = o_strlen(alg_id), key_data_len = 0;

  kdf->data = NULL;
  kdf->size = 0;
  do {
    if ((kdf->data = o_malloc(4+Z->size)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error malloc kdf->data");
      ret = RHN_ERROR_MEMORY;
      break;
    }

    memset(kdf->data, 0, 3);
    memset(kdf->data+3, 1, 1);
    memcpy(kdf->data+4, Z->data, Z->size);
    kdf->size = 4+Z->size;

    if ((kdf->data = o_realloc(kdf->data, kdf->size+4+alg_id_len)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error realloc kdf->data (1)");
      ret = RHN_ERROR_MEMORY;
      break;
    }

    memset(kdf->data+kdf->size, 0, 3);
    memset(kdf->data+kdf->size+3, (uint8_t)alg_id_len, 1);
    memcpy(kdf->data+kdf->size+4, alg_id, alg_id_len);
    kdf->size += 4+alg_id_len;

    if (!o_strnullempty(apu)) {
      if ((apu_dec = o_malloc(o_strlen(apu))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error malloc apu_dec");
        ret = RHN_ERROR_MEMORY;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)apu, o_strlen(apu), apu_dec, &apu_dec_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error o_base64url_decode apu");
        ret = RHN_ERROR;
        break;
      }
    }

    if ((kdf->data = o_realloc(kdf->data, kdf->size+4+apu_dec_len)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error realloc kdf->data (2)");
      ret = RHN_ERROR_MEMORY;
      break;
    }

    kdf->data[kdf->size] = (unsigned char)(apu_dec_len>>24) & 0xFF;
    kdf->data[kdf->size+1] = (unsigned char)(apu_dec_len>>16) & 0xFF;
    kdf->data[kdf->size+2] = (unsigned char)(apu_dec_len>>8) & 0xFF;
    kdf->data[kdf->size+3] = (unsigned char)(apu_dec_len) & 0xFF;
    if (apu_dec_len) {
      memcpy(kdf->data+kdf->size+4, apu_dec, apu_dec_len);
    }
    kdf->size += apu_dec_len+4;

    if (!o_strnullempty(apv)) {
      if ((apv_dec = o_malloc(o_strlen(apv))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error malloc apv_dec");
        ret = RHN_ERROR_MEMORY;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)apv, o_strlen(apv), apv_dec, &apv_dec_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error o_base64url_decode apv");
        ret = RHN_ERROR;
        break;
      }
    }

    if ((kdf->data = o_realloc(kdf->data, kdf->size+4+apv_dec_len)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error realloc kdf->data (3)");
      ret = RHN_ERROR_MEMORY;
      break;
    }

    kdf->data[kdf->size] = (unsigned char)(apv_dec_len>>24) & 0xFF;
    kdf->data[kdf->size+1] = (unsigned char)(apv_dec_len>>16) & 0xFF;
    kdf->data[kdf->size+2] = (unsigned char)(apv_dec_len>>8) & 0xFF;
    kdf->data[kdf->size+3] = (unsigned char)(apv_dec_len) & 0xFF;
    if (apv_dec_len) {
      memcpy(kdf->data+kdf->size+4, apv_dec, apv_dec_len);
    }
    kdf->size += apv_dec_len+4;

    if (alg == R_JWA_ALG_ECDH_ES) {
      key_data_len = _r_get_key_size(jwe->enc)*8;
    } else if (alg == R_JWA_ALG_ECDH_ES_A128KW) {
      key_data_len = 16*8;
    } else if (alg == R_JWA_ALG_ECDH_ES_A192KW) {
      key_data_len = 24*8;
    } else if (alg == R_JWA_ALG_ECDH_ES_A256KW) {
      key_data_len = 32*8;
    }

    if (!key_data_len) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error invalid keydatalen");
      ret = RHN_ERROR;
      break;
    }

    if ((kdf->data = o_realloc(kdf->data, kdf->size+4)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_concat_kdf - Error realloc kdf->data (4)");
      ret = RHN_ERROR_MEMORY;
      break;
    }

    kdf->data[kdf->size] = (unsigned char)(key_data_len>>24) & 0xFF;
    kdf->data[kdf->size+1] = (unsigned char)(key_data_len>>16) & 0xFF;
    kdf->data[kdf->size+2] = (unsigned char)(key_data_len>>8) & 0xFF;
    kdf->data[kdf->size+3] = (unsigned char)(key_data_len) & 0xFF;
    kdf->size += 4;

  } while (0);

  o_free(apu_dec);
  o_free(apv_dec);

  if (ret != RHN_OK) {
    o_free(kdf->data);
    kdf->data = NULL;
    kdf->size = 0;
  }

  return ret;
}

static int _r_ecdh_compute(uint8_t * priv_d, size_t pub_d_size, uint8_t * pub_x, size_t pub_x_size, uint8_t * pub_y, size_t pub_y_size, const struct ecc_curve * curve, gnutls_datum_t * Z) {
  int ret = RHN_OK;
  struct ecc_scalar priv;
  struct ecc_point pub, r;
  mpz_t z_priv_d, z_pub_x, z_pub_y, r_x, r_y;
  uint8_t r_x_u[64] = {0};
  size_t r_x_u_len = 64;

  mpz_init(z_priv_d);
  mpz_init(z_pub_x);
  mpz_init(z_pub_y);
  mpz_init(r_x);
  mpz_init(r_y);
  ecc_scalar_init(&priv, curve);
  ecc_point_init(&pub, curve);
  ecc_point_init(&r, curve);
  do {
    mpz_import(z_priv_d, pub_d_size, 1, 1, 0, 0, priv_d);
    if (!ecc_scalar_set(&priv, z_priv_d)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_ecdh_compute - Error ecc_scalar_set");
      ret = RHN_ERROR;
      break;
    }

    mpz_import(z_pub_x, pub_x_size, 1, 1, 0, 0, pub_x);
    mpz_import(z_pub_y, pub_y_size, 1, 1, 0, 0, pub_y);
    if (!ecc_point_set(&pub, z_pub_x, z_pub_y)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_ecdh_compute - Error ecc_point_set");
      ret = RHN_ERROR;
      break;
    }

    ecc_point_mul(&r, &priv, &pub);
    ecc_point_get(&r, r_x, r_y);

    mpz_export(r_x_u, &r_x_u_len, 1, 1, 0, 0, r_x);

    if ((Z->data = gnutls_malloc(r_x_u_len)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_ecdh_compute - Error gnutls_malloc");
      ret = RHN_ERROR_MEMORY;
      break;
    }
    memcpy(Z->data, r_x_u, r_x_u_len);
    Z->size = r_x_u_len;
    ret = RHN_OK;
  } while (0);
  mpz_clear(z_priv_d);
  mpz_clear(z_pub_x);
  mpz_clear(z_pub_y);
  mpz_clear(r_x);
  mpz_clear(r_y);
  ecc_scalar_clear(&priv);
  ecc_point_clear(&pub);
  ecc_point_clear(&r);

  return ret;
}

static int _r_dh_compute(uint8_t * priv_k, uint8_t * pub_x, size_t crv_size, gnutls_datum_t * Z) {
  int ret;
  uint8_t q[CURVE448_SIZE] = {0};

  if (crv_size == CURVE25519_SIZE) {
    curve25519_mul(q, priv_k, pub_x);
  } else {
    curve448_mul(q, priv_k, pub_x);
  }

  if ((Z->data = gnutls_malloc(crv_size)) != NULL) {
    memcpy(Z->data, q, crv_size);
    Z->size = crv_size;
    ret = RHN_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_dh_compute - Error gnutls_malloc");
    ret = RHN_ERROR_MEMORY;
  }

  return ret;
}
#endif

// https://git.lysator.liu.se/nettle/nettle/-/merge_requests/20
#if NETTLE_VERSION_NUMBER >= 0x030400
int
pkcs1_oaep_decrypt (size_t key_size,
	       const mpz_t m,
	       /* Hash function */
	       size_t hlen,
	       void * ctx, const struct nettle_hash *hash, nettle_hash_init_func *hash_init, nettle_hash_update_func *hash_update, nettle_hash_digest_func *hash_digest,
	       size_t label_length, const uint8_t *label,
	       size_t *length, uint8_t *message)
{
  int ret = 1;
  size_t dbMask_len = key_size-1-hlen, i;
  uint8_t lHash[hlen], k[hlen], seedMask[hlen], maskedSeed[hlen];

  uint8_t *em, *maskedDB, *dbMask, *db;

  em = o_malloc(key_size);
  maskedDB = o_malloc(dbMask_len);
  dbMask = o_malloc(dbMask_len);
  db = o_malloc(dbMask_len);

  // lHash = Hash(L)
  hash_init(ctx);
  hash_update(ctx, label_length, label);
  hash_digest(ctx, hlen, lHash);

  nettle_mpz_get_str_256(key_size, em, m);

  if (em[0])
    {
      ret = 0;
    }

  memcpy(maskedSeed, em+1, hlen);
  memcpy(maskedDB, em+1+hlen, key_size-1-hlen);

  // seedMask = MGF(maskedDB, hLen).
  hash_init(ctx);
  hash_update(ctx, dbMask_len, maskedDB);
  pss_mgf1(ctx, hash, hlen, seedMask);

  // seed = maskedSeed \xor seedMask.
  for (i=0; i<hlen; i++)
    {
      k[i] = maskedSeed[i]^seedMask[i];
    }

  // dbMask = MGF(seed, k - hLen - 1).
  hash_init(ctx);
  hash_update(ctx, hlen, k);
  pss_mgf1(ctx, hash, dbMask_len, dbMask);

  // DB = maskedDB \xor dbMask.
  for (i=0; i<dbMask_len; i++)
    {
      db[i] = maskedDB[i]^dbMask[i];
    }

  if (!memeql_sec(db, lHash, hlen))
    {
      ret = 0;
    }

  for (i=hlen; i<dbMask_len-1; i++)
    {
      if (db[i] == 0x01)
      {
        break;
      }
    }

  if (i < dbMask_len-1 && *length >= dbMask_len-i-1 && i < dbMask_len-1)
  {
    *length = dbMask_len-i-1;
    memcpy(message, db+i+1, *length);
  }
  else
  {
    ret = 0;
  }

  o_free(em);
  o_free(maskedDB);
  o_free(dbMask);
  o_free(db);

  return ret;
}

int
rsa_oaep_sha1_decrypt(const struct rsa_private_key *key,
	    size_t label_length, const uint8_t *label,
	    size_t *length, uint8_t *message,
	    const mpz_t gibberish)
{
  mpz_t m;
  int res;
  struct sha1_ctx ctx;

  mpz_init(m);
  rsa_compute_root(key, m, gibberish);

  res = pkcs1_oaep_decrypt (key->size, m, SHA1_DIGEST_SIZE,
                            &ctx, &nettle_sha1, (nettle_hash_init_func*)&sha1_init, (nettle_hash_update_func*)&sha1_update, (nettle_hash_digest_func*)&sha1_digest,
                            label_length, label, length, message);
  mpz_clear(m);
  return res;
}

int
rsa_oaep_sha256_decrypt(const struct rsa_private_key *key,
	    size_t label_length, const uint8_t *label,
	    size_t *length, uint8_t *message,
	    const mpz_t gibberish)
{
  mpz_t m;
  int res;
  struct sha256_ctx ctx;

  mpz_init(m);
  rsa_compute_root(key, m, gibberish);

  res = pkcs1_oaep_decrypt (key->size, m, SHA256_DIGEST_SIZE,
                            &ctx, &nettle_sha256, (nettle_hash_init_func*)&sha256_init, (nettle_hash_update_func*)&sha256_update, (nettle_hash_digest_func*)&sha256_digest,
                            label_length, label, length, message);
  mpz_clear(m);
  return res;
}

int
pkcs1_oaep_encrypt (size_t key_size,
	       void *random_ctx, nettle_random_func *random,
	       /* Hash function */
	       size_t hlen,
	       void * ctx, const struct nettle_hash *hash, nettle_hash_init_func *hash_init, nettle_hash_update_func *hash_update, nettle_hash_digest_func *hash_digest,
	       size_t label_length, const uint8_t *label,
	       size_t message_length, const uint8_t *message,
	       mpz_t m)
{
  size_t ps_len = key_size - message_length - (2*hlen) - 2, dbMask_len = key_size - hlen - 1, i;
  uint8_t lHash[hlen], k[hlen], seedMask[hlen], maskedSeed[hlen];
  int ret = 1;

  if (key_size < (2*hlen) - 2 || message_length > key_size - (2*hlen) - 2)
    {
      return 0;
    }
  uint8_t *em, *maskedDB, *dbMask, *db;

  em = o_malloc(dbMask_len + hlen + 1);
  maskedDB = o_malloc(dbMask_len);
  dbMask = o_malloc(dbMask_len);
  db = o_malloc(dbMask_len);

  // lHash = Hash(L)
  hash_init(ctx);
  hash_update(ctx, label_length, label);
  hash_digest(ctx, hlen, lHash);

  // DB = lHash || PS || 0x01 || M.

  memcpy(db, lHash, hlen);
  memset(db+hlen, 0, ps_len);
  memset(db+hlen+ps_len, 1, 1);
  memcpy(db+hlen+ps_len+1, message, message_length);

  random(random_ctx, hlen, k);

  // dbMask = MGF(seed, k - hLen - 1).
  hash_init(ctx);
  hash_update(ctx, hlen, k);
  pss_mgf1(ctx, hash, dbMask_len, dbMask);

  // maskedDB = DB \xor dbMask.
  for (i=0; i<dbMask_len; i++)
    {
      maskedDB[i] = db[i]^dbMask[i];
    }

  // seedMask = MGF(maskedDB, hLen).
  memset(seedMask, 0, hlen);
  hash_init(ctx);
  hash_update(ctx, dbMask_len, maskedDB);
  pss_mgf1(ctx, hash, hlen, seedMask);

  // maskedSeed = seed \xor seedMask.
  for (i=0; i<hlen; i++)
    {
      maskedSeed[i] = k[i]^seedMask[i];
    }

  // EM = 0x00 || maskedSeed || maskedDB.

  em[0] = 0;
  memcpy(em+1, maskedSeed, hlen);
  memcpy(em+1+hlen, maskedDB, dbMask_len);

  nettle_mpz_set_str_256_u(m, dbMask_len + hlen + 1, em);

  o_free(db);
  o_free(dbMask);
  o_free(maskedDB);
  o_free(em);

  return ret;
}

int
rsa_oaep_sha1_encrypt(const struct rsa_public_key *key,
	    void *random_ctx, nettle_random_func *random,
	    size_t label_length, const uint8_t *label,
	    size_t length, const uint8_t *message,
	    mpz_t gibberish)
{
  struct sha1_ctx ctx;
  if (pkcs1_oaep_encrypt (key->size, random_ctx, random,
         SHA1_DIGEST_SIZE,
         &ctx, &nettle_sha1, (nettle_hash_init_func*)&sha1_init, (nettle_hash_update_func*)&sha1_update, (nettle_hash_digest_func*)&sha1_digest,
         label_length, label,
		     length, message, gibberish))
    {
      mpz_powm(gibberish, gibberish, key->e, key->n);
      return 1;
    }
  else
    return 0;
}

int
rsa_oaep_sha256_encrypt(const struct rsa_public_key *key,
	    void *random_ctx, nettle_random_func *random,
	    size_t label_length, const uint8_t *label,
	    size_t length, const uint8_t *message,
	    mpz_t gibberish)
{
  struct sha256_ctx ctx;
  if (pkcs1_oaep_encrypt (key->size, random_ctx, random,
         SHA256_DIGEST_SIZE,
         &ctx, &nettle_sha256, (nettle_hash_init_func*)&sha256_init, (nettle_hash_update_func*)&sha256_update, (nettle_hash_digest_func*)&sha256_digest,
         label_length, label,
		     length, message, gibberish))
    {
      mpz_powm(gibberish, gibberish, key->e, key->n);
      return 1;
    }
  else
    return 0;
}

static void rnd_nonce_func(void *_ctx, size_t length, uint8_t * data)
{
  (void)_ctx;
	gnutls_rnd(GNUTLS_RND_NONCE, data, length);
}
#endif

// https://git.lysator.liu.se/nettle/nettle/-/merge_requests/19
#if NETTLE_VERSION_NUMBER >= 0x030400
static void
nist_keywrap16(const void *ctx, nettle_cipher_func *encrypt,
               const uint8_t *iv, size_t ciphertext_length,
               uint8_t *ciphertext, const uint8_t *cleartext) {
  uint8_t * R = NULL, A[8] = {0}, I[16] = {0}, B[16] = {0};
  uint64_t A64;
  size_t i, j, n;

  if ((R = o_malloc(ciphertext_length-8)) == NULL)
    return;

  n = (ciphertext_length-8)/8;
  memcpy(R, cleartext, (ciphertext_length-8));
  memcpy(A, iv, 8);

  for (j=0; j<6; j++) {
    for (i=0; i<n; i++) {
      // I = A | R[1]
      memcpy(I, A, 8);
      memcpy(I+8, R+(i*8), 8);

      // B = AES(K, I)
      encrypt(ctx, 16, B, I);

      // A = MSB(64, B) ^ t where t = (n*j)+i
      A64 = ((uint64_t)B[0] << 56) | ((uint64_t)B[1] << 48) | ((uint64_t)B[2] << 40) | ((uint64_t)B[3] << 32) | ((uint64_t)B[4] << 24) | ((uint64_t)B[5] << 16) | ((uint64_t)B[6] << 8) | (uint64_t)B[7];
      A64 ^= (n*j)+(i+1);
      A[7] = (uint8_t)A64;
      A[6] = (uint8_t)(A64 >> 8);
      A[5] = (uint8_t)(A64 >> 16);
      A[4] = (uint8_t)(A64 >> 24);
      A[3] = (uint8_t)(A64 >> 32);
      A[2] = (uint8_t)(A64 >> 40);
      A[1] = (uint8_t)(A64 >> 48);
      A[0] = (uint8_t)(A64 >> 56);

      //  R[i] = LSB(64, B)
      memcpy(R+(i*8), B+8, 8);

    }
  }

  memcpy(ciphertext, A, 8);
  memcpy(ciphertext+8, R, (ciphertext_length-8));
  o_free(R);
}

static int
nist_keyunwrap16(const void *ctx, nettle_cipher_func *decrypt,
                 const uint8_t *iv, size_t cleartext_length,
                 uint8_t *cleartext, const uint8_t *ciphertext) {
  uint8_t * R = NULL, A[8] = {0}, I[16] = {0}, B[16] = {0};
  uint64_t A64;
  int i, j, ret;
  size_t n;

  if ((R = o_malloc(cleartext_length)) == NULL)
    return 0;

  n = (cleartext_length/8);
  memcpy(A, ciphertext, 8);
  memcpy(R, ciphertext+8, cleartext_length);

  for (j=5; j>=0; j--) {
    for (i=n-1; i>=0; i--) {

      // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
      A64 = ((uint64_t)A[0] << 56) | ((uint64_t)A[1] << 48) | ((uint64_t)A[2] << 40) | ((uint64_t)A[3] << 32) | ((uint64_t)A[4] << 24) | ((uint64_t)A[5] << 16) | ((uint64_t)A[6] << 8) | (uint64_t)A[7];
      A64 ^= (n*j)+(i+1);
      I[7] = (uint8_t)A64;
      I[6] = (uint8_t)(A64 >> 8);
      I[5] = (uint8_t)(A64 >> 16);
      I[4] = (uint8_t)(A64 >> 24);
      I[3] = (uint8_t)(A64 >> 32);
      I[2] = (uint8_t)(A64 >> 40);
      I[1] = (uint8_t)(A64 >> 48);
      I[0] = (uint8_t)(A64 >> 56);
      memcpy(I+8, R+(i*8), 8);
      decrypt(ctx, 16, B, I);

      // A = MSB(64, B)
      memcpy(A, B, 8);

      // R[i] = LSB(64, B)
      memcpy(R+(i*8), B+8, 8);
    }
  }

  if (memeql_sec(A, iv, 8)) {
    memcpy(cleartext, R, cleartext_length);
    ret = 1;
  } else {
    ret = 0;
  }
  o_free(R);
  return ret;
}
#endif

#if NETTLE_VERSION_NUMBER >= 0x030400
static int _r_rsa_oaep_encrypt(gnutls_pubkey_t g_pub, jwa_alg alg, uint8_t * cleartext, size_t cleartext_len, uint8_t * ciphertext, size_t * cyphertext_len) {
  struct rsa_public_key pub;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0};
  int ret = RHN_OK;
  mpz_t gibberish;

  rsa_public_key_init(&pub);
  mpz_init(gibberish);
  if (gnutls_pubkey_export_rsa_raw(g_pub, &m, &e) == GNUTLS_E_SUCCESS) {
    mpz_import(pub.n, m.size, 1, 1, 0, 0, m.data);
    mpz_import(pub.e, e.size, 1, 1, 0, 0, e.data);
    rsa_public_key_prepare(&pub);
    if (*cyphertext_len >= pub.size) {
      if (alg == R_JWA_ALG_RSA_OAEP) {
        if (!rsa_oaep_sha1_encrypt(&pub, NULL, rnd_nonce_func, 0, NULL, cleartext_len, cleartext, gibberish)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error rsa_oaep_sha1_encrypt");
          ret = RHN_ERROR;
        }
      } else {
        if (!rsa_oaep_sha256_encrypt(&pub, NULL, rnd_nonce_func, 0, NULL, cleartext_len, cleartext, gibberish)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error rsa_oaep_sha256_encrypt");
          ret = RHN_ERROR;
        }
      }
      if (ret == RHN_OK) {
        nettle_mpz_get_str_256(pub.size, ciphertext, gibberish);
        *cyphertext_len = pub.size;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error cyphertext to small");
      ret = RHN_ERROR_PARAM;
    }
    gnutls_free(m.data);
    gnutls_free(e.data);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error gnutls_pubkey_export_rsa_raw");
    ret = RHN_ERROR;
  }
  rsa_public_key_clear(&pub);
  mpz_clear(gibberish);

  return ret;
}

static int _r_rsa_oaep_decrypt(gnutls_privkey_t g_priv, jwa_alg alg, uint8_t * ciphertext, size_t cyphertext_len, uint8_t * cleartext, size_t * cleartext_len) {
  struct rsa_private_key priv;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, d = {NULL, 0}, p = {NULL, 0}, q = {NULL, 0}, u = {NULL, 0}, e1 = {NULL, 0}, e2 = {NULL, 0};
  int ret = RHN_OK;
  mpz_t gibberish;

  rsa_private_key_init(&priv);
  mpz_init(gibberish);
  nettle_mpz_set_str_256_u(gibberish, cyphertext_len, ciphertext);
  if (gnutls_privkey_export_rsa_raw(g_priv, &m, &e, &d, &p, &q, &u, &e1, &e2) == GNUTLS_E_SUCCESS) {
    mpz_import(priv.d, d.size, 1, 1, 0, 0, d.data);
    mpz_import(priv.p, p.size, 1, 1, 0, 0, p.data);
    mpz_import(priv.q, q.size, 1, 1, 0, 0, q.data);
    mpz_import(priv.a, e1.size, 1, 1, 0, 0, e1.data);
    mpz_import(priv.b, e2.size, 1, 1, 0, 0, e2.data);
    mpz_import(priv.c, u.size, 1, 1, 0, 0, u.data);
    rsa_private_key_prepare(&priv);
    if (cyphertext_len >= priv.size) {
      if (alg == R_JWA_ALG_RSA_OAEP) {
        if (!rsa_oaep_sha1_decrypt(&priv, 0, NULL, cleartext_len, cleartext, gibberish)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_decrypt - Error rsa_oaep_sha1_decrypt");
          ret = RHN_ERROR;
        }
      } else {
        if (!rsa_oaep_sha256_decrypt(&priv, 0, NULL, cleartext_len, cleartext, gibberish)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_decrypt - Error rsa_oaep_sha256_decrypt");
          ret = RHN_ERROR;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error cyphertext to small");
      ret = RHN_ERROR_PARAM;
    }
    gnutls_free(m.data);
    gnutls_free(e.data);
    gnutls_free(d.data);
    gnutls_free(p.data);
    gnutls_free(q.data);
    gnutls_free(u.data);
    gnutls_free(e1.data);
    gnutls_free(e2.data);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_rsa_oaep_encrypt - Error gnutls_pubkey_export_rsa_raw");
    ret = RHN_ERROR;
  }
  rsa_private_key_clear(&priv);
  mpz_clear(gibberish);

  return ret;
}
#endif

#if NETTLE_VERSION_NUMBER >= 0x030400
static void _r_aes_key_wrap(uint8_t * kek, size_t kek_len, uint8_t * key, size_t key_len, uint8_t * wrapped_key) {
  struct aes128_ctx ctx_128;
  struct aes192_ctx ctx_192;
  struct aes256_ctx ctx_256;
  void * ctx = NULL;
  nettle_cipher_func * encrypt = NULL;
  const uint8_t default_iv[] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

  if (kek_len == 16) {
    aes128_set_encrypt_key(&ctx_128, kek);
    ctx = (void*)&ctx_128;
    encrypt = (nettle_cipher_func*)&aes128_encrypt;
  }
  if (kek_len == 24) {
    aes192_set_encrypt_key(&ctx_192, kek);
    ctx = (void*)&ctx_192;
    encrypt = (nettle_cipher_func*)&aes192_encrypt;
  }
  if (kek_len == 32) {
    aes256_set_encrypt_key(&ctx_256, kek);
    ctx = (void*)&ctx_256;
    encrypt = (nettle_cipher_func*)&aes256_encrypt;
  }
  nist_keywrap16(ctx, encrypt, default_iv, key_len+8, wrapped_key, key);
}

static int _r_aes_key_unwrap(uint8_t * kek, size_t kek_len, uint8_t * key, size_t key_len, uint8_t * wrapped_key) {
  struct aes128_ctx ctx_128;
  struct aes192_ctx ctx_192;
  struct aes256_ctx ctx_256;
  void * ctx = NULL;
  nettle_cipher_func * decrypt = NULL;
  const uint8_t default_iv[] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};

  if (kek_len == 16) {
    aes128_set_decrypt_key(&ctx_128, kek);
    ctx = (void*)&ctx_128;
    decrypt = (nettle_cipher_func*)&aes128_decrypt;
  }
  if (kek_len == 24) {
    aes192_set_decrypt_key(&ctx_192, kek);
    ctx = (void*)&ctx_192;
    decrypt = (nettle_cipher_func*)&aes192_decrypt;
  }
  if (kek_len == 32) {
    aes256_set_decrypt_key(&ctx_256, kek);
    ctx = (void*)&ctx_256;
    decrypt = (nettle_cipher_func*)&aes256_decrypt;
  }
  return nist_keyunwrap16(ctx, decrypt, default_iv, key_len, key, wrapped_key);
}
#endif

#if NETTLE_VERSION_NUMBER >= 0x030600
static json_t * _r_jwe_ecdh_encrypt(jwe_t * jwe, jwa_alg alg, jwk_t * jwk_pub, jwk_t * jwk_priv, int type, unsigned int bits, int x5u_flags, int * ret) {
  int type_priv = 0;
  unsigned int bits_priv = 0;
  jwk_t * jwk_ephemeral = NULL, * jwk_ephemeral_pub = NULL;
  gnutls_datum_t Z = {NULL, 0}, kdf = {NULL, 0};
  unsigned char cipherkey_b64url[256] = {0};
  uint8_t derived_key[64] = {0}, wrapped_key[72] = {0}, priv_k[_R_CURVE_MAX_SIZE] = {0}, pub_x[_R_CURVE_MAX_SIZE] = {0}, pub_y[_R_CURVE_MAX_SIZE] = {0};
  size_t derived_key_len = 0, cipherkey_b64url_len = 0, priv_k_size = 0, pub_x_size = 0, pub_y_size = 0, crv_size = 0;
  const char * key = NULL;
  json_t * j_return = NULL;
  const struct ecc_curve * nettle_curve;

  do {
    if (r_jwk_init(&jwk_ephemeral_pub) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error r_jwk_init jwk_ephemeral_pub");
      *ret = RHN_ERROR;
      break;
    }

    if (jwk_priv != NULL) {
      type_priv = r_jwk_key_type(jwk_priv, &bits_priv, x5u_flags);

      if ((type_priv & 0xffffff00) != (type & 0xffffff00)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error invalid ephemeral key");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (bits != bits_priv) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error invalid ephemeral key length");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (r_jwk_extract_pubkey(jwk_priv, jwk_ephemeral_pub, x5u_flags) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error extracting public key from jwk_priv");
        *ret = RHN_ERROR;
        break;
      }
    } else {
      if (r_jwk_init(&jwk_ephemeral) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error r_jwk_init jwk_ephemeral");
        *ret = RHN_ERROR;
        break;
      }

      if (r_jwk_generate_key_pair(jwk_ephemeral, jwk_ephemeral_pub, type&R_KEY_TYPE_EC?R_KEY_TYPE_EC:R_KEY_TYPE_ECDH, bits, NULL) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error r_jwk_generate_key_pair");
        *ret = RHN_ERROR;
        break;
      }

      r_jwk_delete_property_str(jwk_ephemeral_pub, "kid");
    }

    if (type & R_KEY_TYPE_EC) {
      if (bits == 256) {
        nettle_curve = nettle_get_secp_256r1();
        crv_size = 32;
      } else if (bits == 384) {
        nettle_curve = nettle_get_secp_384r1();
        crv_size = 48;
      } else {
        nettle_curve = nettle_get_secp_521r1();
        crv_size = 64;
      }

      if (jwk_priv != NULL) {
        key = r_jwk_get_property_str(jwk_priv, "d");
      } else {
        key = r_jwk_get_property_str(jwk_ephemeral, "d");
      }
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode d (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!priv_k_size || priv_k_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Invalid priv_k_size (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), priv_k, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode d (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      key = r_jwk_get_property_str(jwk_pub, "x");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode x (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_x_size || pub_x_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Invalid pub_x_size (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_x, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode x (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      key = r_jwk_get_property_str(jwk_pub, "y");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_y_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode y (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_y_size || pub_y_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Invalid pub_y_size (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_y, &pub_y_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode y (ecdsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (_r_ecdh_compute(priv_k, priv_k_size, pub_x, pub_x_size, pub_y, pub_y_size, nettle_curve, &Z) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error _r_ecdh_compute (ecdsa)");
        *ret = RHN_ERROR;
        break;
      }
    } else {
      if (bits == 256) {
        crv_size = CURVE25519_SIZE;
      } else {
        crv_size = CURVE448_SIZE;
      }

      if (jwk_priv != NULL) {
        key = r_jwk_get_property_str(jwk_priv, "d");
      } else {
        key = r_jwk_get_property_str(jwk_ephemeral, "d");
      }
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode d (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!priv_k_size || priv_k_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Invalid priv_k_size (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), priv_k, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode d (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      pub_x_size = CURVE448_SIZE;
      key = r_jwk_get_property_str(jwk_pub, "x");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode x (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_x_size || pub_x_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Invalid pub_x_size (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_x, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_decode x (eddsa)");
        *ret = RHN_ERROR_PARAM;
        break;
      }

      if (_r_dh_compute(priv_k, pub_x, crv_size, &Z) != GNUTLS_E_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error _r_dh_compute (eddsa)");
        *ret = RHN_ERROR;
        break;
      }
    }


    if (_r_concat_kdf(jwe, alg, &Z, &kdf) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error _r_concat_kdf");
      *ret = RHN_ERROR;
      break;
    }

    if (gnutls_hash_fast(GNUTLS_DIG_SHA256, kdf.data, kdf.size, derived_key) != GNUTLS_E_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error gnutls_hash_fast");
      *ret = RHN_ERROR;
      break;
    }

    if (alg == R_JWA_ALG_ECDH_ES) {
      derived_key_len = _r_get_key_size(jwe->enc);
    } else if (alg == R_JWA_ALG_ECDH_ES_A128KW) {
      derived_key_len = 16;
    } else if (alg == R_JWA_ALG_ECDH_ES_A192KW) {
      derived_key_len = 24;
    } else if (alg == R_JWA_ALG_ECDH_ES_A256KW) {
      derived_key_len = 32;
    }

    if (alg == R_JWA_ALG_ECDH_ES) {
      r_jwe_set_cypher_key(jwe, derived_key, derived_key_len);
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = NULL;
      j_return = json_pack("{s{ss so}}", "header",
                                           "alg", r_jwa_alg_to_str(alg),
                                           "epk", r_jwk_export_to_json_t(jwk_ephemeral_pub));
    } else {
      _r_aes_key_wrap(derived_key, derived_key_len, jwe->key, jwe->key_len, wrapped_key);
      if (!o_base64url_encode(wrapped_key, jwe->key_len+8, cipherkey_b64url, &cipherkey_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_encrypt - Error o_base64url_encode wrapped_key");
        *ret = RHN_ERROR;
      }
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = (unsigned char *)o_strndup((const char *)cipherkey_b64url, cipherkey_b64url_len);
      j_return = json_pack("{ss%s{ss so}}", "encrypted_key", cipherkey_b64url, cipherkey_b64url_len,
                                             "header",
                                               "alg", r_jwa_alg_to_str(alg),
                                               "epk", r_jwk_export_to_json_t(jwk_ephemeral_pub));
    }
  } while (0);

  o_free(kdf.data);
  gnutls_free(Z.data);
  r_jwk_free(jwk_ephemeral);
  r_jwk_free(jwk_ephemeral_pub);

  return j_return;
}

static int _r_jwe_ecdh_decrypt(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int type, unsigned int bits, int x5u_flags) {
  int ret = RHN_OK;
  jwk_t * jwk_ephemeral_pub = NULL;
  json_t * j_epk = NULL;
  unsigned int epk_bits = 0;
  gnutls_datum_t Z = {NULL, 0}, kdf = {NULL, 0};
  uint8_t derived_key[64] = {0}, key_data[72] = {0}, cipherkey[128] = {0}, priv_k[_R_CURVE_MAX_SIZE] = {0}, pub_x[_R_CURVE_MAX_SIZE] = {0}, pub_y[_R_CURVE_MAX_SIZE] = {0};
  size_t derived_key_len = 0, cipherkey_len = 0, priv_k_size = 0, pub_x_size = 0, pub_y_size = 0, crv_size = 0;
  const char * key = NULL;
  const struct ecc_curve * nettle_curve;

  do {
    if ((j_epk = r_jwe_get_header_json_t_value(jwe, "epk")) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - No epk header");
      ret = RHN_ERROR_PARAM;
      break;
    }

    if (r_jwk_init(&jwk_ephemeral_pub) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error r_jwk_init");
      ret = RHN_ERROR;
      break;
    }

    if (r_jwk_import_from_json_t(jwk_ephemeral_pub, j_epk) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error r_jwk_import_from_json_t");
      ret = RHN_ERROR_PARAM;
      break;
    }

    if (type & R_KEY_TYPE_EC) {
      if (!(r_jwk_key_type(jwk_ephemeral_pub, &epk_bits, x5u_flags) & (R_KEY_TYPE_EC|R_KEY_TYPE_PUBLIC)) || epk_bits != bits) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error invalid private key type (ecc)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (bits == 256) {
        nettle_curve = nettle_get_secp_256r1();
        crv_size = 32;
      } else if (bits == 384) {
        nettle_curve = nettle_get_secp_384r1();
        crv_size = 48;
      } else {
        nettle_curve = nettle_get_secp_521r1();
        crv_size = 64;
      }

      key = r_jwk_get_property_str(jwk, "d");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode d (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!priv_k_size || priv_k_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Invalid priv_k_size (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), priv_k, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode d (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      key = r_jwk_get_property_str(jwk_ephemeral_pub, "x");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode x (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_x_size || pub_x_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Invalid pub_x_size (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_x, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode x (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      key = r_jwk_get_property_str(jwk_ephemeral_pub, "y");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_y_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode y (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_y_size || pub_y_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Invalid pub_y_size (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_y, &pub_y_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode y (ecdsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (_r_ecdh_compute(priv_k, priv_k_size, pub_x, pub_x_size, pub_y, pub_y_size, nettle_curve, &Z) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error _r_ecdh_compute (ecdsa)");
        ret = RHN_ERROR;
        break;
      }
    } else {
      if (!(r_jwk_key_type(jwk_ephemeral_pub, &epk_bits, x5u_flags) & (R_KEY_TYPE_ECDH|R_KEY_TYPE_PUBLIC)) || epk_bits != bits) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error invalid private key type (eddsa)");
        ret = RHN_ERROR_INVALID;
        break;
      }

      if (bits == 256) {
        crv_size = CURVE25519_SIZE;
      } else {
        crv_size = CURVE448_SIZE;
      }

      key = r_jwk_get_property_str(jwk, "d");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), priv_k, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode d (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!priv_k_size || priv_k_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Invalid priv_k_size (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &priv_k_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode d (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      key = r_jwk_get_property_str(jwk_ephemeral_pub, "x");
      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), pub_x, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode x (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!pub_x_size || pub_x_size > _R_CURVE_MAX_SIZE) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Invalid priv_k_size (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (!o_base64url_decode((const unsigned char *)key, o_strlen(key), NULL, &pub_x_size)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode x (eddsa)");
        ret = RHN_ERROR_PARAM;
        break;
      }

      if (_r_dh_compute(priv_k, pub_x, crv_size, &Z) != GNUTLS_E_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error _r_dh_compute (eddsa)");
        ret = RHN_ERROR;
        break;
      }
    }

    if (_r_concat_kdf(jwe, alg, &Z, &kdf) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error _r_concat_kdf");
      ret = RHN_ERROR;
      break;
    }

    if (gnutls_hash_fast(GNUTLS_DIG_SHA256, kdf.data, kdf.size, derived_key) != GNUTLS_E_SUCCESS) {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error gnutls_hash_fast");
      ret = RHN_ERROR;
      break;
    }

    if (alg == R_JWA_ALG_ECDH_ES) {
      derived_key_len = _r_get_key_size(jwe->enc);
    } else if (alg == R_JWA_ALG_ECDH_ES_A128KW) {
      derived_key_len = 16;
    } else if (alg == R_JWA_ALG_ECDH_ES_A192KW) {
      derived_key_len = 24;
    } else if (alg == R_JWA_ALG_ECDH_ES_A256KW) {
      derived_key_len = 32;
    }

    if (alg == R_JWA_ALG_ECDH_ES) {
      r_jwe_set_cypher_key(jwe, derived_key, derived_key_len);
    } else {
      if (o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cipherkey, &cipherkey_len)) {
        if (_r_aes_key_unwrap(derived_key, derived_key_len, key_data, cipherkey_len-8, cipherkey)) {
          r_jwe_set_cypher_key(jwe, key_data, cipherkey_len-8);
        } else {
          ret = RHN_ERROR_INVALID;
          break;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_jwe_ecdh_decrypt - Error o_base64url_decode cipherkey");
        ret = RHN_ERROR;
        break;
      }
    }
  } while (0);

  o_free(kdf.data);
  gnutls_free(Z.data);
  r_jwk_free(jwk_ephemeral_pub);
  json_decref(j_epk);

  return ret;
}
#endif

#if NETTLE_VERSION_NUMBER >= 0x030400
static json_t * r_jwe_aes_key_wrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags, int * ret) {
  uint8_t kek[32] = {0}, wrapped_key[72] = {0};
  unsigned char cipherkey_b64url[256] = {0};
  size_t kek_len = 0, cipherkey_b64url_len = 0;
  unsigned int bits = 0;
  json_t * j_return = NULL;

  if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
    do {
      if (alg == R_JWA_ALG_A128KW && bits != 128) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error invalid key size, expected 128 bits");
        *ret = RHN_ERROR_PARAM;
        break;
      }
      if (alg == R_JWA_ALG_A192KW && bits != 192) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error invalid key size, expected 192 bits");
        *ret = RHN_ERROR_PARAM;
        break;
      }
      if (alg == R_JWA_ALG_A256KW && bits != 256) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error invalid key size, expected 256 bits");
        *ret = RHN_ERROR_PARAM;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, kek, &kek_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error r_jwk_export_to_symmetric_key");
        *ret = RHN_ERROR;
        break;
      }
      _r_aes_key_wrap(kek, kek_len, jwe->key, jwe->key_len, wrapped_key);
      if (!o_base64url_encode(wrapped_key, jwe->key_len+8, cipherkey_b64url, &cipherkey_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error o_base64url_encode wrapped_key");
        *ret = RHN_ERROR;
        break;
      }
      j_return = json_pack("{ss%s{ss}}", "encrypted_key", cipherkey_b64url, cipherkey_b64url_len, "header", "alg", r_jwa_alg_to_str(alg));
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = (unsigned char *)o_strndup((const char *)cipherkey_b64url, cipherkey_b64url_len);
    } while (0);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error invalid key");
    *ret = RHN_ERROR_PARAM;
  }
  return j_return;
}

static int r_jwe_aes_key_unwrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags) {
  int ret;
  uint8_t kek[32] = {0}, key_data[64], cipherkey[128] = {0};
  size_t kek_len = 0, cipherkey_len = 0;
  unsigned int bits = 0;

  if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
    ret = RHN_OK;

    do {
      if (alg == R_JWA_ALG_A128KW && bits != 128) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error invalid key size, expected 128 bits");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (alg == R_JWA_ALG_A192KW && bits != 192) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error invalid key size, expected 192 bits");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (alg == R_JWA_ALG_A256KW && bits != 256) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error invalid key size, expected 256 bits");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, kek, &kek_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error r_jwk_export_to_symmetric_key");
        ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), NULL, &cipherkey_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error o_base64url_decode cipherkey");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (cipherkey_len > 72) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error invalid cipherkey len");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (!o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cipherkey, &cipherkey_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error o_base64url_decode cipherkey");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (!_r_aes_key_unwrap(kek, kek_len, key_data, cipherkey_len-8, cipherkey)) {
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (r_jwe_set_cypher_key(jwe, key_data, cipherkey_len-8) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error r_jwe_set_cypher_key");
        ret = RHN_ERROR;
      }
    } while (0);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_unwrap - Error invalid key");
    ret = RHN_ERROR_INVALID;
  }
  return ret;
}
#endif

#if GNUTLS_VERSION_NUMBER >= 0x03060d
static json_t * r_jwe_pbes2_key_wrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags, int * ret) {
  unsigned char salt_seed[_R_PBES_DEFAULT_SALT_LENGTH] = {0}, salt_seed_b64[_R_PBES_DEFAULT_SALT_LENGTH*2], * salt = NULL, kek[64] = {0}, * key = NULL, wrapped_key[72] = {0}, cipherkey_b64url[256] = {0}, * p2s_dec = NULL;
  size_t alg_len, salt_len, key_len = 0, cipherkey_b64url_len = 0, salt_seed_b64_len = 0, p2s_dec_len = 0, kek_len = 0;
  const char * p2s = NULL;
  unsigned int p2c = 0;
  gnutls_datum_t password = {NULL, 0}, g_salt = {NULL, 0};
  gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;
  json_t * j_return = NULL;

  if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
    do {
      alg_len = o_strlen(r_jwa_alg_to_str(alg));
      if ((p2s = r_jwe_get_header_str_value(jwe, "p2s")) != NULL) {
        if ((p2s_dec = o_malloc(o_strlen(p2s)*2)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_malloc p2s_dec");
          *ret = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)p2s, o_strlen(p2s), p2s_dec, &p2s_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_base64url_decode p2s");
          *ret = RHN_ERROR_PARAM;
          break;
        }
        if (p2s_dec_len < 8) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error invalid p2s length");
          *ret = RHN_ERROR_PARAM;
          break;
        }
        salt_len = p2s_dec_len + alg_len + 1;
        if ((salt = o_malloc(salt_len)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_malloc salt (1)");
          *ret = RHN_ERROR_MEMORY;
          break;
        }
        memcpy(salt, r_jwa_alg_to_str(alg), alg_len);
        memset(salt+alg_len, 0, 1);
        memcpy(salt+alg_len+1, p2s_dec, p2s_dec_len);
      } else {
        if (gnutls_rnd(GNUTLS_RND_NONCE, salt_seed, _R_PBES_DEFAULT_SALT_LENGTH)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error gnutls_rnd");
          *ret = RHN_ERROR;
          break;
        }
        salt_len = _R_PBES_DEFAULT_SALT_LENGTH + alg_len + 1;
        if ((salt = o_malloc(salt_len)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_malloc salt (2)");
          *ret = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_encode(salt_seed, _R_PBES_DEFAULT_SALT_LENGTH, salt_seed_b64, &salt_seed_b64_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_base64url_encode salt_seed");
          *ret = RHN_ERROR;
          break;
        }
        salt_seed_b64[salt_seed_b64_len] = '\0';

        memcpy(salt, r_jwa_alg_to_str(alg), alg_len);
        memset(salt+alg_len, 0, 1);
        memcpy(salt+alg_len+1, salt_seed, _R_PBES_DEFAULT_SALT_LENGTH);
      }
      if ((p2c = (unsigned int)r_jwe_get_header_int_value(jwe, "p2c")) <= 0) {
        p2c = _R_PBES_DEFAULT_ITERATION;
      }

      if (r_jwk_export_to_symmetric_key(jwk, NULL, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error r_jwk_export_to_symmetric_key (1)");
        *ret = RHN_ERROR;
        break;
      }
      key_len += 4;
      if ((key = o_malloc(key_len)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error o_malloc key");
        *ret = RHN_ERROR_MEMORY;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error r_jwk_export_to_symmetric_key (2)");
        *ret = RHN_ERROR;
        break;
      }
      password.data = key;
      password.size = key_len;
      g_salt.data = salt;
      g_salt.size = salt_len;
      if (alg == R_JWA_ALG_PBES2_H256) {
        kek_len = 16;
        mac = GNUTLS_MAC_SHA256;
      } else if (alg == R_JWA_ALG_PBES2_H384) {
        kek_len = 24;
        mac = GNUTLS_MAC_SHA384;
      } else if (alg == R_JWA_ALG_PBES2_H512) {
        kek_len = 32;
        mac = GNUTLS_MAC_SHA512;
      }
      if (gnutls_pbkdf2(mac, &password, &g_salt, p2c, kek, kek_len) != GNUTLS_E_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error gnutls_pbkdf2");
        *ret = RHN_ERROR;
        break;
      }
      _r_aes_key_wrap(kek, kek_len, jwe->key, jwe->key_len, wrapped_key);
      if (!o_base64url_encode(wrapped_key, jwe->key_len+8, cipherkey_b64url, &cipherkey_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aes_key_wrap - Error o_base64url_encode wrapped_key");
        *ret = RHN_ERROR;
        break;
      }
      j_return = json_pack("{ss%s{sssssi}}", "encrypted_key", cipherkey_b64url, cipherkey_b64url_len,
                                             "header",
                                               "alg", r_jwa_alg_to_str(alg),
                                               "p2s", p2s!=NULL?p2s:(const char*)salt_seed_b64,
                                               "p2c", p2c);
    } while (0);
    o_free(key);
    o_free(salt);
    o_free(p2s_dec);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_wrap - Error invalid key");
  }
  return j_return;
}

static int r_jwe_pbes2_key_unwrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags) {
  unsigned char * salt = NULL, kek[64] = {0}, * key = NULL, cipherkey[128] = {0}, key_data[64] = {0}, * p2s_dec = NULL;
  size_t alg_len, salt_len, key_len = 0, cipherkey_len = 0, p2s_dec_len = 0, kek_len = 0;
  int ret;
  const char * p2s;
  unsigned int p2c;
  gnutls_datum_t password = {NULL, 0}, g_salt = {NULL, 0};
  gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;

  if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
    ret = RHN_OK;

    do {
      alg_len = o_strlen(r_jwe_get_header_str_value(jwe, "alg"));
      if ((p2c = (unsigned int)r_jwe_get_header_int_value(jwe, "p2c")) <= 0) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error invalid p2c");
        ret = RHN_ERROR_PARAM;
        break;
      }
      if (o_strlen(r_jwe_get_header_str_value(jwe, "p2s")) < 8) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error invalid p2s");
        ret = RHN_ERROR_PARAM;
        break;
      }
      p2s = r_jwe_get_header_str_value(jwe, "p2s");
      if ((p2s_dec = o_malloc(o_strlen(p2s))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error o_malloc p2s_dec");
        ret = RHN_ERROR_MEMORY;
        break;
      }
      if (!o_base64url_decode((const unsigned char *)p2s, o_strlen(p2s), p2s_dec, &p2s_dec_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error o_base64url_decode p2s_dec");
        ret = RHN_ERROR;
        break;
      }
      salt_len = p2s_dec_len + alg_len + 1;
      if ((salt = o_malloc(salt_len)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error o_malloc salt");
        ret = RHN_ERROR_MEMORY;
        break;
      }
      memcpy(salt, r_jwe_get_header_str_value(jwe, "alg"), alg_len);
      memset(salt+alg_len, 0, 1);
      memcpy(salt+alg_len+1, p2s_dec, p2s_dec_len);

      if (r_jwk_export_to_symmetric_key(jwk, NULL, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error r_jwk_export_to_symmetric_key (1)");
        ret = RHN_ERROR;
        break;
      }
      key_len += 4;
      if ((key = o_malloc(key_len)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error o_malloc key");
        ret = RHN_ERROR_MEMORY;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error r_jwk_export_to_symmetric_key (2)");
        ret = RHN_ERROR;
        break;
      }
      password.data = key;
      password.size = key_len;
      g_salt.data = salt;
      g_salt.size = salt_len;
      if (alg == R_JWA_ALG_PBES2_H256) {
        kek_len = 16;
        mac = GNUTLS_MAC_SHA256;
      } else if (alg == R_JWA_ALG_PBES2_H384) {
        kek_len = 24;
        mac = GNUTLS_MAC_SHA384;
      } else if (alg == R_JWA_ALG_PBES2_H512) {
        kek_len = 32;
        mac = GNUTLS_MAC_SHA512;
      }
      if (gnutls_pbkdf2(mac, &password, &g_salt, p2c, kek, kek_len) != GNUTLS_E_SUCCESS) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error gnutls_pbkdf2");
        ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cipherkey, &cipherkey_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error o_base64url_decode cipherkey");
        ret = RHN_ERROR;
        break;
      }
      if (!_r_aes_key_unwrap(kek, kek_len, key_data, cipherkey_len-8, cipherkey)) {
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (r_jwe_set_cypher_key(jwe, key_data, cipherkey_len-8) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error r_jwe_set_cypher_key");
        ret = RHN_ERROR;
      }
    } while (0);
    o_free(key);
    o_free(salt);
    o_free(p2s_dec);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_pbes2_key_unwrap - Error invalid key");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}
#endif

static gnutls_mac_algorithm_t r_jwe_get_digest_from_enc(jwa_enc enc) {
  gnutls_mac_algorithm_t digest;

  switch (enc) {
    case R_JWA_ENC_A128CBC:
      digest = GNUTLS_MAC_SHA256;
      break;
    case R_JWA_ENC_A192CBC:
      digest = GNUTLS_MAC_SHA384;
      break;
    case R_JWA_ENC_A256CBC:
      digest = GNUTLS_MAC_SHA512;
      break;
    case R_JWA_ENC_A128GCM:
      digest = GNUTLS_MAC_SHA256;
      break;
    case R_JWA_ENC_A192GCM:
      digest = GNUTLS_MAC_SHA384;
      break;
    case R_JWA_ENC_A256GCM:
      digest = GNUTLS_MAC_SHA512;
      break;
    default:
      digest = GNUTLS_MAC_UNKNOWN;
      break;
  }
  return digest;
}

static gnutls_cipher_algorithm_t r_jwe_get_alg_from_alg(jwa_alg alg) {
  gnutls_cipher_algorithm_t ret_alg = GNUTLS_CIPHER_UNKNOWN;

  switch (alg) {
    case R_JWA_ALG_A128GCMKW:
      ret_alg = GNUTLS_CIPHER_AES_128_GCM;
      break;
    case R_JWA_ALG_A192GCMKW:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      ret_alg = GNUTLS_CIPHER_AES_192_GCM;
#else
      ret_alg = GNUTLS_CIPHER_UNKNOWN; // Unsupported until GnuTLS 3.6.14
#endif
      break;
    case R_JWA_ALG_A256GCMKW:
      ret_alg = GNUTLS_CIPHER_AES_256_GCM;
      break;
    default:
      ret_alg = GNUTLS_CIPHER_UNKNOWN;
      break;
  }
  return ret_alg;
}

static json_t * r_jwe_aesgcm_key_wrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags, int * ret) {
  int res;
  unsigned char iv[96] = {0}, iv_b64url[192] = {0}, * key = NULL, cipherkey[64] = {0}, cipherkey_b64url[128] = {0}, tag[128] = {0}, tag_b64url[256] = {0};
  size_t iv_b64url_len = 0, key_len = 0, cipherkey_b64url_len = 0, tag_b64url_len = 0, iv_size = gnutls_cipher_get_iv_size(r_jwe_get_alg_from_alg(alg)), tag_len = gnutls_cipher_get_tag_size(r_jwe_get_alg_from_alg(alg));
  unsigned int bits = 0;
  gnutls_datum_t key_g, iv_g;
  gnutls_cipher_hd_t handle = NULL;
  json_t * j_return = NULL;

  if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
    key_len = bits;

    do {
      if ((key = o_malloc(key_len+4)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error allocating resources for key");
        *ret = RHN_ERROR_MEMORY;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error r_jwk_export_to_symmetric_key");
        *ret = RHN_ERROR_PARAM;
        break;
      }
      if (r_jwe_get_header_str_value(jwe, "iv") == NULL) {
        if (gnutls_rnd(GNUTLS_RND_NONCE, iv, iv_size)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error gnutls_rnd");
          *ret = RHN_ERROR;
          break;
        }
        if (!o_base64url_encode(iv, iv_size, iv_b64url, &iv_b64url_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error o_base64url_encode iv");
          *ret = RHN_ERROR;
          break;
        }
        iv_b64url[iv_b64url_len] = '\0';
      } else {
        if (!o_base64url_decode((const unsigned char *)r_jwe_get_header_str_value(jwe, "iv"), o_strlen(r_jwe_get_header_str_value(jwe, "iv")), iv, &iv_size)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error o_base64url_decode iv");
          *ret = RHN_ERROR_PARAM;
          break;
        }
        if (iv_size != gnutls_cipher_get_iv_size(r_jwe_get_alg_from_alg(alg))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error invalid iv size");
          *ret = RHN_ERROR_PARAM;
          break;
        }
      }
      key_g.data = key;
      key_g.size = key_len;
      iv_g.data = iv;
      iv_g.size = iv_size;
      if ((res = gnutls_cipher_init(&handle, r_jwe_get_alg_from_alg(alg), &key_g, &iv_g))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error gnutls_cipher_init: '%s'", gnutls_strerror(res));
        *ret = RHN_ERROR_PARAM;
        break;
      }
      if ((res = gnutls_cipher_encrypt2(handle, jwe->key, jwe->key_len, cipherkey, jwe->key_len))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error gnutls_cipher_encrypt2: '%s'", gnutls_strerror(res));
        *ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_encode(cipherkey, jwe->key_len, cipherkey_b64url, &cipherkey_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error o_base64url_encode cipherkey");
        *ret = RHN_ERROR;
        break;
      }
      if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
        *ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_encode(tag, tag_len, tag_b64url, &tag_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error o_base64url_encode tag");
        *ret = RHN_ERROR;
        break;
      }
      tag_b64url[tag_b64url_len] = '\0';
      j_return = json_pack("{ss%s{ssssss}}", "encrypted_key", cipherkey_b64url, cipherkey_b64url_len,
                                             "header",
                                               "iv", r_jwe_get_header_str_value(jwe, "iv")==NULL?(const char *)iv_b64url:r_jwe_get_header_str_value(jwe, "iv"),
                                               "tag", tag_b64url,
                                               "alg", r_jwa_alg_to_str(alg));
    } while (0);
    o_free(key);
    if (handle != NULL) {
      gnutls_cipher_deinit(handle);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_wrap - Error invalid key");
    *ret = RHN_ERROR_PARAM;
  }
  return j_return;
}

static int r_jwe_set_alg_header(jwe_t * jwe, json_t * j_header) {
  int ret = RHN_OK;
  switch (jwe->alg) {
    case R_JWA_ALG_NONE:
      json_object_set_new(j_header, "alg", json_string("none"));
      break;
    case R_JWA_ALG_RSA1_5:
      json_object_set_new(j_header, "alg", json_string("RSA1_5"));
      break;
    case R_JWA_ALG_RSA_OAEP:
      json_object_set_new(j_header, "alg", json_string("RSA-OAEP"));
      break;
    case R_JWA_ALG_RSA_OAEP_256:
      json_object_set_new(j_header, "alg", json_string("RSA-OAEP-256"));
      break;
    case R_JWA_ALG_A128KW:
      json_object_set_new(j_header, "alg", json_string("A128KW"));
      break;
    case R_JWA_ALG_A192KW:
      json_object_set_new(j_header, "alg", json_string("A192KW"));
      break;
    case R_JWA_ALG_A256KW:
      json_object_set_new(j_header, "alg", json_string("A256KW"));
      break;
    case R_JWA_ALG_DIR:
      json_object_set_new(j_header, "alg", json_string("dir"));
      break;
    case R_JWA_ALG_ECDH_ES:
      json_object_set_new(j_header, "alg", json_string("ECDH-ES"));
      break;
    case R_JWA_ALG_ECDH_ES_A128KW:
      json_object_set_new(j_header, "alg", json_string("ECDH-ES+A128KW"));
      break;
    case R_JWA_ALG_ECDH_ES_A192KW:
      json_object_set_new(j_header, "alg", json_string("ECDH-ES+A192KW"));
      break;
    case R_JWA_ALG_ECDH_ES_A256KW:
      json_object_set_new(j_header, "alg", json_string("ECDH-ES+A256KW"));
      break;
    case R_JWA_ALG_A128GCMKW:
      json_object_set_new(j_header, "alg", json_string("A128GCMKW"));
      break;
    case R_JWA_ALG_A192GCMKW:
      json_object_set_new(j_header, "alg", json_string("A192GCMKW"));
      break;
    case R_JWA_ALG_A256GCMKW:
      json_object_set_new(j_header, "alg", json_string("A256GCMKW"));
      break;
    case R_JWA_ALG_PBES2_H256:
      json_object_set_new(j_header, "alg", json_string("PBES2-HS256+A128KW"));
      break;
    case R_JWA_ALG_PBES2_H384:
      json_object_set_new(j_header, "alg", json_string("PBES2-HS384+A192KW"));
      break;
    case R_JWA_ALG_PBES2_H512:
      json_object_set_new(j_header, "alg", json_string("PBES2-HS512+A256KW"));
      break;
    default:
      ret = RHN_ERROR_PARAM;
      break;
  }
  return ret;
}

static int r_jwe_set_enc_header(jwe_t * jwe, json_t * j_header) {
  int ret = RHN_OK;
  switch (jwe->enc) {
    case R_JWA_ENC_A128CBC:
      json_object_set_new(j_header, "enc", json_string("A128CBC-HS256"));
      break;
    case R_JWA_ENC_A192CBC:
      json_object_set_new(j_header, "enc", json_string("A192CBC-HS384"));
      break;
    case R_JWA_ENC_A256CBC:
      json_object_set_new(j_header, "enc", json_string("A256CBC-HS512"));
      break;
    case R_JWA_ENC_A128GCM:
      json_object_set_new(j_header, "enc", json_string("A128GCM"));
      break;
    case R_JWA_ENC_A192GCM:
      json_object_set_new(j_header, "enc", json_string("A192GCM"));
      break;
    case R_JWA_ENC_A256GCM:
      json_object_set_new(j_header, "enc", json_string("A256GCM"));
      break;
    default:
      ret = RHN_ERROR_PARAM;
      break;
  }
  return ret;
}

static int r_jwe_aesgcm_key_unwrap(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags) {
  int ret, res;
  unsigned char iv[96] = {0}, * key = NULL, cipherkey[64] = {0}, tag[128] = {0}, tag_b64url[256] = {0};
  size_t iv_len = 0, key_len = 0, cipherkey_len = 0, tag_b64url_len = 0, tag_len = gnutls_cipher_get_tag_size(r_jwe_get_alg_from_alg(alg));
  unsigned int bits = 0;
  gnutls_datum_t key_g, iv_g;
  gnutls_cipher_hd_t handle = NULL;

  if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && o_strlen(r_jwe_get_header_str_value(jwe, "iv")) && o_strlen(r_jwe_get_header_str_value(jwe, "tag"))) {
    ret = RHN_OK;
    key_len = bits;

    do {
      if ((key = o_malloc(key_len+4)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error allocating resources for key");
        ret = RHN_ERROR_MEMORY;
        break;
      }
      if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error r_jwk_export_to_symmetric_key");
        ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_decode((const unsigned char *)r_jwe_get_header_str_value(jwe, "iv"), o_strlen(r_jwe_get_header_str_value(jwe, "iv")), iv, &iv_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error o_base64url_decode iv");
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (!o_base64url_decode((const unsigned char *)jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cipherkey, &cipherkey_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error o_base64url_decode cipherkey");
        ret = RHN_ERROR_INVALID;
        break;
      }
      key_g.data = key;
      key_g.size = key_len;
      iv_g.data = iv;
      iv_g.size = iv_len;
      if ((res = gnutls_cipher_init(&handle, r_jwe_get_alg_from_alg(alg), &key_g, &iv_g))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error gnutls_cipher_init: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR_INVALID;
        break;
      }
      if ((res = gnutls_cipher_decrypt(handle, cipherkey, cipherkey_len))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error gnutls_cipher_decrypt: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR;
        break;
      }
      if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR;
        break;
      }
      if (!o_base64url_encode(tag, tag_len, tag_b64url, &tag_b64url_len)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error o_base64url_encode tag");
        ret = RHN_ERROR;
        break;
      }
      tag_b64url[tag_b64url_len] = '\0';
      if (0 != o_strcmp((const char *)tag_b64url, r_jwe_get_header_str_value(jwe, "tag"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Invalid tag %s %s", tag_b64url, r_jwe_get_header_str_value(jwe, "tag"));
        ret = RHN_ERROR_INVALID;
        break;
      }
      if (r_jwe_set_cypher_key(jwe, cipherkey, cipherkey_len) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error r_jwe_set_cypher_key");
        ret = RHN_ERROR;
      }

    } while (0);
    o_free(key);
    if (handle != NULL) {
      gnutls_cipher_deinit(handle);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_aesgcm_key_unwrap - Error invalid key");
    ret = RHN_ERROR_INVALID;
  }
  return ret;
}

static int r_jwe_set_ptext_with_block(unsigned char * data, size_t data_len, unsigned char ** ptext, size_t * ptext_len, gnutls_cipher_algorithm_t alg, int cipher_cbc) {
  size_t b_size = (size_t)gnutls_cipher_get_block_size(alg);
  int ret;

  *ptext = NULL;
  if (cipher_cbc) {
    if (data_len % b_size) {
      *ptext_len = ((data_len/b_size)+1)*b_size;
    } else {
      *ptext_len = data_len;
    }
    if (*ptext_len) {
      if ((*ptext = o_malloc(*ptext_len)) != NULL) {
        memcpy(*ptext, data, data_len);
        memset(*ptext+data_len, (*ptext_len)-data_len, (*ptext_len)-data_len);
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_ptext_with_block - Error allocating resources for ptext (1)");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      ret = RHN_ERROR;
    }
  } else {
    *ptext_len = data_len;
    if ((*ptext = o_malloc(data_len)) != NULL) {
      memcpy(*ptext, data, data_len);
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_ptext_with_block - Error allocating resources for ptext (2)");
      ret = RHN_ERROR_MEMORY;
    }
  }
  return ret;
}

static int r_jwe_extract_header(jwe_t * jwe, json_t * j_header, uint32_t parse_flags, int x5u_flags) {
  int ret;
  jwk_t * jwk;

  if (json_is_object(j_header)) {
    ret = RHN_OK;

    if (json_object_get(j_header, "alg") != NULL) {
      if (0 != o_strcmp("RSA1_5", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("RSA-OAEP", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("RSA-OAEP-256", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A128KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A192KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A256KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("dir", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("ECDH-ES", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("ECDH-ES+A128KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("ECDH-ES+A192KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("ECDH-ES+A256KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A128GCMKW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A192GCMKW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("A256GCMKW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("PBES2-HS256+A128KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("PBES2-HS384+A192KW", json_string_value(json_object_get(j_header, "alg"))) &&
      0 != o_strcmp("PBES2-HS512+A256KW", json_string_value(json_object_get(j_header, "alg")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Invalid alg");
        ret = RHN_ERROR_PARAM;
      } else {
        jwe->alg = r_str_to_jwa_alg(json_string_value(json_object_get(j_header, "alg")));
      }
    }

    if (json_object_get(j_header, "enc") != NULL) {
      if (0 != o_strcmp("A128CBC-HS256", json_string_value(json_object_get(j_header, "enc"))) &&
      0 != o_strcmp("A192CBC-HS384", json_string_value(json_object_get(j_header, "enc"))) &&
      0 != o_strcmp("A256CBC-HS512", json_string_value(json_object_get(j_header, "enc"))) &&
      0 != o_strcmp("A128GCM", json_string_value(json_object_get(j_header, "enc"))) &&
      0 != o_strcmp("A192GCM", json_string_value(json_object_get(j_header, "enc"))) &&
      0 != o_strcmp("A256GCM", json_string_value(json_object_get(j_header, "enc")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Invalid enc");
        ret = RHN_ERROR_PARAM;
      } else {
        jwe->enc = r_str_to_jwa_enc(json_string_value(json_object_get(j_header, "enc")));
      }
    }

    if (json_string_length(json_object_get(j_header, "jku")) && (parse_flags&R_PARSE_HEADER_JKU)) {
      if (r_jwks_import_from_uri(jwe->jwks_pubkey, json_string_value(json_object_get(j_header, "jku")), x5u_flags) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Error loading jwks from uri %s", json_string_value(json_object_get(j_header, "jku")));
      }
    }

    if (json_object_get(j_header, "jwk") != NULL && (parse_flags&R_PARSE_HEADER_JWK)) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_json_t(jwk, json_object_get(j_header, "jwk")) == RHN_OK && r_jwk_key_type(jwk, NULL, 0)&R_KEY_TYPE_PUBLIC) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Error parsing header jwk");
          ret = RHN_ERROR;
        }
      } else {
        ret = RHN_ERROR_PARAM;
      }
      r_jwk_free(jwk);
    }

    if (json_object_get(j_header, "x5u") != NULL && (parse_flags&R_PARSE_HEADER_X5U)) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_x5u(jwk, x5u_flags, json_string_value(json_object_get(j_header, "x5u"))) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Error importing x5u");
        ret = RHN_ERROR_PARAM;
      }
      r_jwk_free(jwk);
    }

    if (json_object_get(j_header, "x5c") != NULL && (parse_flags&R_PARSE_HEADER_X5C)) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_x5c(jwk, json_string_value(json_array_get(json_object_get(j_header, "x5c"), 0))) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Error importing x5c");
        ret = RHN_ERROR_PARAM;
      }
      r_jwk_free(jwk);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }

  return ret;
}

static void r_jwe_remove_padding(unsigned char * text, size_t * text_len, unsigned int block_size) {
  unsigned char pad = text[(*text_len)-1], i;
  int pad_ok = 1;

  if (pad && pad < (unsigned char)block_size) {
    for (i=0; i<pad; i++) {
      if (text[((*text_len)-i-1)] != pad) {
        pad_ok = 0;
      }
    }
    if (pad_ok) {
      *text_len -= pad;
    }
  }
}

static int r_jwe_compute_hmac_tag(jwe_t * jwe, unsigned char * ciphertext, size_t cyphertext_len, const unsigned char * aad, unsigned char * tag, size_t * tag_len) {
  int ret, res;
  unsigned char al[8], * compute_hmac = NULL;
  uint64_t aad_len;
  size_t hmac_size = 0, aad_size = o_strlen((const char *)aad), i;
  gnutls_mac_algorithm_t mac = r_jwe_get_digest_from_enc(jwe->enc);

  aad_len = (uint64_t)(o_strlen((const char *)aad)*8);
  memset(al, 0, 8);
  for(i = 0; i < 8; i++) {
    al[i] = (uint8_t)((aad_len >> 8*(7 - i)) & 0xFF);
  }

  if ((compute_hmac = o_malloc(aad_size+jwe->iv_len+cyphertext_len+8)) != NULL) {
    if (aad_size) {
      memcpy(compute_hmac, aad, aad_size);
      hmac_size += aad_size;
    }
    memcpy(compute_hmac+hmac_size, jwe->iv, jwe->iv_len);
    hmac_size += jwe->iv_len;
    memcpy(compute_hmac+hmac_size, ciphertext, cyphertext_len);
    hmac_size += cyphertext_len;
    memcpy(compute_hmac+hmac_size, al, 8);
    hmac_size += 8;

    if (!(res = gnutls_hmac_fast(mac, jwe->key, jwe->key_len/2, compute_hmac, hmac_size, tag))) {
      *tag_len = gnutls_hmac_get_len(mac)/2;
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compute_hmac_tag - Error gnutls_hmac_fast: '%s'", gnutls_strerror(res));
      ret = RHN_ERROR;
    }
    o_free(compute_hmac);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compute_hmac_tag - Error allocating resources for compute_hmac");
    ret = RHN_ERROR;
  }
  return ret;
}

static json_t * r_jwe_perform_key_encryption(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags, int * ret) {
  json_t * j_return = NULL;
  int res;
  unsigned int bits = 0;
  gnutls_pubkey_t g_pub = NULL;
  gnutls_datum_t plainkey, cypherkey = {NULL, 0};
  unsigned char * cypherkey_b64 = NULL, key[128] = {0};
  size_t cypherkey_b64_len = 0, key_len = 0, index = 0;
  const char * key_ref = NULL;
  json_t * j_element = NULL, * j_reference, * j_key_ref_array;
#if NETTLE_VERSION_NUMBER >= 0x030400
  uint8_t * cyphertext = NULL;
  size_t cyphertext_len = 0;
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
  json_t * jwk_priv = NULL;
#endif

  switch (alg) {
    case R_JWA_ALG_RSA1_5:
      res = r_jwk_key_type(jwk, &bits, x5u_flags);
      if (res & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC) && bits >= 2048) {
        if (jwk != NULL && (g_pub = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
          plainkey.data = jwe->key;
          plainkey.size = jwe->key_len;
          if (!(res = gnutls_pubkey_encrypt_data(g_pub, 0, &plainkey, &cypherkey))) {
            if ((cypherkey_b64 = o_malloc(cypherkey.size*2)) != NULL) {
              if (o_base64url_encode(cypherkey.data, cypherkey.size, cypherkey_b64, &cypherkey_b64_len)) {
                j_return = json_pack("{ss%s{ss}}", "encrypted_key", cypherkey_b64, cypherkey_b64_len, "header", "alg", r_jwa_alg_to_str(alg));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error o_base64url_encode cypherkey_b64");
                *ret = RHN_ERROR;
              }
              o_free(cypherkey_b64);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error o_malloc cypherkey_b64");
              *ret = RHN_ERROR_MEMORY;
            }
            gnutls_free(cypherkey.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error gnutls_pubkey_encrypt_data: %s", gnutls_strerror(res));
            *ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Unable to export public key");
          *ret = RHN_ERROR;
        }
        gnutls_pubkey_deinit(g_pub);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error invalid key type");
        *ret = RHN_ERROR_PARAM;
      }
      break;
#if NETTLE_VERSION_NUMBER >= 0x030400
    case R_JWA_ALG_RSA_OAEP:
    case R_JWA_ALG_RSA_OAEP_256:
      res = r_jwk_key_type(jwk, &bits, x5u_flags);
      if (res & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC) && bits >= 2048) {
        if (jwk != NULL && (g_pub = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
          if ((cyphertext = o_malloc(bits+1)) != NULL) {
            cyphertext_len = bits+1;
            if (_r_rsa_oaep_encrypt(g_pub, alg, jwe->key, jwe->key_len, cyphertext, &cyphertext_len) == RHN_OK) {
              if ((cypherkey_b64 = o_malloc(cyphertext_len*2)) != NULL) {
                if (o_base64url_encode(cyphertext, cyphertext_len, cypherkey_b64, &cypherkey_b64_len)) {
                  j_return = json_pack("{ss%s{ss}}", "encrypted_key", cypherkey_b64, cypherkey_b64_len, "header", "alg", r_jwa_alg_to_str(alg));
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error o_base64url_encode cypherkey_b64");
                  *ret = RHN_ERROR;
                }
                o_free(cypherkey_b64);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error o_malloc cypherkey_b64");
                *ret = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error _r_rsa_oaep_encrypt");
              *ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error allocating resources for cyphertext");
            *ret = RHN_ERROR_MEMORY;
          }
          o_free(cyphertext);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Unable to export public key");
          *ret = RHN_ERROR;
        }
        gnutls_pubkey_deinit(g_pub);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error invalid key type");
        *ret = RHN_ERROR_PARAM;
      }
      break;
#endif
    case R_JWA_ALG_DIR:
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = NULL;
      if (jwk != NULL) {
        if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == _r_get_key_size(jwe->enc)*8) {
          key_len = bits/8;
          if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error r_jwk_export_to_symmetric_key");
            *ret = RHN_ERROR;
          } else {
            if (r_jwe_set_cypher_key(jwe, key, key_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error r_jwe_set_cypher_key");
              *ret = RHN_ERROR;
            } else {
              j_return = json_object();
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error invalid key type");
          *ret = RHN_ERROR_PARAM;
        }
      } else if (jwe->key != NULL && jwe->key_len > 0) {
        j_return = json_object();
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error no key available for alg 'dir'");
        *ret = RHN_ERROR_PARAM;
      }
      break;
    case R_JWA_ALG_A128GCMKW:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
    case R_JWA_ALG_A192GCMKW:
#endif
    case R_JWA_ALG_A256GCMKW:
      if ((j_return = r_jwe_aesgcm_key_wrap(jwe, alg, jwk, x5u_flags, ret)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error r_jwe_aesgcm_key_wrap");
      }
      break;
#if NETTLE_VERSION_NUMBER >= 0x030400
    case R_JWA_ALG_A128KW:
    case R_JWA_ALG_A192KW:
    case R_JWA_ALG_A256KW:
      if ((j_return = r_jwe_aes_key_wrap(jwe, alg, jwk, x5u_flags, ret)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error r_jwe_aes_key_wrap");
      }
      break;
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060d
    case R_JWA_ALG_PBES2_H256:
    case R_JWA_ALG_PBES2_H384:
    case R_JWA_ALG_PBES2_H512:
      if ((j_return = r_jwe_pbes2_key_wrap(jwe, alg, jwk, x5u_flags, ret)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error r_jwe_pbes2_key_wrap");
      }
      break;
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
    case R_JWA_ALG_ECDH_ES:
    case R_JWA_ALG_ECDH_ES_A128KW:
    case R_JWA_ALG_ECDH_ES_A192KW:
    case R_JWA_ALG_ECDH_ES_A256KW:
      res = r_jwk_key_type(jwk, &bits, x5u_flags);
      if (res & (R_KEY_TYPE_EC|R_KEY_TYPE_PUBLIC)) {
        if (r_jwks_size(jwe->jwks_privkey) == 1) {
          jwk_priv = r_jwks_get_at(jwe->jwks_privkey, 0);
        }
        if ((j_return = _r_jwe_ecdh_encrypt(jwe, alg, jwk, jwk_priv, res, bits, x5u_flags, ret)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Error _r_jwe_ecdh_encrypt");
        }
        r_jwk_free(jwk_priv);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - invalid public key type");
        *ret = RHN_ERROR_PARAM;
      }
      break;
#endif
    default:
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_perform_key_encryption - Unsupported alg");
      *ret = RHN_ERROR_PARAM;
      break;
  }
  j_key_ref_array = json_array();
  json_object_foreach(json_object_get(j_return, "header"), key_ref, j_element) {
    j_reference = json_object_get(jwe->j_header, key_ref);
    if (j_reference == NULL) {
      j_reference = json_object_get(jwe->j_unprotected_header, key_ref);
    }
    if (j_reference != NULL && json_equal(j_reference, j_element)) {
      json_array_append_new(j_key_ref_array, json_string(key_ref));
    }
  }
  json_array_foreach(j_key_ref_array, index, j_element) {
    json_object_del(json_object_get(j_return, "header"), json_string_value(j_element));
  }
  json_decref(j_key_ref_array);
  if (!json_object_size(json_object_get(j_return, "header"))) {
    json_object_del(j_return, "header");
  }
  return j_return;
}

static int r_preform_key_decryption(jwe_t * jwe, jwa_alg alg, jwk_t * jwk, int x5u_flags) {
  int ret, res;
  gnutls_datum_t plainkey = {NULL, 0}, cypherkey;
  gnutls_privkey_t g_priv = NULL;
  unsigned int bits = 0;
  unsigned char * cypherkey_dec = NULL, * key = NULL;
  size_t cypherkey_dec_len = 0, key_len = 0;
#if NETTLE_VERSION_NUMBER >= 0x030400
  uint8_t * clearkey = NULL;
  size_t clearkey_len = 0;
#endif

  switch (alg) {
    case R_JWA_ALG_RSA1_5:
      if (r_jwk_key_type(jwk, &bits, x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE) && bits >= 2048) {
        if (jwk != NULL && !o_strnullempty((const char *)jwe->encrypted_key_b64url) && (g_priv = r_jwk_export_to_gnutls_privkey(jwk)) != NULL) {
          if ((cypherkey_dec = o_malloc(o_strlen((const char *)jwe->encrypted_key_b64url))) != NULL) {
            memset(cypherkey_dec, 0, o_strlen((const char *)jwe->encrypted_key_b64url));
            if (o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cypherkey_dec, &cypherkey_dec_len)) {
              cypherkey.size = cypherkey_dec_len;
              cypherkey.data = cypherkey_dec;
              if (!(res = gnutls_privkey_decrypt_data(g_priv, 0, &cypherkey, &plainkey))) {
                if (r_jwe_set_cypher_key(jwe, plainkey.data, plainkey.size) == RHN_OK) {
                  ret = RHN_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwe_set_cypher_key (RSA1_5)");
                  ret = RHN_ERROR;
                }
                gnutls_free(plainkey.data);
              } else if (res == GNUTLS_E_DECRYPTION_FAILED) {
                ret = RHN_ERROR_INVALID;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error gnutls_privkey_decrypt_data: %s", gnutls_strerror(res));
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error o_base64url_decode cypherkey_dec");
              ret = RHN_ERROR_PARAM;
            }
            o_free(cypherkey_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error o_malloc cypherkey_dec");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid RSA1_5 input parameters");
          ret = RHN_ERROR_PARAM;
        }
        gnutls_privkey_deinit(g_priv);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid key size RSA1_5");
        ret = RHN_ERROR_INVALID;
      }
      break;
#if NETTLE_VERSION_NUMBER >= 0x030400
    case R_JWA_ALG_RSA_OAEP:
    case R_JWA_ALG_RSA_OAEP_256:
      if (r_jwk_key_type(jwk, &bits, x5u_flags) & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE) && bits >= 2048) {
        if (jwk != NULL && !o_strnullempty((const char *)jwe->encrypted_key_b64url) && (g_priv = r_jwk_export_to_gnutls_privkey(jwk)) != NULL) {
          if ((cypherkey_dec = o_malloc(o_strlen((const char *)jwe->encrypted_key_b64url))) != NULL) {
            if (o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cypherkey_dec, &cypherkey_dec_len)) {
              if ((clearkey = o_malloc(bits+1)) != NULL) {
                clearkey_len = bits+1;
                if (_r_rsa_oaep_decrypt(g_priv, alg, cypherkey_dec, cypherkey_dec_len, clearkey, &clearkey_len) == RHN_OK) {
                  if (_r_get_key_size(jwe->enc) == clearkey_len) {
                    if (r_jwe_set_cypher_key(jwe, clearkey, clearkey_len) == RHN_OK) {
                      ret = RHN_OK;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwe_set_cypher_key (RSA_OAEP)");
                      ret = RHN_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid key length");
                    ret = RHN_ERROR_PARAM;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error _r_rsa_oaep_decrypt");
                  ret = RHN_ERROR_INVALID;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error o_malloc clearkey");
                ret = RHN_ERROR_MEMORY;
              }
              o_free(clearkey);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error o_base64url_decode cypherkey_dec");
              ret = RHN_ERROR_PARAM;
            }
            o_free(cypherkey_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error o_malloc cypherkey_dec");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid RSA1-OAEP input parameters");
          ret = RHN_ERROR_PARAM;
        }
        gnutls_privkey_deinit(g_priv);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid key size RSA_OAEP");
        ret = RHN_ERROR_INVALID;
      }
      break;
#endif
    case R_JWA_ALG_DIR:
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = NULL;
      if (jwk != NULL) {
        if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == _r_get_key_size(jwe->enc)*8) {
          key_len = (size_t)(bits/8);
          if ((key = o_malloc(key_len+4)) != NULL) {
            if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) == RHN_OK) {
              o_free(jwe->encrypted_key_b64url);
              jwe->encrypted_key_b64url = NULL;
              ret = r_jwe_set_cypher_key(jwe, key, key_len);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwk_export_to_symmetric_key");
              ret = RHN_ERROR_MEMORY;
            }
            o_free(key);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error allocating resources for key");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error invalid key type");
          ret = RHN_ERROR_PARAM;
        }
      } else if (jwe->key != NULL && jwe->key_len > 0) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error no key available for alg 'dir'");
        ret = RHN_ERROR_INVALID;
      }
      break;
    case R_JWA_ALG_A128GCMKW:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
    case R_JWA_ALG_A192GCMKW:
#endif
    case R_JWA_ALG_A256GCMKW:
      if ((res = r_jwe_aesgcm_key_unwrap(jwe, alg, jwk, x5u_flags)) == RHN_OK) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwe_aesgcm_key_unwrap");
        ret = res;
      }
      break;
#if NETTLE_VERSION_NUMBER >= 0x030400
    case R_JWA_ALG_A128KW:
    case R_JWA_ALG_A192KW:
    case R_JWA_ALG_A256KW:
      if ((res = r_jwe_aes_key_unwrap(jwe, alg, jwk, x5u_flags)) == RHN_OK) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwe_aes_key_unwrap");
        ret = res;
      }
      break;
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060d
    case R_JWA_ALG_PBES2_H256:
    case R_JWA_ALG_PBES2_H384:
    case R_JWA_ALG_PBES2_H512:
      if ((res = r_jwe_pbes2_key_unwrap(jwe, alg, jwk, x5u_flags)) == RHN_OK) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error r_jwe_pbes2_key_unwrap");
        ret = res;
      }
      break;
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
    case R_JWA_ALG_ECDH_ES:
    case R_JWA_ALG_ECDH_ES_A128KW:
    case R_JWA_ALG_ECDH_ES_A192KW:
    case R_JWA_ALG_ECDH_ES_A256KW:
      res = r_jwk_key_type(jwk, &bits, x5u_flags);
      if (res & (R_KEY_TYPE_EC|R_KEY_TYPE_PRIVATE) || res & (R_KEY_TYPE_EDDSA|R_KEY_TYPE_PRIVATE)) {
        if ((res = _r_jwe_ecdh_decrypt(jwe, alg, jwk, res, bits, x5u_flags)) == RHN_OK) {
          ret = RHN_OK;
        } else {
          if (res != RHN_ERROR_INVALID) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error _r_jwe_ecdh_decrypt");
          }
          ret = res;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - invalid key type %d", res);
        ret = RHN_ERROR_INVALID;
      }
      break;
#endif
    default:
      y_log_message(Y_LOG_LEVEL_ERROR, "r_preform_key_decryption - Error unsupported algorithm");
      ret = RHN_ERROR_INVALID;
      break;
  }
  return ret;
}

int r_jwe_init(jwe_t ** jwe) {
  int ret;

  if (jwe != NULL) {
    if ((*jwe = o_malloc(sizeof(jwe_t))) != NULL) {
      if (((*jwe)->j_header = json_object()) != NULL) {
        if (r_jwks_init(&(*jwe)->jwks_pubkey) == RHN_OK) {
          if (r_jwks_init(&(*jwe)->jwks_privkey) == RHN_OK) {
            (*jwe)->header_b64url = NULL;
            (*jwe)->encrypted_key_b64url = NULL;
            (*jwe)->iv_b64url = NULL;
            (*jwe)->aad_b64url = NULL;
            (*jwe)->ciphertext_b64url = NULL;
            (*jwe)->auth_tag_b64url = NULL;
            (*jwe)->j_unprotected_header = NULL;
            (*jwe)->alg = R_JWA_ALG_UNKNOWN;
            (*jwe)->enc = R_JWA_ENC_UNKNOWN;
            (*jwe)->key = NULL;
            (*jwe)->key_len = 0;
            (*jwe)->iv = NULL;
            (*jwe)->iv_len = 0;
            (*jwe)->aad = NULL;
            (*jwe)->aad_len = 0;
            (*jwe)->payload = NULL;
            (*jwe)->payload_len = 0;
            (*jwe)->j_json_serialization = NULL;
            (*jwe)->token_mode = R_JSON_MODE_COMPACT;
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_init - Error allocating resources for jwks_privkey");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_init - Error allocating resources for jwks_pubkey");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_init - Error allocating resources for j_header");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_init - Error allocating resources for jwe");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  if (ret != RHN_OK && jwe != NULL) {
    r_jwe_free(*jwe);
    *jwe = NULL;
  }
  return ret;
}

void r_jwe_free(jwe_t * jwe) {
  if (jwe != NULL) {
    r_jwks_free(jwe->jwks_privkey);
    r_jwks_free(jwe->jwks_pubkey);
    o_free(jwe->header_b64url);
    o_free(jwe->encrypted_key_b64url);
    o_free(jwe->iv_b64url);
    o_free(jwe->aad_b64url);
    o_free(jwe->ciphertext_b64url);
    o_free(jwe->auth_tag_b64url);
    json_decref(jwe->j_header);
    json_decref(jwe->j_unprotected_header);
    json_decref(jwe->j_json_serialization);
    o_free(jwe->key);
    o_free(jwe->iv);
    o_free(jwe->aad);
    o_free(jwe->payload);
    o_free(jwe);
  }
}

jwe_t * r_jwe_copy(jwe_t * jwe) {
  jwe_t * jwe_copy = NULL;

  if (jwe != NULL) {
    if (r_jwe_init(&jwe_copy) == RHN_OK) {
      jwe_copy->alg = jwe->alg;
      jwe_copy->enc = jwe->enc;
      jwe_copy->token_mode = jwe->token_mode;
      if (r_jwe_set_payload(jwe_copy, jwe->payload, jwe->payload_len) == RHN_OK &&
          r_jwe_set_iv(jwe_copy, jwe->iv, jwe->iv_len) == RHN_OK &&
          r_jwe_set_aad(jwe_copy, jwe->aad, jwe->aad_len) == RHN_OK &&
          r_jwe_set_cypher_key(jwe_copy, jwe->key, jwe->key_len) == RHN_OK &&
          r_jwe_set_alg(jwe_copy, r_jwe_get_alg(jwe)) == RHN_OK) {
        jwe_copy->header_b64url = (unsigned char *)o_strdup((const char *)jwe->header_b64url);
        jwe_copy->encrypted_key_b64url = (unsigned char *)o_strdup((const char *)jwe->encrypted_key_b64url);
        jwe_copy->ciphertext_b64url = (unsigned char *)o_strdup((const char *)jwe->ciphertext_b64url);
        jwe_copy->auth_tag_b64url = (unsigned char *)o_strdup((const char *)jwe->auth_tag_b64url);
        r_jwks_free(jwe_copy->jwks_privkey);
        jwe_copy->jwks_privkey = r_jwks_copy(jwe->jwks_privkey);
        r_jwks_free(jwe_copy->jwks_pubkey);
        jwe_copy->jwks_pubkey = r_jwks_copy(jwe->jwks_pubkey);
        json_decref(jwe_copy->j_header);
        jwe_copy->j_header = json_deep_copy(jwe->j_header);
        jwe_copy->j_unprotected_header = json_deep_copy(jwe->j_unprotected_header);
        jwe_copy->j_json_serialization = json_deep_copy(jwe->j_json_serialization);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_copy - Error setting values");
        r_jwe_free(jwe_copy);
        jwe_copy = NULL;
      }
    }
  }
  return jwe_copy;
}

int r_jwe_set_payload(jwe_t * jwe, const unsigned char * payload, size_t payload_len) {
  int ret;

  if (jwe != NULL) {
    o_free(jwe->payload);
    if (payload != NULL && payload_len) {
      if ((jwe->payload = o_malloc(payload_len)) != NULL) {
        memcpy(jwe->payload, payload, payload_len);
        jwe->payload_len = payload_len;
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_payload - Error allocating resources for payload");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jwe->payload = NULL;
      jwe->payload_len = 0;
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const unsigned char * r_jwe_get_payload(jwe_t * jwe, size_t * payload_len) {
  if (jwe != NULL) {
    if (payload_len != NULL) {
      *payload_len = jwe->payload_len;
    }
    return jwe->payload;
  }
  return NULL;
}

int r_jwe_set_cypher_key(jwe_t * jwe, const unsigned char * key, size_t key_len) {
  int ret;

  if (jwe != NULL) {
    o_free(jwe->key);
    if (key != NULL && key_len) {
      if ((jwe->key = o_malloc(key_len)) != NULL) {
        memcpy(jwe->key, key, key_len);
        jwe->key_len = key_len;
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_cypher_key - Error allocating resources for key");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jwe->key = NULL;
      jwe->key_len = 0;
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const unsigned char * r_jwe_get_cypher_key(jwe_t * jwe, size_t * key_len) {
  if (jwe != NULL) {
    if (key_len != NULL) {
      *key_len = jwe->key_len;
    }
    return jwe->key;
  }
  return NULL;
}

int r_jwe_generate_cypher_key(jwe_t * jwe) {
  int ret;

  if (jwe != NULL && jwe->enc != R_JWA_ENC_UNKNOWN) {
    o_free(jwe->encrypted_key_b64url);
    jwe->encrypted_key_b64url = NULL;
    jwe->key_len = _r_get_key_size(jwe->enc);
    o_free(jwe->key);
    if (!jwe->key_len) {
      ret = RHN_ERROR_PARAM;
    } else if ((jwe->key = o_malloc(jwe->key_len)) != NULL) {
      if (!gnutls_rnd(GNUTLS_RND_KEY, jwe->key, jwe->key_len)) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_cypher_key - Error gnutls_rnd");
        ret = RHN_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_cypher_key - Error allocating resources for key");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_cypher_key - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_set_iv(jwe_t * jwe, const unsigned char * iv, size_t iv_len) {
  int ret;
  unsigned char * iv_b64 = NULL;
  size_t iv_b64_len = 0;

  if (jwe != NULL) {
    o_free(jwe->iv);
    if (iv != NULL && iv_len) {
      if ((jwe->iv = o_malloc(iv_len)) != NULL) {
        memcpy(jwe->iv, iv, iv_len);
        jwe->iv_len = iv_len;
        if ((iv_b64 = o_malloc(jwe->iv_len*2)) != NULL) {
          if (o_base64url_encode(jwe->iv, jwe->iv_len, iv_b64, &iv_b64_len)) {
            o_free(jwe->iv_b64url);
            jwe->iv_b64url = (unsigned char *)o_strndup((const char *)iv_b64, iv_b64_len);
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_iv - Error o_base64url_encode iv_b64");
            ret = RHN_ERROR;
          }
          o_free(iv_b64);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_iv - Error allocating resources for iv_b64");
          ret = RHN_ERROR_MEMORY;
        }
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_iv - Error allocating resources for iv");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jwe->iv = NULL;
      jwe->iv_len = 0;
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const unsigned char * r_jwe_get_iv(jwe_t * jwe, size_t * iv_len) {
  if (jwe != NULL) {
    if (iv_len != NULL) {
      *iv_len = jwe->iv_len;
    }
    return jwe->iv;
  }
  return NULL;
}

int r_jwe_set_aad(jwe_t * jwe, const unsigned char * aad, size_t aad_len) {
  int ret;
  unsigned char * aad_b64 = NULL;
  size_t aad_b64_len = 0;

  if (jwe != NULL) {
    o_free(jwe->aad_b64url);
    jwe->aad_b64url = NULL;
    o_free(jwe->aad);
    if (aad != NULL && aad_len) {
      if ((jwe->aad = o_malloc(aad_len)) != NULL) {
        memcpy(jwe->aad, aad, aad_len);
        jwe->aad_len = aad_len;
        if ((aad_b64 = o_malloc(jwe->aad_len*2)) != NULL) {
          if (o_base64url_encode(jwe->aad, jwe->aad_len, aad_b64, &aad_b64_len)) {
            o_free(jwe->aad_b64url);
            jwe->aad_b64url = (unsigned char *)o_strndup((const char *)aad_b64, aad_b64_len);
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_aad - Error o_base64url_encode aad_b64");
            ret = RHN_ERROR;
          }
          o_free(aad_b64);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_aad - Error allocating resources for aad_b64");
          ret = RHN_ERROR_MEMORY;
        }
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_aad - Error allocating resources for aad");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jwe->aad = NULL;
      jwe->aad_len = 0;
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const unsigned char * r_jwe_get_aad(jwe_t * jwe, size_t * aad_len) {
  if (jwe != NULL) {
    if (aad_len != NULL) {
      *aad_len = jwe->aad_len;
    }
    return jwe->aad;
  }
  return NULL;
}

int r_jwe_generate_iv(jwe_t * jwe) {
  int ret;
  unsigned char * iv_b64 = NULL;
  size_t iv_b64_len = 0;

  if (jwe != NULL && jwe->enc != R_JWA_ENC_UNKNOWN) {
    o_free(jwe->iv_b64url);
    jwe->iv_b64url = NULL;
    jwe->iv_len = gnutls_cipher_get_iv_size(_r_get_alg_from_enc(jwe->enc));
    o_free(jwe->iv);
    jwe->iv = NULL;
    if (jwe->iv_len) {
      if ((jwe->iv = o_malloc(jwe->iv_len)) != NULL) {
        if (!gnutls_rnd(GNUTLS_RND_NONCE, jwe->iv, jwe->iv_len)) {
          if ((iv_b64 = o_malloc(jwe->iv_len*2)) != NULL) {
            if (o_base64url_encode(jwe->iv, jwe->iv_len, iv_b64, &iv_b64_len)) {
              jwe->iv_b64url = (unsigned char *)o_strndup((const char *)iv_b64, iv_b64_len);
              ret = RHN_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_iv - Error o_base64url_encode iv_b64");
              ret = RHN_ERROR;
            }
            o_free(iv_b64);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_iv - Error allocating resources for iv_b64");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_iv - Error gnutls_rnd");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_generate_iv - Error allocating resources for iv");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jwe->iv_b64url = (unsigned char *)o_strdup("");
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_set_alg(jwe_t * jwe, jwa_alg alg) {
  int ret = RHN_OK;

  if (jwe != NULL) {
    jwe->alg = alg;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwa_alg r_jwe_get_alg(jwe_t * jwe) {
  if (jwe != NULL) {
    return jwe->alg;
  } else {
    return R_JWA_ALG_UNKNOWN;
  }
}

int r_jwe_set_enc(jwe_t * jwe, jwa_enc enc) {
  int ret = RHN_OK;

  if (jwe != NULL) {
    jwe->enc = enc;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwa_enc r_jwe_get_enc(jwe_t * jwe) {
  if (jwe != NULL) {
    return jwe->enc;
  } else {
    return R_JWA_ENC_UNKNOWN;
  }
}

const char * r_jwe_get_kid(jwe_t * jwe) {
  return r_jwe_get_header_str_value(jwe, "kid");
}

int r_jwe_set_header_str_value(jwe_t * jwe, const char * key, const char * str_value) {
  int ret;

  if (jwe != NULL) {
    if ((ret = _r_json_set_str_value(jwe->j_header, key, str_value)) == RHN_OK) {
      o_free(jwe->header_b64url);
      jwe->header_b64url = NULL;
    }
    return ret;
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwe_set_header_int_value(jwe_t * jwe, const char * key, rhn_int_t i_value) {
  int ret;

  if (jwe != NULL) {
    if ((ret = _r_json_set_int_value(jwe->j_header, key, i_value)) == RHN_OK) {
      o_free(jwe->header_b64url);
      jwe->header_b64url = NULL;
    }
    return ret;
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwe_set_header_json_t_value(jwe_t * jwe, const char * key, json_t * j_value) {
  int ret;

  if (jwe != NULL) {
    if ((ret = _r_json_set_json_t_value(jwe->j_header, key, j_value)) == RHN_OK) {
      o_free(jwe->header_b64url);
      jwe->header_b64url = NULL;
    }
    return ret;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const char * r_jwe_get_header_str_value(jwe_t * jwe, const char * key) {
  if (jwe != NULL) {
    return _r_json_get_str_value(jwe->j_header, key);
  }
  return NULL;
}

rhn_int_t r_jwe_get_header_int_value(jwe_t * jwe, const char * key) {
  if (jwe != NULL) {
    return _r_json_get_int_value(jwe->j_header, key);
  }
  return 0;
}

json_t * r_jwe_get_header_json_t_value(jwe_t * jwe, const char * key) {
  if (jwe != NULL) {
    return _r_json_get_json_t_value(jwe->j_header, key);
  }
  return NULL;
}

json_t * r_jwe_get_full_header_json_t(jwe_t * jwe) {
  if (jwe != NULL) {
    return _r_json_get_full_json_t(jwe->j_header);
  }
  return NULL;
}

char * r_jwe_get_full_header_str(jwe_t * jwe) {
  char * to_return = NULL;
  if (jwe != NULL) {
    to_return = json_dumps(jwe->j_header, JSON_COMPACT);
  }
  return to_return;
}

json_t * r_jwe_get_full_unprotected_header_json_t(jwe_t * jwe) {
  if (jwe != NULL) {
    return _r_json_get_full_json_t(jwe->j_unprotected_header);
  }
  return NULL;
}

char * r_jwe_get_full_unprotected_header_str(jwe_t * jwe) {
  char * to_return = NULL;
  if (jwe != NULL) {
    to_return = json_dumps(jwe->j_unprotected_header, JSON_COMPACT);
  }
  return to_return;
}

int r_jwe_add_keys(jwe_t * jwe, jwk_t * jwk_privkey, jwk_t * jwk_pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;

  if (jwe != NULL && (jwk_privkey != NULL || jwk_pubkey != NULL)) {
    if (jwk_privkey != NULL) {
      if (r_jwks_append_jwk(jwe->jwks_privkey, jwk_privkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys - Error setting jwk_privkey");
        ret = RHN_ERROR;
      }
      if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(jwk_privkey, "alg"))) != R_JWA_ALG_NONE) {
        r_jwe_set_alg(jwe, alg);
      }
    }
    if (jwk_pubkey != NULL) {
      if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk_pubkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys - Error setting jwk_pubkey");
        ret = RHN_ERROR;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_jwks(jwe_t * jwe, jwks_t * jwks_privkey, jwks_t * jwks_pubkey) {
  size_t i;
  int ret, res;
  jwk_t * jwk;

  if (jwe != NULL && (jwks_privkey != NULL || jwks_pubkey != NULL)) {
    ret = RHN_OK;
    if (jwks_privkey != NULL) {
      for (i=0; ret==RHN_OK && i<r_jwks_size(jwks_privkey); i++) {
        jwk = r_jwks_get_at(jwks_privkey, i);
        if ((res = r_jwe_add_keys(jwe, jwk, NULL)) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_jwks - Error r_jwe_add_keys private key at %zu", i);
          ret = res;
        }
        r_jwk_free(jwk);
      }
    }
    if (jwks_pubkey != NULL) {
      for (i=0; ret==RHN_OK && i<r_jwks_size(jwks_pubkey); i++) {
        jwk = r_jwks_get_at(jwks_pubkey, i);
        if ((res = r_jwe_add_keys(jwe, NULL, jwk)) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_jwks - Error r_jwe_add_keys public key at %zu", i);
          ret = res;
        }
        r_jwk_free(jwk);
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_keys_json_str(jwe_t * jwe, const char * privkey, const char * pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwk_t * j_privkey = NULL, * j_pubkey = NULL;

  if (jwe != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwk_init(&j_privkey) == RHN_OK && r_jwk_import_from_json_str(j_privkey, privkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_privkey, j_privkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_str - Error setting privkey");
          ret = RHN_ERROR;
        }
        if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(j_privkey, "alg"))) != R_JWA_ALG_NONE) {
          r_jwe_set_alg(jwe, alg);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_str - Error parsing privkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_privkey);
    }
    if (pubkey != NULL) {
      if (r_jwk_init(&j_pubkey) == RHN_OK && r_jwk_import_from_json_str(j_pubkey, pubkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, j_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_str - Error setting pubkey");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_str - Error parsing pubkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_pubkey);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_keys_json_t(jwe_t * jwe, json_t * privkey, json_t * pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwk_t * j_privkey = NULL, * j_pubkey = NULL;

  if (jwe != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwk_init(&j_privkey) == RHN_OK && r_jwk_import_from_json_t(j_privkey, privkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_privkey, j_privkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_t - Error setting privkey");
          ret = RHN_ERROR;
        }
        if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(j_privkey, "alg"))) != R_JWA_ALG_NONE) {
          r_jwe_set_alg(jwe, alg);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_t - Error parsing privkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_privkey);
    }
    if (pubkey != NULL) {
      if (r_jwk_init(&j_pubkey) == RHN_OK && r_jwk_import_from_json_t(j_pubkey, pubkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, j_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_t - Error setting pubkey");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_json_t - Error parsing pubkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_pubkey);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_keys_pem_der(jwe_t * jwe, int format, const unsigned char * privkey, size_t privkey_len, const unsigned char * pubkey, size_t pubkey_len) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwk_t * j_privkey = NULL, * j_pubkey = NULL;

  if (jwe != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwk_init(&j_privkey) == RHN_OK && r_jwk_import_from_pem_der(j_privkey, R_X509_TYPE_PRIVKEY, format, privkey, privkey_len) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_privkey, j_privkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_pem_der - Error setting privkey");
          ret = RHN_ERROR;
        }
        if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(j_privkey, "alg"))) != R_JWA_ALG_NONE) {
          r_jwe_set_alg(jwe, alg);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_pem_der - Error parsing privkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_privkey);
    }
    if (pubkey != NULL) {
      if (r_jwk_init(&j_pubkey) == RHN_OK && r_jwk_import_from_pem_der(j_pubkey, R_X509_TYPE_PUBKEY, format, pubkey, pubkey_len) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, j_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_pem_der - Error setting pubkey");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_pem_der - Error parsing pubkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_pubkey);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_keys_gnutls(jwe_t * jwe, gnutls_privkey_t privkey, gnutls_pubkey_t pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwk_t * j_privkey = NULL, * j_pubkey = NULL;

  if (jwe != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwk_init(&j_privkey) == RHN_OK && r_jwk_import_from_gnutls_privkey(j_privkey, privkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_privkey, j_privkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_gnutls - Error setting privkey");
          ret = RHN_ERROR;
        }
        if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(j_privkey, "alg"))) != R_JWA_ALG_NONE) {
          r_jwe_set_alg(jwe, alg);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_gnutls - Error parsing privkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_privkey);
    }
    if (pubkey != NULL) {
      if (r_jwk_init(&j_pubkey) == RHN_OK && r_jwk_import_from_gnutls_pubkey(j_pubkey, pubkey) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, j_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_gnutls - Error setting pubkey");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys_gnutls - Error parsing pubkey");
        ret = RHN_ERROR;
      }
      r_jwk_free(j_pubkey);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_add_key_symmetric(jwe_t * jwe, const unsigned char * key, size_t key_len) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwk_t * j_key = NULL;

  if (jwe != NULL && key != NULL && key_len) {
    if (r_jwk_init(&j_key) == RHN_OK && r_jwk_import_from_symmetric_key(j_key, key, key_len) == RHN_OK) {
      if (r_jwks_append_jwk(jwe->jwks_privkey, j_key) != RHN_OK || r_jwks_append_jwk(jwe->jwks_pubkey, j_key) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_enc_key_symmetric - Error setting key");
        ret = RHN_ERROR;
      }
      if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(j_key, "alg"))) != R_JWA_ALG_NONE) {
        r_jwe_set_alg(jwe, alg);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_enc_key_symmetric - Error parsing key");
      ret = RHN_ERROR;
    }
    r_jwk_free(j_key);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwks_t * r_jwe_get_jwks_privkey(jwe_t * jwe) {
  if (jwe != NULL) {
    return r_jwks_copy(jwe->jwks_privkey);
  } else {
    return NULL;
  }
}

jwks_t * r_jwe_get_jwks_pubkey(jwe_t * jwe) {
  if (jwe != NULL) {
    return r_jwks_copy(jwe->jwks_pubkey);
  } else {
    return NULL;
  }
}

int r_jwe_encrypt_payload(jwe_t * jwe) {
  int ret = RHN_OK, res;
  gnutls_cipher_hd_t handle;
  gnutls_datum_t key, iv;
  unsigned char * ptext = NULL, * text_zip = NULL, * ciphertext_b64url = NULL, tag[128] = {0}, * tag_b64url = NULL, * str_header_b64 = NULL, * aad = NULL;
  size_t ptext_len = 0, ciphertext_b64url_len = 0, tag_len = 0, tag_b64url_len = 0, str_header_b64_len = 0, text_zip_len = 0;
  char * str_header = NULL;
  int cipher_cbc;

  if (jwe != NULL &&
      jwe->payload != NULL &&
      jwe->payload_len &&
      jwe->enc != R_JWA_ENC_UNKNOWN &&
      jwe->key != NULL &&
      jwe->iv != NULL &&
      jwe->iv_len &&
      jwe->key_len == _r_get_key_size(jwe->enc) &&
      r_jwe_set_enc_header(jwe, jwe->j_header) == RHN_OK) {
    cipher_cbc = (jwe->enc == R_JWA_ENC_A128CBC || jwe->enc == R_JWA_ENC_A192CBC || jwe->enc == R_JWA_ENC_A256CBC);

    if ((str_header = json_dumps(jwe->j_header, JSON_COMPACT)) != NULL) {
      if ((str_header_b64 = o_malloc(o_strlen(str_header)*2)) != NULL) {
        if (o_base64url_encode((const unsigned char *)str_header, o_strlen(str_header), str_header_b64, &str_header_b64_len)) {
          o_free(jwe->header_b64url);
          jwe->header_b64url = (unsigned char *)o_strndup((const char *)str_header_b64, str_header_b64_len);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error o_base64url_encode str_header");
          ret = RHN_ERROR;
        }
        o_free(str_header_b64);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error allocating resources for str_header_b64");
        ret = RHN_ERROR_MEMORY;
      }
      o_free(str_header);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error json_dumps j_header");
      ret = RHN_ERROR;
    }

    ptext_len = gnutls_cipher_get_block_size(_r_get_alg_from_enc(jwe->enc));
    if (0 == o_strcmp("DEF", r_jwe_get_header_str_value(jwe, "zip"))) {
      if (_r_deflate_payload(jwe->payload, jwe->payload_len, &text_zip, &text_zip_len) == RHN_OK) {
        if (r_jwe_set_ptext_with_block(text_zip, text_zip_len, &ptext, &ptext_len, _r_get_alg_from_enc(jwe->enc), cipher_cbc) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_set_ptext_with_block");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error _r_deflate_payload");
        ret = RHN_ERROR;
      }
      o_free(text_zip);
    } else {
      if (r_jwe_set_ptext_with_block(jwe->payload, jwe->payload_len, &ptext, &ptext_len, _r_get_alg_from_enc(jwe->enc), cipher_cbc) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_set_ptext_with_block");
        ret = RHN_ERROR;
      }
    }

    if (ret == RHN_OK) {
      if (cipher_cbc) {
        key.data = jwe->key+(jwe->key_len/2);
        key.size = jwe->key_len/2;
      } else {
        key.data = jwe->key;
        key.size = jwe->key_len;
      }
      iv.data = jwe->iv;
      iv.size = jwe->iv_len;
      if (!(res = gnutls_cipher_init(&handle, _r_get_alg_from_enc(jwe->enc), &key, &iv))) {
        if (jwe->aad_b64url == NULL || jwe->token_mode == R_JSON_MODE_COMPACT) {
          aad = (unsigned char *)o_strdup((const char *)jwe->header_b64url);
        } else {
          aad = (unsigned char *)msprintf("%s.%s", jwe->header_b64url, jwe->aad_b64url);
        }
        if (!cipher_cbc && (res = gnutls_cipher_add_auth(handle, aad, o_strlen((const char *)aad)))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_add_auth: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        if (ret == RHN_OK) {
          if (!(res = gnutls_cipher_encrypt(handle, ptext, ptext_len))) {
            if ((ciphertext_b64url = o_malloc(2*ptext_len)) != NULL) {
              if (o_base64url_encode(ptext, ptext_len, ciphertext_b64url, &ciphertext_b64url_len)) {
                o_free(jwe->ciphertext_b64url);
                jwe->ciphertext_b64url = (unsigned char *)o_strndup((const char *)ciphertext_b64url, ciphertext_b64url_len);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error o_base64url_encode ciphertext");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error allocating resources for ciphertext_b64url");
              ret = RHN_ERROR_MEMORY;
            }
            o_free(ciphertext_b64url);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_encrypt: '%s'", gnutls_strerror(res));
            ret = RHN_ERROR;
          }
        } else if (!cipher_cbc) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_add_auth: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        if (ret == RHN_OK) {
          if (cipher_cbc) {
            if (r_jwe_compute_hmac_tag(jwe, ptext, ptext_len, aad, tag, &tag_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_compute_hmac_tag");
              ret = RHN_ERROR;
            }
          } else {
            tag_len = gnutls_cipher_get_tag_size(_r_get_alg_from_enc(jwe->enc));
            memset(tag, 0, tag_len);
            if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
              ret = RHN_ERROR;
            }
          }
          if (ret == RHN_OK && tag_len) {
            if ((tag_b64url = o_malloc(tag_len*2)) != NULL) {
              if (o_base64url_encode(tag, tag_len, tag_b64url, &tag_b64url_len)) {
                o_free(jwe->auth_tag_b64url);
                jwe->auth_tag_b64url = (unsigned char *)o_strndup((const char *)tag_b64url, tag_b64url_len);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error o_base64url_encode tag_b64url");
                ret = RHN_ERROR;
              }
              o_free(tag_b64url);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error allocating resources for tag_b64url");
              ret = RHN_ERROR_MEMORY;
            }
          }
        }
        o_free(aad);
        gnutls_cipher_deinit(handle);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_init: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  o_free(ptext);
  return ret;
}

int r_jwe_decrypt_payload(jwe_t * jwe) {
  int ret = RHN_OK, res;
  gnutls_cipher_hd_t handle;
  gnutls_datum_t key, iv;
  unsigned char * payload_enc = NULL, * ciphertext = NULL, * unzip = NULL, * aad = NULL;
  size_t payload_enc_len = 0, ciphertext_len = 0, unzip_len = 0;
  unsigned char tag[128], * tag_b64url = NULL;
  size_t tag_len = 0, tag_b64url_len = 0;
  int cipher_cbc;

  if (jwe != NULL && jwe->enc != R_JWA_ENC_UNKNOWN && !o_strnullempty((const char *)jwe->ciphertext_b64url) && !o_strnullempty((const char *)jwe->iv_b64url) && jwe->key != NULL && jwe->key_len && jwe->key_len == _r_get_key_size(jwe->enc)) {
    // Decode iv and payload_b64
    o_free(jwe->iv);
    if ((jwe->iv = o_malloc(o_strlen((const char *)jwe->iv_b64url))) != NULL) {
      if (o_base64url_decode(jwe->iv_b64url, o_strlen((const char *)jwe->iv_b64url), jwe->iv, &jwe->iv_len)) {
        if ((jwe->iv = o_realloc(jwe->iv, jwe->iv_len)) != NULL) {
          if ((payload_enc = o_malloc(o_strlen((const char *)jwe->ciphertext_b64url))) != NULL && (ciphertext = o_malloc(o_strlen((const char *)jwe->ciphertext_b64url))) != NULL) {
            if (!o_base64url_decode(jwe->ciphertext_b64url, o_strlen((const char *)jwe->ciphertext_b64url), ciphertext, &ciphertext_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error o_base64url_decode ciphertext");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error allocating resources for payload_enc or ciphertext");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error reallocating resources for iv");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error o_base64url_decode iv");
        ret = RHN_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error allocating resources for iv");
      ret = RHN_ERROR_MEMORY;
    }

    if (ret == RHN_OK) {
      if (jwe->enc == R_JWA_ENC_A128CBC || jwe->enc == R_JWA_ENC_A192CBC || jwe->enc == R_JWA_ENC_A256CBC) {
        key.data = jwe->key+(jwe->key_len/2);
        key.size = jwe->key_len/2;
        cipher_cbc = 1;
      } else {
        key.data = jwe->key;
        key.size = jwe->key_len;
        cipher_cbc = 0;
      }
      iv.data = jwe->iv;
      iv.size = jwe->iv_len;
      payload_enc_len = ciphertext_len;
      if (!(res = gnutls_cipher_init(&handle, _r_get_alg_from_enc(jwe->enc), &key, &iv))) {
        if (jwe->aad_b64url == NULL || jwe->token_mode == R_JSON_MODE_COMPACT) {
          aad = (unsigned char *)o_strdup((const char *)jwe->header_b64url);
        } else {
          aad = (unsigned char *)msprintf("%s.%s", jwe->header_b64url, jwe->aad_b64url);
        }
        if (!cipher_cbc && (res = gnutls_cipher_add_auth(handle, aad, o_strlen((const char *)aad)))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error gnutls_cipher_add_auth: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        if (!(res = gnutls_cipher_decrypt2(handle, ciphertext, ciphertext_len, payload_enc, payload_enc_len))) {
          if (cipher_cbc) {
            r_jwe_remove_padding(payload_enc, &payload_enc_len, gnutls_cipher_get_block_size(_r_get_alg_from_enc(jwe->enc)));
          }
          if (0 == o_strcmp("DEF", r_jwe_get_header_str_value(jwe, "zip"))) {
            if (_r_inflate_payload(payload_enc, payload_enc_len, &unzip, &unzip_len) == RHN_OK) {
              if (r_jwe_set_payload(jwe, unzip, unzip_len) != RHN_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error r_jwe_set_payload");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error _r_inflate_payload");
              ret = RHN_ERROR;
            }
            o_free(unzip);
          } else {
            if (r_jwe_set_payload(jwe, payload_enc, payload_enc_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error r_jwe_set_payload");
              ret = RHN_ERROR;
            }
          }
        } else if (res == GNUTLS_E_DECRYPTION_FAILED) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - decryption failed: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR_INVALID;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error gnutls_cipher_decrypt: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        if (ret == RHN_OK) {
          if (cipher_cbc) {
            if (r_jwe_compute_hmac_tag(jwe, ciphertext, ciphertext_len, aad, tag, &tag_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error r_jwe_compute_hmac_tag");
              ret = RHN_ERROR;
            }
          } else {
            tag_len = gnutls_cipher_get_tag_size(_r_get_alg_from_enc(jwe->enc));
            memset(tag, 0, tag_len);
            if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
              ret = RHN_ERROR;
            }
          }
          if (ret == RHN_OK && tag_len) {
            if ((tag_b64url = o_malloc(tag_len*2)) != NULL) {
              if (o_base64url_encode(tag, tag_len, tag_b64url, &tag_b64url_len)) {
                if (tag_b64url_len != o_strlen((const char *)jwe->auth_tag_b64url) || 0 != memcmp(tag_b64url, jwe->auth_tag_b64url, tag_b64url_len)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Invalid tag");
                  ret = RHN_ERROR_INVALID;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error o_base64url_encode tag_b64url");
                ret = RHN_ERROR;
              }
              o_free(tag_b64url);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error allocating resources for tag_b64url");
              ret = RHN_ERROR_MEMORY;
            }
          }
        }
        o_free(aad);
        gnutls_cipher_deinit(handle);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error gnutls_cipher_init: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  o_free(payload_enc);
  o_free(ciphertext);

  return ret;
}

int r_jwe_encrypt_key(jwe_t * jwe, jwk_t * jwk_s, int x5u_flags) {
  int ret, res = RHN_OK;
  jwk_t * jwk = NULL;
  jwa_alg alg;
  const char * kid;
  json_t * j_header = NULL, * j_cur_header = NULL;

  if (jwe != NULL) {
    if (jwk_s != NULL) {
      jwk = r_jwk_copy(jwk_s);
      if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = r_str_to_jwa_alg(r_jwk_get_property_str(jwk, "alg"))) != R_JWA_ALG_NONE) {
        r_jwe_set_alg(jwe, alg);
      }
    } else {
      if (r_jwe_get_header_str_value(jwe, "kid") != NULL) {
        jwk = r_jwks_get_by_kid(jwe->jwks_pubkey, r_jwe_get_header_str_value(jwe, "kid"));
      } else if (r_jwks_size(jwe->jwks_pubkey) == 1) {
        jwk = r_jwks_get_at(jwe->jwks_pubkey, 0);
      }
    }
  }

  if (jwe != NULL && jwe->key != NULL && jwe->key_len && jwe->alg != R_JWA_ALG_UNKNOWN && jwe->alg != R_JWA_ALG_NONE) {
    if ((kid = r_jwk_get_property_str(jwk, "kid")) != NULL && r_jwe_get_header_str_value(jwe, "kid") == NULL) {
      r_jwe_set_header_str_value(jwe, "kid", kid);
    }
    if ((j_header = r_jwe_perform_key_encryption(jwe, jwe->alg, jwk, x5u_flags, &res)) != NULL) {
      j_cur_header = r_jwe_get_full_header_json_t(jwe);
      json_object_update(j_cur_header, json_object_get(j_header, "header"));
      r_jwe_set_full_header_json_t(jwe, j_cur_header);
      json_decref(j_cur_header);
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(j_header, "encrypted_key")));
      json_decref(j_header);
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error r_jwe_perform_key_encryption");
      ret = res;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - invalid input parameters");
    ret = RHN_ERROR_PARAM;
  }

  r_jwk_free(jwk);
  return ret;
}

int r_jwe_decrypt_key(jwe_t * jwe, jwk_t * jwk_s, int x5u_flags) {
  int ret;
  jwk_t * jwk = NULL;

  if (jwe != NULL) {
    if (jwk_s != NULL) {
      jwk = r_jwk_copy(jwk_s);
    } else {
      if (r_jwe_get_header_str_value(jwe, "kid") != NULL) {
        jwk = r_jwks_get_by_kid(jwe->jwks_privkey, r_jwe_get_header_str_value(jwe, "kid"));
      } else if (r_jwks_size(jwe->jwks_privkey) == 1) {
        jwk = r_jwks_get_at(jwe->jwks_privkey, 0);
      }
    }
  }

  if (jwe != NULL && jwe->alg != R_JWA_ALG_UNKNOWN && jwe->alg != R_JWA_ALG_NONE) {
    ret = r_preform_key_decryption(jwe, jwe->alg, jwk, x5u_flags);
  } else {
    ret = RHN_ERROR_PARAM;
  }

  r_jwk_free(jwk);
  return ret;
}

int r_jwe_parse(jwe_t * jwe, const char * jwe_str, int x5u_flags) {
  return r_jwe_parsen(jwe, jwe_str, o_strlen(jwe_str), x5u_flags);
}

int r_jwe_parsen(jwe_t * jwe, const char * jwe_str, size_t jwe_str_len, int x5u_flags) {
  int ret;
  char * str = (char *)jwe_str;

  if (jwe != NULL && str != NULL && jwe_str_len) {
    while(isspace((unsigned char)*str) && jwe_str_len) {
      str++;
      jwe_str_len--;
    }

    if (0 == o_strncmp("ey", str, 2)) {
      ret = r_jwe_compact_parsen(jwe, jwe_str, jwe_str_len, x5u_flags);
    } else if (*str == '{') {
      ret = r_jwe_parsen_json_str(jwe, jwe_str, jwe_str_len, x5u_flags);
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_advanced_parse(jwe_t * jwe, const char * jwe_str, uint32_t parse_flags, int x5u_flags) {
  return r_jwe_advanced_parsen(jwe, jwe_str, o_strlen(jwe_str), parse_flags, x5u_flags);
}

int r_jwe_advanced_parsen(jwe_t * jwe, const char * jwe_str, size_t jwe_str_len, uint32_t parse_flags, int x5u_flags) {
  int ret;
  char * str = (char *)jwe_str;

  if (jwe != NULL && str != NULL && jwe_str_len) {
    while(isspace((unsigned char)*str) && jwe_str_len) {
      str++;
      jwe_str_len--;
    }

    if (0 == o_strncmp("ey", str, 2)) {
      ret = r_jwe_advanced_compact_parsen(jwe, jwe_str, jwe_str_len, parse_flags, x5u_flags);
    } else if (*str == '{') {
      ret = r_jwe_advanced_parsen_json_str(jwe, jwe_str, jwe_str_len, parse_flags, x5u_flags);
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_compact_parsen(jwe_t * jwe, const char * jwe_str, size_t jwe_str_len, int x5u_flags) {
  return r_jwe_advanced_compact_parsen(jwe, jwe_str, jwe_str_len, R_PARSE_HEADER_ALL, x5u_flags);
}

int r_jwe_compact_parse(jwe_t * jwe, const char * jwe_str, int x5u_flags) {
  return r_jwe_compact_parsen(jwe, jwe_str, o_strlen(jwe_str), x5u_flags);
}

int r_jwe_advanced_compact_parse(jwe_t * jwe, const char * jwe_str, uint32_t parse_flags, int x5u_flags) {
  return r_jwe_advanced_compact_parsen(jwe, jwe_str, o_strlen(jwe_str), parse_flags, x5u_flags);
}

int r_jwe_advanced_compact_parsen(jwe_t * jwe, const char * jwe_str, size_t jwe_str_len, uint32_t parse_flags, int x5u_flags) {
  int ret;
  char ** str_array = NULL;
  char * str_header = NULL, * token = NULL, * tmp;
  unsigned char * iv = NULL;
  size_t header_len = 0, cypher_key_len = 0, iv_len = 0, cypher_len = 0, tag_len = 0;
  json_t * j_header = NULL;

  if (jwe != NULL && jwe_str != NULL && jwe_str_len) {
    token = o_strndup(jwe_str, jwe_str_len);
    // Remove whitespaces and newlines
    tmp = str_replace(token, " ", "");
    o_free(token);
    token = tmp;
    tmp = str_replace(token, "\n", "");
    o_free(token);
    token = tmp;
    tmp = str_replace(token, "\t", "");
    o_free(token);
    token = tmp;
    tmp = str_replace(token, "\v", "");
    o_free(token);
    token = tmp;
    tmp = str_replace(token, "\f", "");
    o_free(token);
    token = tmp;
    tmp = str_replace(token, "\r", "");
    o_free(token);
    token = tmp;
    if (split_string(token, ".", &str_array) == 5 && !o_strnullempty(str_array[0]) && !o_strnullempty(str_array[2]) && !o_strnullempty(str_array[3]) && !o_strnullempty(str_array[4])) {
      // Check if all elements 0, 2 and 3 are base64url encoded
      if (o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), NULL, &header_len) &&
         (o_strnullempty(str_array[1]) || o_base64url_decode((unsigned char *)str_array[1], o_strlen(str_array[1]), NULL, &cypher_key_len)) &&
          o_base64url_decode((unsigned char *)str_array[2], o_strlen(str_array[2]), NULL, &iv_len) &&
          o_base64url_decode((unsigned char *)str_array[3], o_strlen(str_array[3]), NULL, &cypher_len) &&
          o_base64url_decode((unsigned char *)str_array[4], o_strlen(str_array[4]), NULL, &tag_len)) {
        ret = RHN_OK;
        jwe->token_mode = R_JSON_MODE_COMPACT;
        do {
          // Decode header
          if ((str_header = o_malloc(header_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error allocating resources for str_header");
            ret = RHN_ERROR_MEMORY;
            break;
          }

          if (!o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), (unsigned char *)str_header, &header_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error o_base64url_decode str_header");
            ret = RHN_ERROR_PARAM;
            break;
          }
          str_header[header_len] = '\0';

          if ((j_header = json_loads(str_header, JSON_DECODE_ANY, NULL)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error json_loads str_header");
            ret = RHN_ERROR_PARAM;
            break;
          }

          if (r_jwe_extract_header(jwe, j_header, parse_flags, x5u_flags) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - error extracting header params");
            ret = RHN_ERROR_PARAM;
            break;
          }
          json_decref(jwe->j_header);

          jwe->j_header = json_incref(j_header);

          // Decode iv
          if ((iv = o_malloc(iv_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error allocating resources for iv");
            ret = RHN_ERROR_MEMORY;
            break;
          }

          if (!o_base64url_decode((unsigned char *)str_array[2], o_strlen(str_array[2]), iv, &iv_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error o_base64url_decode iv");
            ret = RHN_ERROR_PARAM;
            break;
          }

          if (r_jwe_set_iv(jwe, iv, iv_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_compact_parsen - Error r_jwe_set_iv");
            ret = RHN_ERROR;
            break;
          }

          o_free(jwe->header_b64url);
          jwe->header_b64url = (unsigned char *)o_strdup(str_array[0]);
          o_free(jwe->aad_b64url);
          jwe->aad_b64url = (unsigned char *)o_strdup(str_array[0]);
          o_free(jwe->encrypted_key_b64url);
          jwe->encrypted_key_b64url = (unsigned char *)o_strdup(str_array[1]);
          o_free(jwe->iv_b64url);
          jwe->iv_b64url = (unsigned char *)o_strdup(str_array[2]);
          o_free(jwe->ciphertext_b64url);
          jwe->ciphertext_b64url = (unsigned char *)o_strdup(str_array[3]);
          o_free(jwe->auth_tag_b64url);
          jwe->auth_tag_b64url = (unsigned char *)o_strdup(str_array[4]);

        } while (0);
        json_decref(j_header);
        o_free(str_header);
        o_free(iv);
      } else {
        ret = RHN_ERROR_PARAM;
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
    free_string_array(str_array);
    o_free(token);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_parse_json_str(jwe_t * jwe, const char * jwe_json_str, int x5u_flags) {
  return r_jwe_parsen_json_str(jwe, jwe_json_str, o_strlen(jwe_json_str), x5u_flags);
}

int r_jwe_parsen_json_str(jwe_t * jwe, const char * jwe_json_str, size_t jwe_json_str_len, int x5u_flags) {
  json_t * jwe_json = NULL;
  int ret;

  jwe_json = json_loadb(jwe_json_str, jwe_json_str_len, JSON_DECODE_ANY, NULL);
  ret = r_jwe_parse_json_t(jwe, jwe_json, x5u_flags);
  json_decref(jwe_json);

  return ret;
}

int r_jwe_parse_json_t(jwe_t * jwe, json_t * jwe_json, int x5u_flags) {
  return r_jwe_advanced_parse_json_t(jwe, jwe_json, R_PARSE_HEADER_ALL, x5u_flags);
}

int r_jwe_advanced_parse_json_str(jwe_t * jwe, const char * jwe_json_str, uint32_t parse_flags, int x5u_flags) {
  return r_jwe_advanced_parsen_json_str(jwe, jwe_json_str, o_strlen(jwe_json_str), parse_flags, x5u_flags);
}

int r_jwe_advanced_parsen_json_str(jwe_t * jwe, const char * jwe_json_str, size_t jwe_json_str_len, uint32_t parse_flags, int x5u_flags) {
  json_t * jwe_json = NULL;
  int ret;

  jwe_json = json_loadb(jwe_json_str, jwe_json_str_len, JSON_DECODE_ANY, NULL);
  ret = r_jwe_advanced_parse_json_t(jwe, jwe_json, parse_flags, x5u_flags);
  json_decref(jwe_json);

  return ret;
}

int r_jwe_advanced_parse_json_t(jwe_t * jwe, json_t * jwe_json, uint32_t parse_flags, int x5u_flags) {
  int ret;
  size_t header_len = 0, cypher_key_len = 0, iv_len = 0, index = 0;;
  char * str_header = NULL;
  json_t * j_header = NULL, * j_recipient;
  unsigned char * iv = NULL;

  if (jwe != NULL && json_is_object(jwe_json)) {
    if (json_string_length(json_object_get(jwe_json, "protected")) &&
        json_string_length(json_object_get(jwe_json, "iv")) &&
        json_string_length(json_object_get(jwe_json, "ciphertext")) &&
        json_string_length(json_object_get(jwe_json, "tag"))) {
      ret = RHN_OK;
      r_jwe_set_cypher_key(jwe, NULL, 0);
      r_jwe_set_iv(jwe, NULL, 0);
      r_jwe_set_aad(jwe, NULL, 0);
      r_jwe_set_payload(jwe, NULL, 0);
      o_free(jwe->header_b64url);
      jwe->header_b64url = NULL;
      o_free(jwe->encrypted_key_b64url);
      jwe->encrypted_key_b64url = NULL;
      o_free(jwe->iv_b64url);
      jwe->iv_b64url = NULL;
      o_free(jwe->ciphertext_b64url);
      jwe->ciphertext_b64url = NULL;
      o_free(jwe->auth_tag_b64url);
      jwe->auth_tag_b64url = NULL;
      o_free(jwe->aad_b64url);
      jwe->aad_b64url = NULL;
      json_decref(jwe->j_header);
      jwe->j_header = json_object();
      json_decref(jwe->j_unprotected_header);
      jwe->j_unprotected_header = NULL;
      do {
        json_decref(jwe->j_json_serialization);
        if ((jwe->j_json_serialization = json_deep_copy(jwe_json)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error setting j_json_serialization");
          ret = RHN_ERROR;
          break;
        }

        if (json_object_get(jwe_json, "unprotected") != NULL && r_jwe_set_full_unprotected_header_json_t(jwe, json_object_get(jwe_json, "unprotected")) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error r_jwe_set_full_unprotected_header_json_t");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if (!o_base64url_decode((unsigned char *)json_string_value(json_object_get(jwe_json, "protected")), json_string_length(json_object_get(jwe_json, "protected")), NULL, &header_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error invalid protected base64");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if ((str_header = o_malloc(header_len+4)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error allocating resources for str_header");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if (!o_base64url_decode((unsigned char *)json_string_value(json_object_get(jwe_json, "protected")), json_string_length(json_object_get(jwe_json, "protected")), (unsigned char *)str_header, &header_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error invalid protected base64");
          ret = RHN_ERROR_PARAM;
          break;
        }
        str_header[header_len] = '\0';

        if ((j_header = json_loads(str_header, JSON_DECODE_ANY, NULL)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error json_loads str_header");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if (r_jwe_extract_header(jwe, j_header, parse_flags, x5u_flags) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - error extracting header params");
          ret = RHN_ERROR_PARAM;
          break;
        }
        json_decref(jwe->j_header);

        jwe->j_header = json_incref(j_header);

        // Decode iv
        if (!o_base64url_decode((unsigned char *)json_string_value(json_object_get(jwe_json, "iv")), json_string_length(json_object_get(jwe_json, "iv")), NULL, &iv_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error invalid iv base64");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if ((iv = o_malloc(iv_len+4)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error allocating resources for iv");
          ret = RHN_ERROR_MEMORY;
          break;
        }

        if (!o_base64url_decode((unsigned char *)json_string_value(json_object_get(jwe_json, "iv")), json_string_length(json_object_get(jwe_json, "iv")), iv, &iv_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error o_base64url_decode iv");
          ret = RHN_ERROR_PARAM;
          break;
        }

        if (r_jwe_set_iv(jwe, iv, iv_len) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error r_jwe_set_iv");
          ret = RHN_ERROR;
          break;
        }
        jwe->header_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(jwe_json, "protected")));
        jwe->ciphertext_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(jwe_json, "ciphertext")));
        jwe->auth_tag_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(jwe_json, "tag")));
        jwe->aad_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(jwe_json, "aad")));

      } while (0);
      json_decref(j_header);
      o_free(str_header);
      o_free(iv);
      if (ret == RHN_OK) {
        if (json_array_size(json_object_get(jwe_json, "recipients"))) {
          jwe->token_mode = R_JSON_MODE_GENERAL;
          json_array_foreach(json_object_get(jwe_json, "recipients"), index, j_recipient) {
            if (!json_is_object(j_recipient)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Invalid recipient at index %zu, must be a JSON object", index);
              ret = RHN_ERROR_PARAM;
              break;
            } else {
              if (!o_base64url_decode((const unsigned char*)json_string_value(json_object_get(j_recipient, "encrypted_key")), json_string_length(json_object_get(j_recipient, "encrypted_key")), NULL, &cypher_key_len)) {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error at index %zu, invalid encrypted_key base64 %s", index);
                ret = RHN_ERROR_PARAM;
                break;
              }
              if (json_object_get(j_recipient, "header") != NULL && !json_is_object(json_object_get(j_recipient, "header"))) {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Invalid header at index %zu, must be a JSON object", index);
                ret = RHN_ERROR_PARAM;
                break;
              }
            }
          }
        } else {
          jwe->token_mode = R_JSON_MODE_FLATTENED;
          jwe->encrypted_key_b64url = (unsigned char *)o_strdup(json_string_value(json_object_get(jwe_json, "encrypted_key")));
          if (json_object_get(jwe_json, "header") == NULL || r_jwe_extract_header(jwe, json_object_get(jwe_json, "header"), parse_flags, x5u_flags) == RHN_OK) {
            json_object_update_missing(jwe->j_header, json_object_get(jwe_json, "header"));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - error extracting header params");
            ret = RHN_ERROR_PARAM;
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error invalid content");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse_json_t - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwe_t * r_jwe_quick_parse(const char * jwe_str, uint32_t parse_flags, int x5u_flags) {
  return r_jwe_quick_parsen(jwe_str, o_strlen(jwe_str), parse_flags, x5u_flags);
}

jwe_t * r_jwe_quick_parsen(const char * jwe_str, size_t jwe_str_len, uint32_t parse_flags, int x5u_flags) {
  jwe_t * jwe = NULL;
  int ret;

  if (r_jwe_init(&jwe) == RHN_OK) {
    ret = r_jwe_advanced_parsen(jwe, jwe_str, jwe_str_len, parse_flags, x5u_flags);
    if (ret != RHN_OK) {
      r_jwe_free(jwe);
      jwe = NULL;
    }
  } else {
    r_jwe_free(jwe);
    jwe = NULL;
  }
  return jwe;
}

int r_jwe_decrypt(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags) {
  int ret, res;
  json_t * j_recipient = NULL, * j_header, * j_cur_header;
  size_t index = 0, i;
  jwk_t * jwk = NULL, * cur_jwk = NULL;
  jwa_alg alg;

  if (jwe != NULL) {
    if (jwk_privkey != NULL) {
      jwk = r_jwk_copy(jwk_privkey);
    } else {
      if (r_jwe_get_header_str_value(jwe, "kid") != NULL) {
        jwk = r_jwks_get_by_kid(jwe->jwks_privkey, r_jwe_get_header_str_value(jwe, "kid"));
      } else if (r_jwks_size(jwe->jwks_privkey) == 1) {
        jwk = r_jwks_get_at(jwe->jwks_privkey, 0);
      }
    }
  }

  if (jwe != NULL) {
    if (jwe->token_mode == R_JSON_MODE_GENERAL) {
      ret = RHN_ERROR_INVALID;
      o_free(jwe->encrypted_key_b64url);
      j_header = r_jwe_get_full_header_json_t(jwe);
      json_array_foreach(json_object_get(jwe->j_json_serialization, "recipients"), index, j_recipient) {
        j_cur_header = json_deep_copy(j_header);
        json_object_update(j_cur_header, json_object_get(j_recipient, "header"));
        r_jwe_set_full_header_json_t(jwe, j_cur_header);
        json_decref(j_cur_header);
        jwe->encrypted_key_b64url = (unsigned char *)json_string_value(json_object_get(j_recipient, "encrypted_key"));
        alg = r_jwe_get_alg(jwe);
        if (json_object_get(jwe->j_unprotected_header, "alg") != NULL) {
          alg = r_str_to_jwa_alg(json_string_value(json_object_get(jwe->j_unprotected_header, "alg")));
        }
        if (json_object_get(json_object_get(j_recipient, "header"), "alg") != NULL) {
          alg = r_str_to_jwa_alg(json_string_value(json_object_get(json_object_get(j_recipient, "header"), "alg")));
        }
        if (alg != R_JWA_ALG_UNKNOWN && alg != R_JWA_ALG_ECDH_ES) {
          if (jwk_privkey != NULL) {
            if (r_jwk_get_property_str(jwk_privkey, "kid") == NULL || json_object_get(json_object_get(j_recipient, "header"), "kid") == NULL || 0 == o_strcmp(json_string_value(json_object_get(json_object_get(j_recipient, "header"), "kid")), r_jwk_get_property_str(jwk_privkey, "kid"))) {
              if ((res = r_preform_key_decryption(jwe, alg, jwk_privkey, x5u_flags)) != RHN_ERROR_INVALID) {
                ret = res;
                break;
              }
            }
          } else {
            if (json_object_get(json_object_get(j_recipient, "header"), "kid") != NULL) {
              cur_jwk = r_jwks_get_by_kid(jwe->jwks_privkey, json_string_value(json_object_get(json_object_get(j_recipient, "header"), "kid")));
              if ((res = r_preform_key_decryption(jwe, alg, cur_jwk, x5u_flags)) != RHN_ERROR_INVALID) {
                ret = res;
                r_jwk_free(cur_jwk);
                break;
              }
              r_jwk_free(cur_jwk);
            } else {
              for (i=0; i<r_jwks_size(jwe->jwks_privkey); i++) {
                cur_jwk = r_jwks_get_at(jwe->jwks_privkey, i);
                if ((res = r_preform_key_decryption(jwe, alg, cur_jwk, x5u_flags)) != RHN_ERROR_INVALID) {
                  ret = res;
                  r_jwk_free(cur_jwk);
                  break;
                }
                r_jwk_free(cur_jwk);
              }
              if (ret != RHN_ERROR_INVALID) {
                break;
              }
            }
          }
          cur_jwk = NULL;
        } else if (alg == R_JWA_ALG_ECDH_ES) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_decrypt - Unsupported algorithm ECDH-ES on general serialization");
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt - Invalid alg value at index %zu: %d", index, (alg));
          ret = RHN_ERROR_PARAM;
        }
      }
      r_jwe_set_full_header_json_t(jwe, j_header);
      json_decref(j_header);
      jwe->encrypted_key_b64url = NULL;
      if (ret == RHN_OK) {
        ret = r_jwe_decrypt_payload(jwe);
      }
    } else {
      j_header = r_jwe_get_full_header_json_t(jwe);
      j_cur_header = json_deep_copy(j_header);
      json_object_update(j_cur_header, json_object_get(j_recipient, "header"));
      if (jwe->j_unprotected_header != NULL) {
        json_object_update(j_cur_header, jwe->j_unprotected_header);
      }
      r_jwe_set_full_header_json_t(jwe, j_cur_header);
      json_decref(j_cur_header);
      if ((res = r_jwe_decrypt_key(jwe, jwk, x5u_flags)) == RHN_OK && (res = r_jwe_decrypt_payload(jwe)) == RHN_OK) {
        ret = RHN_OK;
      } else {
        if (res != RHN_ERROR_INVALID) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt - Error decrypting data");
        }
        ret = res;
      }
      r_jwe_set_full_header_json_t(jwe, j_header);
      json_decref(j_header);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  r_jwk_free(jwk);
  return ret;
}

char * r_jwe_serialize(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags) {
  char * jwe_str = NULL;
  int res = RHN_OK;
  unsigned int bits = 0;
  unsigned char * key = NULL;
  size_t key_len = 0;

  if (jwk_pubkey != NULL && jwe != NULL && jwe->alg == R_JWA_ALG_DIR) {
    if (r_jwk_key_type(jwk_pubkey, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == _r_get_key_size(jwe->enc)*8) {
      key_len = (size_t)(bits/8);
      if ((key = o_malloc(key_len+4)) != NULL) {
        if (r_jwk_export_to_symmetric_key(jwk_pubkey, key, &key_len) == RHN_OK) {
          res = r_jwe_set_cypher_key(jwe, key, key_len);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error r_jwk_export_to_symmetric_key");
          res = RHN_ERROR_MEMORY;
        }
        o_free(key);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error allocating resources for key");
        res = RHN_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error invalid key type");
      res = RHN_ERROR_PARAM;
    }
  } else {
    res = RHN_OK;
  }

  if (res == RHN_OK) {
    if (jwe->key == NULL || !jwe->key_len) {
      if (r_jwe_generate_cypher_key(jwe) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error r_jwe_generate_cypher_key");
        res = RHN_ERROR;
      }
    }
    if (jwe->iv == NULL || !jwe->iv_len) {
      if (r_jwe_generate_iv(jwe) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error r_jwe_generate_iv");
        res = RHN_ERROR;
      }
    }
  }
  if (res == RHN_OK && r_jwe_set_alg_header(jwe, jwe->j_header) == RHN_OK && r_jwe_encrypt_key(jwe, jwk_pubkey, x5u_flags) == RHN_OK && r_jwe_encrypt_payload(jwe) == RHN_OK) {
    jwe_str = msprintf("%s.%s.%s.%s.%s",
                      jwe->header_b64url,
                      jwe->encrypted_key_b64url!=NULL?(const char *)jwe->encrypted_key_b64url:"",
                      jwe->iv_b64url,
                      jwe->ciphertext_b64url,
                      jwe->auth_tag_b64url);

  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error input parameters");
  }
  return jwe_str;
}

char * r_jwe_serialize_json_str(jwe_t * jwe, jwks_t * jwks_pubkey, int x5u_flags, int mode) {
  json_t * j_result = r_jwe_serialize_json_t(jwe, jwks_pubkey, x5u_flags, mode);
  char * str_result = json_dumps(j_result, JSON_COMPACT);
  json_decref(j_result);
  return str_result;
}

json_t * r_jwe_serialize_json_t(jwe_t * jwe, jwks_t * jwks_pubkey, int x5u_flags, int mode) {
  json_t * j_return = NULL, * j_result;
  jwk_t * jwk = NULL;
  jwa_alg alg = R_JWA_ALG_NONE;
  const char * kid = NULL;
  size_t i = 0;
  int res = RHN_OK;

  if (jwks_pubkey == NULL) {
    jwks_pubkey = jwe->jwks_pubkey;
  }
  if (jwe != NULL && r_jwks_size(jwks_pubkey)) {
    jwe->token_mode = mode;
    if (mode == R_JSON_MODE_FLATTENED) {
      if ((kid = r_jwe_get_header_str_value(jwe, "kid")) != NULL) {
        jwk = r_jwks_get_by_kid(jwks_pubkey, kid);
      } else {
        jwk = r_jwks_get_at(jwks_pubkey, 0);
        kid = r_jwk_get_property_str(jwk, "kid");
      }
      alg = r_str_to_jwa_alg(r_jwk_get_property_str(jwk, "alg"));
      if (alg == R_JWA_ALG_UNKNOWN) {
        alg = jwe->alg;
      }
      if (jwe->key == NULL || !jwe->key_len) {
        if (r_jwe_generate_cypher_key(jwe) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error r_jwe_generate_cypher_key");
          res = RHN_ERROR;
        }
      }
      if (jwe->iv == NULL || !jwe->iv_len) {
        if (r_jwe_generate_iv(jwe) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error r_jwe_generate_iv");
          res = RHN_ERROR;
        }
      }
      if (res == RHN_OK) {
        if ((j_result = r_jwe_perform_key_encryption(jwe, alg, jwk, x5u_flags, &res)) != NULL) {
          if (r_jwe_encrypt_payload(jwe) == RHN_OK) {
            if ((kid = r_jwe_get_header_str_value(jwe, "kid")) == NULL) {
              kid = r_jwk_get_property_str(jwk, "kid");
            }
            j_return = json_pack("{ss sO* ss ss ss sO*}", "protected", jwe->header_b64url,
                                                          "encrypted_key", json_object_get(j_result, "encrypted_key"),
                                                          "iv", jwe->iv_b64url,
                                                          "ciphertext", jwe->ciphertext_b64url,
                                                          "tag", jwe->auth_tag_b64url,
                                                          "header", json_object_get(j_result, "header"));
            if (jwe->aad_b64url != NULL) {
              json_object_set_new(j_return, "aad", json_string((const char *)jwe->aad_b64url));
            }
            if (jwe->j_unprotected_header != NULL) {
              json_object_set_new(j_return, "unprotected", json_deep_copy(jwe->j_unprotected_header));
            }
            if (kid != NULL) {
              json_object_set_new(json_object_get(j_return, "header"), "kid", json_string(kid));
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error input parameters");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error invalid encryption key");
        }
        json_decref(j_result);
      }
      r_jwk_free(jwk);
    } else if (mode == R_JSON_MODE_GENERAL) {
      if (jwe->key == NULL || !jwe->key_len) {
        if (r_jwe_generate_cypher_key(jwe) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error r_jwe_generate_cypher_key");
          res = RHN_ERROR;
        }
      }
      if (jwe->iv == NULL || !jwe->iv_len) {
        if (r_jwe_generate_iv(jwe) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error r_jwe_generate_iv");
          res = RHN_ERROR;
        }
      }
      if (res == RHN_OK && r_jwe_encrypt_payload(jwe) == RHN_OK) {
        j_return = json_pack("{ss ss ss ss s[]}", "protected", jwe->header_b64url,
                                              "iv", jwe->iv_b64url,
                                              "ciphertext", jwe->ciphertext_b64url,
                                              "tag", jwe->auth_tag_b64url,
                                              "recipients");
        if (jwe->aad_b64url != NULL) {
          json_object_set_new(j_return, "aad", json_string((const char *)jwe->aad_b64url));
        }
        if (jwe->j_unprotected_header != NULL) {
          json_object_set_new(j_return, "unprotected", json_deep_copy(jwe->j_unprotected_header));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error input parameters");
      }
      //r_jwe_set_header_str_value(jwe, "alg", NULL);
      for (i=0; i<r_jwks_size(jwks_pubkey); i++) {
        jwk = r_jwks_get_at(jwks_pubkey, i);
        kid = r_jwk_get_property_str(jwk, "kid");
        if ((alg = r_jwe_get_alg(jwe)) == R_JWA_ALG_UNKNOWN || alg == R_JWA_ALG_NONE) {
          alg = r_str_to_jwa_alg(r_jwk_get_property_str(jwk, "alg"));
        }
        if (alg != R_JWA_ALG_UNKNOWN && alg != R_JWA_ALG_ECDH_ES) {
          if ((j_result = r_jwe_perform_key_encryption(jwe, alg, jwk, x5u_flags, &res)) != NULL) {
            if (json_object_get(jwe->j_header, "kid") == NULL && json_object_get(jwe->j_unprotected_header, "kid") == NULL) {
              json_object_set_new(json_object_get(j_result, "header"), "kid", json_string(r_jwk_get_property_str(jwk, "kid")));
            }
            json_array_append(json_object_get(j_return, "recipients"), j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error invalid encryption key at index %zu", i);
          }
          json_decref(j_result);
        } else if (alg == R_JWA_ALG_ECDH_ES) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_serialize_json_t - Unsupported algorithm for JWE with multiple recipients");
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error invalid encryption algorithm at index %zu", i);
        }
        r_jwk_free(jwk);
      }
      if (!json_array_size(json_object_get(j_return, "recipients"))) {
        json_decref(j_return);
        j_return = NULL;
      }
    }
    json_decref(jwe->j_json_serialization);
    jwe->j_json_serialization = json_deep_copy(j_return);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize_json_t - Error input parameters");
  }
  return j_return;
}

int r_jwe_set_full_header_json_t(jwe_t * jwe, json_t * j_header) {
  int ret = RHN_OK;
  jwa_alg alg;
  jwa_enc enc;

  if (jwe != NULL && json_is_object(j_header)) {
    if (json_object_get(j_header, "alg") != NULL) {
      if ((alg = r_str_to_jwa_alg(json_string_value(json_object_get(j_header, "alg")))) != R_JWA_ALG_UNKNOWN) {
        jwe->alg = alg;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_header_json_t - Error invalid alg parameter");
        ret = RHN_ERROR_PARAM;
      }
    }
    if (json_object_get(j_header, "enc") != NULL) {
      if ((enc = r_str_to_jwa_enc(json_string_value(json_object_get(j_header, "enc")))) != R_JWA_ENC_UNKNOWN) {
        jwe->enc = enc;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_header_json_t - Error invalid enc parameter");
        ret = RHN_ERROR_PARAM;
      }
    }
    if (ret == RHN_OK) {
      json_decref(jwe->j_header);
      if ((jwe->j_header = json_deep_copy(j_header)) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_header_json_t - Error setting header");
        ret = RHN_ERROR_MEMORY;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_header_json_t - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_set_full_header_json_str(jwe_t * jwe, const char * str_header) {
  int ret;
  json_t * j_header = json_loads(str_header, JSON_DECODE_ANY, NULL);

  ret = r_jwe_set_full_header_json_t(jwe, j_header);
  json_decref(j_header);

  return ret;
}

int r_jwe_set_full_unprotected_header_json_t(jwe_t * jwe, json_t * j_unprotected_header) {
  int ret = RHN_OK;

  if (jwe != NULL && json_is_object(j_unprotected_header)) {
    json_decref(jwe->j_unprotected_header);
    if ((jwe->j_unprotected_header = json_deep_copy(j_unprotected_header)) == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_unprotected_header_json_t - Error setting header");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_full_unprotected_header_json_t - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_set_full_unprotected_header_json_str(jwe_t * jwe, const char * str_unprotected_header) {
  int ret;
  json_t * j_unprotected_header = json_loads(str_unprotected_header, JSON_DECODE_ANY, NULL);

  ret = r_jwe_set_full_unprotected_header_json_t(jwe, j_unprotected_header);
  json_decref(j_unprotected_header);

  return ret;
}

int r_jwe_set_properties(jwe_t * jwe, ...) {
  rhn_opt option;
  int ret = RHN_OK;
  int i_value;
  rhn_int_t r_value;
  unsigned int ui_value;
  const char * str_key, * str_value;
  json_t * j_value;
  const unsigned char * ustr_value;
  size_t size_value;
  jwk_t * jwk;
  jwks_t * jwks;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey;
  va_list vl;

  if (jwe != NULL) {
    va_start(vl, jwe);
    for (option = va_arg(vl, rhn_opt); option != RHN_OPT_NONE && ret == RHN_OK; option = va_arg(vl, rhn_opt)) {
      switch (option) {
        case RHN_OPT_HEADER_INT_VALUE:
          str_key = va_arg(vl, const char *);
          i_value = va_arg(vl, int);
          ret = r_jwe_set_header_int_value(jwe, str_key, (rhn_int_t)i_value);
          break;
        case RHN_OPT_HEADER_RHN_INT_VALUE:
          str_key = va_arg(vl, const char *);
          r_value = va_arg(vl, rhn_int_t);
          ret = r_jwe_set_header_int_value(jwe, str_key, r_value);
          break;
        case RHN_OPT_HEADER_STR_VALUE:
          str_key = va_arg(vl, const char *);
          str_value = va_arg(vl, const char *);
          ret = r_jwe_set_header_str_value(jwe, str_key, str_value);
          break;
        case RHN_OPT_HEADER_JSON_T_VALUE:
          str_key = va_arg(vl, const char *);
          j_value = va_arg(vl, json_t *);
          ret = r_jwe_set_header_json_t_value(jwe, str_key, j_value);
          break;
        case RHN_OPT_HEADER_FULL_JSON_T:
          j_value = va_arg(vl, json_t *);
          ret = r_jwe_set_full_header_json_t(jwe, j_value);
          break;
        case RHN_OPT_HEADER_FULL_JSON_STR:
          str_value = va_arg(vl, const char *);
          ret = r_jwe_set_full_header_json_str(jwe, str_value);
          break;
        case RHN_OPT_UN_HEADER_FULL_JSON_T:
          j_value = va_arg(vl, json_t *);
          ret = r_jwe_set_full_unprotected_header_json_t(jwe, j_value);
          break;
        case RHN_OPT_UN_HEADER_FULL_JSON_STR:
          str_value = va_arg(vl, const char *);
          ret = r_jwe_set_full_unprotected_header_json_str(jwe, str_value);
          break;
        case RHN_OPT_PAYLOAD:
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_set_payload(jwe, ustr_value, size_value);
          break;
        case RHN_OPT_ENC_ALG:
          ui_value = va_arg(vl, unsigned int);
          ret = r_jwe_set_alg(jwe, (jwa_alg)ui_value);
          break;
        case RHN_OPT_ENC:
          ui_value = va_arg(vl, unsigned int);
          ret = r_jwe_set_enc(jwe, (jwa_enc)ui_value);
          break;
        case RHN_OPT_CIPHER_KEY:
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_set_cypher_key(jwe, ustr_value, size_value);
          break;
        case RHN_OPT_IV:
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_set_iv(jwe, ustr_value, size_value);
          break;
        case RHN_OPT_AAD:
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_set_aad(jwe, ustr_value, size_value);
          break;
        case RHN_OPT_ENCRYPT_KEY_JWK:
          jwk = va_arg(vl, jwk_t *);
          ret = r_jwe_add_keys(jwe, NULL, jwk);
          break;
        case RHN_OPT_ENCRYPT_KEY_JWKS:
          jwks = va_arg(vl, jwks_t *);
          ret = r_jwe_add_jwks(jwe, NULL, jwks);
          break;
        case RHN_OPT_ENCRYPT_KEY_GNUTLS:
          pubkey = va_arg(vl, gnutls_pubkey_t);
          ret = r_jwe_add_keys_gnutls(jwe, NULL, pubkey);
          break;
        case RHN_OPT_ENCRYPT_KEY_JSON_T:
          j_value = va_arg(vl, json_t *);
          ret = r_jwe_add_keys_json_t(jwe, NULL, j_value);
          break;
        case RHN_OPT_ENCRYPT_KEY_JSON_STR:
          str_value = va_arg(vl, const char *);
          ret = r_jwe_add_keys_json_str(jwe, NULL, str_value);
          break;
        case RHN_OPT_ENCRYPT_KEY_PEM_DER:
          ui_value = va_arg(vl, unsigned int);
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_add_keys_pem_der(jwe, ui_value, NULL, 0, ustr_value, size_value);
          break;
        case RHN_OPT_DECRYPT_KEY_JWK:
          jwk = va_arg(vl, jwk_t *);
          ret = r_jwe_add_keys(jwe, jwk, NULL);
          break;
        case RHN_OPT_DECRYPT_KEY_JWKS:
          jwks = va_arg(vl, jwks_t *);
          ret = r_jwe_add_jwks(jwe, jwks, NULL);
          break;
        case RHN_OPT_DECRYPT_KEY_GNUTLS:
          privkey = va_arg(vl, gnutls_privkey_t);
          ret = r_jwe_add_keys_gnutls(jwe, privkey, NULL);
          break;
        case RHN_OPT_DECRYPT_KEY_JSON_T:
          j_value = va_arg(vl, json_t *);
          ret = r_jwe_add_keys_json_t(jwe, j_value, NULL);
          break;
        case RHN_OPT_DECRYPT_KEY_JSON_STR:
          str_value = va_arg(vl, const char *);
          ret = r_jwe_add_keys_json_str(jwe, str_value, NULL);
          break;
        case RHN_OPT_DECRYPT_KEY_PEM_DER:
          ui_value = va_arg(vl, unsigned int);
          ustr_value = va_arg(vl, const unsigned char *);
          size_value = va_arg(vl, size_t);
          ret = r_jwe_add_keys_pem_der(jwe, ui_value, ustr_value, size_value, NULL, 0);
          break;
        default:
          ret = RHN_ERROR_PARAM;
          break;
      }
    }
    va_end(vl);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_properties - Error input parameter");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}
