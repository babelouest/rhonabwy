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

#include <stdint.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <zlib.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define R_TAG_MAX_SIZE 16

static gnutls_cipher_algorithm_t r_jwe_get_alg_from_enc(jwa_enc enc) {
  gnutls_cipher_algorithm_t alg = GNUTLS_CIPHER_UNKNOWN;
  
  switch (enc) {
    case R_JWA_ENC_A128CBC:
      alg = GNUTLS_CIPHER_AES_128_CBC;
      break;
    case R_JWA_ENC_A192CBC:
      alg = GNUTLS_CIPHER_AES_192_CBC;
      break;
    case R_JWA_ENC_A256CBC:
      alg = GNUTLS_CIPHER_AES_256_CBC;
      break;
    case R_JWA_ENC_A128GCM:
      alg = GNUTLS_CIPHER_AES_128_GCM;
      break;
    case R_JWA_ENC_A192GCM:
      alg = GNUTLS_CIPHER_UNKNOWN; // Unsupported on GnuTLS 3.6
      break;
    case R_JWA_ENC_A256GCM:
      alg = GNUTLS_CIPHER_AES_256_GCM;
      break;
    default:
      alg = GNUTLS_CIPHER_UNKNOWN;
      break;
  }
  return alg;
}

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

static unsigned char * r_jwe_set_ptext_with_block(const unsigned char * data, size_t data_len, size_t * ptext_len, gnutls_cipher_algorithm_t alg) {
  size_t b_size = (size_t)gnutls_cipher_get_block_size(alg);
  unsigned char * ptext = NULL;
  
  if (data_len % b_size) {
    *ptext_len = ((data_len/b_size)+1)*b_size;
  } else {
    *ptext_len = data_len;
  }
  if (*ptext_len) {
    if ((ptext = o_malloc(*ptext_len)) != NULL) {
      memcpy(ptext, data, data_len);
      memset(ptext+data_len, (*ptext_len)-data_len, (*ptext_len)-data_len);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_set_ptext_with_block - Error allocating resources for ptext");
    }
  }
  return ptext;
}

static size_t r_jwe_get_key_size(jwa_enc enc) {
  size_t size = 0;
  switch (enc) {
    case R_JWA_ENC_A128CBC:
      size = 32;
      break;
    case R_JWA_ENC_A192CBC:
      size = 48;
      break;
    case R_JWA_ENC_A256CBC:
      size = 64;
      break;
    case R_JWA_ENC_A128GCM:
    case R_JWA_ENC_A192GCM:
    case R_JWA_ENC_A256GCM:
      size = 32;
      break;
    default:
      size = 0;
      break;
  }
  return size;
}

static int r_jwe_extract_header(jwe_t * jwe, json_t * j_header, int x5u_flags) {
  int ret;
  jwk_t * jwk;
  
  if (json_is_object(j_header)) {
    ret = RHN_OK;
    
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
      jwe->alg = str_to_jwa_alg(json_string_value(json_object_get(j_header, "alg")));
    }
    
    if (0 != o_strcmp("A128CBC-HS256", json_string_value(json_object_get(j_header, "enc"))) && 
    0 != o_strcmp("A192CBC-HS384", json_string_value(json_object_get(j_header, "enc"))) && 
    0 != o_strcmp("A256CBC-HS512", json_string_value(json_object_get(j_header, "enc"))) &&
    0 != o_strcmp("A128GCM", json_string_value(json_object_get(j_header, "enc"))) && 
    0 != o_strcmp("A192GCM", json_string_value(json_object_get(j_header, "enc"))) && 
    0 != o_strcmp("A256GCM", json_string_value(json_object_get(j_header, "enc")))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Invalid enc");
      ret = RHN_ERROR_PARAM;
    } else {
      jwe->enc = str_to_jwa_enc(json_string_value(json_object_get(j_header, "enc")));
    }
    
    if (json_string_length(json_object_get(j_header, "jku"))) {
      if (r_jwks_import_from_uri(jwe->jwks_pubkey, json_string_value(json_object_get(j_header, "jku")), x5u_flags) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_extract_header - Error loading jwks from uri %s", json_string_value(json_object_get(j_header, "jku")));
      }
    }
    
    if (json_object_get(j_header, "jwk") != NULL) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_json_t(jwk, json_object_get(j_header, "jwk")) != RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
      } else {
        ret = RHN_ERROR_PARAM;
      }
      r_jwk_free(jwk);
    }
    
    if (json_object_get(j_header, "x5u") != NULL || json_object_get(j_header, "x5c") != NULL) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_json_t(jwk, j_header) == RHN_OK) {
        if (r_jwks_append_jwk(jwe->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
      } else {
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

static int r_jwe_compute_hmac_tag(jwe_t * jwe, unsigned char * ciphertext, size_t cyphertext_len, unsigned char * tag, size_t * tag_len) {
  int ret, res;
  unsigned char al[8], * compute_hmac = NULL;
  uint64_t aad_len;
  size_t hmac_size = 0, aad_size = o_strlen((const char *)jwe->header_b64url);
  gnutls_mac_algorithm_t mac = r_jwe_get_digest_from_enc(jwe->enc);
  
  aad_len = (uint64_t)(o_strlen((const char *)jwe->header_b64url)*8);
  memset(al, 0, 8);
  for(int i = 0; i < 8; i++) {
    al[i] = (uint8_t)((aad_len >> 8*(7 - i)) & 0xFF);
  }
  
  if ((compute_hmac = o_malloc(aad_size+jwe->iv_len+cyphertext_len+8)) != NULL) {
    memcpy(compute_hmac, jwe->header_b64url, aad_size);
    hmac_size += aad_size;
    memcpy(compute_hmac+hmac_size, jwe->iv, jwe->iv_len);
    hmac_size += jwe->iv_len;
    memcpy(compute_hmac+hmac_size, ciphertext, cyphertext_len);
    hmac_size += cyphertext_len;
    memcpy(compute_hmac+hmac_size, al, 8);
    hmac_size += 8;
    
    if (!(res = gnutls_hmac_fast(mac, jwe->key, 16, compute_hmac, hmac_size, tag))) {
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
            (*jwe)->ciphertext_b64url = NULL;
            (*jwe)->auth_tag_b64url = NULL;
            (*jwe)->alg = R_JWA_ALG_UNKNOWN;
            (*jwe)->enc = R_JWA_ENC_UNKNOWN;
            (*jwe)->key = NULL;
            (*jwe)->key_len = 0;
            (*jwe)->iv = NULL;
            (*jwe)->iv_len = 0;
            (*jwe)->payload = NULL;
            (*jwe)->payload_len = 0;
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
    o_free(jwe->ciphertext_b64url);
    o_free(jwe->auth_tag_b64url);
    json_decref(jwe->j_header);
    o_free(jwe->key);
    o_free(jwe->iv);
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
      if (r_jwe_set_payload(jwe_copy, jwe->payload, jwe->payload_len) == RHN_OK &&
          r_jwe_set_iv(jwe_copy, jwe->iv, jwe->iv_len) == RHN_OK &&
          r_jwe_set_cypher_key(jwe_copy, jwe->key, jwe->key_len) == RHN_OK &&
          r_jwe_set_alg(jwe_copy, r_jwe_get_alg(jwe)) == RHN_OK) {
        jwe_copy->header_b64url = (unsigned char *)o_strdup((const char *)jwe->header_b64url);
        jwe_copy->encrypted_key_b64url = (unsigned char *)o_strdup((const char *)jwe->encrypted_key_b64url);
        jwe_copy->iv_b64url = (unsigned char *)o_strdup((const char *)jwe->iv_b64url);
        jwe_copy->ciphertext_b64url = (unsigned char *)o_strdup((const char *)jwe->ciphertext_b64url);
        jwe_copy->auth_tag_b64url = (unsigned char *)o_strdup((const char *)jwe->auth_tag_b64url);
        r_jwks_free(jwe_copy->jwks_privkey);
        jwe_copy->jwks_privkey = r_jwks_copy(jwe->jwks_privkey);
        r_jwks_free(jwe_copy->jwks_pubkey);
        jwe_copy->jwks_pubkey = r_jwks_copy(jwe->jwks_pubkey);
        json_decref(jwe_copy->j_header);
        jwe_copy->j_header = json_deep_copy(jwe->j_header);
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
    o_free(jwe->ciphertext_b64url);
    jwe->ciphertext_b64url = NULL;
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
    o_free(jwe->encrypted_key_b64url);
    jwe->encrypted_key_b64url = NULL;
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
    jwe->key_len = r_jwe_get_key_size(jwe->enc);
    o_free(jwe->key);
    if ((jwe->key = o_malloc(jwe->key_len)) != NULL) {
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
  
  if (jwe != NULL) {
    o_free(jwe->iv_b64url);
    jwe->iv_b64url = NULL;
    o_free(jwe->iv);
    if (iv != NULL && iv_len) {
      if ((jwe->iv = o_malloc(iv_len)) != NULL) {
        memcpy(jwe->iv, iv, iv_len);
        jwe->iv_len = iv_len;
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

int r_jwe_generate_iv(jwe_t * jwe) {
  int ret;
  unsigned char * iv_b64 = NULL;
  size_t iv_b64_len = 0;
  
  if (jwe != NULL && jwe->enc != R_JWA_ENC_UNKNOWN) {
    o_free(jwe->iv_b64url);
    jwe->iv_b64url = NULL;
    jwe->iv_len = gnutls_cipher_get_iv_size(r_jwe_get_alg_from_enc(jwe->enc));
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
    switch (alg) {
      case R_JWA_ALG_NONE:
        json_object_set_new(jwe->j_header, "alg", json_string("none"));
        break;
      case R_JWA_ALG_RSA1_5:
        json_object_set_new(jwe->j_header, "alg", json_string("RSA1_5"));
        break;
      case R_JWA_ALG_RSA_OAEP:
        json_object_set_new(jwe->j_header, "alg", json_string("RSA-OAEP"));
        break;
      case R_JWA_ALG_RSA_OAEP_256:
        json_object_set_new(jwe->j_header, "alg", json_string("RSA-OAEP-256"));
        break;
      case R_JWA_ALG_A128KW:
        json_object_set_new(jwe->j_header, "alg", json_string("A128KW"));
        break;
      case R_JWA_ALG_A192KW:
        json_object_set_new(jwe->j_header, "alg", json_string("A192KW"));
        break;
      case R_JWA_ALG_A256KW:
        json_object_set_new(jwe->j_header, "alg", json_string("A256KW"));
        break;
      case R_JWA_ALG_DIR:
        json_object_set_new(jwe->j_header, "alg", json_string("dir"));
        break;
      case R_JWA_ALG_ECDH_ES:
        json_object_set_new(jwe->j_header, "alg", json_string("ECDH-ES"));
        break;
      case R_JWA_ALG_ECDH_ES_A128KW:
        json_object_set_new(jwe->j_header, "alg", json_string("ECDH-ES+A128KW"));
        break;
      case R_JWA_ALG_ECDH_ES_A192KW:
        json_object_set_new(jwe->j_header, "alg", json_string("ECDH-ES+A192KW"));
        break;
      case R_JWA_ALG_ECDH_ES_A256KW:
        json_object_set_new(jwe->j_header, "alg", json_string("ECDH-ES+A256KW"));
        break;
      case R_JWA_ALG_A128GCMKW:
        json_object_set_new(jwe->j_header, "alg", json_string("A128GCMKW"));
        break;
      case R_JWA_ALG_A192GCMKW:
        json_object_set_new(jwe->j_header, "alg", json_string("A192GCMKW"));
        break;
      case R_JWA_ALG_A256GCMKW:
        json_object_set_new(jwe->j_header, "alg", json_string("A256GCMKW"));
        break;
      case R_JWA_ALG_PBES2_H256:
        json_object_set_new(jwe->j_header, "alg", json_string("PBES2-HS256+A128KW"));
        break;
      case R_JWA_ALG_PBES2_H384:
        json_object_set_new(jwe->j_header, "alg", json_string("PBES2-HS384+A192KW"));
        break;
      case R_JWA_ALG_PBES2_H512:
        json_object_set_new(jwe->j_header, "alg", json_string("PBES2-HS512+A256KW"));
        break;
      default:
        ret = RHN_ERROR_PARAM;
        break;
    }
    if (ret == RHN_OK) {
      jwe->alg = alg;
    }
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
    switch (enc) {
      case R_JWA_ENC_A128CBC:
        json_object_set_new(jwe->j_header, "enc", json_string("A128CBC-HS256"));
        break;
      case R_JWA_ENC_A192CBC:
        json_object_set_new(jwe->j_header, "enc", json_string("A192CBC-HS384"));
        break;
      case R_JWA_ENC_A256CBC:
        json_object_set_new(jwe->j_header, "enc", json_string("A256CBC-HS512"));
        break;
      case R_JWA_ENC_A128GCM:
        json_object_set_new(jwe->j_header, "enc", json_string("A128GCM"));
        break;
      case R_JWA_ENC_A192GCM:
        json_object_set_new(jwe->j_header, "enc", json_string("A192GCM"));
        break;
      case R_JWA_ENC_A256GCM:
        json_object_set_new(jwe->j_header, "enc", json_string("A256GCM"));
        break;
      default:
        ret = RHN_ERROR_PARAM;
        break;
    }
    if (ret == RHN_OK) {
      jwe->enc = enc;
    }
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

int r_jwe_set_header_int_value(jwe_t * jwe, const char * key, int i_value) {
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

int r_jwe_get_header_int_value(jwe_t * jwe, const char * key) {
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

int r_jwe_add_keys(jwe_t * jwe, jwk_t * jwk_privkey, jwk_t * jwk_pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  
  if (jwe != NULL && (jwk_privkey != NULL || jwk_pubkey != NULL)) {
    if (jwk_privkey != NULL) {
      if (r_jwks_append_jwk(jwe->jwks_privkey, jwk_privkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_add_keys - Error setting jwk_privkey");
        ret = RHN_ERROR;
      }
      if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = str_to_jwa_alg(r_jwk_get_property_str(jwk_privkey, "alg"))) != R_JWA_ALG_NONE) {
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

int r_jwe_encrypt_payload(jwe_t * jwe) {
  int ret = RHN_OK, res;
  gnutls_cipher_hd_t handle;
  gnutls_datum_t key, iv;
  z_stream defstream;
  unsigned char * ptext = NULL, * text_zip = NULL, * ciphertext_b64url = NULL, tag[128] = {0}, * tag_b64url = NULL, * str_header_b64 = NULL;
  size_t ptext_len = 0, ciphertext_b64url_len = 0, tag_len = 0, tag_b64url_len = 0, str_header_b64_len = 0;
  char * str_header = NULL;
  int cipher_cbc;
  
  if (jwe != NULL && jwe->payload != NULL && jwe->payload_len && jwe->enc != R_JWA_ENC_UNKNOWN && jwe->key != NULL && jwe->key_len && jwe->iv != NULL && jwe->iv_len && jwe->key_len == r_jwe_get_key_size(jwe->enc)) {
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

    ptext_len = gnutls_cipher_get_block_size(r_jwe_get_alg_from_enc(jwe->enc));
    if (0 == o_strcmp("DEF", json_string_value(json_object_get(jwe->j_header, "zip")))) {
      if ((text_zip = o_malloc(jwe->payload_len)) != NULL) {
        defstream.zalloc = Z_NULL;
        defstream.zfree = Z_NULL;
        defstream.opaque = Z_NULL;
        defstream.avail_in = (uInt)jwe->payload_len;
        defstream.next_in = (Bytef *)jwe->payload;
        defstream.avail_out = (uInt)jwe->payload_len;
        defstream.next_out = (Bytef *)text_zip;
        
        if (deflateInit(&defstream, Z_BEST_COMPRESSION) == Z_OK) {
          if (deflate(&defstream, Z_FINISH) == Z_STREAM_END) {
            if ((ptext = r_jwe_set_ptext_with_block(text_zip, defstream.total_out, &ptext_len, r_jwe_get_alg_from_enc(jwe->enc))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_set_ptext_with_block");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error deflate");
            ret = RHN_ERROR;
          }
          deflateEnd(&defstream);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error deflateInit");
          ret = RHN_ERROR;
        }
        o_free(text_zip);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error allocating resources for text_zip");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      if ((ptext = r_jwe_set_ptext_with_block(jwe->payload, jwe->payload_len, &ptext_len, r_jwe_get_alg_from_enc(jwe->enc))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_set_ptext_with_block");
        ret = RHN_ERROR;
      }
    }

    if (ret == RHN_OK) {
      if (jwe->enc == R_JWA_ENC_A128CBC || jwe->enc == R_JWA_ENC_A192CBC || jwe->enc == R_JWA_ENC_A256CBC) {
        key.data = jwe->key+(jwe->key_len/2);
        key.size = (jwe->key_len/2);
        cipher_cbc = 1;
      } else {
        key.data = jwe->key;
        key.size = jwe->key_len;
        cipher_cbc = 0;
      }
      iv.data = jwe->iv;
      iv.size = jwe->iv_len;
      if (!(res = gnutls_cipher_init(&handle, r_jwe_get_alg_from_enc(jwe->enc), &key, &iv))) {
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
        if (ret == RHN_OK) {
          if (cipher_cbc) {
            if (r_jwe_compute_hmac_tag(jwe, ptext, ptext_len, tag, &tag_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error r_jwe_compute_hmac_tag");
              ret = RHN_ERROR;
            }
          } else {
            // This doesn't work at all according to the RFC example
            // https://tools.ietf.org/html/rfc7516#appendix-A.1
            // TODO: Fix AES GCM tag
            tag_len = gnutls_cipher_get_tag_size(r_jwe_get_alg_from_enc(jwe->enc));
            memset(tag, 0, tag_len);
            if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_encrypt_payload - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
              ret = RHN_ERROR;
            }
          }
          if (ret == RHN_OK) {
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
        gnutls_cipher_deinit(handle);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_payload - Error gnutls_cipher_init: '%s'", gnutls_strerror(res));
        ret = RHN_ERROR;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  o_free(ptext);
  return ret;
}

int r_jwe_decrypt_payload(jwe_t * jwe) {
  int ret = RHN_OK, res;
  gnutls_cipher_hd_t handle;
  gnutls_datum_t key, iv;
  unsigned char * payload_enc = NULL, * ciphertext = NULL;
  size_t payload_enc_len = 0, ciphertext_len = 0;
  z_stream infstream;
  unsigned char inf_out[256] = {0}, tag[128], * tag_b64url = NULL;
  size_t tag_len = 0, tag_b64url_len = 0;
  int cipher_cbc;
  
  if (jwe != NULL && jwe->enc != R_JWA_ENC_UNKNOWN && o_strlen((const char *)jwe->ciphertext_b64url) && o_strlen((const char *)jwe->iv_b64url) && jwe->key != NULL && jwe->key_len && jwe->key_len == r_jwe_get_key_size(jwe->enc)) {
    // Decode iv and payload_b64
    o_free(jwe->iv);
    if ((jwe->iv = o_malloc(o_strlen((const char *)jwe->iv_b64url))) != NULL) {
      if (o_base64url_decode(jwe->iv_b64url, o_strlen((const char *)jwe->iv_b64url), jwe->iv, &jwe->iv_len)) {
        jwe->iv = o_realloc(jwe->iv, jwe->iv_len);
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
        key.size = gnutls_hmac_get_len(r_jwe_get_digest_from_enc(jwe->enc))/2;
        cipher_cbc = 1;
      } else {
        key.data = jwe->key;
        key.size = jwe->key_len;
        cipher_cbc = 0;
      }
      iv.data = jwe->iv;
      iv.size = jwe->iv_len;
      payload_enc_len = ciphertext_len;
      if (!(res = gnutls_cipher_init(&handle, r_jwe_get_alg_from_enc(jwe->enc), &key, &iv))) {
        if (!(res = gnutls_cipher_decrypt2(handle, ciphertext, ciphertext_len, payload_enc, payload_enc_len))) {
          r_jwe_remove_padding(payload_enc, &payload_enc_len, gnutls_cipher_get_block_size(r_jwe_get_alg_from_enc(jwe->enc)));
          if (0 == o_strcmp("DEF", json_string_value(json_object_get(jwe->j_header, "zip")))) {
            infstream.zalloc = Z_NULL;
            infstream.zfree = Z_NULL;
            infstream.opaque = Z_NULL;
            infstream.avail_in = (uInt)payload_enc_len;
            infstream.next_in = (Bytef *)payload_enc;
            infstream.avail_out = 256;
            infstream.next_out = (Bytef *)inf_out;
            
            if (inflateInit(&infstream) == Z_OK) {
              o_free(jwe->payload);
              jwe->payload = NULL;
              jwe->payload_len = 0;
              do {
                memset(inf_out, 0, 256);
                if ((res = inflate(&infstream, Z_NO_FLUSH)) > 0) {
                  if ((jwe->payload = o_realloc(jwe->payload, (jwe->payload_len + infstream.total_out))) != NULL) {
                    memcpy(jwe->payload+jwe->payload_len, inf_out, infstream.total_out);
                    jwe->payload_len += infstream.total_out;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error o_realloc for payload");
                    ret = RHN_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error inflate");
                  ret = RHN_ERROR;
                }
              } while (res != Z_STREAM_END && ret == RHN_OK);
              inflateEnd(&infstream);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error inflateInit");
              ret = RHN_ERROR;
            }
          } else {
            if (r_jwe_set_payload(jwe, payload_enc, payload_enc_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error r_jwe_set_payload");
              ret = RHN_ERROR;
            }
          }
        } else if (res == GNUTLS_E_DECRYPTION_FAILED) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_decrypt_payload - decryption failed: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR_INVALID;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error gnutls_cipher_decrypt: '%s'", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        if (ret == RHN_OK) {
          if (cipher_cbc) {
            if (r_jwe_compute_hmac_tag(jwe, ciphertext, ciphertext_len, tag, &tag_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_payload - Error r_jwe_compute_hmac_tag");
              ret = RHN_ERROR;
            }
          } else {
            // This doesn't work at all according to the RFC example
            // https://tools.ietf.org/html/rfc7516#appendix-A.1
            // TODO: Fix AES GCM tag
            tag_len = gnutls_cipher_get_tag_size(r_jwe_get_alg_from_enc(jwe->enc));
            memset(tag, 0, tag_len);
            if ((res = gnutls_cipher_tag(handle, tag, tag_len))) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_decrypt_payload - Error gnutls_cipher_tag: '%s'", gnutls_strerror(res));
              ret = RHN_ERROR;
            }
          }
          if (ret == RHN_OK) {
            if ((tag_b64url = o_malloc(tag_len*2)) != NULL) {
              if (o_base64url_encode(tag, tag_len, tag_b64url, &tag_b64url_len)) {
                if (tag_b64url_len != o_strlen((const char *)jwe->auth_tag_b64url) || 0 != memcmp(tag_b64url, jwe->auth_tag_b64url, tag_b64url_len)) {
                  y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwe_decrypt_payload - Invalid tag");
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

int r_jwe_encrypt_key(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags) {
  int ret, res;
  jwk_t * jwk = NULL;
  gnutls_datum_t plainkey, cypherkey = {NULL, 0};
  gnutls_pubkey_t g_pub = NULL;
  unsigned int bits = 0;
  unsigned char * cypherkey_b64 = NULL, * key = NULL;
  size_t cypherkey_b64_len = 0, key_len = 0;
  jwa_alg alg;
  
  if (jwe != NULL) {
    if (jwk_pubkey != NULL) {
      jwk = r_jwk_copy(jwk_pubkey);
      if (jwe->alg == R_JWA_ALG_UNKNOWN && (alg = str_to_jwa_alg(r_jwk_get_property_str(jwk, "alg"))) != R_JWA_ALG_NONE) {
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
      switch (jwe->alg) {
        case R_JWA_ALG_RSA1_5:
          if (jwk != NULL && (g_pub = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
            res = r_jwk_key_type(jwk, &bits, x5u_flags);
            if (res & (R_KEY_TYPE_RSA|R_KEY_TYPE_PUBLIC) && bits >= 2048) {
              plainkey.data = jwe->key;
              plainkey.size = jwe->key_len;
              if (!(res = gnutls_pubkey_encrypt_data(g_pub, 0, &plainkey, &cypherkey))) {
                if ((cypherkey_b64 = o_malloc(cypherkey.size*2)) != NULL) {
                  if (o_base64url_encode(cypherkey.data, cypherkey.size, cypherkey_b64, &cypherkey_b64_len)) {
                    o_free(jwe->encrypted_key_b64url);
                    jwe->encrypted_key_b64url = (unsigned char *)o_strndup((const char *)cypherkey_b64, cypherkey_b64_len);
                    ret = RHN_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error o_base64url_encode cypherkey_b64");
                    ret = RHN_ERROR_MEMORY;
                  }
                  o_free(cypherkey_b64);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error o_malloc cypherkey_b64");
                  ret = RHN_ERROR_MEMORY;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error gnutls_pubkey_encrypt_data: %s", gnutls_strerror(res));
                ret = RHN_ERROR;
              }
              gnutls_free(cypherkey.data);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - invalid key type");
              ret = RHN_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Unable to export public key");
            ret = RHN_ERROR_PARAM;
          }
          break;
        case R_JWA_ALG_DIR:
          o_free(jwe->encrypted_key_b64url);
          jwe->encrypted_key_b64url = (unsigned char *)o_strdup("");
          o_free(jwe->encrypted_key_b64url);
          jwe->encrypted_key_b64url = NULL;
          if (jwk != NULL) {
            if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == r_jwe_get_key_size(jwe->enc)) {
              key_len = bits;
              if ((key = o_malloc(key_len+4)) != NULL) {
                if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) == RHN_OK) {
                  ret = r_jwe_set_cypher_key(jwe, key, key_len);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error r_jwk_export_to_symmetric_key");
                  ret = RHN_ERROR_MEMORY;
                }
                o_free(key);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error allocating resoures for key");
                ret = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error invalid key type");
              ret = RHN_ERROR_PARAM;
            }
          } else if (jwe->key != NULL && jwe->key_len > 0) {
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Error no key available for alg 'dir'");
            ret = RHN_ERROR_PARAM;
          }
          break;
        default:
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - Unsupported alg");
          ret = RHN_ERROR_PARAM;
          break;
      }
      gnutls_pubkey_deinit(g_pub);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_encrypt_key - invalid input parameters");
    ret = RHN_ERROR_PARAM;
  }
  
  r_jwk_free(jwk);
  return ret;
}

int r_jwe_decrypt_key(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags) {
  int ret, res;
  jwk_t * jwk = NULL;
  gnutls_datum_t plainkey = {NULL, 0}, cypherkey;
  gnutls_privkey_t g_priv = NULL;
  unsigned int bits = 0;
  unsigned char * cypherkey_dec = NULL, * key = NULL;
  size_t cypherkey_dec_len = 0, key_len = 0;
  
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
  
  if (jwe != NULL && jwe->alg != R_JWA_ALG_UNKNOWN && jwe->alg != R_JWA_ALG_NONE) {
      switch (jwe->alg) {
        case R_JWA_ALG_RSA1_5:
          if (jwk != NULL && o_strlen((const char *)jwe->encrypted_key_b64url) && (g_priv = r_jwk_export_to_gnutls_privkey(jwk, x5u_flags)) != NULL) {
            res = r_jwk_key_type(jwk, &bits, x5u_flags);
            if (res & (R_KEY_TYPE_RSA|R_KEY_TYPE_PRIVATE) && bits >= 2048) {
              if ((cypherkey_dec = o_malloc(o_strlen((const char *)jwe->encrypted_key_b64url))) != NULL) {
                memset(cypherkey_dec, 0, o_strlen((const char *)jwe->encrypted_key_b64url));
                if (o_base64url_decode(jwe->encrypted_key_b64url, o_strlen((const char *)jwe->encrypted_key_b64url), cypherkey_dec, &cypherkey_dec_len)) {
                  cypherkey.size = cypherkey_dec_len;
                  cypherkey.data = cypherkey_dec;
                  if (!(res = gnutls_privkey_decrypt_data(g_priv, 0, &cypherkey, &plainkey))) {
                    o_free(jwe->key);
                    jwe->key = NULL;
                    if (r_jwe_set_cypher_key(jwe, plainkey.data, plainkey.size) == RHN_OK) {
                      ret = RHN_OK;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error r_jwe_set_cypher_key (RSA1_5)");
                      ret = RHN_ERROR;
                    }
                  } else if (res == GNUTLS_E_DECRYPTION_FAILED) {
                    ret = RHN_ERROR_INVALID;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error gnutls_privkey_decrypt_data: %s", gnutls_strerror(res));
                    ret = RHN_ERROR;
                  }
                  gnutls_free(plainkey.data);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error o_base64url_decode cypherkey_dec");
                  ret = RHN_ERROR_PARAM;
                }
                o_free(cypherkey_dec);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error o_malloc cypherkey_dec");
                ret = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error invalid key size");
              ret = RHN_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error invalid RSA1_5 input parameters");
            ret = RHN_ERROR_PARAM;
          }
          break;
        case R_JWA_ALG_DIR:
          o_free(jwe->encrypted_key_b64url);
          jwe->encrypted_key_b64url = NULL;
          if (jwk != NULL) {
            if (r_jwk_key_type(jwk, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == r_jwe_get_key_size(jwe->enc)) {
              key_len = (size_t)bits;
              if ((key = o_malloc(key_len+4)) != NULL) {
                if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) == RHN_OK) {
                  ret = r_jwe_set_cypher_key(jwe, key, key_len);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error r_jwk_export_to_symmetric_key");
                  ret = RHN_ERROR_MEMORY;
                }
                o_free(key);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error allocating resoures for key");
                ret = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error invalid key type");
              ret = RHN_ERROR_PARAM;
            }
          } else if (jwe->key != NULL && jwe->key_len > 0) {
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error no key available for alg 'dir'");
            ret = RHN_ERROR_PARAM;
          }
          break;
        default:
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt_key - Error unsupported algorithm");
          ret = RHN_ERROR_PARAM;
          break;
      }
      gnutls_privkey_deinit(g_priv);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  
  r_jwk_free(jwk);
  return ret;
}

int r_jwe_parse(jwe_t * jwe, const char * jwe_str, int x5u_flags) {
  int ret;
  char ** str_array = NULL;
  char * str_header = NULL;
  unsigned char * iv = NULL;
  size_t header_len = 0, iv_len = 0, cypher_len = 0, tag_len = 0;
  json_t * j_header = NULL;
  
  if (jwe != NULL && o_strlen(jwe_str)) {
    if (split_string(jwe_str, ".", &str_array) == 5) {
      // Check if all elements 0, 2 and 3 are base64url encoded
      if (o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), NULL, &header_len) && 
          o_base64url_decode((unsigned char *)str_array[2], o_strlen(str_array[2]), NULL, &iv_len) &&
          o_base64url_decode((unsigned char *)str_array[3], o_strlen(str_array[3]), NULL, &cypher_len) &&
          o_base64url_decode((unsigned char *)str_array[4], o_strlen(str_array[4]), NULL, &tag_len)) {
        ret = RHN_OK;
        do {
          // Decode header
          if ((str_header = o_malloc(header_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error allocating resources for str_header");
            ret = RHN_ERROR_MEMORY;
            break;
          }
          
          if (!o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), (unsigned char *)str_header, &header_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error o_base64url_decode str_header");
            ret = RHN_ERROR_PARAM;
            break;
          }
          str_header[header_len] = '\0';
          
          if ((j_header = json_loads(str_header, JSON_DECODE_ANY, NULL)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error json_loads str_header");
            ret = RHN_ERROR_PARAM;
            break;
          }
          
          if (r_jwe_extract_header(jwe, j_header, x5u_flags) != RHN_OK) {
            ret = RHN_ERROR_PARAM;
            break;
          }
          json_decref(jwe->j_header);
          
          jwe->j_header = json_incref(j_header);
          
          // Decode iv
          if ((iv = o_malloc(iv_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error allocating resources for iv");
            ret = RHN_ERROR_MEMORY;
            break;
          }
          
          if (!o_base64url_decode((unsigned char *)str_array[2], o_strlen(str_array[2]), iv, &iv_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error o_base64url_decode iv");
            ret = RHN_ERROR_PARAM;
            break;
          }
          
          if (r_jwe_set_iv(jwe, iv, iv_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_parse - Error r_jwe_set_iv");
            ret = RHN_ERROR;
            break;
          }
          
          o_free(jwe->header_b64url);
          jwe->header_b64url = (unsigned char *)o_strdup(str_array[0]);
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
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwe_decrypt(jwe_t * jwe, jwk_t * jwk_privkey, int x5u_flags) {
  int ret, res;
  
  if ((res = r_jwe_decrypt_key(jwe, jwk_privkey, x5u_flags)) == RHN_OK && (res = r_jwe_decrypt_payload(jwe)) == RHN_OK) {
    ret = RHN_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_decrypt - Error decrypting data");
    ret = res;
  }
  return ret;
}

char * r_jwe_serialize(jwe_t * jwe, jwk_t * jwk_pubkey, int x5u_flags) {
  char * jwe_str = NULL;
  int res = RHN_OK;
  unsigned int bits = 0;
  unsigned char * key = NULL;
  size_t key_len = 0;
  
  if (jwk_pubkey != NULL && jwe != NULL && jwe->alg == R_JWA_ALG_DIR) {
    if (r_jwk_key_type(jwk_pubkey, &bits, x5u_flags) & R_KEY_TYPE_SYMMETRIC && bits == r_jwe_get_key_size(jwe->enc)) {
      key_len = (size_t)bits;
      if ((key = o_malloc(key_len+4)) != NULL) {
        if (r_jwk_export_to_symmetric_key(jwk_pubkey, key, &key_len) == RHN_OK) {
          res = r_jwe_set_cypher_key(jwe, key, key_len);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error r_jwk_export_to_symmetric_key");
          res = RHN_ERROR_MEMORY;
        }
        o_free(key);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error allocating resoures for key");
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
  if (res == RHN_OK && r_jwe_encrypt_payload(jwe) == RHN_OK && r_jwe_encrypt_key(jwe, jwk_pubkey, x5u_flags) == RHN_OK) {
    jwe_str = msprintf("%s.%s.%s.%s.%s", 
                      jwe->header_b64url, 
                      jwe->encrypted_key_b64url!=NULL?(const char *)jwe->encrypted_key_b64url:"",
                      jwe->iv_b64url,
                      jwe->ciphertext_b64url,
                      jwe->auth_tag_b64url);
          
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwe_serialize - Error encrypting data");
  }
  return jwe_str;
}
