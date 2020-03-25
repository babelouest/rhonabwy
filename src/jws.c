/**
 * 
 * Rhonabwy JSON Web Key (JWK) library
 * 
 * jws.c: functions definitions
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

/* Workaround to use GnuTLS 3.5 EC signature encode/decode functions that
 * are not public. */
#if GNUTLS_VERSION_MAJOR == 3 && GNUTLS_VERSION_MINOR == 5
extern int _gnutls_encode_ber_rs_raw(gnutls_datum_t *sig_value, const gnutls_datum_t *r, const gnutls_datum_t *s);
extern int _gnutls_decode_ber_rs_raw(const gnutls_datum_t *sig_value, gnutls_datum_t *r, gnutls_datum_t *s);

static int gnutls_encode_rs_value(gnutls_datum_t *sig_value, const gnutls_datum_t *r, const gnutls_datum_t * s) {
	return _gnutls_encode_ber_rs_raw(sig_value, r, s);
}

static int gnutls_decode_rs_value(const gnutls_datum_t *sig_value, gnutls_datum_t *r, gnutls_datum_t *s) {
	return _gnutls_decode_ber_rs_raw(sig_value, r, s);
}
#endif /* End of pre-3.6 work-arounds. */

static int r_jws_extract_header(jws_t * jws, json_t * j_header, int x5u_flags) {
  int ret;
  jwk_t * jwk;
  
  if (json_is_object(j_header)) {
    ret = RHN_OK;
    
    if (0 != o_strcmp("HS256", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("HS384", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("HS512", json_string_value(json_object_get(j_header, "alg"))) &&
    0 != o_strcmp("RS256", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("RS384", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("RS512", json_string_value(json_object_get(j_header, "alg"))) &&
    0 != o_strcmp("PS256", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("PS384", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("PS512", json_string_value(json_object_get(j_header, "alg"))) &&
    0 != o_strcmp("ES256", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("ES384", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("ES512", json_string_value(json_object_get(j_header, "alg"))) && 0 != o_strcmp("none", json_string_value(json_object_get(j_header, "alg")))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_extract_header - Invalid alg");
      ret = RHN_ERROR_PARAM;
    } else {
      jws->alg = str_to_js_alg(json_string_value(json_object_get(j_header, "alg")));
    }
    
    if (json_string_length(json_object_get(j_header, "jku"))) {
      if (r_jwks_import_from_uri(jws->jwks_pubkey, json_string_value(json_object_get(j_header, "jku")), x5u_flags) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_extract_header - Error loading jwks from uri %s", json_string_value(json_object_get(j_header, "jku")));
      }
    }
    
    if (json_object_get(j_header, "jwk") != NULL) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_json_t(jwk, json_object_get(j_header, "jwk")) != RHN_OK) {
        if (r_jwks_append_jwk(jws->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_HMAC) {
          if (r_jwks_append_jwk(jws->jwks_privkey, jwk) != RHN_OK) {
            ret = RHN_ERROR;
          }
        }
      } else {
        ret = RHN_ERROR_PARAM;
      }
      r_jwk_free(jwk);
    }
    
    if (json_object_get(j_header, "x5u") != NULL || json_object_get(j_header, "x5c") != NULL) {
      r_jwk_init(&jwk);
      if (r_jwk_import_from_json_t(jwk, j_header) == RHN_OK) {
        if (r_jwks_append_jwk(jws->jwks_pubkey, jwk) != RHN_OK) {
          ret = RHN_ERROR;
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_HMAC) {
          if (r_jwks_append_jwk(jws->jwks_privkey, jwk) != RHN_OK) {
            ret = RHN_ERROR;
          }
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

static int r_jws_set_token_values(jws_t * jws, int force) {
  int ret = RHN_OK;
  char * header_str = NULL;
  unsigned char * token_b64 = NULL;
  size_t token_b64_len = 0;
  
  if (jws != NULL) {
    if (jws->header_b64url == NULL || force) {
      if ((header_str = json_dumps(jws->j_header, JSON_COMPACT)) != NULL) {
        if ((token_b64 = o_malloc((2*o_strlen(header_str))+4)) != NULL) {
          if (o_base64url_encode((const unsigned char *)header_str, o_strlen(header_str), token_b64, &token_b64_len)) {
            o_free(jws->header_b64url);
            jws->header_b64url = (unsigned char *)o_strndup((const char *)token_b64, token_b64_len);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_token_values - Error o_base64url_encode header_str");
            ret = RHN_ERROR;
          }
          o_free(token_b64);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_token_values - Error allocating resources for token_b64 (1)");
          ret = RHN_ERROR_MEMORY;
        }
        o_free(header_str);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_token_values - Error json_dumps header_str");
        ret = RHN_ERROR;
      }
    }
    if (jws->payload_b64url == NULL || force) {
      if (jws->payload_len) {
        if ((token_b64 = o_malloc((2*jws->payload_len)+4)) != NULL) {
          if (o_base64url_encode(jws->payload, jws->payload_len, token_b64, &token_b64_len)) {
            o_free(jws->payload_b64url);
            jws->payload_b64url = (unsigned char *)o_strndup((const char *)token_b64, token_b64_len);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_token_values - Error o_base64url_encode payload");
            ret = RHN_ERROR;
          }
          o_free(token_b64);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_token_values - Error allocating resources for token_b64 (2)");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_set_token_values - Error empty payload");
        ret = RHN_ERROR_PARAM;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

static unsigned char * r_jws_sign_hmac(jws_t * jws, jwk_t * jwk) {
  int alg;
  unsigned char * data = NULL, * key = NULL, * sig = NULL, * sig_b64 = NULL, * to_return = NULL;
  size_t data_len = 0, key_len = 0, sig_len = 0, sig_b64_len = 0;
  
  if (jws->alg == R_JWS_ALG_HS256) {
    alg = GNUTLS_DIG_SHA256;
  } else if (jws->alg == R_JWS_ALG_HS384) {
    alg = GNUTLS_DIG_SHA384;
  } else if (jws->alg == R_JWS_ALG_HS512) {
    alg = GNUTLS_DIG_SHA512;
  }
  
  sig_len = gnutls_hmac_get_len(alg);
  sig = o_malloc(sig_len);
  sig_b64 = o_malloc(sig_len*2);
  
  key_len = o_strlen(r_jwk_get_property_str(jwk, "k"));
  key = o_malloc(key_len);
  
  if (key != NULL) {
    if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) != RHN_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_hmac - Error r_jwk_export_to_symmetric_key");
      o_free(key);
      key = NULL;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_hmac - Error allocating resources for key");
  }
  
  if (key != NULL && sig != NULL && sig_b64 != NULL) {
    data = (unsigned char *)msprintf("%s.%s", jws->header_b64url, jws->payload_b64url);
    if (!gnutls_hmac_fast(alg, key, key_len, data, data_len, sig)) {
      if (o_base64url_encode(sig, sig_len, sig_b64, &sig_b64_len)) {
        to_return = (unsigned char *)o_strndup((const char *)sig_b64, sig_b64_len);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_hmac - Error o_base64url_encode sig_b64");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_hmac - Error gnutls_hmac_fast");
    }
  }
  
  o_free(data);
  o_free(sig);
  o_free(sig_b64);
  o_free(key);
  
  return to_return;
}

static unsigned char * r_jws_sign_rsa(jws_t * jws, jwk_t * jwk, int x5u_flags) {
  gnutls_privkey_t privkey = r_jwk_export_to_gnutls_privkey(jwk, x5u_flags);
  gnutls_datum_t body_dat, sig_dat;
  unsigned char * to_return = NULL;
  int alg = GNUTLS_DIG_NULL, res, flag = 0;
  size_t ret_size = 0;
  
  switch (jws->alg) {
    case R_JWS_ALG_RS256:
      alg = GNUTLS_DIG_SHA256;
      break;
    case R_JWS_ALG_RS384:
      alg = GNUTLS_DIG_SHA384;
      break;
    case R_JWS_ALG_RS512:
      alg = GNUTLS_DIG_SHA512;
      break;
/* RSA-PSS signature is available with GnuTLS >= 3.6 */
#if GNUTLS_VERSION_NUMBER >= 0x030600
    case R_JWS_ALG_PS256:
      alg = GNUTLS_SIGN_RSA_PSS_SHA256;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
    case R_JWS_ALG_PS384:
      alg = GNUTLS_SIGN_RSA_PSS_SHA384;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
    case R_JWS_ALG_PS512:
      alg = GNUTLS_SIGN_RSA_PSS_SHA512;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
#endif
    default:
      break;
  }
  
  if (privkey != NULL && GNUTLS_PK_RSA == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
    body_dat.data = (unsigned char *)msprintf("%s.%s", jws->header_b64url, jws->payload_b64url);
    body_dat.size = o_strlen((const char *)body_dat.data);
    
    if (!(res = 
#if GNUTLS_VERSION_NUMBER >= 0x030600
                 gnutls_privkey_sign_data2
#else
                 gnutls_privkey_sign_data
#endif
                                           (privkey, alg, flag, &body_dat, &sig_dat))) {
      if ((to_return = o_malloc(sig_dat.size*2)) != NULL) {
        if (o_base64url_encode(sig_dat.data, sig_dat.size, to_return, &ret_size)) {
          to_return[ret_size] = '\0';
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_rsa - Error o_base64url_encode for to_return");
          o_free(to_return);
          to_return = NULL;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_rsa - Error allocating resoures for to_return");
      }
      gnutls_free(sig_dat.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_rsa - Error gnutls_privkey_sign_data2, res %d", res);
    }
    o_free(body_dat.data);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_rsa - Error extracting privkey");
  }
  gnutls_privkey_deinit(privkey);
  return to_return;
}

static unsigned char * r_jws_sign_ecdsa(jws_t * jws, jwk_t * jwk, int x5u_flags) {
#if GNUTLS_VERSION_NUMBER >= 0x030500
  gnutls_privkey_t privkey = r_jwk_export_to_gnutls_privkey(jwk, x5u_flags);
  gnutls_datum_t body_dat, sig_dat, r, s;
  unsigned char * binary_sig = NULL, * to_return = NULL;
  int alg = GNUTLS_DIG_NULL;
  unsigned int adj;
  int r_padding = 0, s_padding = 0, r_out_padding = 0, s_out_padding = 0;
  size_t sig_size, ret_size = 0;
    
  if (jws->alg == R_JWS_ALG_ES256) {
    alg = GNUTLS_DIG_SHA256;
    adj = 32;
  } else if (jws->alg == R_JWS_ALG_ES384) {
    alg = GNUTLS_DIG_SHA384;
    adj = 48;
  } else if (jws->alg == R_JWS_ALG_ES512) {
    alg = GNUTLS_DIG_SHA512;
    adj = 66;
  }
  
  if (privkey != NULL && GNUTLS_PK_EC == gnutls_privkey_get_pk_algorithm(privkey, NULL)) {
    body_dat.data = (unsigned char *)msprintf("%s.%s", jws->header_b64url, jws->payload_b64url);
    body_dat.size = o_strlen((const char *)body_dat.data);
    
    if (!gnutls_privkey_sign_data(privkey, alg, 0, &body_dat, &sig_dat)) {
      if (!gnutls_decode_rs_value(&sig_dat, &r, &s)) {
        if (r.size > adj) {
          r_padding = r.size - adj;
        } else if (r.size < adj) {
          r_out_padding = adj - r.size;
        }

        if (s.size > adj) {
          s_padding = s.size - adj;
        } else if (s.size < adj) {
          s_out_padding = adj - s.size;
        }
        
        sig_size = adj << 1;
        
        if ((binary_sig = o_malloc(sig_size)) != NULL) {
          memset(binary_sig, 0, sig_size);
          memcpy(binary_sig + r_out_padding, r.data + r_padding, r.size - r_padding);
          memcpy(binary_sig + (r.size - r_padding + r_out_padding) + s_out_padding, s.data + s_padding, (s.size - s_padding));
          if ((to_return = o_malloc(sig_size*2)) != NULL) {
            if (o_base64url_encode(binary_sig, sig_size, to_return, &ret_size)) {
              to_return[ret_size] = '\0';
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error o_base64url_encode for to_return");
              o_free(to_return);
              to_return = NULL;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error allocating resoures for to_return");
          }
          o_free(binary_sig);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error allocating resoures for binary_sig");
        }
        gnutls_free(r.data);
        gnutls_free(s.data);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error gnutls_decode_rs_value");
      }
      gnutls_free(sig_dat.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error gnutls_privkey_sign_data");
    }
    o_free(body_dat.data);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_sign_ecdsa - Error extracting privkey");
  }
  gnutls_privkey_deinit(privkey);
  return to_return;
#else
  (void)(jws);
  (void)(jwk);
  (void)(x5u_flags);
  return NULL;
#endif
}

static int r_jws_verify_sig_hmac(jws_t * jws, jwk_t * jwk) {
  unsigned char * sig = r_jws_sign_hmac(jws, jwk);
  int ret;
  
  if (sig != NULL && 0 == o_strcmp((const char *)jws->signature_b64url, (const char *)sig)) {
    ret = RHN_OK;
  } else {
    ret = RHN_ERROR_INVALID;
  }
  o_free(sig);
  return ret;
}

static int r_jws_verify_sig_rsa(jws_t * jws, jwk_t * jwk, int x5u_flags) {
  int alg = GNUTLS_DIG_NULL, ret = RHN_OK, flag = 0;
  gnutls_datum_t sig_dat = {NULL, 0}, data;
  gnutls_pubkey_t pubkey = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags);
  unsigned char * sig = NULL;
  size_t sig_len = 0;
  
  data.data = (unsigned char *)msprintf("%s.%s", jws->header_b64url, jws->payload_b64url);
  data.size = o_strlen((const char *)data.data);
  
  switch (jws->alg) {
    case R_JWS_ALG_RS256:
      alg = GNUTLS_DIG_SHA256;
      break;
    case R_JWS_ALG_RS384:
      alg = GNUTLS_DIG_SHA384;
      break;
    case R_JWS_ALG_RS512:
      alg = GNUTLS_DIG_SHA512;
      break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
    case R_JWS_ALG_PS256:
      alg = GNUTLS_SIGN_RSA_PSS_SHA256;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
    case R_JWS_ALG_PS384:
      alg = GNUTLS_SIGN_RSA_PSS_SHA384;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
    case R_JWS_ALG_PS512:
      alg = GNUTLS_SIGN_RSA_PSS_SHA512;
      flag = GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS;
      break;
#endif
    default:
      break;
  }
  
  if (pubkey != NULL && GNUTLS_PK_RSA == gnutls_pubkey_get_pk_algorithm(pubkey, NULL)) {
    sig = o_malloc(o_strlen((const char *)jws->signature_b64url));
    if (sig != NULL) {
      if (o_base64url_decode(jws->signature_b64url, o_strlen((const char *)jws->signature_b64url), sig, &sig_len)) {
        sig_dat.data = sig;
        sig_dat.size = sig_len;
        if (gnutls_pubkey_verify_data2(pubkey, alg, flag, &data, &sig_dat)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_verify_sig_rsa - Error invalid signature");
          ret = RHN_ERROR_INVALID;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_verify_sig_rsa - Error o_base64url_decode for sig");
        ret = RHN_ERROR;
      }
      o_free(sig);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_verify_sig_rsa - Error allocating resources for sig");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_verify_sig_rsa - Invalid public key");
    ret = RHN_ERROR_PARAM;
  }
  o_free(data.data);
  gnutls_pubkey_deinit(pubkey);
  return ret;
}

static int r_jws_verify_sig_ecdsa(jws_t * jws, jwk_t * jwk, int x5u_flags) {
#if GNUTLS_VERSION_NUMBER >= 0x030500
  int alg = 0, ret = RHN_OK;
  gnutls_datum_t sig_dat = {NULL, 0}, r, s, data;
  gnutls_pubkey_t pubkey = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags);
  unsigned char * sig = NULL;
  size_t sig_len = 0;
  
  data.data = (unsigned char *)msprintf("%s.%s", jws->header_b64url, jws->payload_b64url);
  data.size = o_strlen((const char *)data.data);
  
  switch (jws->alg) {
    case R_JWS_ALG_ES256:
      alg = GNUTLS_SIGN_ECDSA_SHA256;
      break;
    case R_JWS_ALG_ES384:
      alg = GNUTLS_SIGN_ECDSA_SHA384;
      break;
    case R_JWS_ALG_ES512:
      alg = GNUTLS_SIGN_ECDSA_SHA512;
      break;
    default:
      break;
  }
  
  if (pubkey != NULL && GNUTLS_PK_EC == gnutls_pubkey_get_pk_algorithm(pubkey, NULL)) {
    sig = o_malloc(o_strlen((const char *)jws->signature_b64url));
    if (sig != NULL) {
      if (o_base64url_decode(jws->signature_b64url, o_strlen((const char *)jws->signature_b64url), sig, &sig_len)) {
        if (sig_len == 64) {
          r.size = 32;
          r.data = sig;
          s.size = 32;
          s.data = sig + 32;
        } else if (sig_len == 96) {
          r.size = 48;
          r.data = sig;
          s.size = 48;
          s.data = sig + 48;
        } else if (sig_len == 132) {
          r.size = 66;
          r.data = sig;
          s.size = 66;
          s.data = sig + 66;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_verify_sig_ecdsa - Error invalid signature length");
          ret = RHN_ERROR_INVALID;
        }
        
        if (ret == RHN_OK) {
          if (!gnutls_encode_rs_value(&sig_dat, &r, &s)) {
            if (gnutls_pubkey_verify_data2(pubkey, alg, 0, &data, &sig_dat)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_verify_sig_ecdsa - Error invalid signature");
              ret = RHN_ERROR_INVALID;
            }
            if (sig_dat.data != NULL) {
              gnutls_free(sig_dat.data);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_verify_sig_ecdsa - Error gnutls_encode_rs_value");
            ret = RHN_ERROR;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_verify_sig_ecdsa - Error o_base64url_decode for sig");
        ret = RHN_ERROR;
      }
      o_free(sig);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_verify_sig_ecdsa - Error allocating resources for sig");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_verify_sig_ecdsa - Invalid public key");
    ret = RHN_ERROR_PARAM;
  }
  o_free(data.data);
  gnutls_pubkey_deinit(pubkey);
  return ret;
#else
  (void)(jws);
  (void)(jwk);
  (void)(x5u_flags);
  return RHN_ERROR_INVALID;
#endif
}

int r_jws_init(jws_t ** jws) {
  int ret;
  
  if (jws != NULL) {
    if ((*jws = o_malloc(sizeof(jws_t))) != NULL) {
      if (((*jws)->j_header = json_object()) != NULL) {
        if (r_jwks_init(&(*jws)->jwks_pubkey) == RHN_OK) {
          if (r_jwks_init(&(*jws)->jwks_privkey) == RHN_OK) {
            (*jws)->alg = R_JWS_ALG_NONE;
            (*jws)->header_b64url = NULL;
            (*jws)->payload_b64url = NULL;
            (*jws)->signature_b64url = NULL;
            (*jws)->payload = NULL;
            (*jws)->payload_len = 0;
            ret = RHN_OK;
          } else {
            o_free(*jws);
            r_jwks_free((*jws)->jwks_pubkey);
            json_decref((*jws)->j_header);
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_init - Error allocating resources for jwks_privkey");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          o_free(*jws);
          json_decref((*jws)->j_header);
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_init - Error allocating resources for jwks_pubkey");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        o_free(*jws);
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_init - Error allocating resources for j_header");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_init - Error allocating resources for jws");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

void r_jws_free(jws_t * jws) {
  if (jws != NULL) {
    r_jwks_free(jws->jwks_privkey);
    r_jwks_free(jws->jwks_pubkey);
    o_free(jws->header_b64url);
    o_free(jws->payload_b64url);
    o_free(jws->signature_b64url);
    json_decref(jws->j_header);
    o_free(jws->payload);
    o_free(jws);
  }
}

jws_alg str_to_js_alg(const char * alg) {
  if (0 == o_strcmp("HS256", alg)) {
    return R_JWS_ALG_HS256;
  } else if (0 == o_strcmp("HS384", alg)) {
    return R_JWS_ALG_HS384;
  } else if (0 == o_strcmp("HS512", alg)) {
    return R_JWS_ALG_HS512;
  } else if (0 == o_strcmp("RS256", alg)) {
    return R_JWS_ALG_RS256;
  } else if (0 == o_strcmp("RS384", alg)) {
    return R_JWS_ALG_RS384;
  } else if (0 == o_strcmp("RS512", alg)) {
    return R_JWS_ALG_RS512;
  } else if (0 == o_strcmp("ES256", alg)) {
    return R_JWS_ALG_ES256;
  } else if (0 == o_strcmp("ES384", alg)) {
    return R_JWS_ALG_ES384;
  } else if (0 == o_strcmp("ES512", alg)) {
    return R_JWS_ALG_ES512;
  } else if (0 == o_strcmp("PS256", alg)) {
    return R_JWS_ALG_PS256;
  } else if (0 == o_strcmp("PS384", alg)) {
    return R_JWS_ALG_PS384;
  } else if (0 == o_strcmp("PS512", alg)) {
    return R_JWS_ALG_PS512;
  } else {
    return R_JWS_ALG_NONE;
  }
}

int r_jws_set_payload(jws_t * jws, const unsigned char * payload, size_t payload_len) {
  int ret;
  
  if (jws != NULL) {
    o_free(jws->payload);
    if (payload != NULL && payload_len) {
      if ((jws->payload = o_malloc(payload_len)) != NULL) {
        memcpy(jws->payload, payload, payload_len);
        jws->payload_len = payload_len;
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_payload - Error allocating resources for payload");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      jws->payload = NULL;
      jws->payload_len = 0;
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const unsigned char * r_jws_get_payload(jws_t * jws, size_t * payload_len) {
  if (jws != NULL) {
    if (payload_len != NULL) {
      *payload_len = jws->payload_len;
    }
    return jws->payload;
  }
  return NULL;
}

int r_jws_set_alg(jws_t * jws, jws_alg alg) {
  if (jws != NULL) {
    jws->alg = alg;
    switch (alg) {
      case R_JWS_ALG_NONE:
        json_object_set_new(jws->j_header, "alg", json_string("none"));
        break;
      case R_JWS_ALG_HS256:
        json_object_set_new(jws->j_header, "alg", json_string("HS256"));
        break;
      case R_JWS_ALG_HS384:
        json_object_set_new(jws->j_header, "alg", json_string("HS384"));
        break;
      case R_JWS_ALG_HS512:
        json_object_set_new(jws->j_header, "alg", json_string("HS512"));
        break;
      case R_JWS_ALG_RS256:
        json_object_set_new(jws->j_header, "alg", json_string("RS256"));
        break;
      case R_JWS_ALG_RS384:
        json_object_set_new(jws->j_header, "alg", json_string("RS384"));
        break;
      case R_JWS_ALG_RS512:
        json_object_set_new(jws->j_header, "alg", json_string("RS512"));
        break;
      case R_JWS_ALG_ES256:
        json_object_set_new(jws->j_header, "alg", json_string("ES256"));
        break;
      case R_JWS_ALG_ES384:
        json_object_set_new(jws->j_header, "alg", json_string("ES384"));
        break;
      case R_JWS_ALG_ES512:
        json_object_set_new(jws->j_header, "alg", json_string("ES512"));
        break;
      case R_JWS_ALG_PS256:
        json_object_set_new(jws->j_header, "alg", json_string("PS256"));
        break;
      case R_JWS_ALG_PS384:
        json_object_set_new(jws->j_header, "alg", json_string("PS384"));
        break;
      case R_JWS_ALG_PS512:
        json_object_set_new(jws->j_header, "alg", json_string("PS512"));
        break;
      default:
        break;
    }
    return RHN_OK;
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jws_set_header_str_value(jws_t * jws, const char * key, const char * str_value) {
  int ret;
  
  if (jws != NULL && o_strlen(key)) {
    if (str_value != NULL) {
      if (!json_object_set_new(jws->j_header, key, json_string(str_value))) {
        o_free(jws->header_b64url);
        jws->header_b64url = NULL;
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_header_str_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(jws->j_header, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jws_set_header_int_value(jws_t * jws, const char * key, int i_value) {
  int ret;
  
  if (jws != NULL && o_strlen(key)) {
    if (!json_object_set_new(jws->j_header, key, json_integer(i_value))) {
      o_free(jws->header_b64url);
      jws->header_b64url = NULL;
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_header_int_value - Error json_object_set_new");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jws_set_header_json_t_value(jws_t * jws, const char * key, json_t * j_value) {
  int ret;
  
  if (jws != NULL && o_strlen(key)) {
    if (j_value != NULL) {
      if (!json_object_set_new(jws->j_header, key, json_deep_copy(j_value))) {
        o_free(jws->header_b64url);
        jws->header_b64url = NULL;
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_set_header_json_t_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(jws->j_header, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jws_alg r_jws_get_alg(jws_t * jws) {
  if (jws != NULL) {
    return jws->alg;
  } else {
    return R_JWS_ALG_NONE;
  }
}

const char * r_jws_get_header_str_value(jws_t * jws, const char * key) {
  if (jws != NULL && o_strlen(key)) {
    return json_string_value(json_object_get(jws->j_header, key));
  }
  return NULL;
}

int r_jws_get_header_int_value(jws_t * jws, const char * key) {
  if (jws != NULL && o_strlen(key)) {
    return json_integer_value(json_object_get(jws->j_header, key));
  }
  return 0;
}

json_t * r_jws_get_header_json_t_value(jws_t * jws, const char * key) {
  json_t * j_value;
  
  if (jws != NULL && o_strlen(key) && (j_value = json_object_get(jws->j_header, key)) != NULL) {
    return json_deep_copy(j_value);
  }
  return NULL;
}

json_t * r_jws_get_full_header_json_t(jws_t * jws) {
  if (jws != NULL) {
    return json_deep_copy(jws->j_header);
  }
  return NULL;
}

int r_jws_add_keys(jws_t * jws, jwk_t * jwk_privkey, jwk_t * jwk_pubkey) {
  int ret = RHN_OK;
  jws_alg alg;
  
  if (jws != NULL && (jwk_privkey != NULL || jwk_pubkey != NULL)) {
    if (jwk_privkey != NULL) {
      if (r_jwks_empty(jws->jwks_privkey) != RHN_OK || r_jwks_append_jwk(jws->jwks_privkey, jwk_privkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_add_keys - Error setting jwk_privkey");
        ret = RHN_ERROR;
      }
      if (jws->alg == R_JWS_ALG_NONE && (alg = str_to_js_alg(r_jwk_get_property_str(jwk_privkey, "alg"))) != R_JWS_ALG_NONE) {
        r_jws_set_alg(jws, alg);
      }
    }
    if (jwk_pubkey != NULL) {
      if (r_jwks_empty(jws->jwks_pubkey) != RHN_OK || r_jwks_append_jwk(jws->jwks_pubkey, jwk_pubkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_add_keys - Error setting jwk_pubkey");
        ret = RHN_ERROR;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jws_parse(jws_t * jws, const char * jws_str, int x5u_flags) {
  int ret;
  char ** str_array = NULL;
  char * str_header = NULL;
  size_t header_len = 0, payload_len = 0;
  json_t * j_header = NULL;
  
  
  if (jws != NULL && o_strlen(jws_str)) {
    if (split_string(jws_str, ".", &str_array) == 3) {
      // Check if all 3 elements are base64url
      if (o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), NULL, &header_len) && o_base64url_decode((unsigned char *)str_array[1], o_strlen(str_array[1]), NULL, &payload_len)) {
        ret = RHN_OK;
        do {
          // Decode header
          if ((str_header = o_malloc(header_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - error allocating resources for str_header");
            ret = RHN_ERROR_MEMORY;
            break;
          }
          
          if (!o_base64url_decode((unsigned char *)str_array[0], o_strlen(str_array[0]), (unsigned char *)str_header, &header_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - error decoding str_header");
            ret = RHN_ERROR_PARAM;
            break;
          }
          str_header[header_len] = '\0';
          
          j_header = json_loads(str_header, JSON_DECODE_ANY, NULL);
          if (r_jws_extract_header(jws, j_header, x5u_flags) != RHN_OK) {
            ret = RHN_ERROR_PARAM;
            break;
          }
          json_decref(jws->j_header);
          
          jws->j_header = json_incref(j_header);
          
          // Decode payload
          o_free(jws->payload);
          if ((jws->payload = o_malloc(payload_len+4)) == NULL) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - error allocating resources for payload");
            ret = RHN_ERROR_MEMORY;
            break;
          }
          
          if (!o_base64url_decode((unsigned char *)str_array[1], o_strlen(str_array[1]), jws->payload, &jws->payload_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - error decoding jws->payload");
            ret = RHN_ERROR_PARAM;
            break;
          }
          
          o_free(jws->header_b64url);
          jws->header_b64url = (unsigned char *)o_strdup(str_array[0]);
          
          o_free(jws->signature_b64url);
          jws->signature_b64url = NULL;
          if (str_array[2] != NULL) {
            jws->signature_b64url = (unsigned char *)o_strdup(str_array[2]);
          }
        } while (0);
        json_decref(j_header);
        o_free(str_header);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - error decoding jws from base64url format");
        ret = RHN_ERROR_PARAM;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "r_jws_parse - jws_str invalid format");
      ret = RHN_ERROR_PARAM;
    }
    free_string_array(str_array);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jws_verify_signature(jws_t * jws, jwk_t * jwk_pubkey, int x5u_flags) {
  int ret;
  jwk_t * jwk = NULL;
  
  if (jwk_pubkey != NULL) {
    jwk = r_jwk_copy(jwk_pubkey);
  } else {
    if (r_jws_get_header_str_value(jws, "kid") != NULL) {
      jwk = r_jwks_get_by_kid(jws->jwks_pubkey, r_jws_get_header_str_value(jws, "kid"));
    } else if (r_jwks_size(jws->jwks_pubkey) == 1) {
      jwk = r_jwks_get_at(jws->jwks_pubkey, 0);
    }
  }
  
  if (r_jws_set_token_values(jws, 0) == RHN_OK && jws->signature_b64url != NULL && jws->alg != R_JWS_ALG_NONE) {
    if (jwk != NULL) {
      switch (jws->alg) {
        case R_JWS_ALG_HS256:
        case R_JWS_ALG_HS384:
        case R_JWS_ALG_HS512:
          if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_HMAC) {
            ret = r_jws_verify_sig_hmac(jws, jwk);
          } else {
            ret = RHN_ERROR_INVALID;
          }
          break;
        case R_JWS_ALG_RS256:
        case R_JWS_ALG_RS384:
        case R_JWS_ALG_RS512:
        case R_JWS_ALG_PS256:
        case R_JWS_ALG_PS384:
        case R_JWS_ALG_PS512:
          if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_RSA) {
            ret = r_jws_verify_sig_rsa(jws, jwk, x5u_flags);
          } else {
            ret = RHN_ERROR_INVALID;
          }
          break;
        case R_JWS_ALG_ES256:
        case R_JWS_ALG_ES384:
        case R_JWS_ALG_ES512:
          if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_ECDSA) {
            ret = r_jws_verify_sig_ecdsa(jws, jwk, x5u_flags);
          } else {
            ret = RHN_ERROR_INVALID;
          }
          break;
        default:
          ret = RHN_ERROR_INVALID;
          break;
      }
    } else {
      ret = RHN_ERROR_INVALID;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  r_jwk_free(jwk);
  return ret;
}

char * r_jws_serialize(jws_t * jws, jwk_t * jwk_privkey, int x5u_flags) {
  jwk_t * jwk = NULL;
  char * jws_str = NULL;
  
  if (jwk_privkey != NULL) {
    jwk = r_jwk_copy(jwk_privkey);
  } else {
    if (r_jws_get_header_str_value(jws, "kid") != NULL) {
      jwk = r_jwks_get_by_kid(jws->jwks_privkey, r_jws_get_header_str_value(jws, "kid"));
    } else if (jws != NULL && r_jwks_size(jws->jwks_privkey) == 1) {
      jwk = r_jwks_get_at(jws->jwks_privkey, 0);
    }
  }
  
  if (r_jwk_get_property_str(jwk, "kid") != NULL && r_jws_get_header_str_value(jws, "kid") == NULL) {
    r_jws_set_header_str_value(jws, "kid", r_jwk_get_property_str(jwk, "kid"));
  }
  
  if (jwk != NULL && r_jws_set_token_values(jws, 1) == RHN_OK && jws->alg != R_JWS_ALG_NONE) {
    switch (jws->alg) {
      case R_JWS_ALG_HS256:
      case R_JWS_ALG_HS384:
      case R_JWS_ALG_HS512:
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_HMAC) {
          o_free(jws->signature_b64url);
          jws->signature_b64url = r_jws_sign_hmac(jws, jwk);
        }
        break;
      case R_JWS_ALG_RS256:
      case R_JWS_ALG_RS384:
      case R_JWS_ALG_RS512:
      case R_JWS_ALG_PS256:
      case R_JWS_ALG_PS384:
      case R_JWS_ALG_PS512:
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_RSA) {
          o_free(jws->signature_b64url);
          jws->signature_b64url = r_jws_sign_rsa(jws, jwk, x5u_flags);
        }
        break;
      case R_JWS_ALG_ES256:
      case R_JWS_ALG_ES384:
      case R_JWS_ALG_ES512:
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_ECDSA) {
          o_free(jws->signature_b64url);
          jws->signature_b64url = r_jws_sign_ecdsa(jws, jwk, x5u_flags);
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_serialize - Unsupported algorithm");
        break;
    }
    if (jws->signature_b64url != NULL) {
      jws_str = msprintf("%s.%s.%s", jws->header_b64url, jws->payload_b64url, jws->signature_b64url);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_serialize - No signature");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jws_serialize - Error input parameters");
  }
  r_jwk_free(jwk);
  return jws_str;
}
