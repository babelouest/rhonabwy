/**
 * 
 * Rhonabwy JSON Web Token (JWT) library
 * 
 * jwt.c: functions definitions
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

#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

int r_jwt_init(jwt_t ** jwt) {
  int ret;
  
  if (jwt != NULL) {
    if ((*jwt = o_malloc(sizeof(jwt_t))) != NULL) {
      if (((*jwt)->j_header = json_object()) != NULL) {
        if (((*jwt)->j_claims = json_object()) != NULL) {
          if (r_jwks_init(&(*jwt)->jwks_privkey_sign) == RHN_OK) {
            if (r_jwks_init(&(*jwt)->jwks_pubkey_sign) == RHN_OK) {
              if (r_jwks_init(&(*jwt)->jwks_privkey_enc) == RHN_OK) {
                if (r_jwks_init(&(*jwt)->jwks_pubkey_enc) == RHN_OK) {
                  (*jwt)->sign_alg = R_JWA_ALG_UNKNOWN;
                  (*jwt)->enc_alg = R_JWA_ALG_UNKNOWN;
                  (*jwt)->enc = R_JWA_ENC_UNKNOWN;
                  (*jwt)->jws = NULL;
                  (*jwt)->jwe = NULL;
                  ret = RHN_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for jwks_pubkey_enc");
                  ret = RHN_ERROR_MEMORY;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for jwks_privkey_enc");
                ret = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for jwks_pubkey_sign");
              ret = RHN_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for jwks_privkey_sign");
            ret = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for j_claims");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for j_header");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_init - Error allocating resources for jwt");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  if (ret != RHN_OK && jwt != NULL) {
    r_jwt_free(*jwt);
    jwt = NULL;
  }
  return ret;
}

void r_jwt_free(jwt_t * jwt) {
  if (jwt != NULL) {
    r_jwks_free(jwt->jwks_privkey_sign);
    r_jwks_free(jwt->jwks_pubkey_sign);
    r_jwks_free(jwt->jwks_privkey_enc);
    r_jwks_free(jwt->jwks_pubkey_enc);
    r_jwe_free(jwt->jwe);
    r_jws_free(jwt->jws);
    json_decref(jwt->j_header);
    json_decref(jwt->j_claims);
    o_free(jwt);
  }
}

jwt_t * r_jwt_copy(jwt_t * jwt) {
  jwt_t * jwt_copy = NULL;
  
  if (jwt != NULL) {
    if (r_jwt_init(&jwt_copy) == RHN_OK) {
      jwt_copy->sign_alg = jwt->sign_alg;
      jwt_copy->enc_alg = jwt->enc_alg;
      jwt_copy->enc = jwt->enc;
      if (r_jwt_set_full_claims_json_t(jwt_copy, jwt->j_claims)) {
        r_jwks_free(jwt_copy->jwks_privkey_sign);
        jwt_copy->jwks_privkey_sign = r_jwks_copy(jwt->jwks_privkey_sign);
        r_jwks_free(jwt_copy->jwks_pubkey_sign);
        jwt_copy->jwks_pubkey_sign = r_jwks_copy(jwt->jwks_pubkey_sign);
        r_jwks_free(jwt_copy->jwks_privkey_enc);
        jwt_copy->jwks_privkey_enc = r_jwks_copy(jwt->jwks_privkey_enc);
        r_jwks_free(jwt_copy->jwks_pubkey_enc);
        jwt_copy->jwks_pubkey_enc = r_jwks_copy(jwt->jwks_pubkey_enc);
        json_decref(jwt_copy->j_header);
        jwt_copy->j_header = json_deep_copy(jwt->j_header);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_copy - Error setting claims");
        r_jwt_free(jwt_copy);
        jwt_copy = NULL;
      }
    }
  }
  return jwt_copy;
}

int r_jwt_set_header_str_value(jwt_t * jwt, const char * key, const char * str_value) {
  if (jwt != NULL) {
    return _r_json_set_str_value(jwt->j_header, key, str_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_set_header_int_value(jwt_t * jwt, const char * key, int i_value) {
  if (jwt != NULL) {
    return _r_json_set_int_value(jwt->j_header, key, i_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_set_header_json_t_value(jwt_t * jwt, const char * key, json_t * j_value) {
  if (jwt != NULL) {
    return _r_json_set_json_t_value(jwt->j_header, key, j_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

const char * r_jwt_get_header_str_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_str_value(jwt->j_header, key);
  }
  return NULL;
}

int r_jwt_get_header_int_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_int_value(jwt->j_header, key);
  }
  return 0;
}

json_t * r_jwt_get_header_json_t_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_json_t_value(jwt->j_header, key);
  }
  return NULL;
}

json_t * r_jwt_get_full_header_json_t(jwt_t * jwt) {
  if (jwt != NULL) {
    return _r_json_get_full_json_t(jwt->j_header);
  }
  return NULL;
}

char * r_jwt_get_full_header_str(jwt_t * jwt) {
  char * to_return = NULL;
  if (jwt != NULL) {
    to_return = json_dumps(jwt->j_header, JSON_COMPACT);
  }
  return to_return;
}

int r_jwt_set_claim_str_value(jwt_t * jwt, const char * key, const char * str_value) {
  if (jwt != NULL) {
    return _r_json_set_str_value(jwt->j_claims, key, str_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_set_claim_int_value(jwt_t * jwt, const char * key, int i_value) {
  if (jwt != NULL) {
    return _r_json_set_int_value(jwt->j_claims, key, i_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_set_claim_json_t_value(jwt_t * jwt, const char * key, json_t * j_value) {
  if (jwt != NULL) {
    return _r_json_set_json_t_value(jwt->j_claims, key, j_value);
  } else {
    return RHN_ERROR_PARAM;
  }
}

const char * r_jwt_get_claim_str_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_str_value(jwt->j_claims, key);
  }
  return NULL;
}

int r_jwt_get_claim_int_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_int_value(jwt->j_claims, key);
  }
  return 0;
}

json_t * r_jwt_get_claim_json_t_value(jwt_t * jwt, const char * key) {
  if (jwt != NULL) {
    return _r_json_get_json_t_value(jwt->j_claims, key);
  }
  return NULL;
}

json_t * r_jwt_get_full_claims_json_t(jwt_t * jwt) {
  if (jwt != NULL) {
    return _r_json_get_full_json_t(jwt->j_claims);
  }
  return NULL;
}

char * r_jwt_get_full_claims_str(jwt_t * jwt) {
  char * to_return = NULL;
  if (jwt != NULL) {
    to_return = json_dumps(jwt->j_claims, JSON_COMPACT);
  }
  return to_return;
}

int r_jwt_set_full_claims_json_t(jwt_t * jwt, json_t * j_claim) {
  if (jwt != NULL && j_claim != NULL) {
    json_decref(jwt->j_claims);
    jwt->j_claims = json_deep_copy(j_claim);
    return RHN_OK;
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_append_claims_json_t(jwt_t * jwt, json_t * j_claim) {
  json_t * j_claim_copy = json_deep_copy(j_claim);
  int ret;
  
  if (jwt != NULL && j_claim_copy != NULL) {
    if (!json_object_update(jwt->j_claims, j_claim_copy)) {
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_append_claims_json_t - Error json_object_update");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  json_decref(j_claim_copy);
  return ret;
}

int r_jwt_add_sign_keys(jwt_t * jwt, jwk_t * privkey, jwk_t * pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  
  if (jwt != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwks_append_jwk(jwt->jwks_privkey_sign, privkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_add_sign_keys - Error setting privkey");
        ret = RHN_ERROR;
      }
      if (jwt->sign_alg == R_JWA_ALG_UNKNOWN && (alg = str_to_jwa_alg(r_jwk_get_property_str(privkey, "alg"))) != R_JWA_ALG_NONE) {
        r_jwt_set_sign_alg(jwt, alg);
      }
    }
    if (pubkey != NULL) {
      if (r_jwks_append_jwk(jwt->jwks_pubkey_sign, pubkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_add_sign_keys - Error setting pubkey");
        ret = RHN_ERROR;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwt_add_enc_keys(jwt_t * jwt, jwk_t * privkey, jwk_t * pubkey) {
  int ret = RHN_OK;
  jwa_alg alg;
  
  if (jwt != NULL && (privkey != NULL || pubkey != NULL)) {
    if (privkey != NULL) {
      if (r_jwks_append_jwk(jwt->jwks_privkey_enc, privkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_add_enc_keys - Error setting privkey");
        ret = RHN_ERROR;
      }
    }
    if (pubkey != NULL) {
      if (r_jwks_append_jwk(jwt->jwks_pubkey_enc, pubkey) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_add_enc_keys - Error setting pubkey");
        ret = RHN_ERROR;
      }
      if (jwt->sign_alg == R_JWA_ALG_UNKNOWN && (alg = str_to_jwa_alg(r_jwk_get_property_str(pubkey, "alg"))) != R_JWA_ALG_NONE) {
        r_jwt_set_enc_alg(jwt, alg);
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwt_set_sign_alg(jwt_t * jwt, jwa_alg alg) {
  int ret;
  
  if (jwt != NULL) {
    jwt->sign_alg = alg;
    ret = RHN_OK;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwa_alg r_jwt_get_sign_alg(jwt_t * jwt) {
  if (jwt != NULL) {
    return jwt->sign_alg;
  } else {
    return R_JWA_ALG_UNKNOWN;
  }
}

int r_jwt_set_enc_alg(jwt_t * jwt, jwa_alg alg) {
  int ret;
  
  if (jwt != NULL) {
    jwt->enc_alg = alg;
    ret = RHN_OK;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwa_alg r_jwt_get_enc_alg(jwt_t * jwt) {
  if (jwt != NULL) {
    return jwt->enc_alg;
  } else {
    return R_JWA_ALG_UNKNOWN;
  }
}

int r_jwt_set_enc(jwt_t * jwt, jwa_enc enc) {
  int ret;
  
  if (jwt != NULL) {
    jwt->enc = enc;
    ret = RHN_OK;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwa_enc r_jwt_get_enc(jwt_t * jwt) {
  if (jwt != NULL) {
    return jwt->enc;
  } else {
    return R_JWA_ENC_UNKNOWN;
  }
}

char * r_jwt_serialize_signed(jwt_t * jwt, jwk_t * privkey, int x5u_flags) {
  jws_t * jws = NULL;
  char * token = NULL, * payload = NULL;
  jwa_alg alg;
  json_t * j_header, * j_value = NULL;
  const char * key = NULL;
  jwk_t * jwk;
  size_t jwks_size, i;
  
  if (jwt != NULL && (alg = r_jwt_get_sign_alg(jwt)) != R_JWA_ALG_UNKNOWN) {
    if (r_jws_init(&jws) == RHN_OK) {
      r_jws_set_header_str_value(jws, "typ", "JWT");
      j_header = r_jwt_get_full_header_json_t(jwt);
      json_object_foreach(j_header, key, j_value) {
        r_jws_set_header_json_t_value(jws, key, j_value);
      }
      json_decref(j_header);
      jwks_size = r_jwks_size(jwt->jwks_privkey_sign);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_privkey_sign, i);
        r_jws_add_keys(jws, jwk, NULL);
        r_jwk_free(jwk);
      }
      jwks_size = r_jwks_size(jwt->jwks_pubkey_sign);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_pubkey_sign, i);
        r_jws_add_keys(jws, NULL, jwk);
        r_jwk_free(jwk);
      }
      if ((payload = json_dumps(jwt->j_claims, JSON_COMPACT)) != NULL) {
        if (r_jws_set_alg(jws, alg) == RHN_OK && r_jws_set_payload(jws, (const unsigned char *)payload, o_strlen(payload)) == RHN_OK) {
          token = r_jws_serialize(jws, privkey, x5u_flags);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_signed - Error setting jws");
        }
        o_free(payload);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_signed - Error json_dumps claims");
      }
      r_jws_free(jws);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_signed - Error r_jws_init");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_signed - Error invaid input parameters");
  }
  return token;
}

char * r_jwt_serialize_encrypted(jwt_t * jwt, jwk_t * pubkey, int x5u_flags) {
  jwe_t * jwe = NULL;
  char * token = NULL, * payload = NULL;
  jwa_alg alg;
  jwa_enc enc;
  json_t * j_header, * j_value = NULL;
  const char * key = NULL;
  jwk_t * jwk;
  size_t jwks_size, i;
  
  if (jwt != NULL && (alg = r_jwt_get_enc_alg(jwt)) != R_JWA_ALG_UNKNOWN && (enc = r_jwt_get_enc(jwt)) != R_JWA_ENC_UNKNOWN) {
    if (r_jwe_init(&jwe) == RHN_OK) {
      r_jwe_set_header_str_value(jwe, "typ", "JWT");
      j_header = r_jwt_get_full_header_json_t(jwt);
      json_object_foreach(j_header, key, j_value) {
        r_jwe_set_header_json_t_value(jwe, key, j_value);
      }
      json_decref(j_header);
      jwks_size = r_jwks_size(jwt->jwks_privkey_enc);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_privkey_enc, i);
        r_jwe_add_keys(jwe, jwk, NULL);
        r_jwk_free(jwk);
      }
      jwks_size = r_jwks_size(jwt->jwks_pubkey_enc);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_pubkey_enc, i);
        r_jwe_add_keys(jwe, NULL, jwk);
        r_jwk_free(jwk);
      }
      if ((payload = json_dumps(jwt->j_claims, JSON_COMPACT)) != NULL) {
        if (r_jwe_set_alg(jwe, alg) == RHN_OK && r_jwe_set_enc(jwe, enc) == RHN_OK && r_jwe_set_payload(jwe, (const unsigned char *)payload, o_strlen(payload)) == RHN_OK) {
          token = r_jwe_serialize(jwe, pubkey, x5u_flags);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_encrypted - Error setting jwe");
        }
        o_free(payload);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_encrypted - Error json_dumps claims");
      }
      r_jwe_free(jwe);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_encrypted - Error r_jwe_init");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_encrypted - Error invaid input parameters");
  }
  return token;
}

char * r_jwt_serialize_nested(jwt_t * jwt, unsigned int type, jwk_t * sign_key, int sign_key_x5u_flags, jwk_t * encrypt_key, int encrypt_key_x5u_flags) {
  jwe_t * jwe = NULL;
  jws_t * jws = NULL;
  char * token = NULL, * token_intermediate = NULL;
  jwa_alg sign_alg, enc_alg;
  jwa_enc enc;
  json_t * j_header, * j_value = NULL;
  const char * key = NULL;
  jwk_t * jwk;
  size_t jwks_size, i;
  
  if (jwt != NULL && (sign_alg = r_jwt_get_sign_alg(jwt)) != R_JWA_ALG_UNKNOWN && (enc_alg = r_jwt_get_enc_alg(jwt)) != R_JWA_ALG_UNKNOWN && (enc = r_jwt_get_enc(jwt)) != R_JWA_ENC_UNKNOWN) {
    if (type == R_JWT_NESTED_SIGN_THEN_ENCRYPT) {
      if ((token_intermediate = r_jwt_serialize_signed(jwt, sign_key, sign_key_x5u_flags)) != NULL) {
        if (r_jwe_init(&jwe) == RHN_OK) {
          r_jwe_set_header_str_value(jwe, "typ", "JWT");
          j_header = r_jwt_get_full_header_json_t(jwt);
          json_object_foreach(j_header, key, j_value) {
            r_jwe_set_header_json_t_value(jwe, key, j_value);
          }
          json_decref(j_header);
          jwks_size = r_jwks_size(jwt->jwks_privkey_enc);
          for (i=0; i<jwks_size; i++) {
            jwk = r_jwks_get_at(jwt->jwks_privkey_enc, i);
            r_jwe_add_keys(jwe, jwk, NULL);
            r_jwk_free(jwk);
          }
          jwks_size = r_jwks_size(jwt->jwks_pubkey_enc);
          for (i=0; i<jwks_size; i++) {
            jwk = r_jwks_get_at(jwt->jwks_pubkey_enc, i);
            r_jwe_add_keys(jwe, NULL, jwk);
            r_jwk_free(jwk);
          }
          r_jwe_set_header_str_value(jwe, "cty", "JWT");
          if (r_jwe_set_alg(jwe, enc_alg) == RHN_OK && r_jwe_set_enc(jwe, enc) == RHN_OK && r_jwe_set_payload(jwe, (const unsigned char *)token_intermediate, o_strlen(token_intermediate)) == RHN_OK) {
            token = r_jwe_serialize(jwe, encrypt_key, encrypt_key_x5u_flags);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error setting jwe");
          }
          r_jwe_free(jwe);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error r_jwe_init");
        }
        o_free(token_intermediate);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error r_jwt_serialize_signed");
      }
    } else if (type == R_JWT_NESTED_ENCRYPT_THEN_SIGN) {
      if ((token_intermediate = r_jwt_serialize_encrypted(jwt, encrypt_key, encrypt_key_x5u_flags)) != NULL) {
        if (r_jws_init(&jws) == RHN_OK) {
          r_jws_set_header_str_value(jws, "typ", "JWT");
          j_header = r_jwt_get_full_header_json_t(jwt);
          json_object_foreach(j_header, key, j_value) {
            r_jws_set_header_json_t_value(jws, key, j_value);
          }
          json_decref(j_header);
          jwks_size = r_jwks_size(jwt->jwks_privkey_sign);
          for (i=0; i<jwks_size; i++) {
            jwk = r_jwks_get_at(jwt->jwks_privkey_sign, i);
            r_jws_add_keys(jws, jwk, NULL);
            r_jwk_free(jwk);
          }
          jwks_size = r_jwks_size(jwt->jwks_pubkey_sign);
          for (i=0; i<jwks_size; i++) {
            jwk = r_jwks_get_at(jwt->jwks_pubkey_sign, i);
            r_jws_add_keys(jws, NULL, jwk);
            r_jwk_free(jwk);
          }
          r_jws_set_header_str_value(jws, "cty", "JWT");
          if (r_jws_set_alg(jws, sign_alg) == RHN_OK && r_jws_set_payload(jws, (const unsigned char *)token_intermediate, o_strlen(token_intermediate)) == RHN_OK) {
            token = r_jws_serialize(jws, sign_key, sign_key_x5u_flags);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error setting jws");
          }
          r_jws_free(jws);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error r_jws_init");
        }
        o_free(token_intermediate);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error r_jwt_serialize_encrypted");
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_serialize_nested - Error input parameters");
  }
  return token;
}

int r_jwt_parse(jwt_t * jwt, const char * token, int x5u_flags) {
  size_t nb_dots = 0, i, payload_len = 0;
  int ret, res;
  const unsigned char * payload = NULL;
  char * payload_str = NULL;
  
  if (jwt != NULL && o_strlen(token)) {
    for (i=0; i<o_strlen(token); i++) {
      if (token[i] == '.') {
        nb_dots++;
      }
    }
    if (nb_dots == 2) { // JWS
      r_jws_free(jwt->jws);
      if ((r_jws_init(&jwt->jws)) == RHN_OK) {
        if ((res = r_jws_parse(jwt->jws, token, x5u_flags)) == RHN_OK) {
          json_decref(jwt->j_header);
          jwt->j_header = json_deep_copy(jwt->jws->j_header);
          json_decref(jwt->j_claims);
          jwt->j_claims = NULL;
          jwt->sign_alg = jwt->jws->alg;
          if (0 != o_strcmp("JWT", r_jwt_get_header_str_value(jwt, "cty"))) {
            if ((payload = r_jws_get_payload(jwt->jws, &payload_len)) != NULL && payload_len > 0) {
              payload_str = o_strndup((const char *)payload, payload_len);
              if ((jwt->j_claims = json_loads(payload_str, JSON_DECODE_ANY, NULL)) != NULL) {
                ret = RHN_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error parsing payload as JSON");
                ret = RHN_ERROR;
              }
              o_free(payload_str);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error getting payload");
              ret = RHN_ERROR;
            }
          } else {
            // Nested JWT
            ret = RHN_OK;
          }
        } else if (res == RHN_ERROR_PARAM) {
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jws_parse");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jws_init");
        ret = RHN_ERROR;
      }
    } else if (nb_dots == 4) { // JWE
      r_jwe_free(jwt->jwe);
      if ((r_jwe_init(&jwt->jwe)) == RHN_OK) {
        if ((res = r_jwe_parse(jwt->jwe, token, x5u_flags)) == RHN_OK) {
          json_decref(jwt->j_header);
          jwt->j_header = json_deep_copy(jwt->jwe->j_header);
          jwt->enc_alg = jwt->jwe->alg;
          jwt->enc = jwt->jwe->enc;
          ret = RHN_OK;
        } else if (res == RHN_ERROR_PARAM) {
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jwe_parse");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jwe_init");
        ret = RHN_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error invalid token format");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error invalid input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwt_verify_signature(jwt_t * jwt, jwk_t * pubkey, int x5u_flags) {
  size_t jwks_size, i;
  jwk_t * jwk;
  
  if (jwt != NULL && jwt->jws != NULL) {
    r_jwks_empty(jwt->jws->jwks_privkey);
    r_jwks_empty(jwt->jws->jwks_pubkey);
    jwks_size = r_jwks_size(jwt->jwks_privkey_sign);
    for (i=0; i<jwks_size; i++) {
      jwk = r_jwks_get_at(jwt->jwks_privkey_sign, i);
      r_jws_add_keys(jwt->jws, jwk, NULL);
      r_jwk_free(jwk);
    }
    jwks_size = r_jwks_size(jwt->jwks_pubkey_sign);
    for (i=0; i<jwks_size; i++) {
      jwk = r_jwks_get_at(jwt->jwks_pubkey_sign, i);
      r_jws_add_keys(jwt->jws, NULL, jwk);
      r_jwk_free(jwk);
    }
    return r_jws_verify_signature(jwt->jws, pubkey, x5u_flags);
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwt_decrypt(jwt_t * jwt, jwk_t * privkey, int x5u_flags) {
  const unsigned char * payload = NULL;
  char * str_payload;
  size_t payload_len = 0, jwks_size, i;
  json_t * j_payload = NULL;
  int res, ret;
  jwk_t * jwk;
  
  if (jwt != NULL && jwt->jwe != NULL) {
    r_jwks_empty(jwt->jwe->jwks_privkey);
    r_jwks_empty(jwt->jwe->jwks_pubkey);
    jwks_size = r_jwks_size(jwt->jwks_privkey_enc);
    for (i=0; i<jwks_size; i++) {
      jwk = r_jwks_get_at(jwt->jwks_privkey_enc, i);
      r_jwe_add_keys(jwt->jwe, jwk, NULL);
      r_jwk_free(jwk);
    }
    jwks_size = r_jwks_size(jwt->jwks_pubkey_enc);
    for (i=0; i<jwks_size; i++) {
      jwk = r_jwks_get_at(jwt->jwks_pubkey_enc, i);
      r_jwe_add_keys(jwt->jwe, NULL, jwk);
      r_jwk_free(jwk);
    }
    if ((res = r_jwe_decrypt(jwt->jwe, privkey, x5u_flags)) == RHN_OK) {
      if ((payload = r_jwe_get_payload(jwt->jwe, &payload_len)) != NULL && payload_len > 0) {
        str_payload = o_strndup((const char *)payload, payload_len);
        if ((j_payload = json_loads(str_payload, JSON_DECODE_ANY, NULL)) != NULL) {
          if (r_jwt_set_full_claims_json_t(jwt, j_payload) == RHN_OK) {
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error r_jwt_set_full_claims_json_t");
            ret = RHN_ERROR;
          }
        } else {
          ret = RHN_ERROR_PARAM;
        }
        json_decref(j_payload);
        o_free(str_payload);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error getting jwe payload");
        ret = RHN_ERROR;
      }
    } else if (res == RHN_ERROR_INVALID || res == RHN_ERROR_PARAM || res == RHN_ERROR_UNSUPPORTED) {
      ret = res;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error r_jwe_decrypt");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwt_decrypt_verify_signature_nested(jwt_t * jwt, jwk_t * verify_key, int verify_key_x5u_flags, jwk_t * decrypt_key, int decrypt_key_x5u_flags) {
  const unsigned char * payload = NULL;
  char * str_payload, * str_payload_2;
  size_t payload_len = 0, jwks_size, i;
  json_t * j_payload = NULL;
  int res, ret;
  jwk_t * jwk;
  
  if (jwt != NULL && 0 == o_strcmp("JWT", r_jwt_get_header_str_value(jwt, "cty"))) {
    if (jwt->jws != NULL) {
      // Type R_JWT_NESTED_ENCRYPT_THEN_SIGN
      jwks_size = r_jwks_size(jwt->jwks_privkey_sign);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_privkey_sign, i);
        r_jws_add_keys(jwt->jws, jwk, NULL);
        r_jwk_free(jwk);
      }
      jwks_size = r_jwks_size(jwt->jwks_pubkey_sign);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_pubkey_sign, i);
        r_jws_add_keys(jwt->jws, NULL, jwk);
        r_jwk_free(jwk);
      }
      if ((res = r_jws_verify_signature(jwt->jws, verify_key, verify_key_x5u_flags)) == RHN_OK) {
        if ((payload = r_jws_get_payload(jwt->jws, &payload_len)) != NULL && payload_len > 0) {
          str_payload = o_strndup((const char *)payload, payload_len);
          r_jwe_free(jwt->jwe);
          if ((r_jwe_init(&jwt->jwe)) == RHN_OK) {
            if (r_jwe_parse(jwt->jwe, str_payload, decrypt_key_x5u_flags) == RHN_OK) {
              jwks_size = r_jwks_size(jwt->jwks_privkey_enc);
              for (i=0; i<jwks_size; i++) {
                jwk = r_jwks_get_at(jwt->jwks_privkey_enc, i);
                r_jwe_add_keys(jwt->jwe, jwk, NULL);
                r_jwk_free(jwk);
              }
              jwks_size = r_jwks_size(jwt->jwks_pubkey_enc);
              for (i=0; i<jwks_size; i++) {
                jwk = r_jwks_get_at(jwt->jwks_pubkey_enc, i);
                r_jwe_add_keys(jwt->jwe, NULL, jwk);
                r_jwk_free(jwk);
              }
              json_decref(jwt->j_header);
              jwt->j_header = json_deep_copy(jwt->jwe->j_header);
              jwt->enc_alg = jwt->jwe->alg;
              jwt->enc = jwt->jwe->enc;
              if ((res = r_jwe_decrypt(jwt->jwe, decrypt_key, decrypt_key_x5u_flags)) == RHN_OK) {
                if ((payload = r_jwe_get_payload(jwt->jwe, &payload_len)) != NULL && payload_len > 0) {
                  str_payload_2 = o_strndup((const char *)payload, payload_len);
                  if ((j_payload = json_loads(str_payload_2, JSON_DECODE_ANY, NULL)) != NULL) {
                    ret = r_jwt_set_full_claims_json_t(jwt, j_payload);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error JWE payload format");
                    ret = RHN_ERROR;
                  }
                  json_decref(j_payload);
                  o_free(str_payload_2);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error getting JWE payload");
                  ret = RHN_ERROR;
                }
              } else if (res == RHN_ERROR_INVALID || res == RHN_ERROR_PARAM || res == RHN_ERROR_UNSUPPORTED) {
                ret = res;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error r_jwe_decrypt");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error r_jwe_parse");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error r_jwe_init");
            ret = RHN_ERROR;
          }
          o_free(str_payload);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error getting JWS payload");
          ret = RHN_ERROR;
        }
      } else if (res == RHN_ERROR_INVALID || res == RHN_ERROR_PARAM || res == RHN_ERROR_UNSUPPORTED) {
        ret = res;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error r_jws_verify_signature");
        ret = RHN_ERROR;
      }
    } else if (jwt->jwe != NULL) {
      // Type R_JWT_NESTED_SIGN_THEN_ENCRYPT
      jwks_size = r_jwks_size(jwt->jwks_privkey_enc);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_privkey_enc, i);
        r_jwe_add_keys(jwt->jwe, jwk, NULL);
        r_jwk_free(jwk);
      }
      jwks_size = r_jwks_size(jwt->jwks_pubkey_enc);
      for (i=0; i<jwks_size; i++) {
        jwk = r_jwks_get_at(jwt->jwks_pubkey_enc, i);
        r_jwe_add_keys(jwt->jwe, NULL, jwk);
        r_jwk_free(jwk);
      }
      if ((res = r_jwe_decrypt(jwt->jwe, decrypt_key, decrypt_key_x5u_flags)) == RHN_OK) {
        if ((payload = r_jwe_get_payload(jwt->jwe, &payload_len)) != NULL && payload_len > 0) {
          str_payload = o_strndup((const char *)payload, payload_len);
          r_jws_free(jwt->jws);
          if ((r_jws_init(&jwt->jws)) == RHN_OK) {
            if (r_jws_parse(jwt->jws, str_payload, verify_key_x5u_flags) == RHN_OK) {
              jwks_size = r_jwks_size(jwt->jwks_privkey_sign);
              for (i=0; i<jwks_size; i++) {
                jwk = r_jwks_get_at(jwt->jwks_privkey_sign, i);
                r_jws_add_keys(jwt->jws, jwk, NULL);
                r_jwk_free(jwk);
              }
              jwks_size = r_jwks_size(jwt->jwks_pubkey_sign);
              for (i=0; i<jwks_size; i++) {
                jwk = r_jwks_get_at(jwt->jwks_pubkey_sign, i);
                r_jws_add_keys(jwt->jws, NULL, jwk);
                r_jwk_free(jwk);
              }
              json_decref(jwt->j_claims);
              jwt->j_claims = NULL;
              jwt->sign_alg = jwt->jws->alg;
              if ((res = r_jws_verify_signature(jwt->jws, verify_key, verify_key_x5u_flags)) == RHN_OK) {
                if ((payload = r_jws_get_payload(jwt->jws, &payload_len)) != NULL && payload_len > 0) {
                  str_payload_2 = o_strndup((const char *)payload, payload_len);
                  if ((jwt->j_claims = json_loads(str_payload_2, JSON_DECODE_ANY, NULL)) != NULL) {
                    ret = RHN_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error parsing payload as JSON");
                    ret = RHN_ERROR;
                  }
                  o_free(str_payload_2);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error getting payload");
                  ret = RHN_ERROR;
                }
              } else if (res == RHN_ERROR_INVALID || res == RHN_ERROR_PARAM || res == RHN_ERROR_UNSUPPORTED) {
                ret = res;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt_verify_signature_nested - Error r_jws_verify_signature");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jws_parse");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_parse - Error r_jws_init");
            ret = RHN_ERROR;
          }
          o_free(str_payload);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error getting jwe payload");
          ret = RHN_ERROR;
        }
      } else if (res == RHN_ERROR_INVALID || res == RHN_ERROR_PARAM || res == RHN_ERROR_UNSUPPORTED) {
        ret = res;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error r_jwe_decrypt");
        ret = RHN_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error no token to decrypt and verify");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwt_decrypt - Error invalid input token");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}
