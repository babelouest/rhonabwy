/**
 * 
 * Rhonabwy library
 * 
 * misc.c: Misc functions definitions
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

int _r_header_set_str_value(json_t * j_header, const char * key, const char * str_value) {
  int ret;
  
  if (j_header != NULL && o_strlen(key)) {
    if (str_value != NULL) {
      if (!json_object_set_new(j_header, key, json_string(str_value))) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_header_set_str_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(j_header, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int _r_header_set_int_value(json_t * j_header, const char * key, int i_value) {
  int ret;
  
  if (j_header != NULL && o_strlen(key)) {
    if (!json_object_set_new(j_header, key, json_integer(i_value))) {
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_header_set_int_value - Error json_object_set_new");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int _r_header_set_json_t_value(json_t * j_header, const char * key, json_t * j_value) {
  int ret;
  
  if (j_header != NULL && o_strlen(key)) {
    if (j_value != NULL) {
      if (!json_object_set_new(j_header, key, json_deep_copy(j_value))) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_header_set_json_t_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(j_header, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const char * _r_header_get_str_value(json_t * j_header, const char * key) {
  if (j_header != NULL && o_strlen(key)) {
    return json_string_value(json_object_get(j_header, key));
  }
  return NULL;
}

int _r_header_get_int_value(json_t * j_header, const char * key) {
  if (j_header != NULL && o_strlen(key)) {
    return json_integer_value(json_object_get(j_header, key));
  }
  return 0;
}

json_t * _r_header_get_json_t_value(json_t * j_header, const char * key) {
  json_t * j_value;
  
  if (j_header != NULL && o_strlen(key) && (j_value = json_object_get(j_header, key)) != NULL) {
    return json_deep_copy(j_value);
  }
  return NULL;
}

json_t * _r_header_get_full_json_t(json_t * j_header) {
  if (j_header != NULL) {
    return json_deep_copy(j_header);
  }
  return NULL;
}

jwa_alg str_to_jwa_alg(const char * alg) {
  if (0 == o_strcmp("none", alg)) {
    return R_JWA_ALG_NONE;
  } else if (0 == o_strcmp("HS256", alg)) {
    return R_JWA_ALG_HS256;
  } else if (0 == o_strcmp("HS384", alg)) {
    return R_JWA_ALG_HS384;
  } else if (0 == o_strcmp("HS512", alg)) {
    return R_JWA_ALG_HS512;
  } else if (0 == o_strcmp("RS256", alg)) {
    return R_JWA_ALG_RS256;
  } else if (0 == o_strcmp("RS384", alg)) {
    return R_JWA_ALG_RS384;
  } else if (0 == o_strcmp("RS512", alg)) {
    return R_JWA_ALG_RS512;
  } else if (0 == o_strcmp("ES256", alg)) {
    return R_JWA_ALG_ES256;
  } else if (0 == o_strcmp("ES384", alg)) {
    return R_JWA_ALG_ES384;
  } else if (0 == o_strcmp("ES512", alg)) {
    return R_JWA_ALG_ES512;
  } else if (0 == o_strcmp("EdDSA", alg)) {
    return R_JWA_ALG_EDDSA;
  } else if (0 == o_strcmp("PS256", alg)) {
    return R_JWA_ALG_PS256;
  } else if (0 == o_strcmp("PS384", alg)) {
    return R_JWA_ALG_PS384;
  } else if (0 == o_strcmp("PS512", alg)) {
    return R_JWA_ALG_PS512;
  } else if (0 == o_strcmp("RSA1_5", alg)) {
    return R_JWA_ALG_RSA1_5;
  } else if (0 == o_strcmp("RSA-OAEP", alg)) {
    return R_JWA_ALG_RSA_OAEP;
  } else if (0 == o_strcmp("RSA-OAEP-256", alg)) {
    return R_JWA_ALG_RSA_OAEP_256;
  } else if (0 == o_strcmp("A128KW", alg)) {
    return R_JWA_ALG_A128KW;
  } else if (0 == o_strcmp("A192KW", alg)) {
    return R_JWA_ALG_A192KW;
  } else if (0 == o_strcmp("A256KW", alg)) {
    return R_JWA_ALG_A256KW;
  } else if (0 == o_strcmp("dir", alg)) {
    return R_JWA_ALG_DIR;
  } else if (0 == o_strcmp("ECDH-ES", alg)) {
    return R_JWA_ALG_ECDH_ES;
  } else if (0 == o_strcmp("ECDH-ES+A128KW", alg)) {
    return R_JWA_ALG_ECDH_ES_A128KW;
  } else if (0 == o_strcmp("ECDH-ES+A192KW", alg)) {
    return R_JWA_ALG_ECDH_ES_A192KW;
  } else if (0 == o_strcmp("ECDH-ES+A256KW", alg)) {
    return R_JWA_ALG_ECDH_ES_A256KW;
  } else if (0 == o_strcmp("A128GCMKW", alg)) {
    return R_JWA_ALG_A128GCMKW;
  } else if (0 == o_strcmp("A192GCMKW", alg)) {
    return R_JWA_ALG_A192GCMKW;
  } else if (0 == o_strcmp("A256GCMKW", alg)) {
    return R_JWA_ALG_A256GCMKW;
  } else if (0 == o_strcmp("PBES2-HS256+A128KW", alg)) {
    return R_JWA_ALG_PBES2_H256;
  } else if (0 == o_strcmp("PBES2-HS384+A192KW", alg)) {
    return R_JWA_ALG_PBES2_H384;
  } else if (0 == o_strcmp("PBES2-HS512+A256KW", alg)) {
    return R_JWA_ALG_PBES2_H512;
  } else {
    return R_JWA_ALG_UNKNOWN;
  }
}

jwa_enc str_to_jwa_enc(const char * enc) {
  if (0 == o_strcmp("A128CBC-HS256", enc)) {
    return R_JWA_ENC_A128CBC;
  } else if (0 == o_strcmp("A192CBC-HS384", enc)) {
    return R_JWA_ENC_A192CBC;
  } else if (0 == o_strcmp("A256CBC-HS512", enc)) {
    return R_JWA_ENC_A256CBC;
  } else if (0 == o_strcmp("A128GCM", enc)) {
    return R_JWA_ENC_A128GCM;
  } else if (0 == o_strcmp("A192GCM", enc)) {
    return R_JWA_ENC_A192GCM;
  } else if (0 == o_strcmp("A256GCM", enc)) {
    return R_JWA_ENC_A256GCM;
  } else {
    return R_JWA_ENC_UNKNOWN;
  }
}

json_t * r_library_info_json_t() {
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[s]s[ssssss]}}",
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
                                "enc",
                                  "A128CBC-HS256",
                                  "A192CBC-HS384",
                                  "A256CBC-HS512",
                                  "A128GCM",
                                  "A192GCM",
                                  "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
  return j_info;
}

char * r_library_info_json_str() {
  char * to_return = NULL;
  json_t * j_info = r_library_info_json_t();
  if (j_info != NULL) {
    to_return = json_dumps(j_info, JSON_COMPACT);
  }
  json_decref(j_info);
  return to_return;
}

void r_free(void * data) {
  o_free(data);
}
