/**
 *
 * Rhonabwy library
 *
 * misc.c: Misc functions definitions
 *
 * Copyright 2020-2021 Nicolas Mora <mail@babelouest.org>
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

#ifdef R_WITH_ULFIUS
  #include <ulfius.h>
#endif

int r_global_init() {
#ifdef R_WITH_ULFIUS
  if (ulfius_global_init() == U_OK) {
    return RHN_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_global_init - Error ulfius_global_init");
    return RHN_ERROR;
  }
#else
  o_malloc_t malloc_fn;
  o_realloc_t realloc_fn;
  o_free_t free_fn;

  o_get_alloc_funcs(&malloc_fn, &realloc_fn, &free_fn);
  json_set_alloc_funcs((json_malloc_t)malloc_fn, (json_free_t)free_fn);
  return RHN_OK;
#endif
}

void r_global_close() {
#ifdef R_WITH_ULFIUS
  ulfius_global_close();
#endif
}

char * _r_get_http_content(const char * url, int x5u_flags, const char * expected_content_type) {
  char * to_return = NULL;
#ifdef R_WITH_ULFIUS
  struct _u_request request;
  struct _u_response response;
  
  if (ulfius_init_request(&request) == U_OK) {
    if (ulfius_init_response(&response) == U_OK) {
      ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "GET",
                                              U_OPT_HTTP_URL, url,
                                              U_OPT_CHECK_SERVER_CERTIFICATE, !(x5u_flags & R_FLAG_IGNORE_SERVER_CERTIFICATE),
                                              U_OPT_FOLLOW_REDIRECT, (x5u_flags & R_FLAG_FOLLOW_REDIRECT),
                                              U_OPT_HEADER_PARAMETER, "User-Agent", "Rhonabwy/" RHONABWY_VERSION_STR,
                                              U_OPT_NONE);
      if (ulfius_send_http_request(&request, &response) == U_OK && response.status >= 200 && response.status < 300) {
        if (!o_strlen(expected_content_type)) {
          to_return = o_strndup(response.binary_body, response.binary_body_length);
        } else {
          if (NULL != o_strstr(u_map_get_case(response.map_header, ULFIUS_HTTP_HEADER_CONTENT), ULFIUS_HTTP_ENCODING_JSON)) {
            to_return = o_strndup(response.binary_body, response.binary_body_length);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "_r_get_http_content - Error invalid content-type");
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_get_http_content - Error ulfius_send_http_request");
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_get_http_content - Error ulfius_init_response");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_get_http_content - Error ulfius_init_request");
  }
#else
  (void)url;
  (void)x5u_flags;
  (void)expected_content_type;
#endif
  return to_return;
}

int _r_json_set_str_value(json_t * j_json, const char * key, const char * str_value) {
  int ret;

  if (j_json != NULL && o_strlen(key)) {
    if (str_value != NULL) {
      if (!json_object_set_new(j_json, key, json_string(str_value))) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_json_set_str_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(j_json, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int _r_json_set_int_value(json_t * j_json, const char * key, int i_value) {
  int ret;

  if (j_json != NULL && o_strlen(key)) {
    if (!json_object_set_new(j_json, key, json_integer(i_value))) {
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "_r_json_set_int_value - Error json_object_set_new");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int _r_json_set_json_t_value(json_t * j_json, const char * key, json_t * j_value) {
  int ret;

  if (j_json != NULL && o_strlen(key)) {
    if (j_value != NULL) {
      if (!json_object_set_new(j_json, key, json_deep_copy(j_value))) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_json_set_json_t_value - Error json_object_set_new");
        ret = RHN_ERROR;
      }
    } else {
      json_object_del(j_json, key);
      ret = RHN_OK;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const char * _r_json_get_str_value(json_t * j_json, const char * key) {
  if (j_json != NULL && o_strlen(key)) {
    return json_string_value(json_object_get(j_json, key));
  }
  return NULL;
}

int _r_json_get_int_value(json_t * j_json, const char * key) {
  if (j_json != NULL && o_strlen(key)) {
    return json_integer_value(json_object_get(j_json, key));
  }
  return 0;
}

json_t * _r_json_get_json_t_value(json_t * j_json, const char * key) {
  json_t * j_value;

  if (j_json != NULL && o_strlen(key) && (j_value = json_object_get(j_json, key)) != NULL) {
    return json_deep_copy(j_value);
  }
  return NULL;
}

json_t * _r_json_get_full_json_t(json_t * j_json) {
  if (j_json != NULL) {
    return json_deep_copy(j_json);
  }
  return NULL;
}

jwa_alg r_str_to_jwa_alg(const char * alg) {
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
  } else if (0 == o_strcmp("ES256K", alg)) {
    return R_JWA_ALG_ES256K;
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
  } else if (0 == o_strcmp("ES256K", alg)) {
    return R_JWA_ALG_ES256K;
  } else {
    return R_JWA_ALG_UNKNOWN;
  }
}

const char * r_jwa_alg_to_str(jwa_alg alg) {
  switch (alg) {
    case R_JWA_ALG_NONE:
      return "none";
      break;
    case R_JWA_ALG_HS256:
      return "HS256";
      break;
    case R_JWA_ALG_HS384:
      return "HS384";
      break;
    case R_JWA_ALG_HS512:
      return "HS512";
      break;
    case R_JWA_ALG_RS256:
      return "RS256";
      break;
    case R_JWA_ALG_RS384:
      return "RS384";
      break;
    case R_JWA_ALG_RS512:
      return "RS512";
      break;
    case R_JWA_ALG_ES256:
      return "ES256";
      break;
    case R_JWA_ALG_ES384:
      return "ES384";
      break;
    case R_JWA_ALG_ES512:
      return "ES512";
      break;
    case R_JWA_ALG_EDDSA:
      return "EdDSA";
      break;
    case R_JWA_ALG_ES256K:
      return "ES256K";
      break;
    case R_JWA_ALG_PS256:
      return "PS256";
      break;
    case R_JWA_ALG_PS384:
      return "PS384";
      break;
    case R_JWA_ALG_PS512:
      return "PS512";
      break;
     case R_JWA_ALG_RSA1_5:
      return "RSA1_5";
      break;
     case R_JWA_ALG_RSA_OAEP:
      return "RSA-OAEP";
      break;
     case R_JWA_ALG_RSA_OAEP_256:
      return "RSA-OAEP-256";
      break;
     case R_JWA_ALG_A128KW:
      return "A128KW";
      break;
     case R_JWA_ALG_A192KW:
      return "A192KW";
      break;
     case R_JWA_ALG_A256KW:
      return "A256KW";
      break;
     case R_JWA_ALG_DIR:
      return "dir";
      break;
     case R_JWA_ALG_ECDH_ES:
      return "ECDH-ES";
      break;
     case R_JWA_ALG_ECDH_ES_A128KW:
      return "ECDH-ES+A128KW";
      break;
     case R_JWA_ALG_ECDH_ES_A192KW:
      return "ECDH-ES+A192KW";
      break;
     case R_JWA_ALG_ECDH_ES_A256KW:
      return "ECDH-ES+A256KW";
      break;
     case R_JWA_ALG_A128GCMKW:
      return "A128GCMKW";
      break;
     case R_JWA_ALG_A192GCMKW:
      return "A192GCMKW";
      break;
     case R_JWA_ALG_A256GCMKW:
      return "A256GCMKW";
      break;
     case R_JWA_ALG_PBES2_H256:
      return "PBES2-HS256+A128KW";
      break;
     case R_JWA_ALG_PBES2_H384:
      return "PBES2-HS384+A192KW";
      break;
     case R_JWA_ALG_PBES2_H512:
      return "PBES2-HS512+A256KW";
      break;
    default:
      return NULL;
      break;
  }
}

jwa_enc r_str_to_jwa_enc(const char * enc) {
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

const char * r_jwa_enc_to_str(jwa_enc enc) {
  switch (enc) {
    case R_JWA_ENC_A128CBC:
      return "A128CBC-HS256";
      break;
    case R_JWA_ENC_A192CBC:
      return "A192CBC-HS384";
      break;
    case R_JWA_ENC_A256CBC:
      return "A256CBC-HS512";
      break;
    case R_JWA_ENC_A128GCM:
      return "A128GCM";
      break;
    case R_JWA_ENC_A192GCM:
      return "A192GCM";
      break;
    case R_JWA_ENC_A256GCM:
      return "A256GCM";
      break;
    default:
      return NULL;
      break;
  }
}

json_t * r_library_info_json_t() {
  json_t * j_info = json_pack("{sss{s[sssssss]}s{s[ssss]s[sssss]}}",
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
                                  "dir",
                                  "A128GCMKW",
                                  "A256GCMKW",
                                "enc",
                                  "A128CBC-HS256",
                                  "A192CBC-HS384",
                                  "A256CBC-HS512",
                                  "A128GCM",
                                  "A256GCM");
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES512"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("EdDSA"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256K"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS384"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("PS512"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060e
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192GCMKW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "enc"), json_string("A192GCM"));
#endif
#if NETTLE_VERSION_NUMBER >= 0x030400
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("RSA-OAEP-256"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("A256KW"));
#endif
#if GNUTLS_VERSION_NUMBER >= 0x03060d
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS256+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS384+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("PBES2-HS512+A256KW"));
#endif
#if defined(R_ECDH_ENABLED) && GNUTLS_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A256KW"));
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
