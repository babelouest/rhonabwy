/**
 *
 * Rhonabwy library
 *
 * misc.c: Misc functions definitions
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

#include <zlib.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define _R_BLOCK_SIZE 256

#ifdef R_WITH_CURL
#include <curl/curl.h>
#include <string.h>
#define _R_HEADER_CONTENT_TYPE "Content-Type"
#endif

int r_global_init(void) {
  o_malloc_t malloc_fn;
  o_realloc_t realloc_fn;
  o_free_t free_fn;
  int ret = RHN_OK;

  o_get_alloc_funcs(&malloc_fn, &realloc_fn, &free_fn);
  json_set_alloc_funcs((json_malloc_t)malloc_fn, (json_free_t)free_fn);
#ifdef R_WITH_CURL
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_global_init - Error curl_global_init");
    ret = RHN_ERROR;
  } else {
    if (curl_global_init_mem(CURL_GLOBAL_DEFAULT, malloc_fn, free_fn, realloc_fn, *o_strdup, *calloc) != CURLE_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_global_init - Error curl_global_init_mem");
      ret = RHN_ERROR_MEMORY;
    }
  }
#endif
  return ret;
}

void r_global_close(void) {
#ifdef R_WITH_CURL
  curl_global_cleanup();
#endif
}

#ifdef R_WITH_CURL

struct _r_response_str {
  char * ptr;
  size_t len;
};

struct _r_expected_content_type {
  const char * expected;
  int found;
};

static size_t write_response(char *ptr, size_t size, size_t nmemb, void * userdata) {
  struct _r_response_str * resp = (struct _r_response_str *)userdata;
  size_t len = (size*nmemb);
  if ((resp->ptr = o_realloc(resp->ptr, (resp->len + len + 1))) != NULL) {
    memcpy(resp->ptr+resp->len, ptr, len);
    resp->len += len;
    resp->ptr[resp->len] = '\0';
    return len;
  } else {
    return 0;
  }
}

static size_t write_header(void * buffer, size_t size, size_t nitems, void * user_data) {
  const char * header = (const char *)buffer;
  struct _r_expected_content_type * expected_content_type = (struct _r_expected_content_type *)user_data;
  
  if (o_strncasecmp(header, _R_HEADER_CONTENT_TYPE, o_strlen(_R_HEADER_CONTENT_TYPE)) == 0 &&
     o_strstr(header+o_strlen(_R_HEADER_CONTENT_TYPE)+1, expected_content_type->expected)) {
    expected_content_type->found = 1;
  }
  return nitems * size;
}
#endif

char * _r_get_http_content(const char * url, int x5u_flags, const char * expected_content_type) {
  char * to_return = NULL;
#ifdef R_WITH_CURL
  CURL *curl;
  struct curl_slist *list = NULL;
  struct _r_response_str resp;
  struct _r_expected_content_type ct;
  long status = 0;

  curl = curl_easy_init();
  if(curl != NULL) {
    resp.ptr = NULL;
    resp.len = 0;
    ct.expected = expected_content_type;
    ct.found = 0;
    
    do {
      if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
        break;
      }
      if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response) != CURLE_OK) {
        break;
      }
      if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp) != CURLE_OK) {
        break;
      }
      if ((list = curl_slist_append(list, "User-Agent: Rhonabwy/" RHONABWY_VERSION_STR)) == NULL) {
        break;
      }
      if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list) != CURLE_OK) {
        break;
      }
      if (curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L) != CURLE_OK) {
        break;
      }
      if (x5u_flags & R_FLAG_FOLLOW_REDIRECT) {
        if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1) != CURLE_OK) {
          break;
        }
      }
      if (x5u_flags & R_FLAG_IGNORE_SERVER_CERTIFICATE) {
        if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0) != CURLE_OK) {
          break;
        }
        if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0) != CURLE_OK) {
          break;
        }
      }
      if (o_strlen(expected_content_type)) {
        if (curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header) != CURLE_OK) {
          break;
        }
        if (curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &ct) != CURLE_OK) {
          break;
        }
      }
      if (curl_easy_perform(curl) != CURLE_OK) {
        break;
      }

      if (curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) {
        break;
      }
    } while (0);

    curl_easy_cleanup(curl);
    curl_slist_free_all(list);
    
    if (status >= 200 && status < 300) {
      if (!o_strlen(expected_content_type)) {
        to_return = resp.ptr;
      } else {
        if (ct.found) {
          to_return = resp.ptr;
        } else {
          o_free(resp.ptr);
        }
      }
    } else {
      o_free(resp.ptr);
    }
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

int _r_json_set_int_value(json_t * j_json, const char * key, rhn_int_t i_value) {
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

rhn_int_t _r_json_get_int_value(json_t * j_json, const char * key) {
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

size_t _r_get_key_size(jwa_enc enc) {
  size_t size = 0;
  switch (enc) {
    case R_JWA_ENC_A128GCM:
      size = 16;
      break;
    case R_JWA_ENC_A192GCM:
      size = 24;
      break;
    case R_JWA_ENC_A128CBC:
    case R_JWA_ENC_A256GCM:
      size = 32;
      break;
    case R_JWA_ENC_A192CBC:
      size = 48;
      break;
    case R_JWA_ENC_A256CBC:
      size = 64;
      break;
    default:
      size = 0;
      break;
  }
  return size;
}

gnutls_cipher_algorithm_t _r_get_alg_from_enc(jwa_enc enc) {
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
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      alg = GNUTLS_CIPHER_AES_192_GCM;
#else
      alg = GNUTLS_CIPHER_UNKNOWN; // Unsupported until GnuTLS 3.6.14
#endif
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

int _r_deflate_payload(const unsigned char * uncompressed, size_t uncompressed_len, unsigned char ** compressed, size_t * compressed_len) {
  int ret = RHN_OK, res;
  z_stream defstream;
  
  *compressed_len = 0;
  *compressed = NULL;
  
  defstream.zalloc = Z_NULL;
  defstream.zfree = Z_NULL;
  defstream.opaque = Z_NULL;
  defstream.avail_in = (uInt)uncompressed_len;
  defstream.next_in = (Bytef *)uncompressed;

  if (deflateInit2(&defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -9, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
    do {
      if ((*compressed = o_realloc(*compressed, (*compressed_len)+_R_BLOCK_SIZE)) != NULL) {
        defstream.avail_out = _R_BLOCK_SIZE;
        defstream.next_out = ((Bytef *)*compressed)+(*compressed_len);
        switch ((res = deflate(&defstream, Z_FINISH))) {
          case Z_OK:
          case Z_STREAM_END:
          case Z_BUF_ERROR:
            break;
          default:
            y_log_message(Y_LOG_LEVEL_ERROR, "_r_deflate_payload - Error deflate %d", res);
            ret = RHN_ERROR;
            break;
        }
        (*compressed_len) += _R_BLOCK_SIZE - defstream.avail_out;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_deflate_payload - Error allocating resources for *compressed");
        ret = RHN_ERROR;
      }
    } while (RHN_OK == ret && defstream.avail_out == 0);

    deflateEnd(&defstream);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_deflate_payload - Error deflateInit");
    ret = RHN_ERROR;
  }
  return ret;
}

int _r_inflate_payload(const unsigned char * compressed, size_t compressed_len, unsigned char ** uncompressed, size_t * uncompressed_len) {
  int ret = RHN_OK, res;
  z_stream infstream;
  
  *uncompressed = NULL;
  *uncompressed_len = 0;
  infstream.zalloc = Z_NULL;
  infstream.zfree = Z_NULL;
  infstream.opaque = Z_NULL;
  infstream.avail_in = (uInt)compressed_len;
  infstream.next_in = (Bytef *)compressed;

  if (inflateInit2(&infstream, -8) == Z_OK) {
    do {
      if (((*uncompressed) = o_realloc((*uncompressed), (*uncompressed_len)+_R_BLOCK_SIZE)) != NULL) {
        infstream.avail_out = _R_BLOCK_SIZE;
        infstream.next_out = ((Bytef *)(*uncompressed))+(*uncompressed_len);
        switch ((res = inflate(&infstream, Z_FINISH))) {
          case Z_OK:
          case Z_STREAM_END:
          case Z_BUF_ERROR:
            break;
          default:
            y_log_message(Y_LOG_LEVEL_ERROR, "_r_inflate_payload - Error inflate %d", res);
            ret = RHN_ERROR;
            break;
        }
        (*uncompressed_len) += _R_BLOCK_SIZE - infstream.avail_out;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "_r_inflate_payload - Error allocating resources for data_in_suffix");
        ret = RHN_ERROR;
      }
    } while (RHN_OK == ret && infstream.avail_out == 0);

    inflateEnd(&infstream);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "_r_inflate_payload - Error inflateInit");
    ret = RHN_ERROR;
  }
  return ret;
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

json_t * r_library_info_json_t(void) {
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
  //json_array_append_new(json_object_get(json_object_get(j_info, "jws"), "alg"), json_string("ES256K"));
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
#if NETTLE_VERSION_NUMBER >= 0x030600
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A128KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A192KW"));
  json_array_append_new(json_object_get(json_object_get(j_info, "jwe"), "alg"), json_string("ECDH-ES+A256KW"));
#endif
  return j_info;
}

char * r_library_info_json_str(void) {
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
