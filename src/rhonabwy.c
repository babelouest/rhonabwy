/**
 * 
 * Rhonabwy JSON Web Key (JWK) library
 * 
 * rhonabwy.c: functions definitions
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

#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <rhonabwy.h>
#include <orcania.h>
#include <yder.h>

int r_init_jwk(jwk_t ** jwk) {
  if (jwk != NULL) {
    *jwk = json_object();
    return R_OK;
  } else {
    return R_ERROR_PARAM;
  }
}

void r_free_jwk(jwk_t * jwk) {
  if (jwk != NULL) {
    json_decref(jwk);
  }
}

int r_jwk_is_valid(jwk_t * jwk) {
  int ret = R_OK, has_x5cu = 0, has_pubkey_parameters = 0, has_privkey_parameters = 0, has_kty = 0, has_alg = 0;
  json_t * j_element = NULL;
  size_t index = 0, b64dec_len = 0;
  
  if (jwk != NULL) {
    if (json_is_object(jwk)) {
      // JWK parameters
      if (json_object_get(jwk, "x5u") != NULL) {
        if (!json_is_array(json_object_get(jwk, "x5u"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5u");
          ret = R_ERROR_PARAM;
        } else {
          if (json_array_size(json_object_get(jwk, "x5u"))) {
            has_x5cu = 1;
          }
          json_array_foreach(json_object_get(jwk, "x5u"), index, j_element) {
            if (!json_string_length(j_element) || o_strncasecmp("https://", json_string_value(j_element), o_strlen("https://"))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5u");
              ret = R_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "x5c") != NULL) {
        if (!json_is_array(json_object_get(jwk, "x5c"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5c");
          ret = R_ERROR_PARAM;
        } else {
          if (json_array_size(json_object_get(jwk, "x5c"))) {
            has_x5cu = 1;
          }
          json_array_foreach(json_object_get(jwk, "x5c"), index, j_element) {
            if (!json_string_length(j_element) || !o_base64_decode((const unsigned char *)json_string_value(j_element), json_string_length(j_element), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5c");
              ret = R_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "kty") != NULL) {
        if (!json_string_length(json_object_get(jwk, "kty"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid kty");
          ret = R_ERROR_PARAM;
        }
        has_kty = 1;
      }
      if (json_object_get(jwk, "use") != NULL && !json_is_string(json_object_get(jwk, "use"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid use");
        ret = R_ERROR_PARAM;
      }
      if (json_object_get(jwk, "key_ops") != NULL) {
        if (!json_is_array(json_object_get(jwk, "key_ops"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid key_ops");
          ret = R_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "key_ops"), index, j_element) {
            if (!json_string_length(j_element)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid key_ops");
              ret = R_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "alg") != NULL) {
        if (0 != o_strcmp("HS256", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("HS384", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("HS512", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("RS256", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("RS384", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("RS512", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("ES256", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("ES384", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("ES512", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("PS256", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("PS384", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("PS512", json_string_value(json_object_get(jwk, "alg"))) &&
            0 != o_strcmp("none", json_string_value(json_object_get(jwk, "alg")))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid alg");
          ret = R_ERROR_PARAM;
        }
        has_alg = 1;
      }
      if (json_object_get(jwk, "kid") != NULL && !json_is_string(json_object_get(jwk, "kid"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid kid");
        ret = R_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t") != NULL && !json_is_string(json_object_get(jwk, "x5t"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5t");
        ret = R_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t#S256") != NULL && !json_is_string(json_object_get(jwk, "x5t#S256"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5t#S256");
        ret = R_ERROR_PARAM;
      }
      
      // JWA parameters validation
      if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "EC")) {
        if (json_object_get(jwk, "crv")) {
          if (0 != o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv")))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid crv");
            ret = R_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "x"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x");
          ret = R_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x format");
            ret = R_ERROR_PARAM;
          }
        }
        if (!json_string_length(json_object_get(jwk, "y"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid y");
          ret = R_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid y format");
            ret = R_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d");
            ret = R_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = R_ERROR_PARAM;
            }
            has_privkey_parameters = 1;
          }
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "RSA")) {
        if (!json_string_length(json_object_get(jwk, "n"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid n");
          ret = R_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid n format");
            ret = R_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "e"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid e");
          ret = R_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid e format");
            ret = R_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d");
            ret = R_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = R_ERROR_PARAM;
            }
          }
          has_privkey_parameters = 1;
        }
        if (json_object_get(jwk, "p") != NULL) {
          if (!json_string_length(json_object_get(jwk, "p"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid p");
            ret = R_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = R_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "q") != NULL) {
          if (!json_string_length(json_object_get(jwk, "q"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid q");
            ret = R_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid q format");
              ret = R_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dp") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dp"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dp");
            ret = R_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dp format");
              ret = R_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dq") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dq"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dq");
            ret = R_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dq format");
              ret = R_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "qi") != NULL) {
          if (!json_string_length(json_object_get(jwk, "qi"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid qi");
            ret = R_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "qi")), json_string_length(json_object_get(jwk, "qi")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid qi format");
              ret = R_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "oth") != NULL) {
          ret = R_ERROR_UNSUPPORTED;
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct")) {
        if (!json_string_length(json_object_get(jwk, "k"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid k");
          ret = R_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "k")), json_string_length(json_object_get(jwk, "k")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid k format");
            ret = R_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
      }
      
      // Validate if required parameters are present and consistent
      if (ret == R_OK) {
        if (!has_kty) {
          if (!has_x5cu || !has_alg) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid data");
            ret = R_ERROR_PARAM;
          }
        } else {
          if (has_kty && !has_pubkey_parameters) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - public key parameters missing");
            ret = R_ERROR_PARAM;
          }
        }
      }
    } else {
      ret = R_ERROR_PARAM;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_key_type(jwk_t * jwk) {
  gnutls_x509_crt_t crt = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_datum_t data;
  int ret = R_KEY_TYPE_NONE, pk_alg;
  unsigned char * data_dec = NULL;
  size_t data_dec_len = 0;
  
  if (r_jwk_is_valid(jwk) == R_OK) {
    if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "RSA")) {
      ret = R_KEY_TYPE_RSA;
      if (json_object_get(jwk, "d") != NULL && json_object_get(jwk, "p") != NULL && json_object_get(jwk, "q") != NULL && json_object_get(jwk, "dp") != NULL && json_object_get(jwk, "dq") != NULL && json_object_get(jwk, "qi") != NULL) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "EC")) {
      ret = R_KEY_TYPE_ECDSA;
      if (json_object_get(jwk, "d") != NULL) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (json_object_get(jwk, "x5c") != NULL) {
        if (o_base64_decode((unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), NULL, &data_dec_len)) {
          if ((data_dec = o_malloc((data_dec_len+1)*sizeof(char))) != NULL) {
            if (o_base64_decode((unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), data_dec, &data_dec_len)) {
              data.data = data_dec;
              data.size = data_dec_len;
              if (!gnutls_x509_crt_init(&crt)) {
                if (!gnutls_x509_privkey_init(&x509_key)) {
                  if (!gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_DER)) {
                    pk_alg = gnutls_x509_privkey_get_pk_algorithm(x509_key);
                    if (pk_alg == GNUTLS_PK_RSA) {
                      ret = R_KEY_TYPE_RSA;
                    } else if (pk_alg == GNUTLS_PK_RSA) {
                      ret = R_KEY_TYPE_ECDSA;
                    }
                    ret |= R_KEY_TYPE_PRIVATE;
                  } else if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
                    pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
                    if (pk_alg == GNUTLS_PK_RSA) {
                      ret = R_KEY_TYPE_RSA;
                    } else if (pk_alg == GNUTLS_PK_RSA) {
                      ret = R_KEY_TYPE_ECDSA;
                    }
                    ret |= R_KEY_TYPE_PUBLIC;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error gnutls_x509_crt_import");
                    ret = R_ERROR;
                  }
                  gnutls_x509_privkey_deinit(x509_key);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error gnutls_x509_privkey_init");
                  ret = R_ERROR;
                }
                gnutls_x509_crt_deinit(crt);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error gnutls_x509_crt_init");
                ret = R_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error o_base64_decode (2)");
              ret = R_ERROR;
            }
            o_free(data_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error o_malloc");
            ret = R_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error o_base64_decode (1)");
          ret = R_ERROR;
        }
    } else if (json_object_get(jwk, "x5u") != NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Unsupported x5u");
    } else {
      ret = R_KEY_TYPE_HMAC|R_KEY_TYPE_SYMMETRIC;
    }
  }
  return ret;
}

int r_import_from_json_str(jwk_t * jwk, const char * input) {
  int ret;
  json_t * jwk_input;
  
  if (input != NULL && jwk != NULL) {
    if ((jwk_input = json_loads(input, JSON_DECODE_ANY, NULL)) != NULL) {
      ret = r_import_from_json_t(jwk, jwk_input);
    } else {
      ret = R_ERROR_PARAM;
    }
    json_decref(jwk_input);
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_import_from_json_t(jwk_t * jwk, json_t * j_input) {
  int ret;
  
  if (j_input != NULL && json_is_object(j_input)) {
    if (!json_object_update(jwk, j_input)) {
      ret = r_jwk_is_valid(jwk);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error json_object_update");
      ret = R_ERROR;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_import_from_pem_der(jwk_t * jwk, int type, int format, const unsigned char * input, size_t input_len) {
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_privkey_t key           = NULL;
  gnutls_pubkey_t pub            = NULL;
  gnutls_x509_crt_t crt          = NULL;
  gnutls_datum_t data;
  int ret, res;
  
  if (jwk != NULL && input != NULL && input_len) {
    switch (type) {
      case R_X509_TYPE_PUBKEY:
        if (!(res = gnutls_pubkey_init(&pub))) {
          data.data = (unsigned char *)input;
          data.size = input_len;
          if (!(res = gnutls_pubkey_import(pub, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER))) {
            ret = r_import_from_gnutls_pubkey(jwk, pub);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error r_import_from_gnutls_pubkey: %s", gnutls_strerror(res));
            ret = R_ERROR;
          }
          gnutls_pubkey_deinit(pub);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_pubkey_init: %s", gnutls_strerror(res));
          ret = R_ERROR;
        }
        break;
      case R_X509_TYPE_PRIVKEY:
        if ((res = gnutls_privkey_init(&key)) < 0) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_privkey_init: %s", gnutls_strerror(res));
          ret = R_ERROR;
        } else if ((res = gnutls_x509_privkey_init(&x509_key)) < 0) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_privkey_init: %s", gnutls_strerror(res));
          ret = R_ERROR;
        } else {
          data.data = (unsigned char *)input;
          data.size = input_len;
          if ((res = gnutls_x509_privkey_import(x509_key, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER)) < 0) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_privkey_import: %s", gnutls_strerror(res));
            ret = R_ERROR_PARAM;
          } else if ((res = gnutls_privkey_import_x509(key, x509_key, 0)) < 0) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_privkey_import_x509: %s", gnutls_strerror(res));
            ret = R_ERROR;
          } else {
            ret = r_import_from_gnutls_privkey(jwk, key);
          }
        }
        gnutls_privkey_deinit(key);
        gnutls_x509_privkey_deinit(x509_key);
        break;
      case R_X509_TYPE_CERTIFICATE:
        if (!(res = gnutls_x509_crt_init(&crt))) {
          data.data = (unsigned char *)input;
          data.size = input_len;
          if (!(res = gnutls_x509_crt_import(crt, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER))) {
            ret = r_import_from_gnutls_x509_crt(jwk, crt);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error r_import_from_gnutls_x509_crt: %s", gnutls_strerror(res));
            ret = R_ERROR_PARAM;
          }
          gnutls_x509_crt_deinit(crt);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_crt_init: %s", gnutls_strerror(res));
          ret = R_ERROR;
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error invalid type");
        ret = R_ERROR_PARAM;
        break;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_import_from_gnutls_privkey(jwk_t * jwk, gnutls_privkey_t key) {
  int ret, res;
  unsigned int bits = 0;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_datum_t m, e, d, p, q, u, e1, e2;
  unsigned char * b64_enc = NULL, kid[64], kid_b64[128];
  size_t b64_enc_len = 0, kid_len = 64, kid_b64_len = 128;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_datum_t x, y, k;
  gnutls_ecc_curve_t curve;
#endif
  
  if (jwk != NULL && key != NULL) {
    switch (gnutls_privkey_get_pk_algorithm(key, &bits)) {
      case GNUTLS_PK_RSA:
        if ((res = gnutls_privkey_export_rsa_raw(key, &m, &e, &d, &p, &q, &u, &e1, &e2)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("RSA"));
          ret = R_OK;
          do {
            if (!o_base64url_encode(m.data, m.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (1)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (1)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (2)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (3)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (2)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (4)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(d.data, d.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (3)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(d.data, d.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (6)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(p.data, p.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (7)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (4)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(p.data, p.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (8)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "p", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(q.data, q.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (9)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (5)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(q.data, q.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (10)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "q", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(u.data, u.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (11)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (6)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(u.data, u.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (12)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "qi", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e1.data, e1.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (13)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (7)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(e1.data, e1.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (14)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "dp", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e2.data, e2.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (15)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (8)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(e2.data, e2.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (16)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "dq", json_string((const char *)b64_enc));
            
            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_privkey_export_x509");
              ret = R_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_x509_crt_get_key_id");
              ret = R_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(m.data);
          gnutls_free(e.data);
          gnutls_free(d.data);
          gnutls_free(p.data);
          gnutls_free(q.data);
          gnutls_free(u.data);
          gnutls_free(e1.data);
          gnutls_free(e2.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_pubkey_export_rsa_raw2");
          ret = R_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_privkey_export_ecc_raw(key, &curve, &x, &y, &k)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = R_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (1)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (1)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (2)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (3)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (2)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (4)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(k.data, k.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (3)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(k.data, k.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (6)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "k", json_string((const char *)b64_enc));
            
            switch (curve) {
              case GNUTLS_ECC_CURVE_SECP521R1:
                json_object_set_new(jwk, "crv", json_string("P-512"));
                break;
              case GNUTLS_ECC_CURVE_SECP384R1:
                json_object_set_new(jwk, "crv", json_string("P-384"));
                break;
              case GNUTLS_ECC_CURVE_SECP256R1:
                json_object_set_new(jwk, "crv", json_string("P-256"));
                break;
              default:
                y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error curve");
                ret = R_ERROR_PARAM;
                break;
            }

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_privkey_export_x509");
              ret = R_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_x509_crt_get_key_id");
              ret = R_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(y.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error gnutls_pubkey_export_ecc_raw2");
          ret = R_ERROR_PARAM;
        }
        break;
#endif
      default:
        ret = R_ERROR_PARAM;
        break;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_import_from_gnutls_pubkey(jwk_t * jwk, gnutls_pubkey_t pub) {
  int ret, res;
  unsigned int bits = 0;
  gnutls_datum_t m, e;
  unsigned char * b64_enc = NULL, kid[64], kid_b64[128];
  size_t b64_enc_len = 0, kid_len = 64, kid_b64_len = 128;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_datum_t x, y;
  gnutls_ecc_curve_t curve;
#endif
  
  if (jwk != NULL && pub != NULL) {
    switch (gnutls_pubkey_get_pk_algorithm(pub, &bits)) {
      case GNUTLS_PK_RSA:
        if ((res = gnutls_pubkey_export_rsa_raw(pub, &m, &e)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("RSA"));
          ret = R_OK;
          do {
            if (!o_base64url_encode(m.data, m.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (1)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (1)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (2)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (3)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (2)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (4)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_pubkey_get_key_id");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(m.data);
          gnutls_free(e.data);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_pubkey_export_rsa_raw");
          ret = R_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_pubkey_export_ecc_raw(pub, &curve, &x, &y)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = R_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (1)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (1)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (2)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (3)");
              ret = R_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (2)");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (4)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_string((const char *)b64_enc));
            switch (curve) {
              case GNUTLS_ECC_CURVE_SECP521R1:
                json_object_set_new(jwk, "crv", json_string("P-512"));
                break;
              case GNUTLS_ECC_CURVE_SECP384R1:
                json_object_set_new(jwk, "crv", json_string("P-384"));
                break;
              case GNUTLS_ECC_CURVE_SECP256R1:
                json_object_set_new(jwk, "crv", json_string("P-256"));
                break;
              default:
                y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error curve");
                ret = R_ERROR_PARAM;
                break;
            }
            if (ret != R_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error gnutls_pubkey_get_key_id");
              ret = R_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (5)");
              ret = R_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(y.data);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error gnutls_pubkey_export_ecc_raw");
          ret = R_ERROR_PARAM;
        }
        break;
#endif
      default:
        ret = R_ERROR_PARAM;
        break;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

int r_import_from_gnutls_x509_crt(jwk_t * jwk, gnutls_x509_crt_t crt) {
  int ret, res;
  gnutls_pubkey_t pub;
  unsigned char kid[64], kid_b64[128];
  size_t kid_len = 64, kid_b64_len = 128;
  
  if (jwk != NULL && crt != NULL) {
    if (!(res = gnutls_pubkey_init(&pub))) {
      if (!(res = gnutls_pubkey_import_x509(pub, crt, 0))) {
        ret = r_import_from_gnutls_pubkey(jwk, pub);
        if (ret == R_OK) {
          if (gnutls_x509_crt_get_key_id(crt, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_x509_crt_get_key_id");
            ret = R_ERROR;
          } else if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error o_base64url_encode");
            ret = R_ERROR;
          } else {
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_pubkey_import_x509");
        ret = R_ERROR_PARAM;
      }
      gnutls_pubkey_deinit(pub);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_pubkey_init");
      ret = R_ERROR;
    }
  } else {
    ret = R_ERROR_PARAM;
  }
  return ret;
}

char * r_export_to_json_str(jwk_t * jwk, int pretty) {
  char * str_export = NULL;
  if (jwk != NULL) {
    str_export = json_dumps(jwk, pretty?JSON_INDENT(2):JSON_COMPACT);
  }
  return str_export;
}

json_t * r_export_to_json_t(jwk_t * jwk) {
  if (jwk != NULL) {
    return json_deep_copy(jwk);
  } else {
    return NULL;
  }
}

gnutls_privkey_t r_export_to_gnutls_privkey(jwk_t * jwk) {
  gnutls_privkey_t privkey       = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_ecc_curve_t curve;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, d = {NULL, 0}, p = {NULL, 0}, q = {NULL, 0}, e1 = {NULL, 0}, e2 = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, k = {NULL, 0}, data = {NULL, 0};
  
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  int res, type = r_jwk_key_type(jwk);

  if (type & R_KEY_TYPE_PRIVATE) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
      // Export first x5c
      if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), NULL, &b64_dec_len)) {
        if ((b64_dec = o_malloc((b64_dec_len+1)*sizeof(char))) != NULL) {
          if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), b64_dec, &b64_dec_len)) {
            if (!gnutls_x509_privkey_init(&x509_key)) {
              if (!gnutls_privkey_init(&privkey)) {
                data.data = b64_dec;
                data.size = b64_dec_len;
                if (!gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_DER)) {
                  if ((res = gnutls_privkey_import_x509(privkey, x509_key, 0)) < 0) {
                    res = R_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_x509 rsa");
                    res = R_ERROR;
                    gnutls_privkey_deinit(privkey);
                    privkey = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_x509_privkey_import rsa");
                  res = R_ERROR;
                  gnutls_privkey_deinit(privkey);
                  privkey = NULL;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error gnutls_privkey_init");
                res = R_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init rsa");
              res = R_ERROR;
            }
            gnutls_x509_privkey_deinit(x509_key);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_base64_decode (2)");
            res = R_ERROR_MEMORY;
          }
          o_free(b64_dec);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_malloc");
          res = R_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_base64_decode (1)");
        res = R_ERROR_MEMORY;
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = R_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (n)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (n)");
          res = R_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (e)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (e)");
          res = R_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (d)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (d)");
          res = R_ERROR;
          break;
        }
        d.data = b64_dec;
        d.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "p"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (p)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (p)");
          res = R_ERROR;
          break;
        }
        p.data = b64_dec;
        p.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "q"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (q)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (q)");
          res = R_ERROR;
          break;
        }
        q.data = b64_dec;
        q.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dp"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (dp)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (dp)");
          res = R_ERROR;
          break;
        }
        e1.data = b64_dec;
        e1.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dq"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (dq)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (dq)");
          res = R_ERROR;
          break;
        }
        e2.data = b64_dec;
        e2.size = b64_dec_len;
        
        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init rsa");
          res = R_ERROR;
          break;
        }
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &e, &d, &p, &q, NULL, &e1, &e2)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_rsa_raw");
          res = R_ERROR;
          break;
        }
      } while (0);
      if (res != R_OK) {
        if (privkey != NULL) {
          gnutls_privkey_deinit(privkey);
          privkey = NULL;
        }
      }
      o_free(m.data);
      o_free(e.data);
      o_free(d.data);
      o_free(p.data);
      o_free(q.data);
      o_free(e1.data);
      o_free(e2.data);
    } else if (type & R_KEY_TYPE_ECDSA) {
      res = R_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (x)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (x)");
          res = R_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (y)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (y)");
          res = R_ERROR;
          break;
        }
        y.data = b64_dec;
        y.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (d)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (d)");
          res = R_ERROR;
          break;
        }
        k.data = b64_dec;
        k.size = b64_dec_len;

        if (0 == o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP521R1;
        } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP384R1;
        } else if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP256R1;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error crv data");
          res = R_ERROR;
          break;
        }

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init ec");
          res = R_ERROR;
          break;
        }
        if (gnutls_privkey_import_ecc_raw(privkey, curve, &x, &y, &k)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_ecc_raw");
          res = R_ERROR;
          break;
        }
      } while (0);
      if (res != R_OK) {
        if (privkey != NULL) {
          gnutls_privkey_deinit(privkey);
          privkey = NULL;
        }
      }
      o_free(x.data);
      o_free(y.data);
      o_free(k.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - invalid key format, expected 'RSA' or 'EC'");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - invalid key type, expected private key");
  }
  return privkey;
}

gnutls_pubkey_t r_export_to_gnutls_pubkey(jwk_t * jwk) {
  gnutls_pubkey_t pubkey = NULL;
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, data = {NULL, 0};
  int res, type = r_jwk_key_type(jwk);
  gnutls_ecc_curve_t curve;

  if (type & R_KEY_TYPE_PUBLIC) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
      // Export first x5c
      if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), NULL, &b64_dec_len)) {
        if ((b64_dec = o_malloc((b64_dec_len+1)*sizeof(char))) != NULL) {
          if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), b64_dec, &b64_dec_len)) {
            if (!gnutls_pubkey_init(&pubkey)) {
              data.data = b64_dec;
              data.size = b64_dec_len;
              if (!gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_DER)) {
                res = R_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_import rsa");
                res = R_ERROR;
                gnutls_pubkey_deinit(pubkey);
                pubkey = NULL;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_init rsa");
              res = R_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_base64_decode (2)");
            res = R_ERROR_MEMORY;
          }
          o_free(b64_dec);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_malloc");
          res = R_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_base64_decode (1)");
        res = R_ERROR_MEMORY;
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = R_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (n)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (n)");
          res = R_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (e)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (e)");
          res = R_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        
        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_privkey_init rsa");
          res = R_ERROR;
          break;
        }
        if (gnutls_pubkey_import_rsa_raw(pubkey, &m, &e)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_privkey_import_rsa_raw");
          res = R_ERROR;
          break;
        }
      } while (0);
      if (res != R_OK) {
        if (pubkey != NULL) {
          gnutls_pubkey_deinit(pubkey);
          pubkey = NULL;
        }
      }
      o_free(m.data);
      o_free(e.data);
    } else if (type & R_KEY_TYPE_ECDSA) {
      res = R_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (x)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (x)");
          res = R_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (y)");
          res = R_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (y)");
          res = R_ERROR;
          break;
        }
        y.data = b64_dec;
        y.size = b64_dec_len;

        if (0 == o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP521R1;
        } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP384R1;
        } else if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP256R1;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error crv data");
          res = R_ERROR;
          break;
        }

        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_init ec");
          res = R_ERROR;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_import_ecc_raw");
          res = R_ERROR;
          break;
        }
      } while (0);
      if (res != R_OK) {
        if (pubkey != NULL) {
          gnutls_pubkey_deinit(pubkey);
          pubkey = NULL;
        }
      }
      o_free(x.data);
      o_free(y.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error invalid key type");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error not public key");
  }
  return pubkey;
}

int r_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_privkey_t x509_privkey = NULL;
  int res, ret, type = r_jwk_key_type(jwk);
  
  if (type & R_KEY_TYPE_PRIVATE) {
    if ((privkey = r_export_to_gnutls_privkey(jwk)) != NULL) {
      if (!gnutls_privkey_export_x509(privkey, &x509_privkey)) {
        if (!(res = gnutls_x509_privkey_export(x509_privkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
          ret = R_OK;
        } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error buffer size");
          ret = R_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error gnutls_x509_privkey_export");
          ret = R_ERROR;
        }
        gnutls_x509_privkey_deinit(x509_privkey);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error gnutls_privkey_export_x509");
        ret = R_ERROR;
      }
      gnutls_privkey_deinit(privkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error r_export_to_gnutls_privkey");
      ret = R_ERROR;
    }
  } else if (type & R_KEY_TYPE_PUBLIC) {
    if ((pubkey = r_export_to_gnutls_pubkey(jwk)) != NULL) {
      if (!(res = gnutls_pubkey_export(pubkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
        ret = R_OK;
      } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error buffer size");
        ret = R_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error gnutls_pubkey_export");
        ret = R_ERROR;
      }
      gnutls_pubkey_deinit(pubkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error r_export_to_gnutls_pubkey");
      ret = R_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - invalid key type, exptected 'RSA' or 'EC'");
    ret = R_ERROR;
  }
  return ret;
}

const char * r_jwk_get_property_str(jwk_t * jwk, const char * key) {
  if (jwk != NULL && o_strlen(key)) {
    if (json_is_string(json_object_get(jwk, key))) {
      return json_string_value(json_object_get(jwk, key));
    } else {
      return NULL;
    }
  } else {
    return NULL;
  }
}

const char * r_jwk_get_property_array(jwk_t * jwk, const char * key, size_t index) {
  if (jwk != NULL && o_strlen(key)) {
    if (json_is_array(json_object_get(jwk, key))) {
      return json_string_value(json_array_get(json_object_get(jwk, key), index));
    } else {
      return NULL;
    }
  } else {
    return NULL;
  }
  return NULL;
}

int r_jwk_set_property_str(jwk_t * jwk, const char * key, const char * value) {
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
    if (!json_object_set_new(jwk, key, json_string(value))) {
      return R_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property str, error setting value");
      return R_ERROR;
    }
  } else {
    return R_ERROR_PARAM;
  }
}

int r_jwk_set_property_array(jwk_t * jwk, const char * key, size_t index, const char * value) {
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
    if ((json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) || (json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) <= index)) {
      return R_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL && !index) {
      if (!json_object_set_new(jwk, key, json_array()) && !json_array_append_new(json_object_get(jwk, key), json_string(value))) {
        return R_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error appending value");
        return R_ERROR;
      }
    } else  {
      if (!json_array_set_new(json_object_get(jwk, key), index, json_string(value))) {
        return R_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error setting value");
        return R_ERROR;
      }
    }
  } else {
    return R_ERROR_PARAM;
  }
}

int r_jwk_append_property_array(jwk_t * jwk, const char * key, const char * value) {
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
    if (json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) {
      return R_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL) {
      json_object_set_new(jwk, key, json_array());
    }
    if (!json_array_append_new(json_object_get(jwk, key), json_string(value))) {
      return R_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error setting value");
      return R_ERROR;
    }
  } else {
    return R_ERROR_PARAM;
  }
}

int r_jwk_delete_property_str(jwk_t * jwk, const char * key) {
  if (jwk != NULL && o_strlen(key)) {
    if (!json_object_del(jwk, key)) {
      return R_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy delete property str, error deleting value");
      return R_ERROR;
    }
  } else {
    return R_ERROR_PARAM;
  }
}

int r_jwk_delete_property_array_at(jwk_t * jwk, const char * key, size_t index) {
  if (jwk != NULL && o_strlen(key) && json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) > index) {
    if (!json_array_remove(json_object_get(jwk, key), index)) {
      return R_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy delete property array, error deleting index");
      return R_ERROR;
    }
  } else {
    return R_ERROR_PARAM;
  }
}
