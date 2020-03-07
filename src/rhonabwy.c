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
#include <ulfius.h>

int r_init_jwk(jwk_t ** jwk) {
  int ret;
  if (jwk != NULL) {
    *jwk = json_object();
    ret = (*jwk!=NULL)?RHN_OK:RHN_ERROR_MEMORY;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

void r_free_jwk(jwk_t * jwk) {
  if (jwk != NULL) {
    json_decref(jwk);
  }
}

int r_init_jwks(jwks_t ** jwks) {
  int ret;
  if (jwks != NULL) {
    *jwks = json_pack("{s[]}", "keys");
    ret = (*jwks!=NULL)?RHN_OK:RHN_ERROR_MEMORY;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

void r_free_jwks(jwks_t * jwks) {
  if (jwks != NULL) {
    json_decref(jwks);
  }
}

int r_jwk_is_valid(jwk_t * jwk) {
  int ret = RHN_OK, has_pubkey_parameters = 0, has_privkey_parameters = 0, has_kty = 0, has_alg = 0;
  json_t * j_element = NULL;
  size_t index = 0, b64dec_len = 0;
  
  if (jwk != NULL) {
    if (json_is_object(jwk)) {
      // JWK parameters
      if (json_object_get(jwk, "x5u") != NULL) {
        if (!json_is_array(json_object_get(jwk, "x5u"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5u");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "x5u"), index, j_element) {
            if (!json_string_length(j_element) || o_strncasecmp("https://", json_string_value(j_element), o_strlen("https://"))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5u");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "x5c") != NULL) {
        if (!json_is_array(json_object_get(jwk, "x5c"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5c");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "x5c"), index, j_element) {
            if (!json_string_length(j_element) || !o_base64_decode((const unsigned char *)json_string_value(j_element), json_string_length(j_element), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5c");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "kty") != NULL) {
        if (!json_string_length(json_object_get(jwk, "kty"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid kty");
          ret = RHN_ERROR_PARAM;
        }
        has_kty = 1;
      }
      if (json_object_get(jwk, "use") != NULL && !json_is_string(json_object_get(jwk, "use"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid use");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "key_ops") != NULL) {
        if (!json_is_array(json_object_get(jwk, "key_ops"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid key_ops");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "key_ops"), index, j_element) {
            if (!json_string_length(j_element)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid key_ops");
              ret = RHN_ERROR_PARAM;
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
          ret = RHN_ERROR_PARAM;
        }
        has_alg = 1;
      }
      if (json_object_get(jwk, "kid") != NULL && !json_is_string(json_object_get(jwk, "kid"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid kid");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t") != NULL && !json_is_string(json_object_get(jwk, "x5t"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5t");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t#S256") != NULL && !json_is_string(json_object_get(jwk, "x5t#S256"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x5t#S256");
        ret = RHN_ERROR_PARAM;
      }
      
      // JWA parameters validation
      if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "EC")) {
        if (json_object_get(jwk, "crv")) {
          if (0 != o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv")))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid crv");
            ret = RHN_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "x"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x");
          ret = RHN_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid x format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (!json_string_length(json_object_get(jwk, "y"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid y");
          ret = RHN_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid y format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d");
            ret = RHN_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
            has_privkey_parameters = 1;
          }
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "RSA")) {
        if (!json_string_length(json_object_get(jwk, "n"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid n");
          ret = RHN_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid n format");
            ret = RHN_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "e"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid e");
          ret = RHN_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid e format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d");
            ret = RHN_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
          }
          has_privkey_parameters = 1;
        }
        if (json_object_get(jwk, "p") != NULL) {
          if (!json_string_length(json_object_get(jwk, "p"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid p");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "q") != NULL) {
          if (!json_string_length(json_object_get(jwk, "q"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid q");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid q format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dp") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dp"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dp");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dp format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dq") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dq"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dq");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid dq format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "qi") != NULL) {
          if (!json_string_length(json_object_get(jwk, "qi"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid qi");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "qi")), json_string_length(json_object_get(jwk, "qi")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid qi format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "oth") != NULL) {
          ret = RHN_ERROR_UNSUPPORTED;
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct")) {
        if (!json_string_length(json_object_get(jwk, "k"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid k");
          ret = RHN_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "k")), json_string_length(json_object_get(jwk, "k")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid k format");
            ret = RHN_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
      }
      
      // Validate if required parameters are present and consistent
      if (ret == RHN_OK) {
        if (!has_kty) {
          if (!has_alg) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - Invalid data");
            ret = RHN_ERROR_PARAM;
          }
        } else {
          if (has_kty && !has_pubkey_parameters) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy r_jwk_is_valid - public key parameters missing");
            ret = RHN_ERROR_PARAM;
          }
        }
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_is_valid(jwks_t * jwks) {
  int ret;
  json_t * jwk = NULL;
  size_t index = 0;
  
  if (jwks != NULL) {
    if (json_array_size(json_object_get(jwks, "keys"))) {
      json_array_foreach(json_object_get(jwks, "keys"), index, jwk) {
        if ((ret = r_jwk_is_valid(jwk)) != RHN_OK) {
          break;
        }
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_key_type(jwk_t * jwk, int x5u_flags) {
  gnutls_x509_crt_t crt          = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_pubkey_t pubkey         = NULL;
  gnutls_datum_t data;
  int ret = R_KEY_TYPE_NONE, pk_alg;
  unsigned char * data_dec = NULL;
  size_t data_dec_len = 0;
  
  struct _u_request request;
  struct _u_response response;

  if (r_jwk_is_valid(jwk) == RHN_OK) {
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
                  if (!gnutls_pubkey_init(&pubkey)) {
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
                    } else if (!gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_DER)) {
                      pk_alg = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
                      if (pk_alg == GNUTLS_PK_RSA) {
                        ret = R_KEY_TYPE_RSA;
                      } else if (pk_alg == GNUTLS_PK_RSA) {
                        ret = R_KEY_TYPE_ECDSA;
                      }
                      ret |= R_KEY_TYPE_PUBLIC;
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls import");
                      ret = RHN_ERROR;
                    }
                    gnutls_pubkey_deinit(pubkey);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls_pubkey_init");
                    ret = RHN_ERROR;
                  }
                  gnutls_x509_privkey_deinit(x509_key);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls_x509_privkey_init");
                  ret = RHN_ERROR;
                }
                gnutls_x509_crt_deinit(crt);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls_x509_crt_init");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error o_base64_decode (2)");
              ret = RHN_ERROR;
            }
            o_free(data_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error o_malloc");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error o_base64_decode (1)");
          ret = RHN_ERROR;
        }
    } else if (json_object_get(jwk, "x5u") != NULL) {
      // Get first x5u
      if (ulfius_init_request(&request) == U_OK) {
        if (ulfius_init_response(&response) == U_OK) {
          request.http_verb = o_strdup("GET");
          request.http_url = o_strdup(json_string_value(json_array_get(json_object_get(jwk, "x5u"), 0)));
          request.check_server_certificate = !(x5u_flags&R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE);
          request.follow_redirect = x5u_flags&R_X5U_FLAG_FOLLOW_REDIRECT;
          if (ulfius_send_http_request(&request, &response) == U_OK && response.status >= 200 && response.status < 300) {
            data.data = response.binary_body;
            data.size = response.binary_body_length;
            if (!gnutls_x509_crt_init(&crt)) {
              if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
                if (pk_alg == GNUTLS_PK_RSA) {
                  ret = R_KEY_TYPE_RSA;
#if GNUTLS_VERSION_NUMBER >= 0x030600
                } else if (pk_alg == GNUTLS_PK_ECDSA) {
                  ret = R_KEY_TYPE_ECDSA;
#endif
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error unsupported algorithm %s", gnutls_pk_algorithm_get_name(pk_alg));
                }
                ret |= R_KEY_TYPE_PUBLIC;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error gnutls_x509_crt_import");
                ret = RHN_ERROR;
              }
              gnutls_x509_crt_deinit(crt);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error gnutls_x509_crt_init");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_send_http_request %d", response.status);
            ret = RHN_ERROR_MEMORY;
          }
          ulfius_clean_request(&request);
          ulfius_clean_response(&response);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_init_response");
          ret = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_init_request");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      ret = R_KEY_TYPE_HMAC|R_KEY_TYPE_SYMMETRIC;
    }
  }
  return ret;
}

int r_jwk_import_from_json_str(jwk_t * jwk, const char * input) {
  int ret;
  json_t * jwk_input;
  
  if (input != NULL && jwk != NULL) {
    if ((jwk_input = json_loads(input, JSON_DECODE_ANY, NULL)) != NULL) {
      ret = r_jwk_import_from_json_t(jwk, jwk_input);
    } else {
      ret = RHN_ERROR_PARAM;
    }
    json_decref(jwk_input);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_json_t(jwk_t * jwk, json_t * j_input) {
  int ret;
  
  if (j_input != NULL && json_is_object(j_input)) {
    if (!json_object_update(jwk, j_input)) {
      ret = r_jwk_is_valid(jwk);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error json_object_update");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_pem_der(jwk_t * jwk, int type, int format, const unsigned char * input, size_t input_len) {
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
            ret = r_jwk_import_from_gnutls_pubkey(jwk, pub);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error r_jwk_import_from_gnutls_pubkey: %s", gnutls_strerror(res));
            ret = RHN_ERROR;
          }
          gnutls_pubkey_deinit(pub);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_pubkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        break;
      case R_X509_TYPE_PRIVKEY:
        if ((res = gnutls_privkey_init(&key)) < 0) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_privkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        } else if ((res = gnutls_x509_privkey_init(&x509_key)) < 0) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_privkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        } else {
          data.data = (unsigned char *)input;
          data.size = input_len;
          if ((res = gnutls_x509_privkey_import(x509_key, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER)) < 0) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_privkey_import: %s", gnutls_strerror(res));
            ret = RHN_ERROR_PARAM;
          } else if ((res = gnutls_privkey_import_x509(key, x509_key, 0)) < 0) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_privkey_import_x509: %s", gnutls_strerror(res));
            ret = RHN_ERROR;
          } else {
            ret = r_jwk_import_from_gnutls_privkey(jwk, key);
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
            ret = r_jwk_import_from_gnutls_x509_crt(jwk, crt);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error r_jwk_import_from_gnutls_x509_crt: %s", gnutls_strerror(res));
            ret = RHN_ERROR_PARAM;
          }
          gnutls_x509_crt_deinit(crt);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_x509_crt_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error invalid type");
        ret = RHN_ERROR_PARAM;
        break;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_gnutls_privkey(jwk_t * jwk, gnutls_privkey_t key) {
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
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(m.data, m.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(d.data, d.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (3)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(d.data, d.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (6)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(p.data, p.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (7)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (4)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(p.data, p.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (8)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "p", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(q.data, q.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (9)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (5)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(q.data, q.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (10)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "q", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(u.data, u.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (11)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (6)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(u.data, u.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (12)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "qi", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e1.data, e1.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (13)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (7)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e1.data, e1.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (14)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dp", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e2.data, e2.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (15)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (8)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e2.data, e2.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (16)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dq", json_string((const char *)b64_enc));
            
            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
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
          ret = RHN_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_privkey_export_ecc_raw(key, &curve, &x, &y, &k)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(k.data, k.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (3)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(k.data, k.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (6)");
              ret = RHN_ERROR;
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
                ret = RHN_ERROR_PARAM;
                break;
            }

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
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
          ret = RHN_ERROR_PARAM;
        }
        break;
#endif
      default:
        ret = RHN_ERROR_PARAM;
        break;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_gnutls_pubkey(jwk_t * jwk, gnutls_pubkey_t pub) {
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
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(m.data, m.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(m.data);
          gnutls_free(e.data);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import - Error gnutls_pubkey_export_rsa_raw");
          ret = RHN_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_pubkey_export_ecc_raw(pub, &curve, &x, &y)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
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
                ret = RHN_ERROR_PARAM;
                break;
            }
            if (ret != RHN_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(y.data);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import ecdsa - Error gnutls_pubkey_export_ecc_raw");
          ret = RHN_ERROR_PARAM;
        }
        break;
#endif
      default:
        ret = RHN_ERROR_PARAM;
        break;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_gnutls_x509_crt(jwk_t * jwk, gnutls_x509_crt_t crt) {
  int ret, res;
  gnutls_pubkey_t pub;
  unsigned char kid[64], kid_b64[128];
  size_t kid_len = 64, kid_b64_len = 128;
  
  if (jwk != NULL && crt != NULL) {
    if (!(res = gnutls_pubkey_init(&pub))) {
      if (!(res = gnutls_pubkey_import_x509(pub, crt, 0))) {
        ret = r_jwk_import_from_gnutls_pubkey(jwk, pub);
        if (ret == RHN_OK) {
          if (gnutls_x509_crt_get_key_id(crt, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_x509_crt_get_key_id");
            ret = RHN_ERROR;
          } else if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error o_base64url_encode");
            ret = RHN_ERROR;
          } else {
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_pubkey_import_x509");
        ret = RHN_ERROR_PARAM;
      }
      gnutls_pubkey_deinit(pub);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "rhonabwy import x509 - Error gnutls_pubkey_init");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

char * r_jwk_export_to_json_str(jwk_t * jwk, int pretty) {
  char * str_jwk_export = NULL;
  if (jwk != NULL) {
    str_jwk_export = json_dumps(jwk, pretty?JSON_INDENT(2):JSON_COMPACT);
  }
  return str_jwk_export;
}

json_t * r_jwk_export_to_json_t(jwk_t * jwk) {
  if (json_object_size(jwk)) {
    return json_deep_copy(jwk);
  } else {
    return NULL;
  }
}

gnutls_privkey_t r_jwk_export_to_gnutls_privkey(jwk_t * jwk, int x5u_flags) {
  gnutls_privkey_t privkey       = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_ecc_curve_t curve;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, d = {NULL, 0}, p = {NULL, 0}, q = {NULL, 0}, e1 = {NULL, 0}, e2 = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, k = {NULL, 0}, data = {NULL, 0};
  
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  int res, type = r_jwk_key_type(jwk, x5u_flags);
  
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
                    res = RHN_OK;
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_x509 rsa");
                    res = RHN_ERROR;
                    gnutls_privkey_deinit(privkey);
                    privkey = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_x509_privkey_import rsa");
                  res = RHN_ERROR;
                  gnutls_privkey_deinit(privkey);
                  privkey = NULL;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error gnutls_privkey_init");
                res = RHN_ERROR_MEMORY;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init rsa");
              res = RHN_ERROR;
            }
            gnutls_x509_privkey_deinit(x509_key);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_base64_decode (2)");
            res = RHN_ERROR_MEMORY;
          }
          o_free(b64_dec);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_malloc");
          res = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey x5c - Error o_base64_decode (1)");
        res = RHN_ERROR_MEMORY;
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (n)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (n)");
          res = RHN_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (e)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (e)");
          res = RHN_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (d)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (d)");
          res = RHN_ERROR;
          break;
        }
        d.data = b64_dec;
        d.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "p"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (p)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (p)");
          res = RHN_ERROR;
          break;
        }
        p.data = b64_dec;
        p.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "q"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (q)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (q)");
          res = RHN_ERROR;
          break;
        }
        q.data = b64_dec;
        q.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dp"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (dp)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (dp)");
          res = RHN_ERROR;
          break;
        }
        e1.data = b64_dec;
        e1.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dq"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (dq)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (dq)");
          res = RHN_ERROR;
          break;
        }
        e2.data = b64_dec;
        e2.size = b64_dec_len;
        
        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &e, &d, &p, &q, NULL, &e1, &e2)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_rsa_raw");
          res = RHN_ERROR;
          break;
        }
      } while (0);
      if (res != RHN_OK) {
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
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (y)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (y)");
          res = RHN_ERROR;
          break;
        }
        y.data = b64_dec;
        y.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error malloc (d)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error o_base64url_decode (d)");
          res = RHN_ERROR;
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
          res = RHN_ERROR;
          break;
        }

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_ecc_raw(privkey, curve, &x, &y, &k)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey - Error gnutls_privkey_import_ecc_raw");
          res = RHN_ERROR;
          break;
        }
      } while (0);
      if (res != RHN_OK) {
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

gnutls_pubkey_t r_jwk_export_to_gnutls_pubkey(jwk_t * jwk, int x5u_flags) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t crt;
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, data = {NULL, 0};
  int res, type = r_jwk_key_type(jwk, x5u_flags);
  gnutls_ecc_curve_t curve;

  struct _u_request request;
  struct _u_response response;

  if (type & R_KEY_TYPE_PUBLIC) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL || json_array_get(json_object_get(jwk, "x5u"), 0) != NULL)) {
      if (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
        // Export first x5c
        if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), NULL, &b64_dec_len)) {
          if ((b64_dec = o_malloc((b64_dec_len+1)*sizeof(char))) != NULL) {
            if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), b64_dec, &b64_dec_len)) {
              if (!gnutls_pubkey_init(&pubkey)) {
                data.data = b64_dec;
                data.size = b64_dec_len;
                if (!gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_DER)) {
                  res = RHN_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error gnutls_pubkey_import rsa");
                  res = RHN_ERROR;
                  gnutls_pubkey_deinit(pubkey);
                  pubkey = NULL;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error gnutls_pubkey_init rsa");
                res = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_base64_decode (2)");
              res = RHN_ERROR_MEMORY;
            }
            o_free(b64_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_malloc");
            res = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5c - Error o_base64_decode (1)");
          res = RHN_ERROR_MEMORY;
        }
      } else {
        // Get first x5u
        if (ulfius_init_request(&request) == U_OK) {
          if (ulfius_init_response(&response) == U_OK) {
            request.http_verb = o_strdup("GET");
            request.http_url = o_strdup(json_string_value(json_array_get(json_object_get(jwk, "x5u"), 0)));
            request.check_server_certificate = !(x5u_flags&R_X5U_FLAG_IGNORE_SERVER_CERTIFICATE);
            request.follow_redirect = x5u_flags&R_X5U_FLAG_FOLLOW_REDIRECT;
            if (ulfius_send_http_request(&request, &response) == U_OK && response.status >= 200 && response.status < 300) {
              if (!gnutls_x509_crt_init(&crt)) {
                if (!gnutls_pubkey_init(&pubkey)) {
                  data.data = response.binary_body;
                  data.size = response.binary_body_length;
                  if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                    if (!gnutls_pubkey_import_x509(pubkey, crt, 0)) {
                      res = RHN_OK;
                    } else {
                      gnutls_pubkey_deinit(pubkey);
                      pubkey = NULL;
                      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error gnutls_pubkey_import_x509");
                      res = RHN_ERROR;
                    }
                  } else {
                    gnutls_pubkey_deinit(pubkey);
                    pubkey = NULL;
                    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error gnutls_pubkey_import");
                    res = RHN_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error gnutls_pubkey_init rsa");
                  res = RHN_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error gnutls_x509_crt_init");
                res = RHN_ERROR;
              }
              gnutls_x509_crt_deinit(crt);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error ulfius_send_http_request");
              res = RHN_ERROR_MEMORY;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error ulfius_init_response");
            res = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey x5u - Error ulfius_init_request");
          res = RHN_ERROR_MEMORY;
        }
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (n)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (n)");
          res = RHN_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (e)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (e)");
          res = RHN_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        
        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_rsa_raw(pubkey, &m, &e)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_privkey_import_rsa_raw");
          res = RHN_ERROR;
          break;
        }
      } while (0);
      if (res != RHN_OK) {
        if (pubkey != NULL) {
          gnutls_pubkey_deinit(pubkey);
          pubkey = NULL;
        }
      }
      o_free(m.data);
      o_free(e.data);
    } else if (type & R_KEY_TYPE_ECDSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error malloc (y)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error o_base64url_decode (y)");
          res = RHN_ERROR;
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
          res = RHN_ERROR;
          break;
        }

        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey - Error gnutls_pubkey_import_ecc_raw");
          res = RHN_ERROR;
          break;
        }
      } while (0);
      if (res != RHN_OK) {
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

int r_jwk_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len, int x5u_flags) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_privkey_t x509_privkey = NULL;
  int res, ret, type = r_jwk_key_type(jwk, x5u_flags);
  int test_size = (output==NULL);
  
  if (type & R_KEY_TYPE_PRIVATE) {
    if ((privkey = r_jwk_export_to_gnutls_privkey(jwk, x5u_flags)) != NULL) {
      if (!gnutls_privkey_export_x509(privkey, &x509_privkey)) {
        if (!(res = gnutls_x509_privkey_export(x509_privkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
          ret = RHN_OK;
        } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
          if (!test_size) {
            y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey pem der - Error buffer size");
          }
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey pem der - Error gnutls_x509_privkey_export");
          ret = RHN_ERROR;
        }
        gnutls_x509_privkey_deinit(x509_privkey);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export privkey pem der - Error gnutls_privkey_export_x509");
        ret = RHN_ERROR;
      }
      gnutls_privkey_deinit(privkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error r_jwk_export_to_gnutls_privkey");
      ret = RHN_ERROR;
    }
  } else if (type & R_KEY_TYPE_PUBLIC) {
    if ((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
      if (!(res = gnutls_pubkey_export(pubkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
        ret = RHN_OK;
      } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        if (!test_size) {
          y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error buffer size");
        }
        ret = RHN_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error gnutls_pubkey_export");
        ret = RHN_ERROR;
      }
      gnutls_pubkey_deinit(pubkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - Error r_jwk_export_to_gnutls_pubkey");
      ret = RHN_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy export pubkey pem der - invalid key type, exptected 'RSA' or 'EC'");
    ret = RHN_ERROR;
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
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property str, error setting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_set_property_array(jwk_t * jwk, const char * key, size_t index, const char * value) {
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
    if ((json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) || (json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) <= index)) {
      return RHN_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL && !index) {
      if (!json_object_set_new(jwk, key, json_array()) && !json_array_append_new(json_object_get(jwk, key), json_string(value))) {
        return RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error appending value");
        return RHN_ERROR;
      }
    } else  {
      if (!json_array_set_new(json_object_get(jwk, key), index, json_string(value))) {
        return RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error setting value");
        return RHN_ERROR;
      }
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_append_property_array(jwk_t * jwk, const char * key, const char * value) {
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
    if (json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) {
      return RHN_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL) {
      json_object_set_new(jwk, key, json_array());
    }
    if (!json_array_append_new(json_object_get(jwk, key), json_string(value))) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy set property array, error setting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_delete_property_str(jwk_t * jwk, const char * key) {
  if (jwk != NULL && o_strlen(key)) {
    if (!json_object_del(jwk, key)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy delete property str, error deleting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_delete_property_array_at(jwk_t * jwk, const char * key, size_t index) {
  if (jwk != NULL && o_strlen(key) && json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) > index) {
    if (!json_array_remove(json_object_get(jwk, key), index)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy delete property array, error deleting index");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

size_t r_jwks_size(jwks_t * jwks) {
  if (jwks != NULL) {
    return json_array_size(json_object_get(jwks, "keys"));
  } else {
    return 0;
  }
}

jwk_t * r_jwks_get_at(jwks_t * jwks, size_t index) {
  if (jwks != NULL) {
    return json_deep_copy(json_array_get(json_object_get(jwks, "keys"), index));
  } else {
    return NULL;
  }
}

int r_jwks_append_jwk(jwks_t * jwks, jwk_t * jwk) {
  if (jwks != NULL) {
    if (!json_array_append(json_object_get(jwks, "keys"), jwk)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy jwks append - error json_array_append");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwks_set_at(jwks_t * jwks, size_t index, jwk_t * jwk) {
  if (jwks != NULL) {
    if (!json_array_set(json_object_get(jwks, "keys"), index, jwk)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy jwks append - error json_array_set");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwks_remove_at(jwks_t * jwks, size_t index) {
  if (jwks != NULL) {
    if (!json_array_remove(json_object_get(jwks, "keys"), index)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy jwks append - error json_array_remove");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

char * r_jwks_export_to_json_str(jwks_t * jwks, int pretty) {
  char * str_jwk_export = NULL;
  if (jwks != NULL) {
    str_jwk_export = json_dumps(jwks, pretty?JSON_INDENT(2):JSON_COMPACT);
  }
  return str_jwk_export;
}

json_t * r_jwks_export_to_json_t(jwks_t * jwks) {
  if (jwks != NULL) {
    return json_deep_copy(jwks);
  } else {
    return NULL;
  }
}

gnutls_privkey_t * r_jwks_export_to_gnutls_privkey(jwks_t * jwks, size_t * len, int x5u_flags) {
  gnutls_privkey_t * ret = NULL;
  size_t i;
  
  if (jwks != NULL && len != NULL && r_jwks_size(jwks)) {
    if ((ret = o_malloc(r_jwks_size(jwks)*sizeof(gnutls_privkey_t))) != NULL) {
      *len = r_jwks_size(jwks);
      for (i=0; i<(*len); i++) {
        if ((ret[i] = r_jwk_export_to_gnutls_privkey(r_jwks_get_at(jwks, i), x5u_flags)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks export privkey - Error exporting privkey at index %zu", i);
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks export privkey - Error allocating resources for ret");
    }
  }
  return ret;
}

gnutls_pubkey_t * r_jwks_export_to_gnutls_pubkey(jwks_t * jwks, size_t * len, int x5u_flags) {
  gnutls_pubkey_t * ret = NULL;
  size_t i;
  
  if (jwks != NULL && len != NULL && r_jwks_size(jwks)) {
    if ((ret = o_malloc(r_jwks_size(jwks)*sizeof(gnutls_pubkey_t))) != NULL) {
      *len = r_jwks_size(jwks);
      for (i=0; i<(*len); i++) {
        if ((ret[i] = r_jwk_export_to_gnutls_pubkey(r_jwks_get_at(jwks, i), x5u_flags)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks export pubkey - Error exporting pubkey at index %zu", i);
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks export pubkey - Error allocating resources for ret");
    }
  }
  return ret;
}

int r_jwks_export_to_pem_der(jwks_t * jwks, int format, unsigned char * output, size_t * output_len, int x5u_flags) {
  size_t array_len, i, cur_len;
  unsigned char * cur_output = output;
  int ret;

  if (jwks != NULL && output != NULL && output_len != NULL && (array_len = r_jwks_size(jwks))) {
    cur_len = *output_len;
    for (i=0; i<array_len; i++) {
      if ((ret = r_jwk_export_to_pem_der(r_jwks_get_at(jwks, i), format, cur_output, &cur_len, x5u_flags)) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks export pem der - Error exporting key at index %zu", i);
        break;
      } else {
        cur_output += cur_len;
        *output_len -= cur_len;
        cur_len = *output_len;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_import_from_str(jwks_t * jwks, const char * input) {
  json_t * j_input;
  int ret;
  if (jwks != NULL && input != NULL) {
    j_input = json_loads(input, JSON_DECODE_ANY, NULL);
    if (j_input != NULL) {
      if (json_array_size(json_object_get(j_input, "keys"))) {
        ret = r_jwks_import_from_json_t(jwks, j_input);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks import str - Invalid JWKS format");
        ret = RHN_ERROR_PARAM;
      }
      json_decref(j_input);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks import str - Error parsing input");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_import_from_json_t(jwks_t * jwks, json_t * j_input) {
  int ret = RHN_OK, res;
  size_t index = 0;
  json_t * j_jwk = NULL;
  jwk_t * jwk = NULL;
  
  if (jwks != NULL && j_input != NULL) {
    json_array_foreach(json_object_get(j_input, "keys"), index, j_jwk) {
      if (r_init_jwk(&jwk) == RHN_OK) {
        if ((res = r_jwk_import_from_json_t(jwk, j_jwk)) == RHN_OK) {
          r_jwks_append_jwk(jwks, jwk);
        } else if (res == RHN_ERROR_PARAM) {
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks import json_t - Error r_jwk_import_from_json_t");
          ret = RHN_ERROR;
        }
        r_free_jwk(jwk);
      } else {
        ret = RHN_ERROR_MEMORY;
        break;
      }
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_import_from_uri(jwks_t * jwks, const char * uri) {
  struct _u_request req;
  struct _u_response resp;
  int ret;
  json_t * j_result;
  
  if (jwks != NULL && uri != NULL) {
    if (ulfius_init_request(&req) == U_OK && ulfius_init_response(&resp) == U_OK) {
      req.http_url = o_strdup(uri);
      if (ulfius_send_http_request(&req, &resp) == U_OK) {
        if (resp.status >= 200 && resp.status < 300) {
          j_result = ulfius_get_json_body_response(&resp, NULL);
          if (j_result != NULL) {
            ret = r_jwks_import_from_json_t(jwks, j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "jwks import uri - Error ulfius_get_json_body_response");
            ret = RHN_ERROR;
          }
          json_decref(j_result);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks import uri - Error ulfius_send_http_request");
        ret = RHN_ERROR;
      }
      ulfius_clean_request(&req);
      ulfius_clean_response(&resp);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks import uri - Error ulfius_init_request or ulfius_init_response");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}
