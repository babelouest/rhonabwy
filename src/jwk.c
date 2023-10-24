/**
 *
 * Rhonabwy JSON Web Key (JWK) library
 *
 * jwk.c: functions definitions
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
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define RHN_PEM_HEADER_CERT            "-----BEGIN CERTIFICATE-----"
#define RHN_PEM_HEADER_PUBKEY          "-----BEGIN PUBLIC KEY-----"
#define RHN_PEM_HEADER_PRIVKEY         "-----BEGIN PRIVATE KEY-----"
#define RHN_PEM_HEADER_EC_PRIVKEY      "-----BEGIN EC PRIVATE KEY-----"
#define RHN_PEM_HEADER_RSA_PRIVKEY     "-----BEGIN RSA PRIVATE KEY-----"
#define RHN_PEM_HEADER_UNKNOWN_PRIVKEY "-----BEGIN UNKNOWN-----"

int _r_get_http_content(const char * url, int x5u_flags, const char * expected_content_type, struct _o_datum * datum);

#if NETTLE_VERSION_NUMBER >= 0x030600
#include <nettle/curve25519.h>
#include <nettle/curve448.h>
#endif

int r_jwk_init(jwk_t ** jwk) {
  int ret;
  if (jwk != NULL) {
    *jwk = json_object();
    ret = (*jwk!=NULL)?RHN_OK:RHN_ERROR_MEMORY;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

void r_jwk_free(jwk_t * jwk) {
  if (jwk != NULL) {
    json_decref(jwk);
  }
}

int r_jwk_is_valid(jwk_t * jwk) {
  int ret = RHN_OK, has_privkey_parameters = 0, type_x5c, is_x5_key = 0;
  json_t * j_element = NULL;
  const char * n, * e, * x, * y;
  size_t index = 0, b64dec_len = 0;
  jwk_t * jwk_x5c = NULL;
  gnutls_pubkey_t pubkey = NULL;
  gnutls_x509_crt_t crt  = NULL;
  gnutls_datum_t data;
  struct _o_datum dat = {0, NULL};

  if (jwk != NULL) {
    if (json_is_object(jwk)) {
      // JWK parameters
      if (json_object_get(jwk, "x5u") != NULL) {
        if (!json_is_string(json_object_get(jwk, "x5u")) || o_strncasecmp("https://", json_string_value(json_object_get(jwk, "x5u")), o_strlen("https://"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5u");
          ret = RHN_ERROR_PARAM;
        }
        is_x5_key = 1;
      }
      if (json_object_get(jwk, "x5c") != NULL) {
        is_x5_key = 1;
        if (!json_is_array(json_object_get(jwk, "x5c"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "x5c"), index, j_element) {
            if (!json_string_length(j_element) || !o_base64_decode((const unsigned char *)json_string_value(j_element), json_string_length(j_element), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c");
              ret = RHN_ERROR_PARAM;
            }
          }
          if ((j_element = json_array_get(json_object_get(jwk, "x5c"), 0)) != NULL) {
            if (json_string_length(j_element) && o_base64_decode_alloc((const unsigned char *)json_string_value(j_element), json_string_length(j_element), &dat)) {
              if (!gnutls_x509_crt_init(&crt)) {
                if (!gnutls_pubkey_init(&pubkey)) {
                  data.data = dat.data;
                  data.size = (unsigned int)dat.size;
                  if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
                    if (gnutls_pubkey_import_x509(pubkey, crt, 0)) {
                      gnutls_pubkey_deinit(pubkey);
                      pubkey = NULL;
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Error gnutls_pubkey_import_x509");
                      ret = RHN_ERROR_PARAM;
                    }
                  } else {
                    gnutls_pubkey_deinit(pubkey);
                    pubkey = NULL;
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Error gnutls_pubkey_import");
                    ret = RHN_ERROR_PARAM;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Error gnutls_pubkey_init rsa");
                  ret = RHN_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Error gnutls_x509_crt_init");
                ret = RHN_ERROR;
              }
              gnutls_x509_crt_deinit(crt);
              if (pubkey != NULL) {
                if (r_jwk_init(&jwk_x5c) == RHN_OK) {
                  if (r_jwk_import_from_gnutls_pubkey(jwk_x5c, pubkey) == RHN_OK) {
                    type_x5c = r_jwk_key_type(jwk_x5c, NULL, 0);
                    if (type_x5c & R_KEY_TYPE_RSA) {
                      if (0 != o_strcmp("RSA", r_jwk_get_property_str(jwk, "kty"))) {
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c key type");
                        ret = RHN_ERROR_PARAM;
                      }
                      if ((n = r_jwk_get_property_str(jwk, "n")) != NULL && (e = r_jwk_get_property_str(jwk, "e")) != NULL) {
                        if (0 != o_strcmp(n, r_jwk_get_property_str(jwk_x5c, "n")) || 0 != o_strcmp(e, r_jwk_get_property_str(jwk_x5c, "e"))) {
                          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwk_is_valid - Invalid x5c leaf rsa parameters");
                        }
                      }
                    } else if (type_x5c & R_KEY_TYPE_EC) {
                      if (0 != o_strcmp("EC", r_jwk_get_property_str(jwk, "kty")) || 0 != o_strcmp(r_jwk_get_property_str(jwk, "crv"), r_jwk_get_property_str(jwk_x5c, "crv"))) {
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c key type");
                        ret = RHN_ERROR_PARAM;
                      }
                      if ((x = r_jwk_get_property_str(jwk, "x")) != NULL && (y = r_jwk_get_property_str(jwk, "y")) != NULL) {
                        if (0 != o_strcmp(x, r_jwk_get_property_str(jwk_x5c, "x")) || 0 != o_strcmp(y, r_jwk_get_property_str(jwk_x5c, "y"))) {
                          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwk_is_valid - Invalid x5c leaf ec parameters");
                        }
                      }
                    } else if (type_x5c & R_KEY_TYPE_EDDSA) {
                      if (0 != o_strcmp("OKP", r_jwk_get_property_str(jwk, "kty")) || 0 != o_strcmp(r_jwk_get_property_str(jwk, "crv"), r_jwk_get_property_str(jwk_x5c, "crv"))) {
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c key type");
                        ret = RHN_ERROR_PARAM;
                      }
                      if ((x = r_jwk_get_property_str(jwk, "x")) != NULL) {
                        if (0 != o_strcmp(x, r_jwk_get_property_str(jwk_x5c, "x"))) {
                          y_log_message(Y_LOG_LEVEL_DEBUG, "r_jwk_is_valid - Invalid x5c leaf ec parameters");
                        }
                      }
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5c leaf");
                    ret = RHN_ERROR_PARAM;
                  }
                }
                r_jwk_free(jwk_x5c);
                gnutls_pubkey_deinit(pubkey);
              }
              o_free(dat.data);
            }
          }
        }
      }
      if (!json_string_length(json_object_get(jwk, "kty"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Missing kty");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "use") != NULL && !json_is_string(json_object_get(jwk, "use"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid use");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "key_ops") != NULL) {
        if (!json_is_array(json_object_get(jwk, "key_ops"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid key_ops");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "key_ops"), index, j_element) {
            if (!json_string_length(j_element)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid key_ops");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "alg") != NULL) {
        if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct")) {
          if (r_str_to_jwa_enc(json_string_value(json_object_get(jwk, "alg"))) == R_JWA_ENC_UNKNOWN && r_str_to_jwa_alg(json_string_value(json_object_get(jwk, "alg"))) == R_JWA_ALG_UNKNOWN) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid oct alg value: '%s'", json_string_value(json_object_get(jwk, "alg")));
            ret = RHN_ERROR_PARAM;
          }
        } else {
          if (r_str_to_jwa_alg(json_string_value(json_object_get(jwk, "alg"))) == R_JWA_ALG_UNKNOWN) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid alg alg value: '%s'", json_string_value(json_object_get(jwk, "alg")));
            ret = RHN_ERROR_PARAM;
          }
        }
      }
      if (json_object_get(jwk, "kid") != NULL && !json_is_string(json_object_get(jwk, "kid"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid kid");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t") != NULL && !json_is_string(json_object_get(jwk, "x5t"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5t");
        ret = RHN_ERROR_PARAM;
      }
      if (json_object_get(jwk, "x5t#S256") != NULL && !json_is_string(json_object_get(jwk, "x5t#S256"))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5t#S256");
        ret = RHN_ERROR_PARAM;
      }

      // JWA parameters validation
      if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "EC")) {
        if (json_object_get(jwk, "crv") != NULL) {
          if (0 != o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-521", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("secp256k1", json_string_value(json_object_get(jwk, "crv")))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid EC crv value: '%s'", json_string_value(json_object_get(jwk, "crv")));
            ret = RHN_ERROR_PARAM;
          }
        }
        if (!is_x5_key && !json_string_length(json_object_get(jwk, "x"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x");
          ret = RHN_ERROR_PARAM;
        } else if (json_string_length(json_object_get(jwk, "x"))) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (!is_x5_key && !json_string_length(json_object_get(jwk, "y"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid y");
          ret = RHN_ERROR_PARAM;
        } else if (json_string_length(json_object_get(jwk, "y"))) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid y format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d");
            ret = RHN_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
            has_privkey_parameters = 1;
          }
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "OKP")) {
        if (json_object_get(jwk, "crv")) {
          if (0 != o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("Ed448", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("X25519", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("X448", json_string_value(json_object_get(jwk, "crv")))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid OKP crv value: '%s'", json_string_value(json_object_get(jwk, "crv")));
            ret = RHN_ERROR_PARAM;
          }
        }
        if (!is_x5_key && !json_string_length(json_object_get(jwk, "x"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x");
          ret = RHN_ERROR_PARAM;
        } else if (json_string_length(json_object_get(jwk, "x"))) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d");
            ret = RHN_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
            has_privkey_parameters = 1;
          }
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "RSA")) {
        if (!is_x5_key && !json_string_length(json_object_get(jwk, "n"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid n");
          ret = RHN_ERROR_PARAM;
        } else if (json_string_length(json_object_get(jwk, "n"))) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid n format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (!is_x5_key && !json_string_length(json_object_get(jwk, "e"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid e");
          ret = RHN_ERROR_PARAM;
        } else if (json_string_length(json_object_get(jwk, "e"))) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid e format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (json_object_get(jwk, "d") != NULL) {
          if (!json_string_length(json_object_get(jwk, "d"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d");
            ret = RHN_ERROR_PARAM;
          } else {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
          }
          has_privkey_parameters = 1;
        }
        if (json_object_get(jwk, "p") != NULL) {
          if (!json_string_length(json_object_get(jwk, "p"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid p");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid d format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "q") != NULL) {
          if (!json_string_length(json_object_get(jwk, "q"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid q");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid q format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dp") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dp"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid dp");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid dp format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "dq") != NULL) {
          if (!json_string_length(json_object_get(jwk, "dq"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid dq");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid dq format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "qi") != NULL) {
          if (!json_string_length(json_object_get(jwk, "qi"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid qi");
            ret = RHN_ERROR_PARAM;
          } else if (has_privkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "qi")), json_string_length(json_object_get(jwk, "qi")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid qi format");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
        if (json_object_get(jwk, "oth") != NULL) {
          ret = RHN_ERROR_UNSUPPORTED;
        }
      } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct")) {
        if (!json_string_length(json_object_get(jwk, "k"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid k");
          ret = RHN_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "k")), json_string_length(json_object_get(jwk, "k")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid k format");
            ret = RHN_ERROR_PARAM;
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid kty");
        ret = RHN_ERROR_PARAM;
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_is_valid_x5u(jwk_t * jwk, int x5u_flags) {
  int ret, type, type_x5u;
  jwk_t * jwk_x5u = NULL;

  if (r_jwk_is_valid(jwk) == RHN_OK && r_jwk_get_property_str(jwk, "x5u") != NULL) {
    type = r_jwk_key_type(jwk, NULL, x5u_flags);
    if (type & R_KEY_TYPE_RSA) {
      if (r_jwk_init(&jwk_x5u) == RHN_OK) {
        if (r_jwk_import_from_x5u(jwk_x5u, x5u_flags, r_jwk_get_property_str(jwk, "x5u")) == RHN_OK) {
          type_x5u = r_jwk_key_type(jwk_x5u, NULL, x5u_flags);
          if (type_x5u == type) {
            ret = RHN_OK;
            if (r_jwk_get_property_str(jwk, "n") != NULL && r_jwk_get_property_str(jwk, "e") != NULL && (0 != o_strcmp(r_jwk_get_property_str(jwk, "n"), r_jwk_get_property_str(jwk_x5u, "n")) || 0 != o_strcmp(r_jwk_get_property_str(jwk, "e"), r_jwk_get_property_str(jwk_x5u, "e")))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key parameters (rsa)");
              ret = RHN_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key type (rsa expected)");
            ret = RHN_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_import_from_x5u (rsa)");
          ret = RHN_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_init (rsa)");
        ret = RHN_ERROR;
      }
      r_jwk_free(jwk_x5u);
    } else if (type & R_KEY_TYPE_EC) {
      if (r_jwk_init(&jwk_x5u) == RHN_OK) {
        if (r_jwk_import_from_x5u(jwk_x5u, x5u_flags, r_jwk_get_property_str(jwk, "x5u")) == RHN_OK) {
          type_x5u = r_jwk_key_type(jwk_x5u, NULL, x5u_flags);
          if (type_x5u == type) {
            ret = RHN_OK;
            if (json_object_get(jwk, "x") != NULL && json_object_get(jwk, "y") != NULL && (0 != o_strcmp(r_jwk_get_property_str(jwk, "x"), r_jwk_get_property_str(jwk_x5u, "x")) || 0 != o_strcmp(r_jwk_get_property_str(jwk, "y"), r_jwk_get_property_str(jwk_x5u, "y")))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key parameters (ec)");
              ret = RHN_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key type (ec expected)");
            ret = RHN_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_import_from_x5u (ec)");
          ret = RHN_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_init (ec)");
        ret = RHN_ERROR;
      }
      r_jwk_free(jwk_x5u);
    } else if (type & R_KEY_TYPE_EDDSA) {
      if (r_jwk_init(&jwk_x5u) == RHN_OK) {
        if (r_jwk_import_from_x5u(jwk_x5u, x5u_flags, r_jwk_get_property_str(jwk, "x5u")) == RHN_OK) {
          type_x5u = r_jwk_key_type(jwk_x5u, NULL, x5u_flags);
          if (type_x5u == type) {
            ret = RHN_OK;
            if (json_object_get(jwk, "x") != NULL && (0 != o_strcmp(r_jwk_get_property_str(jwk, "x"), r_jwk_get_property_str(jwk_x5u, "x")))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key parameters (eddsa)");
              ret = RHN_ERROR_PARAM;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error invalid x5u key type (eddsa expected)");
            ret = RHN_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_import_from_x5u (eddsa)");
          ret = RHN_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid_x5u - Error r_jwk_init (eddsa)");
        ret = RHN_ERROR;
      }
      r_jwk_free(jwk_x5u);
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_generate_key_pair(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int type, unsigned int bits, const char * kid) {
  int ret;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey;
#if GNUTLS_VERSION_NUMBER >= 0x030400
  int res;
  unsigned int ec_bits = 0;
  gnutls_pk_algorithm_t alg = GNUTLS_PK_UNKNOWN;
#endif
#if NETTLE_VERSION_NUMBER >= 0x030600
  unsigned char x_ecdh[CURVE448_SIZE] = {0}, d_ecdh[CURVE448_SIZE] = {0}, x_ecdh_b64[CURVE448_SIZE*2];
  const unsigned char * d_b64 = NULL;
  size_t d_ecdh_size = CURVE448_SIZE, x_ecdh_b64_size = 0;
#endif

  if (jwk_privkey != NULL && jwk_pubkey != NULL && (type == R_KEY_TYPE_RSA || type == R_KEY_TYPE_EC || type == R_KEY_TYPE_EDDSA || type == R_KEY_TYPE_ECDH) && bits) {
    if (!gnutls_privkey_init(&privkey) && !gnutls_pubkey_init(&pubkey)) {
      if (type == R_KEY_TYPE_RSA) {
        if (!gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, bits, 0)) {
          if (!gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
            if (r_jwk_import_from_gnutls_privkey(jwk_privkey, privkey) == RHN_OK) {
              if (r_jwk_import_from_gnutls_pubkey(jwk_pubkey, pubkey) == RHN_OK) {
                if (!o_strnullempty(kid)) {
                  r_jwk_set_property_str(jwk_privkey, "kid", kid);
                  r_jwk_set_property_str(jwk_pubkey, "kid", kid);
                }
                ret = RHN_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error r_jwk_import_from_gnutls_pubkey RSA");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error r_jwk_import_from_gnutls_privkey RSA");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_pubkey_import_privkey RSA");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_privkey_generate RSA");
          ret = RHN_ERROR;
        }
#if GNUTLS_VERSION_NUMBER >= 0x030400
      } else if (type == R_KEY_TYPE_EC || type == R_KEY_TYPE_EDDSA || type == R_KEY_TYPE_ECDH) {
        if (type == R_KEY_TYPE_EC) {
          if (bits == 256) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1);
            alg = GNUTLS_PK_ECDSA;
          } else if (bits == 384) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1);
            alg = GNUTLS_PK_ECDSA;
          } else if (bits == 521) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP521R1);
            alg = GNUTLS_PK_ECDSA;
          }
#if GNUTLS_VERSION_NUMBER >= 0x030600
        } else if (type == R_KEY_TYPE_EDDSA || type == R_KEY_TYPE_ECDH) {
          if (bits == 256) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED25519);
            alg = GNUTLS_PK_EDDSA_ED25519;
#if GNUTLS_VERSION_NUMBER >= 0x03060e
          } else if (bits == 448) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED448);
            alg = GNUTLS_PK_EDDSA_ED448;
#endif
          }
#endif
        }
        if (ec_bits) {
          if (!(res = gnutls_privkey_generate(privkey, alg, ec_bits, 0))) {
            if (!gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
              if (r_jwk_import_from_gnutls_privkey(jwk_privkey, privkey) == RHN_OK) {
                if (r_jwk_import_from_gnutls_pubkey(jwk_pubkey, pubkey) == RHN_OK) {
                  if (!o_strnullempty(kid)) {
                    r_jwk_set_property_str(jwk_privkey, "kid", kid);
                    r_jwk_set_property_str(jwk_pubkey, "kid", kid);
                  }
#if NETTLE_VERSION_NUMBER >= 0x030600
                  if (type == R_KEY_TYPE_ECDH) {
                    d_b64 = (const unsigned char *)r_jwk_get_property_str(jwk_privkey, "d");
                    if (o_base64url_decode(d_b64, o_strlen((const char *)d_b64), d_ecdh, &d_ecdh_size)) {
                      ret = RHN_OK;
                      if (bits == 256) {
                        r_jwk_set_property_str(jwk_privkey, "crv", "X25519");
                        r_jwk_set_property_str(jwk_pubkey, "crv", "X25519");
                        curve25519_mul_g(x_ecdh, d_ecdh);
#if GNUTLS_VERSION_NUMBER >= 0x03060e
                      } else if (bits == 448) {
                        r_jwk_set_property_str(jwk_privkey, "crv", "X448");
                        r_jwk_set_property_str(jwk_pubkey, "crv", "X448");
                        curve448_mul_g(x_ecdh, d_ecdh);
#endif
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error unsupported curve");
                        ret = RHN_ERROR;
                      }
                      if (ret == RHN_OK) {
                        if (o_base64url_encode(x_ecdh, bits==256?CURVE25519_SIZE:CURVE448_SIZE, x_ecdh_b64, &x_ecdh_b64_size)) {
                          x_ecdh_b64[x_ecdh_b64_size] = '\0';
                          r_jwk_set_property_str(jwk_pubkey, "x", (const char *)x_ecdh_b64);
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error o_base64url_encode ECDH");
                          ret = RHN_ERROR;
                        }
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error o_base64url_decode ECDH");
                      ret = RHN_ERROR;
                    }
                  } else {
                    ret = RHN_OK;
                  }
#else
                  ret = RHN_OK;
#endif
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error r_jwk_import_from_gnutls_pubkey ECC");
                  ret = RHN_ERROR;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error r_jwk_import_from_gnutls_privkey ECC");
                ret = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_pubkey_import_privkey ECC");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_privkey_generate ECC %d", res);
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error curve length");
          ret = RHN_ERROR_PARAM;
        }
#endif // GNUTLS_VERSION_NUMBER >= 0x030500
      } else {
        ret = RHN_ERROR_PARAM;
      }
      gnutls_privkey_deinit(privkey);
      gnutls_pubkey_deinit(pubkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_privkey_init");
      ret = RHN_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error input parameters");
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_key_type(jwk_t * jwk, unsigned int * bits, int x5u_flags) {
  gnutls_x509_crt_t     crt = NULL;
  gnutls_datum_t        data;
  int ret = R_KEY_TYPE_NONE, pk_alg;
  size_t k_len = 0;
  int bits_set = 0, has_values = 0;
  struct _o_datum dat = {0, NULL}, x5u_datum = {0, NULL};

  if (r_jwk_is_valid(jwk) == RHN_OK) {
    if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "RSA")) {
      ret = R_KEY_TYPE_RSA;
      if (json_object_get(jwk, "n")) {
        has_values = 1;
      }
      if (json_object_get(jwk, "d")) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "EC")) {
      ret = R_KEY_TYPE_EC;
      if (json_object_get(jwk, "x")) {
        has_values = 1;
      }
      if (json_object_get(jwk, "d") != NULL) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "OKP")) {
      if (0 == o_strcmp("X25519", json_string_value(json_object_get(jwk, "crv"))) || 0 == o_strcmp("X448", json_string_value(json_object_get(jwk, "crv")))) {
        ret = R_KEY_TYPE_ECDH;
      } else if (0 == o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv"))) || 0 == o_strcmp("Ed448", json_string_value(json_object_get(jwk, "crv")))) {
        ret = R_KEY_TYPE_EDDSA;
      }
      if (json_object_get(jwk, "x")) {
        has_values = 1;
      }
      if (json_object_get(jwk, "d") != NULL) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct")) {
      ret = R_KEY_TYPE_HMAC|R_KEY_TYPE_SYMMETRIC;
      has_values = 1;
    }
    if (!has_values) {
      if (json_object_get(jwk, "x5c") != NULL) {
          if (o_base64_decode_alloc((unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), &dat)) {
            data.data = dat.data;
            data.size = (unsigned int)dat.size;
            if (!gnutls_x509_crt_init(&crt)) {
              if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
                pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, bits);
                bits_set = 1;
                if ((ret&R_KEY_TYPE_RSA)) {
                  if (pk_alg != GNUTLS_PK_RSA) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Invalid x5c type, expected RSA");
                    ret = R_KEY_TYPE_NONE;
                  }
#if GNUTLS_VERSION_NUMBER >= 0x030600
                } else if ((ret&R_KEY_TYPE_EC)) {
                  if (pk_alg != GNUTLS_PK_ECDSA) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Invalid x5c type, expected EC");
                    ret = R_KEY_TYPE_NONE;
                  }
                } else if ((ret&R_KEY_TYPE_EDDSA)) {
#if GNUTLS_VERSION_NUMBER >= 0x03060e
                  if (pk_alg != GNUTLS_PK_EDDSA_ED25519 && pk_alg != GNUTLS_PK_EDDSA_ED448)
#else
                  if (pk_alg != GNUTLS_PK_EDDSA_ED25519)
#endif
                  {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Invalid x5c type, expected OKP");
                    ret = R_KEY_TYPE_NONE;
                  }
#endif
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error unsupported algorithm %s", gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)pk_alg));
                  ret = R_KEY_TYPE_NONE;
                }
                ret |= R_KEY_TYPE_PUBLIC;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls import");
                ret = R_KEY_TYPE_NONE;
              }
              gnutls_x509_crt_deinit(crt);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error gnutls_x509_crt_init");
              ret = R_KEY_TYPE_NONE;
            }
            o_free(dat.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5c - Error o_base64_decode (1)");
            ret = R_KEY_TYPE_NONE;
          }
      }
      if (json_object_get(jwk, "x5u") != NULL) {
        if (!(x5u_flags & R_FLAG_IGNORE_REMOTE)) {
          // Get first x5u
          if (_r_get_http_content(json_string_value(json_object_get(jwk, "x5u")), x5u_flags, NULL, &x5u_datum) == RHN_OK) {
            data.data = (unsigned char *)x5u_datum.data;
            data.size = (unsigned int)x5u_datum.size;
            if (!gnutls_x509_crt_init(&crt)) {
              if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, bits);
                bits_set = 1;
                if ((ret&R_KEY_TYPE_RSA)) {
                  if (pk_alg != GNUTLS_PK_RSA) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Invalid x5u type, expected RSA");
                    ret = R_KEY_TYPE_NONE;
                  }
#if GNUTLS_VERSION_NUMBER >= 0x030600
                } else if ((ret&R_KEY_TYPE_EC)) {
                  if (pk_alg != GNUTLS_PK_ECDSA) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Invalid x5u type, expected EC");
                    ret = R_KEY_TYPE_NONE;
                  }
                } else if ((ret&R_KEY_TYPE_EDDSA)) {
#if GNUTLS_VERSION_NUMBER >= 0x03060e
                  if (pk_alg != GNUTLS_PK_EDDSA_ED25519 && pk_alg != GNUTLS_PK_EDDSA_ED448)
#else
                  if (pk_alg != GNUTLS_PK_EDDSA_ED25519)
#endif
                  {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Invalid x5u type, expected OKP");
                    ret = R_KEY_TYPE_NONE;
                  }
#endif
                } else {
                  ret = R_KEY_TYPE_NONE;
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error unsupported algorithm %s", gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)pk_alg));
                }
                ret |= R_KEY_TYPE_PUBLIC;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error gnutls_x509_crt_import");
                ret = R_KEY_TYPE_NONE;
              }
              gnutls_x509_crt_deinit(crt);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error gnutls_x509_crt_init");
            }
            o_free(x5u_datum.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error getting x5u content");
          }
        }
      }
    }
  }
  if (bits != NULL && !bits_set) {
    if (ret & R_KEY_TYPE_RSA) {
      if (o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), NULL, &k_len)) {
        *bits = (unsigned int)k_len*8;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error invalid base64url n value");
        ret = R_KEY_TYPE_NONE;
      }
    } else if (ret & R_KEY_TYPE_EC) {
      if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 384;
      } else if (0 == o_strcmp("P-521", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 521;
      } else if (0 == o_strcmp("secp256k1", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      }
    } else if (ret & R_KEY_TYPE_EDDSA) {
      if (0 == o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      } else if (0 == o_strcmp("Ed448", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 448;
      }
    } else if (ret & R_KEY_TYPE_ECDH) {
      if (0 == o_strcmp("X25519", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      } else if (0 == o_strcmp("X448", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 448;
      }
    } else if (ret & R_KEY_TYPE_HMAC) {
      if (o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "k")), json_string_length(json_object_get(jwk, "k")), NULL, &k_len)) {
        *bits = (unsigned int)k_len*8;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error invalid base64url k value");
        ret = R_KEY_TYPE_NONE;
      }
    }
  }
  return ret;
}

int r_jwk_extract_pubkey(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int x5u_flags) {
  int ret, type;

  if ((type = r_jwk_key_type(jwk_privkey, NULL, x5u_flags)) & R_KEY_TYPE_PRIVATE && jwk_pubkey != NULL) {
    if (json_string_length(json_object_get(jwk_privkey, "kid"))) {
      json_object_set_new(jwk_pubkey, "kid", json_string(json_string_value(json_object_get(jwk_privkey, "kid"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "alg"))) {
      json_object_set_new(jwk_pubkey, "alg", json_string(json_string_value(json_object_get(jwk_privkey, "alg"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "use"))) {
      json_object_set_new(jwk_pubkey, "use", json_string(json_string_value(json_object_get(jwk_privkey, "use"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "kty"))) {
      json_object_set_new(jwk_pubkey, "kty", json_string(json_string_value(json_object_get(jwk_privkey, "kty"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "crv"))) {
      json_object_set_new(jwk_pubkey, "crv", json_string(json_string_value(json_object_get(jwk_privkey, "crv"))));
    }
    if (json_object_get(jwk_privkey, "x5c") != NULL) {
      json_object_set_new(jwk_pubkey, "x5c", json_deep_copy(json_object_get(jwk_privkey, "x5c")));
    }
    if (json_string_length(json_object_get(jwk_privkey, "x5u"))) {
      json_object_set_new(jwk_pubkey, "x5u", json_string(json_string_value(json_object_get(jwk_privkey, "x5u"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "x5t"))) {
      json_object_set_new(jwk_pubkey, "x5t", json_string(json_string_value(json_object_get(jwk_privkey, "x5t"))));
    }
    if (json_string_length(json_object_get(jwk_privkey, "x5t#S256"))) {
      json_object_set_new(jwk_pubkey, "x5t#S256", json_string(json_string_value(json_object_get(jwk_privkey, "x5t#S256"))));
    }
    ret = RHN_OK;
    if (type & R_KEY_TYPE_RSA) {
      json_object_set_new(jwk_pubkey, "e", json_string(json_string_value(json_object_get(jwk_privkey, "e"))));
      json_object_set_new(jwk_pubkey, "n", json_string(json_string_value(json_object_get(jwk_privkey, "n"))));
    } else if (type & R_KEY_TYPE_EC) {
      json_object_set_new(jwk_pubkey, "x", json_string(json_string_value(json_object_get(jwk_privkey, "x"))));
      json_object_set_new(jwk_pubkey, "y", json_string(json_string_value(json_object_get(jwk_privkey, "y"))));
    } else if (type & R_KEY_TYPE_EDDSA || type & R_KEY_TYPE_ECDH) {
      json_object_set_new(jwk_pubkey, "x", json_string(json_string_value(json_object_get(jwk_privkey, "x"))));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error invalid key type");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error invalid parameter");
    ret = RHN_ERROR_PARAM;
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
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_json_t - Error json_object_update");
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
  const unsigned char * input_end;
  unsigned char * input_copy, * input_copy_orig;
  size_t input_end_len;

  if (jwk != NULL && input != NULL && input_len) {
    if (R_X509_TYPE_UNSPECIFIED == type) {
      if (0 == o_strncmp((const char *)input, RHN_PEM_HEADER_CERT, o_strlen(RHN_PEM_HEADER_CERT))) {
        type = R_X509_TYPE_CERTIFICATE;
      } else if (0 == o_strncmp((const char *)input, RHN_PEM_HEADER_PUBKEY, o_strlen(RHN_PEM_HEADER_PUBKEY))) {
        type = R_X509_TYPE_PUBKEY;
      } else if (0 == o_strncmp((const char *)input, RHN_PEM_HEADER_PRIVKEY, o_strlen(RHN_PEM_HEADER_PRIVKEY)) ||
                 0 == o_strncmp((const char *)input, RHN_PEM_HEADER_EC_PRIVKEY, o_strlen(RHN_PEM_HEADER_EC_PRIVKEY)) ||
                 0 == o_strncmp((const char *)input, RHN_PEM_HEADER_RSA_PRIVKEY, o_strlen(RHN_PEM_HEADER_RSA_PRIVKEY)) ||
                 0 == o_strncmp((const char *)input, RHN_PEM_HEADER_UNKNOWN_PRIVKEY, o_strlen(RHN_PEM_HEADER_UNKNOWN_PRIVKEY))) {
        type = R_X509_TYPE_PRIVKEY;
      }
    }
    input_copy = (unsigned char *)o_strndup((const char *)input, input_len);
    input_copy_orig = input_copy;
    switch (type) {
      case R_X509_TYPE_PUBKEY:
        if (!(res = gnutls_pubkey_init(&pub))) {
          data.data = (unsigned char *)input_copy;
          data.size = (unsigned int)input_len;
          if (!(res = gnutls_pubkey_import(pub, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER))) {
            ret = r_jwk_import_from_gnutls_pubkey(jwk, pub);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error r_jwk_import_from_gnutls_pubkey: %s", gnutls_strerror(res));
            ret = RHN_ERROR;
          }
          gnutls_pubkey_deinit(pub);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_pubkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        break;
      case R_X509_TYPE_PRIVKEY:
        if ((res = gnutls_privkey_init(&key)) < 0) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_privkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        } else if ((res = gnutls_x509_privkey_init(&x509_key)) < 0) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_privkey_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        } else {
          data.data = (unsigned char *)input_copy;
          data.size = (unsigned int)input_len;
          if ((res = gnutls_x509_privkey_import(x509_key, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER)) < 0) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_privkey_import: %s", gnutls_strerror(res));
            ret = RHN_ERROR_PARAM;
          } else if ((res = gnutls_privkey_import_x509(key, x509_key, 0)) < 0) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_privkey_import_x509: %s", gnutls_strerror(res));
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
          if (format == R_FORMAT_PEM && o_strlen((const char *)input_copy) >= o_strlen(RHN_PEM_HEADER_CERT)) {
            input_end = (const unsigned char *)o_strstr((const char *)input_copy + o_strlen(RHN_PEM_HEADER_CERT), RHN_PEM_HEADER_CERT);
            if (input_end != NULL) {
              input_end_len = (size_t)(input_end - input_copy);
            } else {
              input_end_len = input_len;
            }
            data.data = (unsigned char *)input_copy;
            data.size = (unsigned int)input_end_len;
            if (!(res = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM))) {
              if ((ret = r_jwk_import_from_gnutls_x509_crt(jwk, crt)) == RHN_OK) {
                ret = r_jwk_append_x5c(jwk, R_FORMAT_PEM, input_copy, input_end_len);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error r_jwk_import_from_gnutls_x509_crt (pem)");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_crt_import (pem): %s", gnutls_strerror(res));
              ret = RHN_ERROR_PARAM;
            }
            while (ret == RHN_OK && input_end != NULL) {
              input_copy += input_end_len;
              input_end = (const unsigned char *)o_strstr((const char *)input_copy + o_strlen(RHN_PEM_HEADER_CERT), RHN_PEM_HEADER_CERT);
              if (input_end != NULL) {
                input_end_len = (size_t)(input_end - input_copy);
              } else {
                input_end_len = o_strlen((const char *)input_copy);
              }
              ret = r_jwk_append_x5c(jwk, R_FORMAT_PEM, input_copy, input_end_len);
            }
          } else {
            data.data = (unsigned char *)input_copy;
            data.size = (unsigned int)input_len;
            if (!(res = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER))) {
              if ((ret = r_jwk_import_from_gnutls_x509_crt(jwk, crt)) == RHN_OK) {
                ret = r_jwk_append_x5c(jwk, format, input_copy, input_len);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error r_jwk_import_from_gnutls_x509_crt (der)");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_crt_import (der): %s", gnutls_strerror(res));
              ret = RHN_ERROR_PARAM;
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_crt_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        gnutls_x509_crt_deinit(crt);
        break;
      default:
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error invalid type");
        ret = RHN_ERROR_PARAM;
        break;
    }
    o_free(input_copy_orig);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_gnutls_privkey(jwk_t * jwk, gnutls_privkey_t key) {
  int ret, res, pk_type;
  unsigned int bits = 0;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_datum_t m, e, d, p, q, u, e1, e2;
  unsigned char kid[64], kid_b64[128];
  size_t kid_len = 64, kid_b64_len = 128;
  struct _o_datum dat = {0, NULL};
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_datum_t x, y, k;
  gnutls_ecc_curve_t curve;
#endif

  if (jwk != NULL && key != NULL) {
    switch ((pk_type = gnutls_privkey_get_pk_algorithm(key, &bits))) {
      case GNUTLS_PK_RSA:
        if ((res = gnutls_privkey_export_rsa_raw2(key, &m, &e, &d, &p, &q, &u, &e1, &e2, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("RSA"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(m.data, m.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(e.data, e.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(d.data, d.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (6)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(p.data, p.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (8)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "p", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(q.data, q.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (10)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "q", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(u.data, u.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (12)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "qi", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(e1.data, e1.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (14)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dp", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(e2.data, e2.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode_alloc (16)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dq", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
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
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey - Error gnutls_privkey_export_rsa_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_privkey_export_ecc_raw2(key, &curve, &x, &y, &k, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode_alloc (1)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(y.data, y.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode_alloc (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(k.data, k.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode_alloc (3)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            switch (curve) {
              case GNUTLS_ECC_CURVE_SECP521R1:
                json_object_set_new(jwk, "crv", json_string("P-521"));
                break;
              case GNUTLS_ECC_CURVE_SECP384R1:
                json_object_set_new(jwk, "crv", json_string("P-384"));
                break;
              case GNUTLS_ECC_CURVE_SECP256R1:
                json_object_set_new(jwk, "crv", json_string("P-256"));
                break;
              default:
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error curve");
                ret = RHN_ERROR_PARAM;
                break;
            }

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode");
              ret = RHN_ERROR;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
          gnutls_free(y.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error gnutls_privkey_export_ecc_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_EDDSA_ED25519:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      case GNUTLS_PK_EDDSA_ED448:
#endif
        if ((res = gnutls_privkey_export_ecc_raw2(key, &curve, &x, NULL, &k, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("OKP"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode_alloc (1)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(k.data, k.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode_alloc (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            if (pk_type == GNUTLS_PK_EDDSA_ED25519) {
              json_object_set_new(jwk, "crv", json_string("Ed25519"));
            } else {
              json_object_set_new(jwk, "crv", json_string("Ed448"));
            }

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode");
              ret = RHN_ERROR;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_privkey_export_ecc_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_ECDH_X25519:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      case GNUTLS_PK_ECDH_X448:
#endif
        if ((res = gnutls_privkey_export_ecc_raw2(key, &curve, &x, NULL, &k, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("OKP"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode_alloc (1)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(k.data, k.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode_alloc (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            if (pk_type == GNUTLS_PK_EDDSA_ED25519) {
              json_object_set_new(jwk, "crv", json_string("X25519"));
            } else {
              json_object_set_new(jwk, "crv", json_string("X448"));
            }

            if (gnutls_privkey_export_x509(key, &x509_key)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_privkey_export_x509");
              ret = RHN_ERROR;
              break;
            }
            if (gnutls_x509_privkey_get_key_id(x509_key, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_x509_crt_get_key_id");
              ret = RHN_ERROR;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error o_base64url_encode");
              ret = RHN_ERROR;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey eddsa - Error gnutls_privkey_export_ecc_raw2");
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
  int ret, res, pk_type;
  unsigned int bits = 0;
  gnutls_datum_t m, e;
  unsigned char kid[64], kid_b64[128];
  size_t kid_len = 64, kid_b64_len = 128;
  struct _o_datum dat = {0, NULL};
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_datum_t x, y;
  gnutls_ecc_curve_t curve;
#endif

  if (jwk != NULL && pub != NULL) {
    switch ((pk_type = gnutls_pubkey_get_pk_algorithm(pub, &bits))) {
      case GNUTLS_PK_RSA:
        if ((res = gnutls_pubkey_export_rsa_raw2(pub, &m, &e, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("RSA"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(m.data, m.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode_alloc (1)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(e.data, e.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode_alloc (42)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }

            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(m.data);
          gnutls_free(e.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey - Error gnutls_pubkey_export_rsa_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
#if GNUTLS_VERSION_NUMBER >= 0x030600
      case GNUTLS_PK_ECDSA:
        if ((res = gnutls_pubkey_export_ecc_raw2(pub, &curve, &x, &y, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode_alloc (1)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;

            if (!o_base64url_encode_alloc(y.data, y.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode_alloc (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            switch (curve) {
              case GNUTLS_ECC_CURVE_SECP521R1:
                json_object_set_new(jwk, "crv", json_string("P-521"));
                break;
              case GNUTLS_ECC_CURVE_SECP384R1:
                json_object_set_new(jwk, "crv", json_string("P-384"));
                break;
              case GNUTLS_ECC_CURVE_SECP256R1:
                json_object_set_new(jwk, "crv", json_string("P-256"));
                break;
              default:
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error curve");
                ret = RHN_ERROR_PARAM;
                break;
            }
            if (ret != RHN_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
          gnutls_free(y.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error gnutls_pubkey_export_ecc_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_EDDSA_ED25519:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      case GNUTLS_PK_EDDSA_ED448:
#endif
        if ((res = gnutls_pubkey_export_ecc_raw2(pub, &curve, &x, NULL, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("OKP"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey eddsa - Error o_base64url_encode_alloc");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            if (pk_type == GNUTLS_PK_EDDSA_ED25519) {
              json_object_set_new(jwk, "crv", json_string("Ed25519"));
            } else {
              json_object_set_new(jwk, "crv", json_string("Ed448"));
            }

            if (ret != RHN_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey eddsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey eddsa - Error o_base64url_encode");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey eddsa - Error gnutls_pubkey_export_ecc_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_ECDH_X25519:
#if GNUTLS_VERSION_NUMBER >= 0x03060e
      case GNUTLS_PK_ECDH_X448:
#endif
        if ((res = gnutls_pubkey_export_ecc_raw2(pub, &curve, &x, NULL, GNUTLS_EXPORT_FLAG_NO_LZ)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("OKP"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode_alloc(x.data, x.size, &dat)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdh - Error o_base64url_encode_alloc");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_stringn((const char *)dat.data, dat.size));
            o_free(dat.data);
            dat.data = NULL;
            if (pk_type == GNUTLS_PK_EDDSA_ED25519) {
              json_object_set_new(jwk, "crv", json_string("X25519"));
            } else {
              json_object_set_new(jwk, "crv", json_string("X448"));
            }

            if (ret != RHN_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdh - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdh - Error o_base64url_encode");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          } while (0);
          gnutls_free(x.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdh - Error gnutls_pubkey_export_ecc_raw2");
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
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_x509_crt x509 - Error gnutls_x509_crt_get_key_id");
            ret = RHN_ERROR;
          } else if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_x509_crt x509 - Error o_base64url_encode");
            ret = RHN_ERROR;
          } else {
            json_object_set_new(jwk, "kid", json_stringn((const char *)kid_b64, kid_b64_len));
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_x509_crt x509 - Error gnutls_pubkey_import_x509");
        ret = RHN_ERROR_PARAM;
      }
      gnutls_pubkey_deinit(pub);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_x509_crt x509 - Error gnutls_pubkey_init");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_x5u(jwk_t * jwk, int x5u_flags, const char * x5u) {
  int ret;
  struct _o_datum x5u_datum = {0, NULL};

  if (jwk != NULL && x5u != NULL) {
    if (_r_get_http_content(x5u, x5u_flags, NULL, &x5u_datum) == RHN_OK) {
      if (r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (unsigned const char *)x5u_datum.data, x5u_datum.size) == RHN_OK) {
        ret = RHN_OK;
      } else {
        ret = RHN_ERROR;
      }
      o_free(x5u_datum.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_x5u - Error getting x5u content");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_x5c(jwk_t * jwk, const char * x5c) {
  int ret;
  struct _o_datum dat = {0, NULL};

  if (jwk != NULL && x5c != NULL) {
    if (o_base64_decode_alloc((const unsigned char *)x5c, o_strlen(x5c), &dat)) {
      if (r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_DER, dat.data, dat.size) == RHN_OK) {
        ret = RHN_OK;
      } else {
        ret = RHN_ERROR;
      }
      o_free(dat.data);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_x5u - Error o_base64_decode x5c");
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_symmetric_key(jwk_t * jwk, const unsigned char * key, size_t key_len) {
  int ret;
  char * key_b64 = NULL;
  struct _o_datum dat = {0, NULL};

  if (jwk != NULL && key != NULL && key_len) {
    if (o_base64url_encode_alloc(key, key_len, &dat)) {
      key_b64 = o_strndup((const char *)dat.data, dat.size);
      if (r_jwk_set_property_str(jwk, "kty", "oct") == RHN_OK && r_jwk_set_property_str(jwk, "k", (const char *)key_b64) == RHN_OK) {
        ret = RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_symmetric_key - Error setting key data in jwk");
        ret = RHN_ERROR;
      }
      o_free(dat.data);
    } else {
      ret = RHN_ERROR_PARAM;
    }
    o_free(key_b64);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_password(jwk_t * jwk, const char * password) {
  return r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)password, o_strlen(password));
}

jwk_t * r_jwk_quick_import(rhn_import type, ...) {
  va_list vl;
  jwk_t * jwk = NULL;
  int ret, i_val;
  const char * str;
  json_t * j_jwk;
  const unsigned char * data;
  size_t data_len;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;

  if (r_jwk_init(&jwk) != RHN_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_quick_import - Error r_jwk_init");
    return NULL;
  } else {
    va_start(vl, type);
    switch (type) {
      case R_IMPORT_JSON_STR:
        str = va_arg(vl, const char *);
        ret = r_jwk_import_from_json_str(jwk, str);
        break;
      case R_IMPORT_JSON_T:
        j_jwk = va_arg(vl, json_t *);
        ret = r_jwk_import_from_json_t(jwk, j_jwk);
        break;
      case R_IMPORT_PEM:
        i_val = va_arg(vl, int);
        data = va_arg(vl, const unsigned char *);
        data_len = va_arg(vl, size_t);
        ret = r_jwk_import_from_pem_der(jwk, i_val, R_FORMAT_PEM, data, data_len);
        break;
      case R_IMPORT_DER:
        i_val = va_arg(vl, int);
        data = va_arg(vl, const unsigned char *);
        data_len = va_arg(vl, size_t);
        ret = r_jwk_import_from_pem_der(jwk, i_val, R_FORMAT_DER, data, data_len);
        break;
      case R_IMPORT_G_PRIVKEY:
        privkey = va_arg(vl, gnutls_privkey_t);
        ret = r_jwk_import_from_gnutls_privkey(jwk, privkey);
        break;
      case R_IMPORT_G_PUBKEY:
        pubkey = va_arg(vl, gnutls_pubkey_t);
        ret = r_jwk_import_from_gnutls_pubkey(jwk, pubkey);
        break;
      case R_IMPORT_G_CERT:
        crt = va_arg(vl, gnutls_x509_crt_t);
        ret = r_jwk_import_from_gnutls_x509_crt(jwk, crt);
        break;
      case R_IMPORT_X5U:
        i_val = va_arg(vl, int);
        str = va_arg(vl, const char *);
        ret = r_jwk_import_from_x5u(jwk, i_val, str);
        break;
      case R_IMPORT_SYMKEY:
        data = va_arg(vl, const unsigned char *);
        data_len = va_arg(vl, size_t);
        ret = r_jwk_import_from_symmetric_key(jwk, data, data_len);
        break;
      case R_IMPORT_PASSWORD:
        str = va_arg(vl, const char *);
        ret = r_jwk_import_from_password(jwk, str);
        break;
      default:
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_quick_import - Invalid type");
        ret = RHN_ERROR_PARAM;
        break;
    }
    va_end(vl);
    if (ret != RHN_OK) {
      r_jwk_free(jwk);
      jwk = NULL;
    }
    return jwk;
  }
}

jwk_t * r_jwk_copy(jwk_t * jwk) {
  if (jwk != NULL) {
    return json_deep_copy(jwk);
  } else {
    return NULL;
  }
}

int r_jwk_equal(jwk_t * jwk1, jwk_t * jwk2) {
  return json_equal(jwk1, jwk2);
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

gnutls_privkey_t r_jwk_export_to_gnutls_privkey(jwk_t * jwk) {
  gnutls_privkey_t privkey       = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_ecc_curve_t curve;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, d = {NULL, 0}, p = {NULL, 0}, q = {NULL, 0}, u = {NULL, 0}, e1 = {NULL, 0}, e2 = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, k = {NULL, 0}, data = {NULL, 0};
  struct _o_datum dat = {0, NULL};

  int res, type = r_jwk_key_type(jwk, NULL, R_FLAG_IGNORE_REMOTE);

  if (type & R_KEY_TYPE_PRIVATE) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
      // Export first x5c
      if (o_base64_decode_alloc((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), &dat)) {
        if (!gnutls_x509_privkey_init(&x509_key)) {
          if (!gnutls_privkey_init(&privkey)) {
            data.data = dat.data;
            data.size = (unsigned int)dat.size;
            if (!gnutls_x509_privkey_import(x509_key, &data, GNUTLS_X509_FMT_DER)) {
              if ((res = gnutls_privkey_import_x509(privkey, x509_key, 0)) < 0) {
                res = RHN_OK;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_import_x509 rsa");
                res = RHN_ERROR;
                gnutls_privkey_deinit(privkey);
                privkey = NULL;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_x509_privkey_import rsa");
              res = RHN_ERROR;
              gnutls_privkey_deinit(privkey);
              privkey = NULL;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey x5c - Error gnutls_privkey_init");
            res = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
        }
        gnutls_x509_privkey_deinit(x509_key);
        o_free(dat.data);
        dat.data = NULL;
        dat.size = 0;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey x5c - Error o_base64_decode_alloc (1)");
        res = RHN_ERROR_MEMORY;
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      do {
        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (n)");
          res = RHN_ERROR;
          break;
        }
        m.data = dat.data;
        m.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (e)");
          res = RHN_ERROR;
          break;
        }
        e.data = dat.data;
        e.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (d)");
          res = RHN_ERROR;
          break;
        }
        d.data = dat.data;
        d.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (p)");
          res = RHN_ERROR;
          break;
        }
        p.data = dat.data;
        p.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (q)");
          res = RHN_ERROR;
          break;
        }
        q.data = dat.data;
        q.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "qi")), json_string_length(json_object_get(jwk, "qi")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (qi)");
          res = RHN_ERROR;
          break;
        }
        u.data = dat.data;
        u.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (dp)");
          res = RHN_ERROR;
          break;
        }
        e1.data = dat.data;
        e1.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (dq)");
          res = RHN_ERROR;
          break;
        }
        e2.data = dat.data;
        e2.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &e, &d, &p, &q, &u, &e1, &e2)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_import_rsa_raw");
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
      o_free(u.data);
      o_free(e1.data);
      o_free(e2.data);
    } else if (type & R_KEY_TYPE_EC) {
      res = RHN_OK;
      do {
        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = dat.data;
        x.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (y)");
          res = RHN_ERROR;
          break;
        }
        y.data = dat.data;
        y.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (d)");
          res = RHN_ERROR;
          break;
        }
        k.data = dat.data;
        k.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (0 == o_strcmp("P-521", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP521R1;
        } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP384R1;
        } else if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP256R1;
        //} else if (0 == o_strcmp("secp256k1", json_string_value(json_object_get(jwk, "crv")))) {
        //  curve = GNUTLS_ECC_CURVE_SECP256K1;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error crv data");
          res = RHN_ERROR;
          break;
        }

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_ecc_raw(privkey, curve, &x, &y, &k)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_import_ecc_raw");
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
#if GNUTLS_VERSION_NUMBER >= 0x030600
    } else if (type & R_KEY_TYPE_EDDSA || type & R_KEY_TYPE_ECDH) {
      res = RHN_OK;
      do {
        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = dat.data;
        x.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode_alloc (d)");
          res = RHN_ERROR;
          break;
        }
        k.data = dat.data;
        k.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (0 == o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_ED25519;
#if GNUTLS_VERSION_NUMBER >= 0x03060e
        } else if (0 == o_strcmp("Ed448", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_ED448;
#endif
#if 0 // disabled
        } else if (0 == o_strcmp("X25519", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_X25519;
#if GNUTLS_VERSION_NUMBER >= 0x03060e
        } else if (0 == o_strcmp("X448", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_X448;
#endif
#endif
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error crv data");
          res = RHN_ERROR;
          break;
        }

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_ecc_raw(privkey, curve, &x, NULL, &k)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_import_ecc_raw");
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
      o_free(k.data);
    } else if (type & R_KEY_TYPE_EDDSA || type & R_KEY_TYPE_ECDH) {
#endif
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - invalid key format, expected 'RSA' or 'EC'");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - invalid key type, expected private key");
  }
  return privkey;
}

gnutls_pubkey_t r_jwk_export_to_gnutls_pubkey(jwk_t * jwk, int x5u_flags) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_crt_t crt;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, data = {NULL, 0};
  int res, type = r_jwk_key_type(jwk, NULL, x5u_flags);
  struct _o_datum dat = {0, NULL}, x5u_datum = {0, NULL};
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_ecc_curve_t curve;
  gnutls_datum_t x = {NULL, 0}, y = {NULL, 0};
#endif

  if (type & (R_KEY_TYPE_PUBLIC|R_KEY_TYPE_PRIVATE)) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL || json_object_get(jwk, "x5u") != NULL)) {
      if (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
        // Export first x5c
        if (o_base64_decode_alloc((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), &dat)) {
          if (!gnutls_x509_crt_init(&crt)) {
            if (!gnutls_pubkey_init(&pubkey)) {
              data.data = dat.data;
              data.size = (unsigned int)dat.size;
              if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
                if (!gnutls_pubkey_import_x509(pubkey, crt, 0)) {
                  res = RHN_OK;
                } else {
                  gnutls_pubkey_deinit(pubkey);
                  pubkey = NULL;
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error gnutls_pubkey_import_x509");
                  res = RHN_ERROR;
                }
              } else {
                gnutls_pubkey_deinit(pubkey);
                pubkey = NULL;
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error gnutls_pubkey_import");
                res = RHN_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error gnutls_pubkey_init rsa");
              res = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error gnutls_x509_crt_init");
            res = RHN_ERROR;
          }
          gnutls_x509_crt_deinit(crt);
          o_free(dat.data);
          dat.data = NULL;
          dat.size = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error o_base64_decode (2)");
          res = RHN_ERROR_MEMORY;
        }
        o_free(data.data);
      } else {
        if (!(x5u_flags & R_FLAG_IGNORE_REMOTE)) {
          // Get x5u
          if (_r_get_http_content(json_string_value(json_object_get(jwk, "x5u")), x5u_flags, NULL, &x5u_datum) == RHN_OK) {
            if (!gnutls_pubkey_init(&pubkey)) {
              if (!gnutls_x509_crt_init(&crt)) {
                data.data = (unsigned char *)x5u_datum.data;
                data.size = (unsigned int)x5u_datum.size;
                if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                  if (!gnutls_pubkey_import_x509(pubkey, crt, 0)) {
                    res = RHN_OK;
                  } else {
                    gnutls_pubkey_deinit(pubkey);
                    pubkey = NULL;
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_import_x509");
                    res = RHN_ERROR;
                  }
                } else {
                  gnutls_pubkey_deinit(pubkey);
                  pubkey = NULL;
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_import");
                  res = RHN_ERROR;
                }
                gnutls_x509_crt_deinit(crt);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_x509_crt_init");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_init");
            }
            o_free(x5u_datum.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error getting x5u content");
          }
        } else {
          res = RHN_ERROR_UNSUPPORTED;
        }
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      if (!(type & R_KEY_TYPE_PRIVATE)) {
        do {
          if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), &dat)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode_alloc (n)");
            res = RHN_ERROR;
            break;
          }
          m.data = dat.data;
          m.size = (unsigned int)dat.size;
          dat.data = NULL;
          dat.size = 0;

          if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), &dat)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode_alloc (e)");
            res = RHN_ERROR;
            break;
          }
          e.data = dat.data;
          e.size = (unsigned int)dat.size;
          dat.data = NULL;
          dat.size = 0;

          if (gnutls_pubkey_init(&pubkey)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_privkey_init rsa");
            res = RHN_ERROR;
            break;
          }
          if (gnutls_pubkey_import_rsa_raw(pubkey, &m, &e)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_import_rsa_raw");
            res = RHN_ERROR;
            break;
          }
        } while (0);
      } else {
        do {
          if ((privkey = r_jwk_export_to_gnutls_privkey(jwk)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error r_jwk_export_to_gnutls_privkey rsa");
            res = RHN_ERROR;
            break;
          }
          if (gnutls_pubkey_init(&pubkey)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_privkey_init rsa");
            res = RHN_ERROR;
            break;
          }
          if (gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_import_privkey rsa");
            res = RHN_ERROR;
            break;
          }
        } while (0);
        gnutls_privkey_deinit(privkey);
      }
      if (res != RHN_OK) {
        if (pubkey != NULL) {
          gnutls_pubkey_deinit(pubkey);
          pubkey = NULL;
        }
      }
      o_free(m.data);
      o_free(e.data);
#if GNUTLS_VERSION_NUMBER >= 0x030600
    } else if (type & R_KEY_TYPE_EC) {
      res = RHN_OK;
      do {
        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode_alloc (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = dat.data;
        x.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode_alloc (y)");
          res = RHN_ERROR;
          break;
        }
        y.data = dat.data;
        y.size = (unsigned int)dat.size;
        dat.data = NULL;
        dat.size = 0;

        if (0 == o_strcmp("P-521", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP521R1;
        } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP384R1;
        } else if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_SECP256R1;
        //} else if (0 == o_strcmp("secp256k1", json_string_value(json_object_get(jwk, "crv")))) {
        //  curve = GNUTLS_ECC_CURVE_SECP256K1;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error crv data");
          res = RHN_ERROR;
          break;
        }

        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, &y)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_import_ecc_raw");
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
    } else if (type & R_KEY_TYPE_EDDSA || type & R_KEY_TYPE_ECDH) {
      res = RHN_OK;
      do {
        if (!o_base64url_decode_alloc((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), &dat)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode_alloc (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = dat.data;
        x.size = (unsigned int)dat.size;

        if (0 == o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_ED25519;
#if GNUTLS_VERSION_NUMBER >= 0x03060e
        } else if (0 == o_strcmp("Ed448", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_ED448;
#endif
#if 0 // disabled
        } else if (0 == o_strcmp("X25519", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_X25519;
#if GNUTLS_VERSION_NUMBER >= 0x03060e
        } else if (0 == o_strcmp("X448", json_string_value(json_object_get(jwk, "crv")))) {
          curve = GNUTLS_ECC_CURVE_X448;
#endif
#endif
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error crv data");
          res = RHN_ERROR;
          break;
        }

        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(pubkey, curve, &x, NULL)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_import_ecc_raw");
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
#endif
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error invalid key type");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error not public key");
  }
  return pubkey;
}

gnutls_x509_crt_t r_jwk_export_to_gnutls_crt(jwk_t * jwk, int x5u_flags) {
  gnutls_x509_crt_t crt = NULL;
  gnutls_datum_t data = {NULL, 0};
  int type = r_jwk_key_type(jwk, NULL, x5u_flags);
  struct _o_datum dat = {0, NULL}, x5u_datum = {0, NULL};

  if (type & (R_KEY_TYPE_PUBLIC)) {
    if (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL || json_object_get(jwk, "x5u") != NULL) {
      if (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
        // Export first x5c
        if (o_base64_decode_alloc((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), &dat)) {
          if (!gnutls_x509_crt_init(&crt)) {
            data.data = dat.data;
            data.size = (unsigned int)dat.size;
            if (gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5c - Error gnutls_pubkey_import");
            }
            o_free(dat.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5c - Error gnutls_x509_crt_init");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5c - Error o_base64_decode_alloc");
        }
      } else {
        if (!(x5u_flags & R_FLAG_IGNORE_REMOTE)) {
          // Get x5u
          if (_r_get_http_content(json_string_value(json_object_get(jwk, "x5u")), x5u_flags, NULL, &x5u_datum) == RHN_OK) {
            if (!gnutls_x509_crt_init(&crt)) {
              data.data = (unsigned char *)x5u_datum.data;
              data.size = (unsigned int)x5u_datum.size;
              if (gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5u - Error gnutls_pubkey_import");
                gnutls_x509_crt_deinit(crt);
                crt = NULL;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5u - Error gnutls_x509_crt_init");
            }
            o_free(x5u_datum.data);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt x5u - Error getting x5u content");
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt - Error invalid key type");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_crt - Error not public key");
  }
  return crt;
}

int r_jwk_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len, int x5u_flags) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_privkey_t x509_privkey = NULL;
  int res, ret, type = r_jwk_key_type(jwk, NULL, x5u_flags);
  int test_size = (output==NULL);

  if (type & R_KEY_TYPE_PRIVATE) {
    if ((privkey = r_jwk_export_to_gnutls_privkey(jwk)) != NULL) {
      if (!gnutls_privkey_export_x509(privkey, &x509_privkey)) {
        if (!(res = gnutls_x509_privkey_export(x509_privkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
          ret = RHN_OK;
        } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
          if (!test_size) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error buffer size");
          }
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error gnutls_x509_privkey_export");
          ret = RHN_ERROR;
        }
        gnutls_x509_privkey_deinit(x509_privkey);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error gnutls_privkey_export_x509");
        ret = RHN_ERROR;
      }
      gnutls_privkey_deinit(privkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error r_jwk_export_to_gnutls_privkey");
      ret = RHN_ERROR;
    }
  } else if (type & R_KEY_TYPE_PUBLIC) {
    if ((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
      if (!(res = gnutls_pubkey_export(pubkey, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER, output, output_len))) {
        ret = RHN_OK;
      } else if (res == GNUTLS_E_SHORT_MEMORY_BUFFER) {
        if (!test_size) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error buffer size");
        }
        ret = RHN_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error gnutls_pubkey_export");
        ret = RHN_ERROR;
      }
      gnutls_pubkey_deinit(pubkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - Error r_jwk_export_to_gnutls_pubkey");
      ret = RHN_ERROR;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_pem_der - invalid key type, exptected 'RSA' or 'EC'");
    ret = RHN_ERROR;
  }
  return ret;
}

int r_jwk_export_to_symmetric_key(jwk_t * jwk, unsigned char * key, size_t * key_len) {
  int ret;
  const char * k;
  size_t k_len = 0, k_expected = 0;

  if (jwk != NULL && key_len != NULL) {
    if (r_jwk_key_type(jwk, NULL, 0) & R_KEY_TYPE_SYMMETRIC) {
      k = r_jwk_get_property_str(jwk, "k");
      if ((k_len = o_strlen(k))) {
        if (o_base64url_decode((const unsigned char *)k, k_len, NULL, &k_expected)) {
          if (k_expected <= *key_len) {
            if (o_base64url_decode((const unsigned char *)k, k_len, key, key_len)) {
              ret = RHN_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_symmetric_key - Error o_base64url_decode");
              ret = RHN_ERROR;
            }
          } else {
            ret = RHN_ERROR_PARAM;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_symmetric_key - Error invalid key");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_symmetric_key - Error getting key");
        ret = RHN_ERROR;
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

const char * r_jwk_get_property_str(jwk_t * jwk, const char * key) {
  if (jwk != NULL && !o_strnullempty(key)) {
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
  if (jwk != NULL && !o_strnullempty(key)) {
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

int r_jwk_get_property_array_size(jwk_t * jwk, const char * key) {
  if (jwk != NULL && !o_strnullempty(key)) {
    if (json_is_array(json_object_get(jwk, key))) {
      return (int)json_array_size(json_object_get(jwk, key));
    } else {
      return -1;
    }
  } else {
    return -1;
  }
  return -1;
}

int r_jwk_set_property_str(jwk_t * jwk, const char * key, const char * value) {
  if (jwk != NULL && !o_strnullempty(key) && !o_strnullempty(value)) {
    if (!json_object_set_new(jwk, key, json_string(value))) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_set_property_str, error setting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_set_property_array(jwk_t * jwk, const char * key, size_t index, const char * value) {
  if (jwk != NULL && !o_strnullempty(key) && !o_strnullempty(value)) {
    if ((json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) || (json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) <= index)) {
      return RHN_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL && !index) {
      if (!json_object_set_new(jwk, key, json_array()) && !json_array_append_new(json_object_get(jwk, key), json_string(value))) {
        return RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_set_property_array, error appending value");
        return RHN_ERROR;
      }
    } else  {
      if (!json_array_set_new(json_object_get(jwk, key), index, json_string(value))) {
        return RHN_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_set_property_array, error setting value");
        return RHN_ERROR;
      }
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_append_property_array(jwk_t * jwk, const char * key, const char * value) {
  if (jwk != NULL && !o_strnullempty(key) && !o_strnullempty(value)) {
    if (json_object_get(jwk, key) != NULL && !json_is_array(json_object_get(jwk, key))) {
      return RHN_ERROR_PARAM;
    } else if (json_object_get(jwk, key) == NULL) {
      json_object_set_new(jwk, key, json_array());
    }
    if (!json_array_append_new(json_object_get(jwk, key), json_string(value))) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_append_property_array, error setting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_delete_property_str(jwk_t * jwk, const char * key) {
  if (jwk != NULL && !o_strnullempty(key)) {
    if (!json_object_del(jwk, key)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_delete_property_str, error deleting value");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_delete_property_array_at(jwk_t * jwk, const char * key, size_t index) {
  if (jwk != NULL && !o_strnullempty(key) && json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) > index) {
    if (!json_array_remove(json_object_get(jwk, key), index)) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_delete_property_array_at, error deleting index");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwk_append_x5c(jwk_t * jwk, int format, const unsigned char * input, size_t input_len) {
  int ret, res;
  gnutls_x509_crt_t crt = NULL;
  gnutls_datum_t data, x5c = {NULL, 0};
  char * x5c_b64 = NULL;
  struct _o_datum dat = {0, NULL};

  if (jwk != NULL && input != NULL && input_len) {
    if (!(res = gnutls_x509_crt_init(&crt))) {
      data.data = (unsigned char *)input;
      data.size = (unsigned int)input_len;
      if (!(res = gnutls_x509_crt_import(crt, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER))) {
        if (!(res = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &x5c))) {
          if (o_base64_encode_alloc(x5c.data, x5c.size, &dat)) {
            x5c_b64 = o_strndup((const char *)dat.data, dat.size);
            ret = r_jwk_append_property_array(jwk, "x5c", (const char *)x5c_b64);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_append_x5c - Error o_base64_encode_alloc for x5c_b64");
            ret = RHN_ERROR;
          }
          o_free(x5c_b64);
          o_free(dat.data);
          gnutls_free(x5c.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_append_x5c - Error gnutls_x509_crt_export2: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_append_x5c - Error gnutls_x509_crt_import: %s", gnutls_strerror(res));
        ret = RHN_ERROR_PARAM;
      }
      gnutls_x509_crt_deinit(crt);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_append_x5c - Error gnutls_x509_crt_init: %s", gnutls_strerror(res));
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

char * r_jwk_thumbprint(jwk_t * jwk, int hash, int x5u_flags) {
  int type;
  json_t * key_members = json_object(), * key_export = r_jwk_export_to_json_t(jwk);
  char * thumb = NULL, * key_dump;
  unsigned char jwk_hash[128] = {0}, jwk_hash_b64[256] = {0};
  gnutls_digest_algorithm_t alg = GNUTLS_DIG_NULL;
  size_t jwk_hash_b64_len = 256;

  switch (hash) {
    case R_JWK_THUMB_SHA256:
      alg = GNUTLS_DIG_SHA256;
      break;
    case R_JWK_THUMB_SHA384:
      alg = GNUTLS_DIG_SHA384;
      break;
    case R_JWK_THUMB_SHA512:
      alg = GNUTLS_DIG_SHA512;
      break;
  }

  if (alg != GNUTLS_DIG_NULL) {
    if (key_members != NULL) {
      type = r_jwk_key_type(jwk, NULL, x5u_flags);
      if (type & R_KEY_TYPE_SYMMETRIC) {
        json_object_set(key_members, "kty", json_object_get(key_export, "kty"));
        json_object_set(key_members, "k", json_object_get(key_export, "k"));
      } else if (type & R_KEY_TYPE_RSA) {
        json_object_set(key_members, "kty", json_object_get(key_export, "kty"));
        json_object_set(key_members, "e", json_object_get(key_export, "e"));
        json_object_set(key_members, "n", json_object_get(key_export, "n"));
      } else if (type & R_KEY_TYPE_EC) {
        json_object_set(key_members, "kty", json_object_get(key_export, "kty"));
        json_object_set(key_members, "crv", json_object_get(key_export, "crv"));
        json_object_set(key_members, "x", json_object_get(key_export, "x"));
        json_object_set(key_members, "y", json_object_get(key_export, "y"));
      } else if (type & R_KEY_TYPE_EDDSA || type & R_KEY_TYPE_ECDH) {
        json_object_set(key_members, "kty", json_object_get(key_export, "kty"));
        json_object_set(key_members, "crv", json_object_get(key_export, "crv"));
        json_object_set(key_members, "x", json_object_get(key_export, "x"));
      } else {
        type = R_KEY_TYPE_NONE;
      }
      if (type != R_KEY_TYPE_NONE) {
        key_dump = json_dumps(key_members, JSON_COMPACT|JSON_SORT_KEYS);
        if (key_dump != NULL) {
          if (!gnutls_hash_fast(alg, key_dump, o_strlen(key_dump), jwk_hash)) {
            if (o_base64url_encode(jwk_hash, (unsigned)gnutls_hash_get_len(alg), jwk_hash_b64, &jwk_hash_b64_len)) {
              thumb = o_strndup((const char *)jwk_hash_b64, jwk_hash_b64_len);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, error o_base64url_encode");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, error gnutls_hash_fast");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, error json_dumps key");
        }
        o_free(key_dump);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, error invalid key type");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, error allocating resources for key_members");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_thumbprint, invalid hash option");
  }
  json_decref(key_members);
  json_decref(key_export);
  return thumb;
}

static void scm_gnutls_certificate_status_to_c_string (gnutls_certificate_status_t c_obj) {
  static const struct {
    gnutls_certificate_status_t value;
    const char* name;
  } table[] =
    {
       { GNUTLS_CERT_INVALID, "invalid certificate" },
       { GNUTLS_CERT_REVOKED, "revoked certificate" },
       { GNUTLS_CERT_SIGNER_NOT_FOUND, "signer-not-found certificate" },
       { GNUTLS_CERT_SIGNER_NOT_CA, "signer-not-ca certificate" },
       { GNUTLS_CERT_INSECURE_ALGORITHM, "insecure-algorithm certificate" },
    };
  unsigned i;
  for (i = 0; i < 5; i++)
    {
      if (table[i].value & c_obj)
        {
          y_log_message(Y_LOG_LEVEL_DEBUG, "%s", table[i].name);
        }
    }
}

int r_jwk_validate_x5c_chain(jwk_t * jwk, int x5u_flags) {
  int ret, res;
  gnutls_certificate_status_t result;
  const char * cert;
  jwk_t * jwk_x5u = NULL;
  size_t cert_x509_len = 0, cert_x509_data_len, i;
  gnutls_x509_trust_list_t tlist = NULL;
  gnutls_x509_crt_t * cert_x509 = NULL, root_x509 = NULL;
  gnutls_datum_t cert_dat;
  struct _o_datum dat = {0, NULL};

  if (jwk != NULL) {
    // Build cert_x509 chain
    if ((cert = r_jwk_get_property_str(jwk, "x5u")) != NULL) {
      if (r_jwk_init(&jwk_x5u) == RHN_OK) {
        if (r_jwk_import_from_x5u(jwk_x5u, x5u_flags, cert) == RHN_OK) {
          if (r_jwk_get_property_array_size(jwk_x5u, "x5c") > 0) {
            cert_x509_len = (size_t)r_jwk_get_property_array_size(jwk_x5u, "x5c");
            cert_x509_data_len = cert_x509_len*sizeof(gnutls_x509_crt_t *);
            if ((cert_x509 = o_malloc(cert_x509_data_len)) != NULL) {
              memset(cert_x509, 0, cert_x509_data_len);
              ret = RHN_OK;
              for (i=0; i<cert_x509_len && ret == RHN_OK; i++) {
                cert = r_jwk_get_property_array(jwk_x5u, "x5c", i);
                if (!o_strnullempty(cert)) {
                  if (o_base64_decode_alloc((const unsigned char *)cert, o_strlen(cert), &dat)) {
                    if (!gnutls_x509_crt_init(&cert_x509[i])) {
                      cert_dat.data = dat.data;
                      cert_dat.size = (unsigned int)dat.size;
                      if ((res = gnutls_x509_crt_import(cert_x509[i], &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - Error gnutls_x509_crt_import (x5u): %d", res);
                        ret = RHN_ERROR_INVALID;
                      }
                      root_x509 = cert_x509[i];
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error gnutls_x509_crt_init (x5u)");
                      ret = RHN_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error o_base64_decode (x5u)");
                    ret = RHN_ERROR_INVALID;
                  }
                  o_free(dat.data);
                  dat.data = NULL;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error certificate empty at index %zu", i);
                  ret = RHN_ERROR_INVALID;
                }
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error o_malloc cert_x509 (x5u)");
              ret = RHN_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error x5c (x5u)");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error r_jwk_import_from_x5u");
          ret = RHN_ERROR_INVALID;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error r_jwk_init");
        ret = RHN_ERROR;
      }
      r_jwk_free(jwk_x5u);
    } else if (r_jwk_get_property_array_size(jwk, "x5c") > 0) {
      cert_x509_len = (size_t)r_jwk_get_property_array_size(jwk, "x5c");
      cert_x509_data_len = cert_x509_len*sizeof(gnutls_x509_crt_t *);
      if ((cert_x509 = o_malloc(cert_x509_data_len)) != NULL) {
        memset(cert_x509, 0, cert_x509_data_len);
        ret = RHN_OK;
        for (i=0; i<cert_x509_len && ret == RHN_OK; i++) {
          cert = r_jwk_get_property_array(jwk, "x5c", i);
          if (o_base64_decode_alloc((const unsigned char *)cert, o_strlen(cert), &dat)) {
            if (!gnutls_x509_crt_init(&cert_x509[i])) {
              cert_dat.data = dat.data;
              cert_dat.size = (unsigned int)dat.size;
              if ((res = gnutls_x509_crt_import(cert_x509[i], &cert_dat, GNUTLS_X509_FMT_DER)) < 0) {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - Error gnutls_x509_crt_import (x5c): %d", res);
                ret = RHN_ERROR_INVALID;
              }
              root_x509 = cert_x509[i];
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error gnutls_x509_crt_init (x5c)");
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error o_base64_decode (x5c)");
            ret = RHN_ERROR_INVALID;
          }
          o_free(dat.data);
          dat.data = NULL;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain, error o_malloc cert_x509 (x5c)");
        ret = RHN_ERROR_MEMORY;
      }
    } else {
      ret = RHN_ERROR_PARAM;
    }
    // Check cert chain
    if (ret == RHN_OK) {
      if (!gnutls_x509_trust_list_init(&tlist, 0)) {
        if (gnutls_x509_trust_list_add_cas(tlist, &root_x509, 1, 0) >= 0) {
          if (gnutls_x509_trust_list_verify_crt(tlist, cert_x509, (unsigned int)cert_x509_len, 0, &result, NULL) >= 0) {
            if (result) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - certificate chain invalid");
              scm_gnutls_certificate_status_to_c_string(result);
              ret = RHN_ERROR_INVALID;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - Error gnutls_x509_trust_list_verify_crt");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - Error gnutls_x509_trust_list_add_cas");
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_validate_x5c_chain - Error gnutls_x509_trust_list_init");
        ret = RHN_ERROR;
      }
      gnutls_x509_trust_list_deinit(tlist, 0);
    }
    for (i=0; i<cert_x509_len; i++) {
      if (cert_x509[i] != NULL) {
        gnutls_x509_crt_deinit(cert_x509[i]);
      }
    }
    o_free(cert_x509);
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_match_json_t(jwk_t * jwk, json_t * j_match) {
  int ret;
  json_t * j_value = NULL, * j_jwk = r_jwk_export_to_json_t(jwk);
  const char * key = NULL;

  if (j_jwk != NULL && json_object_size(j_match)) {
    ret = RHN_OK;
    json_object_foreach(j_match, key, j_value) {
      if (json_object_get(j_jwk, key) == NULL || !json_equal(json_object_get(j_jwk, key), j_value)) {
        ret = RHN_ERROR_INVALID;
        break;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_match_json_t - Error invalid input parameters");
    ret = RHN_ERROR_PARAM;
  }
  json_decref(j_jwk);
  return ret;
}

int r_jwk_match_json_str(jwk_t * jwk, const char * str_match) {
  json_t * j_match = json_loads(str_match, JSON_DECODE_ANY, NULL);
  int ret = r_jwk_match_json_t(jwk, j_match);
  json_decref(j_match);
  return ret;
}
