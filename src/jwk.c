/**
 * 
 * Rhonabwy JSON Web Key (JWK) library
 * 
 * jwk.c: functions definitions
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
#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

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
  int ret = RHN_OK, has_pubkey_parameters = 0, has_privkey_parameters = 0, has_kty = 0, has_alg = 0;
  json_t * j_element = NULL;
  size_t index = 0, b64dec_len = 0;
  
  if (jwk != NULL) {
    if (json_is_object(jwk)) {
      // JWK parameters
      if (json_object_get(jwk, "x5u") != NULL) {
        if (!json_is_array(json_object_get(jwk, "x5u"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5u");
          ret = RHN_ERROR_PARAM;
        } else {
          json_array_foreach(json_object_get(jwk, "x5u"), index, j_element) {
            if (!json_string_length(j_element) || o_strncasecmp("https://", json_string_value(j_element), o_strlen("https://"))) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x5u");
              ret = RHN_ERROR_PARAM;
            }
          }
        }
      }
      if (json_object_get(jwk, "x5c") != NULL) {
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
        }
      }
      if (json_object_get(jwk, "kty") != NULL) {
        if (!json_string_length(json_object_get(jwk, "kty"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid kty");
          ret = RHN_ERROR_PARAM;
        }
        has_kty = 1;
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
        if (str_to_jwa_alg(json_string_value(json_object_get(jwk, "alg"))) == R_JWA_ALG_UNKNOWN) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid alg");
          ret = RHN_ERROR_PARAM;
        }
        has_alg = 1;
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
        if (json_object_get(jwk, "crv")) {
          if (0 != o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv"))) &&
              0 != o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid crv");
            ret = RHN_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "x"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x");
          ret = RHN_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid x format");
            ret = RHN_ERROR_PARAM;
          }
        }
        if (0 != o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
          if (!json_string_length(json_object_get(jwk, "y"))) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid y");
            ret = RHN_ERROR_PARAM;
          } else if (has_pubkey_parameters) {
            if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), NULL, &b64dec_len) || !b64dec_len) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid y format");
              ret = RHN_ERROR_PARAM;
            }
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
        if (!json_string_length(json_object_get(jwk, "n"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid n");
          ret = RHN_ERROR_PARAM;
        } else {
          if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), NULL, &b64dec_len) || !b64dec_len) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid n format");
            ret = RHN_ERROR_PARAM;
          }
          has_pubkey_parameters = 1;
        }
        if (!json_string_length(json_object_get(jwk, "e"))) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid e");
          ret = RHN_ERROR_PARAM;
        } else if (has_pubkey_parameters) {
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
          has_pubkey_parameters = 1;
        }
      }
      
      // Validate if required parameters are present and consistent
      if (ret == RHN_OK) {
        if (!has_kty) {
          if (!has_alg) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - Invalid data");
            ret = RHN_ERROR_PARAM;
          }
        } else {
          if (has_kty && !has_pubkey_parameters) {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_is_valid - public key parameters missing");
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

int r_jwk_generate_key_pair(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int type, unsigned int bits, const char * kid) {
  int ret;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey;
#if GNUTLS_VERSION_NUMBER >= 0x030600
  unsigned int ec_bits = 0;
  gnutls_pk_algorithm_t alg = GNUTLS_PK_UNKNOWN;
#endif
  
  if (jwk_privkey != NULL && jwk_pubkey != NULL && (type == R_KEY_TYPE_RSA || type == R_KEY_TYPE_ECDSA || type == R_KEY_TYPE_EDDSA) && bits) {
    if (!gnutls_privkey_init(&privkey) && !gnutls_pubkey_init(&pubkey)) {
      if (type == R_KEY_TYPE_RSA) {
        if (!gnutls_privkey_generate(privkey, GNUTLS_PK_RSA, bits, 0)) {
          if (!gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
            if (r_jwk_import_from_gnutls_privkey(jwk_privkey, privkey) == RHN_OK) {
              if (r_jwk_import_from_gnutls_pubkey(jwk_pubkey, pubkey) == RHN_OK) {
                if (o_strlen(kid)) {
                  json_object_set_new(jwk_privkey, "kid", json_string(kid));
                  json_object_set_new(jwk_pubkey, "kid", json_string(kid));
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
#if GNUTLS_VERSION_NUMBER >= 0x030600
      } else if (type == R_KEY_TYPE_ECDSA || type == R_KEY_TYPE_EDDSA) {
        if (type == R_KEY_TYPE_ECDSA) {
          if (bits == 256) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1);
            alg = GNUTLS_PK_ECDSA;
          } else if (bits == 384) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1);
            alg = GNUTLS_PK_ECDSA;
          } else if (bits == 512) {
            ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP521R1);
            alg = GNUTLS_PK_ECDSA;
          }
#if GNUTLS_VERSION_NUMBER >= 0x030600
        } else {
          ec_bits = GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_ED25519);
          alg = GNUTLS_PK_EDDSA_ED25519;
#endif // GNUTLS_VERSION_NUMBER >= 0x030600
        }
        if (ec_bits) {
          if (!gnutls_privkey_generate(privkey, alg, ec_bits, 0)) {
            if (!gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
              if (r_jwk_import_from_gnutls_privkey(jwk_privkey, privkey) == RHN_OK) {
                if (r_jwk_import_from_gnutls_pubkey(jwk_pubkey, pubkey) == RHN_OK) {
                  if (o_strlen(kid)) {
                    json_object_set_new(jwk_privkey, "kid", json_string(kid));
                    json_object_set_new(jwk_pubkey, "kid", json_string(kid));
                  }
                  ret = RHN_OK;
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
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error gnutls_privkey_generate ECC");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_generate_key_pair - Error curve length, values allowed are 256, 384 or 512");
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
  gnutls_x509_crt_t     crt      = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_pubkey_t       pubkey   = NULL;
  gnutls_datum_t        data;
  int ret = R_KEY_TYPE_NONE, pk_alg;
  unsigned char * data_dec = NULL;
  size_t data_dec_len = 0, k_len = 0;
  int bits_set = 0;
  
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
      if (json_object_get(jwk, "y") != NULL) {
        ret = R_KEY_TYPE_ECDSA;
      } else {
        ret = R_KEY_TYPE_EDDSA;
      }
      if (json_object_get(jwk, "d") != NULL) {
        ret |= R_KEY_TYPE_PRIVATE;
      } else {
        ret |= R_KEY_TYPE_PUBLIC;
      }
    } else if (0 == o_strcmp(json_string_value(json_object_get(jwk, "kty")), "oct") && json_string_length(json_object_get(jwk, "k"))) {
      ret = R_KEY_TYPE_HMAC|R_KEY_TYPE_SYMMETRIC;
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
                      pk_alg = gnutls_x509_privkey_get_pk_algorithm2(x509_key, bits);
                      bits_set = 1;
                      if (pk_alg == GNUTLS_PK_RSA) {
                        ret = R_KEY_TYPE_RSA;
#if GNUTLS_VERSION_NUMBER >= 0x030600
                      } else if (pk_alg == GNUTLS_PK_ECDSA) {
                        ret = R_KEY_TYPE_ECDSA;
                      } else if (pk_alg == GNUTLS_PK_EDDSA_ED25519) {
                        ret = R_KEY_TYPE_EDDSA;
#endif
                      }
                      ret |= R_KEY_TYPE_PRIVATE;
                    } else if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER)) {
                      pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, bits);
                      bits_set = 1;
                      if (pk_alg == GNUTLS_PK_RSA) {
                        ret = R_KEY_TYPE_RSA;
#if GNUTLS_VERSION_NUMBER >= 0x030600
                      } else if (pk_alg == GNUTLS_PK_ECDSA) {
                        ret = R_KEY_TYPE_ECDSA;
                      } else if (pk_alg == GNUTLS_PK_EDDSA_ED25519) {
                        ret = R_KEY_TYPE_EDDSA;
#endif
                      }
                      ret |= R_KEY_TYPE_PUBLIC;
                    } else if (!gnutls_pubkey_import(pubkey, &data, GNUTLS_X509_FMT_DER)) {
                      pk_alg = gnutls_pubkey_get_pk_algorithm(pubkey, bits);
                      bits_set = 1;
                      if (pk_alg == GNUTLS_PK_RSA) {
                        ret = R_KEY_TYPE_RSA;
#if GNUTLS_VERSION_NUMBER >= 0x030600
                      } else if (pk_alg == GNUTLS_PK_ECDSA) {
                        ret = R_KEY_TYPE_ECDSA;
                      } else if (pk_alg == GNUTLS_PK_EDDSA_ED25519) {
                        ret = R_KEY_TYPE_EDDSA;
#endif
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
      if (!(x5u_flags & R_FLAG_IGNORE_REMOTE)) {
        // Get first x5u
        if (ulfius_init_request(&request) == U_OK) {
          if (ulfius_init_response(&response) == U_OK) {
            request.http_verb = o_strdup("GET");
            request.http_url = o_strdup(json_string_value(json_array_get(json_object_get(jwk, "x5u"), 0)));
            request.check_server_certificate = !(x5u_flags & R_FLAG_IGNORE_SERVER_CERTIFICATE);
            request.follow_redirect = x5u_flags & R_FLAG_FOLLOW_REDIRECT;
            if (ulfius_send_http_request(&request, &response) == U_OK && response.status >= 200 && response.status < 300) {
              data.data = response.binary_body;
              data.size = response.binary_body_length;
              if (!gnutls_x509_crt_init(&crt)) {
                if (!gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM)) {
                  pk_alg = gnutls_x509_crt_get_pk_algorithm(crt, bits);
                  bits_set = 1;
                  if (pk_alg == GNUTLS_PK_RSA) {
                    ret = R_KEY_TYPE_RSA;
  #if GNUTLS_VERSION_NUMBER >= 0x030600
                  } else if (pk_alg == GNUTLS_PK_ECDSA) {
                    ret = R_KEY_TYPE_ECDSA;
                  } else if (pk_alg == GNUTLS_PK_EDDSA_ED25519) {
                    ret = R_KEY_TYPE_EDDSA;
  #endif
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error unsupported algorithm %s", gnutls_pk_algorithm_get_name(pk_alg));
                  }
                  ret |= R_KEY_TYPE_PUBLIC;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error gnutls_x509_crt_import");
                  ret = R_KEY_TYPE_NONE;
                }
                gnutls_x509_crt_deinit(crt);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error gnutls_x509_crt_init");
                ret = R_KEY_TYPE_NONE;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_send_http_request %d", response.status);
              ret = R_KEY_TYPE_NONE;
            }
            ulfius_clean_request(&request);
            ulfius_clean_response(&response);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_init_response");
            ret = R_KEY_TYPE_NONE;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type x5u - Error ulfius_init_request");
          ret = R_KEY_TYPE_NONE;
        }
      } else {
        ret = R_KEY_TYPE_NONE;
      }
    }
  }
  if (bits != NULL && !bits_set) {
    if (ret & R_KEY_TYPE_RSA) {
      if ((pubkey = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) != NULL) {
        gnutls_pubkey_get_pk_algorithm(pubkey, bits);
        gnutls_pubkey_deinit(pubkey);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error r_jwk_export_to_gnutls_pubkey");
      }
    } else if (ret & (R_KEY_TYPE_ECDSA|R_KEY_TYPE_EDDSA)) {
      if (0 == o_strcmp("P-256", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      } else if (0 == o_strcmp("P-384", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 384;
      } else if (0 == o_strcmp("P-512", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 512;
      } else if (0 == o_strcmp("Ed25519", json_string_value(json_object_get(jwk, "crv")))) {
        *bits = 256;
      }
    } else if (ret & R_KEY_TYPE_HMAC) {
      if (o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "k")), json_string_length(json_object_get(jwk, "k")), NULL, &k_len)) {
        *bits = (unsigned int)k_len;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_key_type - Error invalid base64url k value");
        ret = R_KEY_TYPE_NONE;
      }
    }
  }
  return ret;
}

int r_jwk_extract_pubkey(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int x5u_flags) {
  int ret;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey = NULL;
  
  if (r_jwk_is_valid(jwk_privkey) == RHN_OK && r_jwk_key_type(jwk_privkey, NULL, x5u_flags) & R_KEY_TYPE_PRIVATE && jwk_pubkey != NULL) {
    if ((privkey = r_jwk_export_to_gnutls_privkey(jwk_privkey, x5u_flags)) != NULL) {
      if (!gnutls_pubkey_init(&pubkey)) {
        if (!gnutls_pubkey_import_privkey(pubkey, privkey, GNUTLS_KEY_DIGITAL_SIGNATURE|GNUTLS_KEY_KEY_ENCIPHERMENT|GNUTLS_KEY_DATA_ENCIPHERMENT, 0)) {
          if (r_jwk_import_from_gnutls_pubkey(jwk_pubkey, pubkey) == RHN_OK) {
            if (json_string_length(json_object_get(jwk_privkey, "kid"))) {
              json_object_set_new(jwk_pubkey, "kid", json_string(json_string_value(json_object_get(jwk_privkey, "kid"))));
            }
            ret = RHN_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error r_jwk_init or r_jwk_import_from_gnutls_pubkey");
            ret = RHN_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error gnutls_pubkey_import_privkey");
          ret = RHN_ERROR;
        }
        gnutls_pubkey_deinit(pubkey);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error gnutls_pubkey_init");
        ret = RHN_ERROR;
      }
      gnutls_privkey_deinit(privkey);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_extract_pubkey - Error r_jwk_export_to_gnutls_privkey");
      ret = RHN_ERROR;
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
  
  if (jwk != NULL && input != NULL && input_len) {
    switch (type) {
      case R_X509_TYPE_PUBKEY:
        if (!(res = gnutls_pubkey_init(&pub))) {
          data.data = (unsigned char *)input;
          data.size = input_len;
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
          data.data = (unsigned char *)input;
          data.size = input_len;
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
          data.data = (unsigned char *)input;
          data.size = input_len;
          if (!(res = gnutls_x509_crt_import(crt, &data, format==R_FORMAT_PEM?GNUTLS_X509_FMT_PEM:GNUTLS_X509_FMT_DER))) {
            ret = r_jwk_import_from_gnutls_x509_crt(jwk, crt);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error r_jwk_import_from_gnutls_x509_crt: %s", gnutls_strerror(res));
            ret = RHN_ERROR_PARAM;
          }
          gnutls_x509_crt_deinit(crt);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error gnutls_x509_crt_init: %s", gnutls_strerror(res));
          ret = RHN_ERROR;
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_pem_der - Error invalid type");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(d.data, d.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (3)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(d.data, d.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (6)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(p.data, p.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (7)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (4)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(p.data, p.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (8)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "p", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(q.data, q.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (9)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (5)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(q.data, q.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (10)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "q", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(u.data, u.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (11)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (6)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(u.data, u.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (12)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "qi", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e1.data, e1.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (13)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (7)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e1.data, e1.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (14)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dp", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(e2.data, e2.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (15)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_malloc (8)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e2.data, e2.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey rsa - Error o_base64url_encode (16)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "dq", json_string((const char *)b64_enc));
            
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
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey - Error gnutls_pubkey_export_rsa_raw2");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "y", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(k.data, k.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_malloc (3)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(k.data, k.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (6)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_string((const char *)b64_enc));
            
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
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error curve");
                ret = RHN_ERROR_PARAM;
                break;
            }

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
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(y.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error gnutls_pubkey_export_ecc_raw2");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_EDDSA_ED25519:
        if ((res = gnutls_privkey_export_ecc_raw(key, &curve, &x, NULL, &k)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            
            if (!o_base64url_encode(k.data, k.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_malloc (3)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(k.data, k.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error o_base64url_encode (6)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "d", json_string((const char *)b64_enc));
            json_object_set_new(jwk, "crv", json_string("Ed25519"));
            
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
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(k.data);
          gnutls_x509_privkey_deinit(x509_key);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_privkey ecdsa - Error gnutls_pubkey_export_ecc_raw2");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(m.data, m.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "n", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(e.data, e.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(e.data, e.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode (4)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "e", json_string((const char *)b64_enc));
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey rsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(m.data);
          gnutls_free(e.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey - Error gnutls_pubkey_export_rsa_raw");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            o_free(b64_enc);
            if (!o_base64url_encode(y.data, y.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (3)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_malloc (2)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(y.data, y.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (4)");
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
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
          gnutls_free(y.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error gnutls_pubkey_export_ecc_raw");
          ret = RHN_ERROR_PARAM;
        }
        break;
      case GNUTLS_PK_EDDSA_ED25519:
        if ((res = gnutls_pubkey_export_ecc_raw(pub, &curve, &x, NULL)) == GNUTLS_E_SUCCESS) {
          json_object_set_new(jwk, "kty", json_string("EC"));
          ret = RHN_OK;
          do {
            if (!o_base64url_encode(x.data, x.size, NULL, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (1)");
              ret = RHN_ERROR;
              break;
            }
            if ((b64_enc = o_malloc((b64_enc_len+4)*sizeof(char))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_malloc (1)");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(x.data, x.size, b64_enc, &b64_enc_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (2)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "x", json_string((const char *)b64_enc));
            
            json_object_set_new(jwk, "crv", json_string("Ed25519"));

            if (ret != RHN_OK) {
              break;
            }
            if (gnutls_pubkey_get_key_id(pub, GNUTLS_KEYID_USE_SHA256, kid, &kid_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error gnutls_pubkey_get_key_id");
              ret = RHN_ERROR;
              break;
            }
            if (!o_base64url_encode(kid, kid_len, kid_b64, &kid_b64_len)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error o_base64url_encode (5)");
              ret = RHN_ERROR;
              break;
            }
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
          } while (0);
          o_free(b64_enc);
          gnutls_free(x.data);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_gnutls_pubkey ecdsa - Error gnutls_pubkey_export_ecc_raw");
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
            json_object_set_new(jwk, "kid", json_string((const char *)kid_b64));
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

int r_jwk_import_from_x5u(jwk_t * jwk, int type, int x5u_flags, const char * x5u) {
  struct _u_request req;
  struct _u_response resp;
  int ret;
  
  if (jwk != NULL && x5u != NULL) {
    if (ulfius_init_request(&req) == U_OK && ulfius_init_response(&resp) == U_OK) {
      req.http_url = o_strdup(x5u);
      req.check_server_certificate = !(x5u_flags & R_FLAG_IGNORE_SERVER_CERTIFICATE);
      req.follow_redirect = x5u_flags & R_FLAG_FOLLOW_REDIRECT;
      if (ulfius_send_http_request(&req, &resp) == U_OK) {
        if (resp.status >= 200 && resp.status < 300) {
          if (r_jwk_import_from_pem_der(jwk, type, R_FORMAT_PEM, resp.binary_body, resp.binary_body_length) == RHN_OK) {
            ret = RHN_OK;
          } else {
            ret = RHN_ERROR;
          }
        } else {
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_x5u - Error ulfius_send_http_request");
        ret = RHN_ERROR;
      }
      ulfius_clean_request(&req);
      ulfius_clean_response(&resp);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_x5u - Error ulfius_init_request or ulfius_init_response");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwk_import_from_symmetric_key(jwk_t * jwk, const unsigned char * key, size_t key_len) {
  int ret;
  unsigned char * key_b64 = NULL;
  size_t key_b64_len = 0;
  
  if (jwk != NULL && key != NULL && key_len) {
    if ((key_b64 = o_malloc(key_len*2)) != NULL) {
      if (o_base64url_encode(key, key_len, key_b64, &key_b64_len)) {
        key_b64[key_b64_len] = '\0';
        if (r_jwk_set_property_str(jwk, "kty", "oct") == RHN_OK && r_jwk_set_property_str(jwk, "k", (const char *)key_b64) == RHN_OK) {
          ret = RHN_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_symmetric_key - Error setting key data in jwk");
          ret = RHN_ERROR;
        }
      } else {
        ret = RHN_ERROR_PARAM;
      }
      o_free(key_b64);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_import_from_symmetric_key - Error allocating resources for key_b64");
      ret = RHN_ERROR_MEMORY;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
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

gnutls_privkey_t r_jwk_export_to_gnutls_privkey(jwk_t * jwk, int x5u_flags) {
  gnutls_privkey_t privkey       = NULL;
  gnutls_x509_privkey_t x509_key = NULL;
  gnutls_ecc_curve_t curve;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, d = {NULL, 0}, p = {NULL, 0}, q = {NULL, 0}, e1 = {NULL, 0}, e2 = {NULL, 0}, x = {NULL, 0}, y = {NULL, 0}, k = {NULL, 0}, data = {NULL, 0};
  
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  int res, type = r_jwk_key_type(jwk, NULL, x5u_flags);
  
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
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey x5c - Error o_base64_decode (2)");
            res = RHN_ERROR_MEMORY;
          }
          o_free(b64_dec);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey x5c - Error o_malloc");
          res = RHN_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey x5c - Error o_base64_decode (1)");
        res = RHN_ERROR_MEMORY;
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (n)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (n)");
          res = RHN_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (e)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (e)");
          res = RHN_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (d)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (d)");
          res = RHN_ERROR;
          break;
        }
        d.data = b64_dec;
        d.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "p"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (p)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "p")), json_string_length(json_object_get(jwk, "p")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (p)");
          res = RHN_ERROR;
          break;
        }
        p.data = b64_dec;
        p.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "q"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (q)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "q")), json_string_length(json_object_get(jwk, "q")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (q)");
          res = RHN_ERROR;
          break;
        }
        q.data = b64_dec;
        q.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dp"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (dp)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dp")), json_string_length(json_object_get(jwk, "dp")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (dp)");
          res = RHN_ERROR;
          break;
        }
        e1.data = b64_dec;
        e1.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "dq"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (dq)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "dq")), json_string_length(json_object_get(jwk, "dq")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (dq)");
          res = RHN_ERROR;
          break;
        }
        e2.data = b64_dec;
        e2.size = b64_dec_len;
        
        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_rsa_raw(privkey, &m, &e, &d, &p, &q, NULL, &e1, &e2)) {
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
      o_free(e1.data);
      o_free(e2.data);
    } else if (type & R_KEY_TYPE_ECDSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (y)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (y)");
          res = RHN_ERROR;
          break;
        }
        y.data = b64_dec;
        y.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (d)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (d)");
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
    } else if (type & R_KEY_TYPE_EDDSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "d"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error malloc (d)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "d")), json_string_length(json_object_get(jwk, "d")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error o_base64url_decode (d)");
          res = RHN_ERROR;
          break;
        }
        k.data = b64_dec;
        k.size = b64_dec_len;

        if (gnutls_privkey_init(&privkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_privkey - Error gnutls_privkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_privkey_import_ecc_raw(privkey, GNUTLS_ECC_CURVE_ED25519, &x, &y, &k)) {
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
  gnutls_x509_crt_t crt;
  unsigned char * b64_dec;
  size_t b64_dec_len = 0;
  gnutls_datum_t m = {NULL, 0}, e = {NULL, 0}, data = {NULL, 0};
  int res, type = r_jwk_key_type(jwk, NULL, x5u_flags);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  gnutls_ecc_curve_t curve;
  gnutls_datum_t x = {NULL, 0}, y = {NULL, 0};
#endif

  struct _u_request request;
  struct _u_response response;

  if (type & (R_KEY_TYPE_PUBLIC|R_KEY_TYPE_PRIVATE)) {
    if (json_object_get(jwk, "n") == NULL && json_object_get(jwk, "x") == NULL && (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL || json_array_get(json_object_get(jwk, "x5u"), 0) != NULL)) {
      if (json_array_get(json_object_get(jwk, "x5c"), 0) != NULL) {
        // Export first x5c
        if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), NULL, &b64_dec_len)) {
          if ((b64_dec = o_malloc((b64_dec_len+1)*sizeof(char))) != NULL) {
            if (o_base64_decode((const unsigned char *)json_string_value(json_array_get(json_object_get(jwk, "x5c"), 0)), json_string_length(json_array_get(json_object_get(jwk, "x5c"), 0)), b64_dec, &b64_dec_len)) {
              if (!gnutls_x509_crt_init(&crt)) {
                if (!gnutls_pubkey_init(&pubkey)) {
                  data.data = b64_dec;
                  data.size = b64_dec_len;
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
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error o_base64_decode (2)");
              res = RHN_ERROR_MEMORY;
            }
            o_free(b64_dec);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error o_malloc");
            res = RHN_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5c - Error o_base64_decode (1)");
          res = RHN_ERROR_MEMORY;
        }
      } else {
        if (!(x5u_flags & R_FLAG_IGNORE_REMOTE)) {
          // Get first x5u
          if (ulfius_init_request(&request) == U_OK) {
            if (ulfius_init_response(&response) == U_OK) {
              request.http_verb = o_strdup("GET");
              request.http_url = o_strdup(json_string_value(json_array_get(json_object_get(jwk, "x5u"), 0)));
              request.check_server_certificate = !(x5u_flags&R_FLAG_IGNORE_SERVER_CERTIFICATE);
              request.follow_redirect = x5u_flags&R_FLAG_FOLLOW_REDIRECT;
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
                        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_import_x509");
                        res = RHN_ERROR;
                      }
                    } else {
                      gnutls_pubkey_deinit(pubkey);
                      pubkey = NULL;
                      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_import");
                      res = RHN_ERROR;
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_pubkey_init rsa");
                    res = RHN_ERROR;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error gnutls_x509_crt_init");
                  res = RHN_ERROR;
                }
                gnutls_x509_crt_deinit(crt);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error ulfius_send_http_request");
                res = RHN_ERROR_MEMORY;
              }
              ulfius_clean_request(&request);
              ulfius_clean_response(&response);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error ulfius_init_response");
              res = RHN_ERROR_MEMORY;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey x5u - Error ulfius_init_request");
            res = RHN_ERROR_MEMORY;
          }
        } else {
          res = RHN_ERROR_UNSUPPORTED;
        }
      }
    } else if (type & R_KEY_TYPE_RSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "n"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error malloc (n)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "n")), json_string_length(json_object_get(jwk, "n")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode (n)");
          res = RHN_ERROR;
          break;
        }
        m.data = b64_dec;
        m.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "e"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error malloc (e)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "e")), json_string_length(json_object_get(jwk, "e")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode (e)");
          res = RHN_ERROR;
          break;
        }
        e.data = b64_dec;
        e.size = b64_dec_len;
        
        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_privkey_init rsa");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_rsa_raw(pubkey, &m, &e)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_privkey_import_rsa_raw");
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
#if GNUTLS_VERSION_NUMBER >= 0x030600
    } else if (type & R_KEY_TYPE_ECDSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "y"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error malloc (y)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "y")), json_string_length(json_object_get(jwk, "y")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode (y)");
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
    } else if (type & R_KEY_TYPE_EDDSA) {
      res = RHN_OK;
      do {
        if ((b64_dec = o_malloc(json_string_length(json_object_get(jwk, "x"))*sizeof(char))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error malloc (x)");
          res = RHN_ERROR_MEMORY;
          break;
        }
        if (!o_base64url_decode((const unsigned char *)json_string_value(json_object_get(jwk, "x")), json_string_length(json_object_get(jwk, "x")), b64_dec, &b64_dec_len)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error o_base64url_decode (x)");
          res = RHN_ERROR;
          break;
        }
        x.data = b64_dec;
        x.size = b64_dec_len;

        if (gnutls_pubkey_init(&pubkey)) {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_gnutls_pubkey - Error gnutls_pubkey_init ec");
          res = RHN_ERROR;
          break;
        }
        if (gnutls_pubkey_import_ecc_raw(pubkey, GNUTLS_ECC_CURVE_ED25519, &x, NULL)) {
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

int r_jwk_export_to_pem_der(jwk_t * jwk, int format, unsigned char * output, size_t * output_len, int x5u_flags) {
  gnutls_pubkey_t pubkey = NULL;
  gnutls_privkey_t privkey = NULL;
  gnutls_x509_privkey_t x509_privkey = NULL;
  int res, ret, type = r_jwk_key_type(jwk, NULL, x5u_flags);
  int test_size = (output==NULL);
  
  if (type & R_KEY_TYPE_PRIVATE) {
    if ((privkey = r_jwk_export_to_gnutls_privkey(jwk, x5u_flags)) != NULL) {
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
  size_t k_len = 0;
  
  if (jwk != NULL && key_len != NULL) {
    if (r_jwk_key_type(jwk, NULL, 0) & R_KEY_TYPE_SYMMETRIC) {
      k = r_jwk_get_property_str(jwk, "k");
      if ((k_len = o_strlen(k))) {
        if (o_base64url_decode((const unsigned char *)k, k_len, key, key_len)) {
          ret = RHN_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_export_to_symmetric_key - Error o_base64url_decode");
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
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwk_set_property_str, error setting value");
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
  if (jwk != NULL && o_strlen(key) && o_strlen(value)) {
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
  if (jwk != NULL && o_strlen(key)) {
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
  if (jwk != NULL && o_strlen(key) && json_is_array(json_object_get(jwk, key)) && json_array_size(json_object_get(jwk, key)) > index) {
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
