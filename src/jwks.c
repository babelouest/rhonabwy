/**
 *
 * Rhonabwy JSON Web Key Set (JWKS) library
 *
 * jwks.c: functions definitions
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

#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

char * _r_get_http_content(const char * url, int x5u_flags, const char * expected_content_type);

int r_jwks_init(jwks_t ** jwks) {
  int ret;
  if (jwks != NULL) {
    *jwks = json_pack("{s[]}", "keys");
    ret = (*jwks!=NULL)?RHN_OK:RHN_ERROR_MEMORY;
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

void r_jwks_free(jwks_t * jwks) {
  if (jwks != NULL) {
    json_decref(jwks);
  }
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

jwk_t * r_jwks_get_by_kid(jwks_t * jwks, const char * kid) {
  json_t * jwk = NULL;
  size_t index = 0;
  if (jwks != NULL && o_strlen(kid)) {
    json_array_foreach(json_object_get(jwks, "keys"), index, jwk) {
      if (0 == o_strcmp(kid, r_jwk_get_property_str(jwk, "kid"))) {
        return json_deep_copy(jwk);
      }
    }
  }
  return NULL;
}

jwks_t * r_jwks_copy(jwks_t * jwks) {
  if (jwks != NULL) {
    return json_deep_copy(jwks);
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

int r_jwks_empty(jwks_t * jwks) {
  if (jwks != NULL) {
    if (!json_array_clear(json_object_get(jwks, "keys"))) {
      return RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "rhonabwy jwks empty - error json_array_clear");
      return RHN_ERROR;
    }
  } else {
    return RHN_ERROR_PARAM;
  }
}

int r_jwks_equal(jwks_t * jwks1, jwks_t * jwks2) {
  return json_equal(jwks1, jwks2);
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

gnutls_privkey_t * r_jwks_export_to_gnutls_privkey(jwks_t * jwks, size_t * len) {
  gnutls_privkey_t * ret = NULL;
  size_t i;
  jwk_t * jwk;

  if (jwks != NULL && len != NULL && r_jwks_size(jwks)) {
    if ((ret = o_malloc(r_jwks_size(jwks)*sizeof(gnutls_privkey_t))) != NULL) {
      *len = r_jwks_size(jwks);
      for (i=0; i<(*len); i++) {
        jwk = r_jwks_get_at(jwks, i);
        if ((ret[i] = r_jwk_export_to_gnutls_privkey(jwk)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks export privkey - Error exporting privkey at index %zu", i);
        }
        r_jwk_free(jwk);
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
  jwk_t * jwk;

  if (jwks != NULL && len != NULL && r_jwks_size(jwks)) {
    if ((ret = o_malloc(r_jwks_size(jwks)*sizeof(gnutls_pubkey_t))) != NULL) {
      *len = r_jwks_size(jwks);
      for (i=0; i<(*len); i++) {
        jwk = r_jwks_get_at(jwks, i);
        if ((ret[i] = r_jwk_export_to_gnutls_pubkey(jwk, x5u_flags)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks export pubkey - Error exporting pubkey at index %zu", i);
        }
        r_jwk_free(jwk);
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
  jwk_t * jwk;

  if (jwks != NULL && output != NULL && output_len != NULL && (array_len = r_jwks_size(jwks))) {
    cur_len = *output_len;
    for (i=0; i<array_len; i++) {
      jwk = r_jwks_get_at(jwks, i);
      if ((ret = r_jwk_export_to_pem_der(jwk, format, cur_output, &cur_len, x5u_flags)) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks export pem der - Error exporting key at index %zu", i);
        r_jwk_free(jwk);
        break;
      } else {
        cur_output += cur_len;
        *output_len -= cur_len;
        cur_len = *output_len;
      }
      r_jwk_free(jwk);
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_import_from_json_str(jwks_t * jwks, const char * input) {
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
  char * tmp;

  if (jwks != NULL && j_input != NULL && json_is_array(json_object_get(j_input, "keys"))) {
    json_array_foreach(json_object_get(j_input, "keys"), index, j_jwk) {
      if (r_jwk_init(&jwk) == RHN_OK) {
        if ((res = r_jwk_import_from_json_t(jwk, j_jwk)) == RHN_OK) {
          r_jwks_append_jwk(jwks, jwk);
        } else if (res == RHN_ERROR_PARAM) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "jwks import json_t - Invalid jwk format");
          tmp = json_dumps(j_jwk, JSON_INDENT(2));
          y_log_message(Y_LOG_LEVEL_DEBUG, "%s", tmp);
          o_free(tmp);
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks import json_t - Error r_jwk_import_from_json_t");
          ret = RHN_ERROR;
        }
        r_jwk_free(jwk);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks import json_t - Error memory");
        ret = RHN_ERROR_MEMORY;
        break;
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "jwks import json_t - Invalid jwks format");
    tmp = json_dumps(j_input, JSON_INDENT(2));
    y_log_message(Y_LOG_LEVEL_DEBUG, "%s", tmp);
    o_free(tmp);
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

int r_jwks_import_from_uri(jwks_t * jwks, const char * uri, int x5u_flags) {
  int ret;
  json_t * j_result = NULL;
  char * x5u_content = NULL;

  if (jwks != NULL && uri != NULL) {
    if ((x5u_content = _r_get_http_content(uri, x5u_flags, "application/json")) != NULL) {
      j_result = json_loads(x5u_content, JSON_DECODE_ANY, NULL);
      if (j_result != NULL) {
        ret = r_jwks_import_from_json_t(jwks, j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_import_from_uri - Error _r_get_http_content");
        ret = RHN_ERROR;
      }
      json_decref(j_result);
      o_free(x5u_content);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_import_from_uri x5u - Error getting x5u content");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}

jwks_t * r_jwks_quick_import(rhn_import type, ...) {
  va_list vl;
  rhn_import opt;
  jwk_t * jwk;
  jwks_t * jwks;
  int i_val;
  const char * str;
  json_t * j_jwk;
  const unsigned char * data;
  size_t data_len;
  gnutls_privkey_t privkey;
  gnutls_pubkey_t pubkey;
  gnutls_x509_crt_t crt;

  if (r_jwks_init(&jwks) != RHN_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_quick_import - Error r_jwks_init");
    return NULL;
  } else {
    va_start(vl, type);
    opt = type;
    while (opt != R_IMPORT_NONE) {
      switch (opt) {
        case R_IMPORT_JSON_STR:
          str = va_arg(vl, const char *);
          j_jwk = json_loads(str, JSON_DECODE_ANY, NULL);
          if (json_is_array(json_object_get(j_jwk, "keys"))) {
            r_jwks_import_from_json_t(jwks, j_jwk);
          } else {
            if ((jwk = r_jwk_quick_import(R_IMPORT_JSON_T, j_jwk)) != NULL) {
              r_jwks_append_jwk(jwks, jwk);
              r_jwk_free(jwk);
            }
          }
          json_decref(j_jwk);
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_JSON_T:
          j_jwk = va_arg(vl, json_t *);
          if (json_is_array(json_object_get(j_jwk, "keys"))) {
            r_jwks_import_from_json_t(jwks, j_jwk);
          } else {
            if ((jwk = r_jwk_quick_import(R_IMPORT_JSON_T, j_jwk)) != NULL) {
              r_jwks_append_jwk(jwks, jwk);
              r_jwk_free(jwk);
            }
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_PEM:
          i_val = va_arg(vl, int);
          data = va_arg(vl, const unsigned char *);
          data_len = va_arg(vl, size_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_PEM, i_val, data, data_len)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_DER:
          i_val = va_arg(vl, int);
          data = va_arg(vl, const unsigned char *);
          data_len = va_arg(vl, size_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_DER, i_val, data, data_len)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_G_PRIVKEY:
          privkey = va_arg(vl, gnutls_privkey_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_G_PRIVKEY, privkey)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_G_PUBKEY:
          pubkey = va_arg(vl, gnutls_pubkey_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_G_PUBKEY, pubkey)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_G_CERT:
          crt = va_arg(vl, gnutls_x509_crt_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_G_CERT, crt)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_X5U:
          i_val = va_arg(vl, int);
          str = va_arg(vl, const char *);
          if ((jwk = r_jwk_quick_import(R_IMPORT_X5U, i_val, str)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_SYMKEY:
          data = va_arg(vl, const unsigned char *);
          data_len = va_arg(vl, size_t);
          if ((jwk = r_jwk_quick_import(R_IMPORT_SYMKEY, data, data_len)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_PASSWORD:
          str = va_arg(vl, const char *);
          if ((jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, str)) != NULL) {
            r_jwks_append_jwk(jwks, jwk);
            r_jwk_free(jwk);
          }
          opt = va_arg(vl, rhn_import);
          break;
        case R_IMPORT_JKU:
          i_val = va_arg(vl, int);
          str = va_arg(vl, const char *);
          r_jwks_import_from_uri(jwks, str, i_val);
          opt = va_arg(vl, rhn_import);
          break;
        default:
          y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_quick_import - Invalid type");
          opt = R_IMPORT_NONE;
          break;
      }
    }
    va_end(vl);
    return jwks;
  }
}

jwks_t * r_jwks_search_json_t(jwks_t * jwks, json_t * j_match) {
  jwks_t * jwks_ret = NULL;
  jwk_t * jwk;
  size_t i;
  
  if (r_jwks_init(&jwks_ret) == RHN_OK) {
    if (r_jwks_size(jwks) && json_object_size(j_match)) {
      for (i=0; i<r_jwks_size(jwks); i++) {
        jwk = r_jwks_get_at(jwks, i);
        if (r_jwk_match_json_t(jwk, j_match) == RHN_OK) {
          r_jwks_append_jwk(jwks_ret, jwk);
        }
        r_jwk_free(jwk);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_search_json_t - Error invalid input parameters");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_jwks_search_json_t - Error r_jwks_init");
  }
  return jwks_ret;
}

jwks_t * r_jwks_search_json_str(jwks_t * jwks, const char * str_match) {
  json_t * j_match = json_loads(str_match, JSON_DECODE_ANY, NULL);
  jwks_t * jwks_ret = r_jwks_search_json_t(jwks, j_match);
  json_decref(j_match);
  return jwks_ret;
}
