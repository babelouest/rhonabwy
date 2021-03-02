/**
 *
 * Rhonabwy JSON Web Key Set (JWKS) library
 *
 * jwks.c: functions definitions
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
#include <ulfius.h>
#include <rhonabwy.h>

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

  if (jwks != NULL && j_input != NULL && json_is_array(json_object_get(j_input, "keys"))) {
    json_array_foreach(json_object_get(j_input, "keys"), index, j_jwk) {
      if (r_jwk_init(&jwk) == RHN_OK) {
        if ((res = r_jwk_import_from_json_t(jwk, j_jwk)) == RHN_OK) {
          r_jwks_append_jwk(jwks, jwk);
        } else if (res == RHN_ERROR_PARAM) {
          ret = RHN_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "jwks import json_t - Error r_jwk_import_from_json_t");
          ret = RHN_ERROR;
        }
        r_jwk_free(jwk);
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

int r_jwks_import_from_uri(jwks_t * jwks, const char * uri, int flags) {
  struct _u_request request;
  struct _u_response response;
  int ret;
  json_t * j_result;

  if (jwks != NULL && uri != NULL) {
    if (ulfius_init_request(&request) == U_OK && ulfius_init_response(&response) == U_OK) {
      ulfius_set_request_properties(&request, U_OPT_HTTP_VERB, "GET",
                                              U_OPT_HTTP_URL, uri,
                                              U_OPT_CHECK_SERVER_CERTIFICATE, !(flags & R_FLAG_IGNORE_SERVER_CERTIFICATE),
                                              U_OPT_FOLLOW_REDIRECT, flags & R_FLAG_FOLLOW_REDIRECT,
                                              U_OPT_HEADER_PARAMETER, "User-Agent", "Rhonabwy/" RHONABWY_VERSION_STR,
                                              U_OPT_NONE);
      if (ulfius_send_http_request(&request, &response) == U_OK) {
        if (response.status >= 200 && response.status < 300) {
          j_result = ulfius_get_json_body_response(&response, NULL);
          if (j_result != NULL) {
            if (r_jwks_import_from_json_t(jwks, j_result) == RHN_OK) {
              ret = RHN_OK;
            } else {
              ret = RHN_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "jwks import uri - Error ulfius_get_json_body_response");
            ret = RHN_ERROR;
          }
          json_decref(j_result);
        } else {
          ret = RHN_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwks import uri - Error ulfius_send_http_request");
        ret = RHN_ERROR;
      }
      ulfius_clean_request(&request);
      ulfius_clean_response(&response);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwks import uri - Error ulfius_init_request or ulfius_init_response");
      ret = RHN_ERROR;
    }
  } else {
    ret = RHN_ERROR_PARAM;
  }
  return ret;
}
