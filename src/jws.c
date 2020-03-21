/**
 * 
 * Rhonabwy JSON Web Key (JWK) library
 * 
 * jws.c: functions definitions
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

int r_init_jws(jws_t ** jws) {
  int ret;
  
  *jws = o_malloc(sizeof(jws_t));
  if (*jws != NULL) {
    (*jws)->j_header = NULL;
    (*jws)->payload = NULL;
    (*jws)->payload_len = 0;
    (*jws)->signature = NULL;
    ret = RHN_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "r_init_jws - Error allocating resources for jws");
    ret = RHN_ERROR_MEMORY;
  }
  return ret;
}

void r_free_jws(jws_t * jws) {
  if (jws != NULL) {
    json_decref(jws->j_header);
    o_free(jws->payload);
    o_free(jws->signature);
  }
}
