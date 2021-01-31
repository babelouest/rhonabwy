/**
 * 
 * Rhonabwy PBKDF2 functions
 * 
 * nettle_pbkdf2.c: pbkdf2_hmac_sha384 and pbkdf2_hmac_sha512 functions definitions
 * 
 * Copyright 2021 Nicolas Mora <mail@babelouest.org>
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

#include "nettle_pbkdf2.h"

void
pbkdf2_hmac_sha384 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst)
{
  struct hmac_sha384_ctx sha384ctx;

  hmac_sha384_set_key (&sha384ctx, key_length, key);
  PBKDF2 (&sha384ctx, hmac_sha384_update, hmac_sha384_digest,
	  SHA384_DIGEST_SIZE, iterations, salt_length, salt, length, dst);
}

void
pbkdf2_hmac_sha512 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst)
{
  struct hmac_sha512_ctx sha512ctx;

  hmac_sha512_set_key (&sha512ctx, key_length, key);
  PBKDF2 (&sha512ctx, hmac_sha512_update, hmac_sha512_digest,
	  SHA512_DIGEST_SIZE, iterations, salt_length, salt, length, dst);
}
