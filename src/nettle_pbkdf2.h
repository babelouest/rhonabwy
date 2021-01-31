/**
 * 
 * Rhonabwy PBKDF2 functions
 * 
 * nettle_pbkdf2.h: pbkdf2_hmac_sha384 and pbkdf2_hmac_sha512 functions declarations
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

#if HAVE_CONFIG_H
# include <nettle/config.h>
#endif

#include <nettle/pbkdf2.h>

#include <nettle/hmac.h>

void
pbkdf2_hmac_sha384 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst);

void
pbkdf2_hmac_sha512 (size_t key_length, const uint8_t *key,
		    unsigned iterations,
		    size_t salt_length, const uint8_t *salt,
		    size_t length, uint8_t *dst);
