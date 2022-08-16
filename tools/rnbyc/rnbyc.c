/**
 *
 * rnbyc: Rhonabwy command-line tool
 *
 * Copyright 2020-2022 Nicolas Mora <mail@babelouest.org>
 *
 * Command-line tool to manipulate JWK, JWKS, JWE, JWS and JWT
 * - Generates random JWK using the specified algorithm
 * - Generates random JWKS using the specified algorithm
 * - Parses cryptographic key to JWK, input format are:
 *   * JWK
 *   * JWKS
 *   * X509 PEM
 *   * X509 DER
 * - Parses JWE, JWS or JWT using key if possible
 *   * verify signature
 *   * decrypt content
 *   * verify claims
 * - Serialize JWE, JWS or JWT based on the key and the content
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <jansson.h>
#include <orcania.h>
#include <yder.h>
#include <rhonabwy.h>

#define _RNBYC_VERSION_ "1.1.7"

#define R_RSA_DEFAULT_SIZE 4096
#define R_OCT_DEFAULT_SIZE 128

#define R_ACTION_NONE            0
#define R_ACTION_JWKS_OUT        1
#define R_ACTION_PARSE_TOKEN     2
#define R_ACTION_SERIALIZE_TOKEN 3

#define RNBYC_FORMAT_JWK 0
#define RNBYC_FORMAT_PEM 1
#define RNBYC_FORMAT_DER 2

static void print_help(FILE * output) {
  fprintf(output, "\nrnbyc - JWK/JWKS parser and generator, JWT parser and serializer, supports signed, encrypted and nested JWTs\n");
  fprintf(output, "\n");
  fprintf(output, "Version %s\n", _RNBYC_VERSION_);
  fprintf(output, "\n");
  fprintf(output, "Copyright 2020-2022 Nicolas Mora <mail@babelouest.org>\n");
  fprintf(output, "\n");
  fprintf(output, "This program is free software; you can redistribute it and/or\n");
  fprintf(output, "modify it under the terms of the GPL 3\n");
  fprintf(output, "\n");
  fprintf(output, "Command-line options:\n");
  fprintf(output, "\n");
  fprintf(output, "-j --jwks\n");
  fprintf(output, "\tAction: JWKS, parse or generate keys and output JWKS\n");
  fprintf(output, "-g --generate <type>\n");
  fprintf(output, "\tGenerate a key pair or a symmetric key\n");
  fprintf(output, "\t<type> - values available:\n");
#if NETTLE_VERSION_NUMBER >= 0x03060e
  fprintf(output, "\tRSA[key size] (default key size: 4096), EC256, EC384, EC521, Ed25519, Ed448, X25519, X448, oct[key size] (default key size: 128 bits)\n");
#elif NETTLE_VERSION_NUMBER >= 0x030600
  fprintf(output, "\tRSA[key size] (default key size: 4096), EC256, EC384, EC521, Ed25519, X25519, oct[key size] (default key size: 128 bits)\n");
#else
  fprintf(output, "\tRSA[key size] (default key size: 4096), EC256, EC384, EC521, oct[key size] (default key size: 128 bits)\n");
#endif
  fprintf(output, "-i --stdin\n");
  fprintf(output, "\tReads key to parse from stdin\n");
  fprintf(output, "-f --in-file\n");
  fprintf(output, "\tReads key to parse from a file\n");
  fprintf(output, "-k --key-id\n");
  fprintf(output, "\tSpecifies the key-id to add to the current key\n");
  fprintf(output, "-a --alg\n");
  fprintf(output, "\tAction: JWKS - Specifies the alg value to add to the current key\n");
  fprintf(output, "\tAction: Serialize - Specifies the alg value to sign the token\n");
  fprintf(output, "-e --enc\n");
  fprintf(output, "\tSpecifies the enc value to encrypt the token (default A128CBC)\n");
  fprintf(output, "-l --enc-alg\n");
  fprintf(output, "\tSpecifies the encryption algorithm for key management of the token\n");
  fprintf(output, "-o --out-file\n");
  fprintf(output, "\tSpecifies the output file for the private keys (or all the keys if no public file is specified) in the JWKS\n");
  fprintf(output, "-p --out-file-public\n");
  fprintf(output, "\tSpecifies the output file for the public keys in the JWKS\n");
  fprintf(output, "-n --indent\n");
  fprintf(output, "\tJWKS output spaces indentation: 0 is compact mode, default is 2 spaces indent\n");
  fprintf(output, "-F --format\n");
  fprintf(output, "\tOutput format, values available are JWK (default), PEM or DER\n");
  fprintf(output, "-x --split\n");
  fprintf(output, "\tSplit JWKS output in public and private keys\n");
  fprintf(output, "-t --parse-token\n");
  fprintf(output, "\tAction: Parse token\n");
  fprintf(output, "-s --serialize-token\n");
  fprintf(output, "\tAction: serialize given claims in a token\n");
  fprintf(output, "-H --header\n");
  fprintf(output, "\tDisplay header of a parsed token\n");
  fprintf(output, "-C --claims\n");
  fprintf(output, "\tDisplay claims of a parsed token, default true\n");
  fprintf(output, "-P --public-key\n");
  fprintf(output, "\tSpecifies the public key for key management encryption or signature verification\n");
  fprintf(output, "\tPublic key must be in JWKS format and can be either a JWKS string or a path to a JWKS file\n");
  fprintf(output, "-K --private-key\n");
  fprintf(output, "\tSpecifies the private key for key management decryption or signature generation\n");
  fprintf(output, "\tPublic key must be in JWKS format and can be either a JWKS string or a path to a JWKS file\n");
  fprintf(output, "-S --self-signed\n");
  fprintf(output, "\tVerifies the JWT signature if the signed JWT has its public key included in its header\n");
  fprintf(output, "\tas 'jwk', 'x5c' or 'x5u' parameter\n");
  fprintf(output, "-W --password\n");
  fprintf(output, "\tSpecifies the password for key management encryption/decryption using PBES2 alg or signature generation/verification using HS alg\n");
  fprintf(output, "-u --x5u-flags\n");
  fprintf(output, "\tSet x5u flags to retrieve online certificate, values available are:\n");
  fprintf(output, "\t\tcert: ignore server certificate errors (self-signed, expired, etc.)\n");
  fprintf(output, "\t\tfollow: follow jwks_uri redirection if any\n");
  fprintf(output, "\t\tvalues can be contatenated, e.g. --x5u-flags cert,follow\n");
  fprintf(output, "-v --version\n");
  fprintf(output, "\tPrint rnbyc's current version\n");
  fprintf(output, "-h --help\n");
  fprintf(output, "\tPrint this message\n\n");
  fprintf(output, "-d --debug\n");
  fprintf(output, "\tDisplay debug messages\n\n");
}

static int write_file_content(const char * file_path, const char * content, size_t content_len) {
  FILE * f;
  int ret;

  f = fopen (file_path, "w+");
  if (f) {
    if (fwrite(content, 1, content_len, f) > 0 && fwrite("\n", 1, 1, f) > 0) {
      ret = 0;
    } else {
      ret = ENOENT;
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
    ret = EACCES;
  }

  return ret;
}

static char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    fprintf(stderr, "error opening file %s\n", file_path);
  }

  return buffer;
}

static char * get_stdin_content() {
  int size = 100;
  char * out = NULL, buffer[size];
  ssize_t length = 0, read_length;

  while ((read_length = read(0, buffer, size)) > 0) {
    out = o_realloc(out, length+read_length+1);
    memcpy(out+length, buffer, read_length);
    length += read_length;
    out[length] = '\0';
  }
  return out;
}

static int jwk_generate(jwks_t * jwks_privkey, jwks_t * jwks_pubkey, json_t * j_element) {
  jwk_t * jwk_priv = NULL, * jwk_pub = NULL;
  unsigned char * oct = NULL, oct_kid[16] = {0}, oct_kid_b64[32] = {0};
  size_t oct_kid_b64_len = 0;
  const char * type = json_string_value(json_object_get(j_element, "type"));
  int ret = 0;
  json_int_t bits;

  if (r_jwk_init(&jwk_priv) == RHN_OK && r_jwk_init(&jwk_pub) == RHN_OK) {
    if (0 == o_strcmp("RSA", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_RSA, json_integer_value(json_object_get(j_element, "bits")), json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
    } else if (0 == o_strcasecmp("EC256", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_EC, 256, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "ES256");
        r_jwk_set_property_str(jwk_pub, "alg", "ES256");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
    } else if (0 == o_strcasecmp("EC384", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_EC, 384, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "ES384");
        r_jwk_set_property_str(jwk_pub, "alg", "ES384");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
    } else if (0 == o_strcasecmp("EC521", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_EC, 521, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "ES512");
        r_jwk_set_property_str(jwk_pub, "alg", "ES512");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
#if NETTLE_VERSION_NUMBER >= 0x030600
    } else if (0 == o_strcasecmp("Ed25519", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_EDDSA, 256, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "EdDSA");
        r_jwk_set_property_str(jwk_pub, "alg", "EdDSA");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
    } else if (0 == o_strcasecmp("X25519", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_ECDH, 256, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "X25519");
        r_jwk_set_property_str(jwk_pub, "alg", "X25519");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
#endif
#if NETTLE_VERSION_NUMBER >= 0x03060e
    } else if (0 == o_strcasecmp("Ed448", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_EDDSA, 448, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "EdDSA");
        r_jwk_set_property_str(jwk_pub, "alg", "EdDSA");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
    } else if (0 == o_strcasecmp("X448", type)) {
      r_jwk_generate_key_pair(jwk_priv, jwk_pub, R_KEY_TYPE_ECDH, 448, json_string_value(json_object_get(j_element, "kid")));
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      } else {
        r_jwk_set_property_str(jwk_priv, "alg", "X25519");
        r_jwk_set_property_str(jwk_pub, "alg", "X25519");
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      if (jwks_pubkey != NULL) {
        r_jwks_append_jwk(jwks_pubkey, jwk_pub);
      } else {
        r_jwks_append_jwk(jwks_privkey, jwk_pub);
      }
#endif
    } else if (0 == o_strcasecmp("oct", type)) {
      bits = json_integer_value(json_object_get(j_element, "bits"));
      bits += (bits%8);
      oct = o_malloc(bits/8);
      gnutls_rnd(GNUTLS_RND_KEY, oct, bits/8);
      r_jwk_import_from_symmetric_key(jwk_priv, oct, bits/8);
      if (json_string_length(json_object_get(j_element, "alg"))) {
        r_jwk_set_property_str(jwk_priv, "alg", json_string_value(json_object_get(j_element, "alg")));
        r_jwk_set_property_str(jwk_pub, "alg", json_string_value(json_object_get(j_element, "alg")));
      }
      if (json_string_value(json_object_get(j_element, "kid")) != NULL) {
        r_jwk_set_property_str(jwk_priv, "kid", json_string_value(json_object_get(j_element, "kid")));
      } else {
        gnutls_rnd(GNUTLS_RND_KEY, oct_kid, 16);
        o_base64url_encode(oct_kid, 16, oct_kid_b64, &oct_kid_b64_len);
        oct_kid_b64[oct_kid_b64_len] = '\0';
        r_jwk_set_property_str(jwk_priv, "kid", (const char *)oct_kid_b64);
      }
      r_jwks_append_jwk(jwks_privkey, jwk_priv);
      o_free(oct);
    } else {
      fprintf(stderr, "Invalid key type");
      ret = EINVAL;
    }
  } else {
    ret = ENOMEM;
  }
  r_jwk_free(jwk_priv);
  r_jwk_free(jwk_pub);
  return ret;
}

static int jwks_parse_str(jwks_t * jwks_priv, jwks_t * jwks_pub, const char * in, const char * kid, int x5u_flags) {
  jwks_t * jwks = NULL;
  jwk_t * jwk = NULL;
  int ret, key_type;
  size_t i;

  if (r_jwks_init(&jwks) == RHN_OK && r_jwks_import_from_json_str(jwks, in) == RHN_OK) {
    for (i=0; i<r_jwks_size(jwks); i++) {
      jwk = r_jwks_get_at(jwks, i);
      if ((key_type = r_jwk_key_type(jwk, NULL, x5u_flags)) & R_KEY_TYPE_PUBLIC && jwks_pub != NULL) {
        r_jwks_append_jwk(jwks_pub, jwk);
      } else {
        r_jwks_append_jwk(jwks_priv, jwk);
      }
      r_jwk_free(jwk);
    }
    ret = 0;
  } else {
    if (r_jwk_init(&jwk) == RHN_OK) {
      if (r_jwk_import_from_json_str(jwk, in) == RHN_OK) {
        ret = 0;
        if (kid != NULL) {
          r_jwk_set_property_str(jwk, "kid", kid);
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_PUBLIC && jwks_pub != NULL) {
          r_jwks_append_jwk(jwks_pub, jwk);
        } else {
          r_jwks_append_jwk(jwks_priv, jwk);
        }
      } else if (r_jwk_import_from_pem_der(jwk, R_X509_TYPE_CERTIFICATE, R_FORMAT_PEM, (const unsigned char *)in, o_strlen(in)) == RHN_OK) {
        ret = 0;
        if (kid != NULL) {
          r_jwk_set_property_str(jwk, "kid", kid);
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_PUBLIC && jwks_pub != NULL) {
          r_jwks_append_jwk(jwks_pub, jwk);
        } else {
          r_jwks_append_jwk(jwks_priv, jwk);
        }
      } else if (r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, (const unsigned char *)in, o_strlen(in)) == RHN_OK) {
        ret = 0;
        if (kid != NULL) {
          r_jwk_set_property_str(jwk, "kid", kid);
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_PUBLIC && jwks_pub != NULL) {
          r_jwks_append_jwk(jwks_pub, jwk);
        } else {
          r_jwks_append_jwk(jwks_priv, jwk);
        }
      } else if (r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)in, o_strlen(in)) == RHN_OK) {
        ret = 0;
        if (kid != NULL) {
          r_jwk_set_property_str(jwk, "kid", kid);
        }
        if (r_jwk_key_type(jwk, NULL, x5u_flags) & R_KEY_TYPE_PUBLIC && jwks_pub != NULL) {
          r_jwks_append_jwk(jwks_pub, jwk);
        } else {
          r_jwks_append_jwk(jwks_priv, jwk);
        }
      } else {
        ret = EINVAL;
      }
    } else {
      ret = ENOMEM;
    }
    r_jwk_free(jwk);
  }
  r_jwks_free(jwks);
  return ret;
}

static int jwk_stdin(jwks_t * jwks_priv, jwks_t * jwks_pub, json_t * j_element, int x5u_flags) {
  char * in = get_stdin_content();
  int ret;

  if (in != NULL) {
    ret = jwks_parse_str(jwks_priv, jwks_pub, in, json_string_value(json_object_get(j_element, "kid")), x5u_flags);
  } else {
    ret = EIO;
  }
  o_free(in);
  return ret;
}

static int jwk_file(jwks_t * jwks_priv, jwks_t * jwks_pub, json_t * j_element, int x5u_flags) {
  char * in = get_file_content(json_string_value(json_object_get(j_element, "path")));
  int ret;

  if (in != NULL) {
    ret = jwks_parse_str(jwks_priv, jwks_pub, in, json_string_value(json_object_get(j_element, "kid")), x5u_flags);
  } else {
    ret = EIO;
  }
  o_free(in);
  return ret;
}

static void get_jwks_out(json_t * j_arguments, int split_keys, int x5u_flags, int indent, int format, const char * out_file, const char * out_file_public) {
  jwks_t * jwks_privkey = NULL, * jwks_pubkey = NULL;
  jwk_t * cur_jwk;
  json_t * j_element = NULL, * j_jwks = NULL;
  size_t index = 0, out_len = 0, str_jwks_len = 0;
  char * str_jwks = NULL;
  unsigned char * out = NULL;

  if (r_jwks_init(&jwks_privkey) == RHN_OK && r_jwks_init(&jwks_pubkey) == RHN_OK) {
    json_array_foreach(j_arguments, index, j_element) {
      if (0 == o_strcmp("generate", json_string_value(json_object_get(j_element, "source")))) {
        if (jwk_generate(jwks_privkey, split_keys?jwks_pubkey:NULL, j_element)) {
          fprintf(stderr, "Error jwk_generate\n");
        }
      } else if (0 == o_strcmp("stdin", json_string_value(json_object_get(j_element, "source")))) {
        if (jwk_stdin(jwks_privkey, split_keys?jwks_pubkey:NULL, j_element, x5u_flags)) {
          fprintf(stderr, "Error jwk_stdin\n");
        }
      } else if (0 == o_strcmp("file", json_string_value(json_object_get(j_element, "source")))) {
        if (jwk_file(jwks_privkey, split_keys?jwks_pubkey:NULL, j_element, x5u_flags)) {
          fprintf(stderr, "Error jwk_file\n");
        }
      }
    }
  } else {
    fprintf(stderr, "Error r_jwks_init\n");
  }
  if (r_jwks_size(jwks_privkey)) {
    if (format == RNBYC_FORMAT_JWK) {
      j_jwks = r_jwks_export_to_json_t(jwks_privkey);
      str_jwks = json_dumps(j_jwks, JSON_INDENT(indent)|JSON_SORT_KEYS);
      str_jwks_len = o_strlen(str_jwks);
    } else {
      str_jwks = NULL;
      for (index=0; index<r_jwks_size(jwks_privkey); index++) {
        cur_jwk = r_jwks_get_at(jwks_privkey, index);
        if (r_jwk_export_to_pem_der(cur_jwk, format==RNBYC_FORMAT_PEM?R_FORMAT_PEM:R_FORMAT_DER, NULL, &out_len, x5u_flags) == RHN_ERROR_PARAM) {
          if ((out = o_malloc(out_len+1)) != NULL) {
            if (r_jwk_export_to_pem_der(cur_jwk, format==RNBYC_FORMAT_PEM?R_FORMAT_PEM:R_FORMAT_DER, out, &out_len, x5u_flags) == RHN_OK) {
              str_jwks = o_realloc(str_jwks, str_jwks_len+out_len);
              memcpy(str_jwks+str_jwks_len, out, out_len);
              str_jwks_len += out_len;
            } else {
              fprintf(stderr, "Error exporting jwks (2)\n");
            }
          } else {
            fprintf(stderr, "Error allocating resources\n");
          }
          o_free(out);
          out_len = 0;
        } else {
          fprintf(stderr, "Error exporting jwks (1)\n");
        }
        r_jwk_free(cur_jwk);
      }
    }
    if (str_jwks != NULL) {
      if (out_file != NULL) {
        if (write_file_content(out_file, str_jwks, str_jwks_len)) {
          fprintf(stderr, "Error writing to file %s\n", out_file);
        }
      } else {
        if (r_jwks_size(jwks_pubkey)) {
          printf("Private keys:\n");
        }
        printf("%.*s\n", (int)str_jwks_len, str_jwks);
      }
    }
    o_free(str_jwks);
    str_jwks = NULL;
    json_decref(j_jwks);
    j_jwks = NULL;
    str_jwks_len = 0;
  }
  if (r_jwks_size(jwks_pubkey)) {
    if (format == RNBYC_FORMAT_JWK) {
      j_jwks = r_jwks_export_to_json_t(jwks_pubkey);
      str_jwks = json_dumps(j_jwks, JSON_INDENT(indent)|JSON_SORT_KEYS);
      str_jwks_len = o_strlen(str_jwks);
    } else {
      for (index=0; index<r_jwks_size(jwks_pubkey); index++) {
        cur_jwk = r_jwks_get_at(jwks_pubkey, index);
        if (r_jwk_export_to_pem_der(cur_jwk, format==RNBYC_FORMAT_PEM?R_FORMAT_PEM:R_FORMAT_DER, NULL, &out_len, x5u_flags) == RHN_ERROR_PARAM) {
          if ((out = o_malloc(out_len+1)) != NULL) {
            if (r_jwk_export_to_pem_der(cur_jwk, format==RNBYC_FORMAT_PEM?R_FORMAT_PEM:R_FORMAT_DER, out, &out_len, x5u_flags) == RHN_OK) {
              str_jwks = o_realloc(str_jwks, str_jwks_len+out_len);
              memcpy(str_jwks+str_jwks_len, out, out_len);
              str_jwks_len += out_len;
            } else {
              fprintf(stderr, "Error exporting jwks public\n");
            }
          } else {
            fprintf(stderr, "Error allocating resources\n");
          }
          o_free(out);
          out_len = 0;
        } else {
          fprintf(stderr, "Error exporting jwks public\n");
        }
        r_jwk_free(cur_jwk);
      }
    }
    if (str_jwks != NULL) {
      if (out_file_public != NULL) {
        if (write_file_content(out_file_public, str_jwks, str_jwks_len)) {
          fprintf(stderr, "Error writing to file %s\n", out_file_public);
        }
      } else {
        printf("\nPublic keys:\n%.*s\n", (int)str_jwks_len, str_jwks);
      }
    }
    o_free(str_jwks);
    json_decref(j_jwks);
  }
  r_jwks_free(jwks_privkey);
  r_jwks_free(jwks_pubkey);
}

static int parse_token(const char * token, int indent, int x5u_flags, const char * str_jwks_pubkey, const char * str_jwks_privkey, const char * password, int show_header, int show_claims, int self_signed) {
  int ret = 0, type, res;
  char * content, * str_value, * token_dup = NULL, * tmp = NULL;
  jwt_t * jwt = NULL;
  jwks_t * jwks_pubkey = NULL, * jwks_privkey = NULL;
  jwk_t * jwk_password;
  json_t * j_value;

  if (r_jwt_init(&jwt) == RHN_OK) {
    tmp = str_replace(token, " ", "");
    token_dup = tmp;
    tmp = str_replace(token_dup, "\n", "");
    o_free(token_dup);
    token_dup = tmp;
    tmp = str_replace(token_dup, "\t", "");
    o_free(token_dup);
    token_dup = tmp;
    tmp = str_replace(token_dup, "\v", "");
    o_free(token_dup);
    token_dup = tmp;
    tmp = str_replace(token_dup, "\f", "");
    o_free(token_dup);
    token_dup = tmp;
    tmp = str_replace(token_dup, "\r", "");
    o_free(token_dup);
    token_dup = tmp;
    if (self_signed) {
      res = r_jwt_advanced_parse(jwt, token_dup, R_PARSE_HEADER_ALL, x5u_flags);
    } else {
      res = r_jwt_advanced_parse(jwt, token_dup, R_PARSE_NONE, x5u_flags);
    }
    if (res == RHN_OK) {
      type = r_jwt_get_type(jwt);
      if (type == R_JWT_TYPE_SIGN || type == R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN || type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
        if (r_jwks_init(&jwks_pubkey) == RHN_OK) {
          if (o_strlen(str_jwks_pubkey) && str_jwks_pubkey[0] == '{') {
            if (r_jwks_import_from_json_str(jwks_pubkey, str_jwks_pubkey) != RHN_OK) {
              fprintf(stderr, "Invalid jwks_pubkey\n");
            }
          } else if (o_strlen(str_jwks_pubkey)) {
            content = get_file_content(str_jwks_pubkey);
            if (r_jwks_import_from_json_str(jwks_pubkey, content) != RHN_OK) {
              fprintf(stderr, "Invalid jwks_pubkey path or content\n");
            }
            o_free(content);
          } else if (o_strlen(password)) {
            r_jwk_init(&jwk_password);
            if (r_jwk_import_from_password(jwk_password, password) != RHN_OK) {
              fprintf(stderr, "Error parsing password\n");
            } else {
              if (r_jwks_append_jwk(jwks_pubkey, jwk_password) != RHN_OK) {
                fprintf(stderr, "Error importing password\n");
              }
            }
            r_jwk_free(jwk_password);
          }
        }
      }
      if (type == R_JWT_TYPE_ENCRYPT || type == R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN || type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
        if (r_jwks_init(&jwks_privkey) == RHN_OK) {
          if (o_strlen(str_jwks_privkey) && str_jwks_privkey[0] == '{') {
            if (r_jwks_import_from_json_str(jwks_privkey, str_jwks_privkey) != RHN_OK) {
              fprintf(stderr, "Invalid jwks_privkey\n");
            }
          } else if (o_strlen(str_jwks_privkey)) {
            content = get_file_content(str_jwks_privkey);
            if (r_jwks_import_from_json_str(jwks_privkey, content) != RHN_OK) {
              fprintf(stderr, "Invalid jwks_privkey path or content\n");
            }
            o_free(content);
          } else if (o_strlen(password)) {
            r_jwk_init(&jwk_password);
            if (r_jwk_import_from_password(jwk_password, password) != RHN_OK) {
              fprintf(stderr, "Error parsing password\n");
            } else {
              if (r_jwks_append_jwk(jwks_privkey, jwk_password) != RHN_OK) {
                fprintf(stderr, "Error importing password\n");
              }
            }
            r_jwk_free(jwk_password);
          }
        }
      }
      if (jwks_pubkey != NULL) {
        if (r_jwt_add_sign_jwks(jwt, NULL, jwks_pubkey) != RHN_OK) {
          fprintf(stderr, "Error setting public key\n");
        }
      }
      if (jwks_privkey != NULL) {
        if (r_jwt_add_enc_jwks(jwt, jwks_privkey, NULL) != RHN_OK) {
          fprintf(stderr, "Error setting private key\n");
        }
      }
      if (r_jwks_size(jwks_privkey)) {
        if (type == R_JWT_TYPE_ENCRYPT) {
          if (r_jwt_decrypt(jwt, NULL, x5u_flags) == RHN_OK) {
            fprintf(stdout, "Token payload decrypted\n");
          } else {
            fprintf(stderr, "Unable to decrypt payload %d\n", r_jwt_decrypt(jwt, NULL, x5u_flags));
            ret = EINVAL;
          }
        } else if (type == R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN || type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
          if (r_jwt_decrypt_nested(jwt, NULL, x5u_flags) == RHN_OK) {
            fprintf(stdout, "Token payload decrypted\n");
          } else {
            fprintf(stderr, "Unable to decrypt payload %d\n", r_jwt_decrypt(jwt, NULL, x5u_flags));
            ret = EINVAL;
          }
        }
      }
      if ((self_signed || r_jwks_size(jwks_pubkey)) && (type == R_JWT_TYPE_SIGN || type == R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN || type == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT)) {
        if (r_jwt_verify_signature(jwt, NULL, x5u_flags) == RHN_OK) {
          fprintf(stdout, "Token signature verified\n");
        } else {
          fprintf(stderr, "Token signature invalid\n");
          ret = EINVAL;
        }
      }
      if (show_header) {
        j_value = r_jwt_get_full_header_json_t(jwt);
        str_value = json_dumps(j_value, JSON_INDENT(indent)|JSON_SORT_KEYS);
        printf("%s\n", str_value);
        o_free(str_value);
        json_decref(j_value);
      }
      if (show_claims) {
        str_value = NULL;
        j_value = r_jwt_get_full_claims_json_t(jwt);
        if (j_value != NULL) {
          str_value = json_dumps(j_value, JSON_INDENT(indent)|JSON_SORT_KEYS);
          printf("%s\n", str_value);
          o_free(str_value);
          json_decref(j_value);
        }
      }
    } else if (res == RHN_ERROR_PARAM) {
      fprintf(stderr, "Invalid token\n");
      ret = EINVAL;
    } else {
      fprintf(stderr, "Error parsing token\n");
      ret = EINVAL;
    }
  }
  r_jwt_free(jwt);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  o_free(token_dup);
  return ret;
}

static int serialize_token(const char * claims, int x5u_flags, const char * str_jwks_pubkey, const char * str_jwks_privkey, const char * password, const char * alg, const char * enc, const char * enc_alg) {
  jwt_t * jwt = NULL;
  jwks_t * jwks_pubkey = NULL, * jwks_privkey = NULL;
  jwk_t * jwk_password;
  char * token = NULL, * content = NULL;
  int ret = 0;

  if (r_jwt_init(&jwt) == RHN_OK) {
    if (r_jwt_set_full_claims_json_str(jwt, claims) == RHN_OK) {
      if (r_jwks_init(&jwks_pubkey) == RHN_OK) {
        if (o_strlen(str_jwks_pubkey) && str_jwks_pubkey[0] == '{') {
          if (r_jwks_import_from_json_str(jwks_pubkey, str_jwks_pubkey) != RHN_OK) {
            fprintf(stderr, "Invalid jwks_pubkey\n");
            ret = EINVAL;
          }
        } else if (o_strlen(str_jwks_pubkey)) {
          content = get_file_content(str_jwks_pubkey);
          if (r_jwks_import_from_json_str(jwks_pubkey, content) != RHN_OK) {
            fprintf(stderr, "Invalid jwks_pubkey path or content\n");
            ret = EAGAIN;
          }
          o_free(content);
        } else if (o_strlen(password) && o_strlen(enc_alg)) {
          r_jwk_init(&jwk_password);
          if (r_jwk_import_from_password(jwk_password, password) != RHN_OK) {
            fprintf(stderr, "Error parsing password\n");
          } else {
            if (r_jwks_append_jwk(jwks_pubkey, jwk_password) != RHN_OK) {
              fprintf(stderr, "Error importing password\n");
            }
          }
          r_jwk_free(jwk_password);
        }
      }
      if (r_jwks_init(&jwks_privkey) == RHN_OK) {
        if (o_strlen(str_jwks_privkey) && str_jwks_privkey[0] == '{') {
          if (r_jwks_import_from_json_str(jwks_privkey, str_jwks_privkey) != RHN_OK) {
            fprintf(stderr, "Invalid jwks_privkey\n");
            ret = EINVAL;
          }
        } else if (o_strlen(str_jwks_privkey)) {
          content = get_file_content(str_jwks_privkey);
          if (r_jwks_import_from_json_str(jwks_privkey, content) != RHN_OK) {
            fprintf(stderr, "Invalid jwks_privkey path or content\n");
            ret = EAGAIN;
          }
          o_free(content);
        } else if (o_strlen(password) && o_strlen(alg)) {
          r_jwk_init(&jwk_password);
          if (r_jwk_import_from_password(jwk_password, password) != RHN_OK) {
            fprintf(stderr, "Error parsing password\n");
          } else {
            if (r_jwks_append_jwk(jwks_privkey, jwk_password) != RHN_OK) {
              fprintf(stderr, "Error importing password\n");
            }
          }
          r_jwk_free(jwk_password);
        }
      }
      if (jwks_pubkey != NULL) {
        if (r_jwt_add_enc_jwks(jwt, NULL, jwks_pubkey) != RHN_OK) {
          fprintf(stderr, "Error setting public key\n");
          ret = ENOMEM;
        }
        if (enc != NULL) {
          if (r_jwt_set_enc(jwt, r_str_to_jwa_enc(enc)) != RHN_OK) {
            fprintf(stderr, "Invalid enc value\n");
            ret = EINVAL;
          }
        } else {
          r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC);
        }
        if (enc_alg != NULL) {
          if (r_jwt_set_enc_alg(jwt, r_str_to_jwa_alg(enc_alg)) != RHN_OK) {
            fprintf(stderr, "Invalid enc_alg value\n");
            ret = EINVAL;
          }
        }
      }
      if (jwks_privkey != NULL) {
        if (r_jwt_add_sign_jwks(jwt, jwks_privkey, NULL) != RHN_OK) {
          fprintf(stderr, "Error setting private key\n");
          ret = ENOMEM;
        }
        if (alg != NULL) {
          if (r_jwt_set_sign_alg(jwt, r_str_to_jwa_alg(alg)) != RHN_OK) {
            fprintf(stderr, "Invalid alg value\n");
            ret = EINVAL;
          }
        }
      }
      if (!ret) {
        if (r_jwks_size(jwks_pubkey) && r_jwks_size(jwks_privkey)) {
          token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, x5u_flags, NULL, x5u_flags);
        } else if (r_jwks_size(jwks_pubkey) && !r_jwks_size(jwks_privkey)) {
          token = r_jwt_serialize_encrypted(jwt, NULL, x5u_flags);
        } else if (!r_jwks_size(jwks_pubkey) && r_jwks_size(jwks_privkey)) {
          token = r_jwt_serialize_signed(jwt, NULL, x5u_flags);
        } else if (o_strlen(password)) {
          token = r_jwt_serialize_encrypted(jwt, NULL, x5u_flags);
        } else {
          r_jwt_set_sign_alg(jwt, R_JWA_ALG_NONE);
          token = r_jwt_serialize_signed(jwt, NULL, x5u_flags);
        }
      }
      if (token == NULL) {
        fprintf(stderr, "Error serializing token\n");
        ret = EINVAL;
      } else {
        printf("%s\n", token);
      }
      o_free(token);
    } else {
      fprintf(stderr, "Error setting JSON claims\n");
      ret = EINVAL;
    }
  }
  r_jwt_free(jwt);
  r_jwks_free(jwks_pubkey);
  r_jwks_free(jwks_privkey);
  return ret;
}

int main (int argc, char ** argv) {
  int next_option,
      action = R_ACTION_NONE,
      ret = 0,
      has_stdin = 0,
      split_keys = 0,
      show_header = 0,
      show_claims = 1,
      self_signed = 0,
      x5u_flags = 0,
      debug_mode = 0,
      format = RNBYC_FORMAT_JWK;
  const char * short_options = "j::g:i::f:k:a:e:l:o:p:n:F:x::t:s:H::C:K:P:S::W:u:v::h::d::";
  char * out_file = NULL,
       * out_file_public = NULL,
       * parsed_token = NULL,
       * str_token_public_key = NULL,
       * str_token_private_key = NULL,
       * password = NULL,
       * alg = NULL,
       * enc = NULL,
       * enc_alg = NULL,
       * claims = NULL;
  static const struct option long_options[]= {
    {"jwks", no_argument, NULL, 'j'},
    {"generate", required_argument, NULL, 'g'},
    {"stdin", no_argument, NULL, 'i'},
    {"in-file", required_argument, NULL, 'f'},
    {"key-id", required_argument, NULL, 'k'},
    {"alg", required_argument, NULL, 'a'},
    {"enc", required_argument, NULL, 'e'},
    {"enc-alg", required_argument, NULL, 'l'},
    {"out-file", required_argument, NULL, 'o'},
    {"out-file-public", required_argument, NULL, 'p'},
    {"indent", required_argument, NULL, 'n'},
    {"format", no_argument, NULL, 'F'},
    {"split", no_argument, NULL, 'x'},
    {"parse-token", required_argument, NULL, 't'},
    {"serialize-token", required_argument, NULL, 's'},
    {"header", no_argument, NULL, 'H'},
    {"claims", required_argument, NULL, 'C'},
    {"public-key", required_argument, NULL, 'P'},
    {"self-signed", required_argument, NULL, 'S'},
    {"private-key", required_argument, NULL, 'K'},
    {"password", required_argument, NULL, 'W'},
    {"x5u-flags", required_argument, NULL, 'u'},
    {"version", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {"debug", no_argument, NULL, 'd'},
    {NULL, 0, NULL, 0}
  };
  json_t * j_arguments = json_array();
  unsigned long bits = 0;
  int indent = 2;

  do {
    next_option = getopt_long(argc, argv, short_options, long_options, NULL);

    switch (next_option) {
      case 'j':
        if (action == R_ACTION_NONE) {
          action = R_ACTION_JWKS_OUT;
        }
        break;
      case 'g':
        if (action == R_ACTION_JWKS_OUT) {
          if (0 == o_strncasecmp(optarg, "RSA", o_strlen("RSA"))) {
            if (o_strlen(optarg) == o_strlen("RSA")) {
              json_array_append_new(j_arguments, json_pack("{sssssi}", "source", "generate", "type", "RSA", "bits", R_RSA_DEFAULT_SIZE));
            } else if ((bits = strtoul(optarg+o_strlen("RSA"), NULL, 10)) >= 128) {
              json_array_append_new(j_arguments, json_pack("{sssssi}", "source", "generate", "type", "RSA", "bits", bits));
            } else {
              fprintf(stderr, "--generate: Invalid argument\n");
              ret = EINVAL;
            }
          } else if (0 == o_strcasecmp("EC256", optarg) ||
                     0 == o_strcasecmp("EC384", optarg) ||
                     0 == o_strcasecmp("EC521", optarg) ||
                     0 == o_strcasecmp("Ed25519", optarg) ||
                     0 == o_strcasecmp("X25519", optarg) ||
                     0 == o_strcasecmp("X448", optarg)) {
            json_array_append_new(j_arguments, json_pack("{ssss}", "source", "generate", "type", optarg));
          } else if (0 == o_strncasecmp(optarg, "oct", o_strlen("oct"))) {
            if (o_strlen(optarg) == o_strlen("oct")) {
              json_array_append_new(j_arguments, json_pack("{sssssi}", "source", "generate", "type", "oct", "bits", R_OCT_DEFAULT_SIZE));
            } else if ((bits = strtoul(optarg+o_strlen("oct"), NULL, 10))) {
              json_array_append_new(j_arguments, json_pack("{sssssi}", "source", "generate", "type", "oct", "bits", bits));
            } else {
              fprintf(stderr, "--generate: Invalid argument\n");
              ret = EINVAL;
            }
          } else {
            fprintf(stderr, "--generate: Invalid argument\n");
            ret = EINVAL;
          }
        } else {
          fprintf(stderr, "--generate: argument incompatible with parse or serialize action\n");
          ret = EINVAL;
        }
        break;
      case 'i':
        if (has_stdin) {
          fprintf(stderr, "--stdin: can not use more than once\n");
          ret = EINVAL;
        } else if (action == R_ACTION_JWKS_OUT) {
          json_array_append_new(j_arguments, json_pack("{ss}", "source", "stdin"));
          has_stdin = 1;
        } else {
          fprintf(stderr, "--stdin: argument incompatible with parse or serialize action\n");
          ret = EINVAL;
        }
        break;
      case 'f':
        if (action == R_ACTION_JWKS_OUT) {
          json_array_append_new(j_arguments, json_pack("{ssss}", "source", "file", "path", optarg));
        } else {
          fprintf(stderr, "--file: argument incompatible with parse or serialize action\n");
          ret = EINVAL;
        }
        break;
      case 'k':
        if (json_array_size(j_arguments)) {
          json_object_set_new(json_array_get(j_arguments, json_array_size(j_arguments)-1), "kid", json_string(optarg));
        }
        break;
      case 'o':
        out_file = o_strdup(optarg);
        break;
      case 'p':
        out_file_public = o_strdup(optarg);
        split_keys = 1;
        break;
      case 'F':
        if (action == R_ACTION_JWKS_OUT) {
          if (0 == o_strncasecmp(optarg, "JWK", o_strlen("JWK"))) {
            format = RNBYC_FORMAT_JWK;
          } else if (0 == o_strncasecmp(optarg, "PEM", o_strlen("PEM"))) {
            format = RNBYC_FORMAT_PEM;
          } else if (0 == o_strncasecmp(optarg, "DER", o_strlen("DER"))) {
            format = RNBYC_FORMAT_DER;
          } else {
            fprintf(stderr, "--format: Invalid format\n");
            ret = EINVAL;
          }
        } else {
          fprintf(stderr, "--format: argument incompatible with parse or serialize action\n");
          ret = EINVAL;
        }
        break;
      case 'x':
        split_keys = 1;
        break;
      case 'a':
        if (action == R_ACTION_JWKS_OUT) {
          json_object_set_new(json_array_get(j_arguments, json_array_size(j_arguments)-1), "alg", json_string(optarg));
        } else {
          o_free(alg);
          alg = o_strdup(optarg);
        }
        break;
      case 'e':
        o_free(enc);
        enc = o_strdup(optarg);
        break;
      case 'l':
        o_free(enc_alg);
        enc_alg = o_strdup(optarg);
        break;
      case 'n':
        indent = strtol(optarg, NULL, 10);
        break;
      case 't':
        action = R_ACTION_PARSE_TOKEN;
        parsed_token = o_strdup(optarg);
        break;
      case 's':
        action = R_ACTION_SERIALIZE_TOKEN;
        claims = o_strdup(optarg);
        break;
      case 'H':
        show_header = 1;
        break;
      case 'C':
        if (0 == o_strcasecmp("false", optarg) || 0 == o_strcasecmp("no", optarg) || 0 == o_strcmp("0", optarg)) {
          show_claims = 0;
        } else {
          show_claims = 1;
        }
        break;
      case 'K':
        str_token_private_key = o_strdup(optarg);
        break;
      case 'P':
        str_token_public_key = o_strdup(optarg);
        break;
      case 'S':
        self_signed = 1;
        break;
      case 'W':
        password = o_strdup(optarg);
        break;
      case 'u':
        if (o_strcasestr(optarg, "cert") != NULL) {
          x5u_flags |= R_FLAG_IGNORE_SERVER_CERTIFICATE;
        }
        if (o_strcasestr(optarg, "follow") != NULL) {
          x5u_flags |= R_FLAG_FOLLOW_REDIRECT;
        }
        break;
      case 'v':
        // Print version and exit
        fprintf(stdout, "%s\n", _RNBYC_VERSION_);
        exit(0);
        break;
      case 'h':
        // Print help and exit
        print_help(stdout);
        exit(0);
        break;
      case 'd':
        // Start yder logs
        debug_mode = 1;
        break;
      default:
        break;
    }
  } while (next_option != -1 && !ret);

  if (debug_mode) {
    y_init_logs("rnbyc", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting rnbyc debug mode");
  }

  if (!ret) {
    if (action == R_ACTION_JWKS_OUT) {
      get_jwks_out(j_arguments, split_keys, x5u_flags, indent, format, out_file, out_file_public);
    } else if (action == R_ACTION_PARSE_TOKEN) {
      ret = parse_token(parsed_token, indent, x5u_flags, str_token_public_key, str_token_private_key, password, show_header, show_claims, self_signed);
    } else if (action == R_ACTION_SERIALIZE_TOKEN) {
      ret = serialize_token(claims, x5u_flags, str_token_public_key, str_token_private_key, password, alg, enc, enc_alg);
    } else {
      ret = EINVAL;
      fprintf(stderr, "Please epecify an action\n");
      print_help(stderr);
    }
  }

  json_decref(j_arguments);
  o_free(out_file);
  o_free(out_file_public);
  o_free(alg);
  o_free(enc);
  o_free(enc_alg);
  o_free(parsed_token);
  o_free(claims);
  o_free(str_token_private_key);
  o_free(str_token_public_key);
  o_free(password);

  if (debug_mode) {
    y_close_logs();
  }
  return ret;
}
