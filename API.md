# Rhonabwy API documentation

Rhonabwy library is made to manage JWK, JWKS, JWS, JWE and JWT according to their respective RFCs:

- [JSON Web Keys](https://tools.ietf.org/html/rfc7517) (JWK) and JSON Web Keys Set (JWKS)
- [JSON Web Signatures](https://tools.ietf.org/html/rfc7515) (JWS)
- [JSON Web Encryption](https://tools.ietf.org/html/rfc7516) (JWE) **limited and experimental!**
- [JSON Web Token](https://tools.ietf.org/html/rfc7519) (JWT)

Rhonabwy is based on the following libraries and actively uses them:

- GnuTLS for the cryptographic functions
- Jansson for the JSON manipulation
- Yder for the logs
- Ulfius when it requires to retrieve keys from an URL

When relevant, a function can accept or return GnuTLS or Jansson data. But if you're not using those in your application and prefer raw data, you can use the more agnostic functions.

## Return values

Lots of functions in Rhonabwy library return an int value. The returned value can be one of the following:

```C
#define RHN_OK                 0
#define RHN_ERROR              1
#define RHN_ERROR_MEMORY       2
#define RHN_ERROR_PARAM        3
#define RHN_ERROR_UNSUPPORTED  4
#define RHN_ERROR_INVALID      5
```

If a function is succesfull, it will return `RHN_OK` (0), otherwise an error code is returned.

### Log messages

Usually, a log message is displayed to explain more specifically what happened on error. The log manager used is [Yder](https://github.com/babelouest/yder). You can enable yder log messages on the console with the following command at the beginning of your program:

```C

int main() {
  y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy client program");
  
  // Do your code here
  
  y_close_logs();
}
```

Example of an error log message:

```
2020-04-05T16:14:31 - Rhonabwy: r_jwk_is_valid - Invalid alg
```

Go to Yder [API Documentation](https://babelouest.github.io/yder/) for more details.

## Memory management

All typedefs managed by Rhonabwy use dedicated init and free functions. You must always use those functions to allocate or free resources manipulated by the library.

```C
int r_jwk_init(jwk_t ** jwk);

void r_jwk_free(jwk_t * jwk);

int r_jwks_init(jwks_t ** jwks);

void r_jwks_free(jwks_t * jwks);

int r_jws_init(jws_t ** jws);

void r_jws_free(jws_t * jws);

int r_jwe_init(jwe_t ** jwe);

void r_jwe_free(jwe_t * jwe);

int r_jwt_init(jwt_t ** jwt);

void r_jwt_free(jwt_t * jwt);
```

In addition, when a function return a `char *` value, this value must be free'd using the function `r_free(void *)`.

```C
void r_free(void * data);
```

## Libary information

The functions `r_library_info_json_t()` and `r_library_info_json_str()` return a JSON object that represents the signature and encryption algorithms supported, as well as the library version.

Example output:

```JSON
{
  "version": "0.9.8",
  "jws": {
    "alg": 
      ["none",
      "HS256",
      "HS384",
      "HS512",
      "RS256",
      "RS384",
      "RS512"]
  },
  "jwe": {
    "alg": 
      ["RSA1_5",
      "dir"],
    "enc":
      ["A128CBC-HS256",
      "A192CBC-HS384",
      "A256CBC-HS512",
      "A128GCM",
      "A256GCM"]
  }
}
```

And finally, all `json_t *` returned values must be deallocated using `json_decref(json_t *)`, see [Jansson Documentation](https://jansson.readthedocs.io/) for more details.

## JWK

A JWK (JSON Web Key) is a format used to store and represent a cryptoraphic key in a JSON object.

Example of JWK:

```JSON
{
  "kty":"EC",
  "crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "kid":"Public key used in JWS spec Appendix A.3 example"
}
```

The standard allows to store public and private keys for RSA and ECC algorithms, it also allows to store symmetric keys. In a JWK, every raw value is encoded in Base64Url format to fit in the JSON object without any issue.

A JWK is represented in Rhonabwy library using the type `jwk_t *`.

### Import and Export JWK

Rhonabwy allows to import and export a JWK in the following formats:
- A JSON structure in a `const char *`
- A JSON structure in a `json_t *`
- A key or certificate in `PEM` or `DER` format
- A `GnuTLS` structure of the following: `gnutls_privkey_t`, `gnutls_pubkey_t` or `gnutls_x509_crt_t` (import only)

If the imported JWK contains a `x5u` property, the key or certificate will be downloaded at the given address. If so, you can give an additional parameter `x5u_flag` which values can be:
- `R_FLAG_IGNORE_SERVER_CERTIFICATE`: ignrore if web server certificate is invalid
- `R_FLAG_FOLLOW_REDIRECT`: follow redirections if necessary
- `R_FLAG_IGNORE_REMOTE`: do not download remote key, but the function may return an error

The values `R_FLAG_IGNORE_SERVER_CERTIFICATE` and `R_FLAG_FOLLOW_REDIRECT` can be merged: `R_FLAG_IGNORE_SERVER_CERTIFICATE|R_FLAG_FOLLOW_REDIRECT`

### Manipulate JWK properties

You can manipulate the JWK properties directly using the dedicated functions:

```C
const char * r_jwk_get_property_str(jwk_t * jwk, const char * key);

const char * r_jwk_get_property_array(jwk_t * jwk, const char * key, size_t index);

int r_jwk_set_property_str(jwk_t * jwk, const char * key, const char * value);

int r_jwk_set_property_array(jwk_t * jwk, const char * key, size_t index, const char * value);

int r_jwk_append_property_array(jwk_t * jwk, const char * key, const char * value);

int r_jwk_delete_property_str(jwk_t * jwk, const char * key);

int r_jwk_delete_property_array_at(jwk_t * jwk, const char * key, size_t index);
```

### Validate the format of a JWK

The function `r_jwk_is_valid` will check the validity of a JWK, i.e. check if all the required properties are present and in the correct format. Note that this function is called each time an import is made.

### Generate a random key pair

You can use Rhonabwy to generate a random key pair for RSA or ECC algorithms. The `jwk_t *` parameters must be initialized first.

The `type` parameter can have one of the following values: `R_KEY_TYPE_RSA` or `R_KEY_TYPE_ECDSA`. The `bits` parameter specifies the length of the key. A RSA key must be at least 2048 bits, and the bits value allowed for an ECC key are 256, 384 or 512.

If the parameter `kid` is used, the generated key kid property will heve the kid specified, otherwise a `kid` will be generated to identify the key pair.

```C
int r_jwk_generate_key_pair(jwk_t * jwk_privkey, jwk_t * jwk_pubkey, int type, unsigned int bits, const char * kid);
```

## JWKS

A JWKS (JSON Web Key Set) is a format used to store and represent a set cryptoraphic key in a JSON object. A JWKS is always a JSON object containing the property `"keys"` that will point to an array of JWK.

Example of JWKS:

```JSON
{
  "keys":
  [
    {
      "kty":"EC",
      "crv":"P-256",
      "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use":"enc",
      "kid":"1"
    },
    {
      "kty":"RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB",
      "alg":"RS256",
      "kid":"2011-04-29"
    }
  ]
}
```

In Rhonabwy library, you can manipulate the JWKs inside a JWKS by iteration or get a JWK by its kid.

```C
jwk_t * r_jwks_get_at(jwks_t * jwks, size_t index);

jwk_t * r_jwks_get_by_kid(jwks_t * jwks, const char * kid);
```

You can also import a JWKS using a JSON object or an URL.

```C
int r_jwks_import_from_str(jwks_t * jwks, const char * input);

int r_jwks_import_from_json_t(jwks_t * jwks, json_t * j_input);

int r_jwks_import_from_uri(jwks_t * jwks, const char * uri, int flags);
```

## JWS

A JWS (JSON Web Signature) is a content digitally signed and serialized in a compact format that can be easily transferred in HTTP requests.

A JWS has 3 elements serialized in base64url format and separated by a dot (.). The 3 elements are:

- A header in JSON format
- A Payload
- A digital signature

Its representaiotn uses the following format:

BASE64URL(UTF8(JWS Protected Header)) || '.' ||
BASE64URL(JWS Payload) || '.' ||
BASE64URL(JWS Signature)

The signature is based on the following data:

BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)

The algorithms supported by Rhonabwy are the following:
- HMAC with SHA-2 Functions: `HS256`, `HS384`, `HS512`
- Digital Signature with RSASSA-PKCS1-v1_5: `RS256`, `RS384`, `RS512`
- Digital Signature with ECDSA: `ES256`, `ES384`, `ES512`
- Digital Signature with RSASSA-PSS: `PS256`, `PS384`, `PS512`
- Digital Signature with Ed25519 Elliptic Curve: `EDdSA`
- Unsecured: `none`

### JWS example

In this example, the payload used is the following message:

```
The true sign of intelligence is not knowledge but imagination.
```

The JWS will be signed using HMAC with SHA256 algorithm, in this example, the signing process will use a key identified by the kid "1", therefore the header is the following:

```JSON
{"alg":"HS256","kid":"1"}
```

The key used to sign the data is the following:

```JSON
{
  "kty":"oct",
  "alg":"HS256",
  "k":"c2VjcmV0",
  "kid":"1"
}
```

Finally, the complete representation of the JWS is the following:

```
eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.GKxWqRBFr-6X4HfflzGeGvKVsJ8v1-J39Ho2RslC-5o
```

### Serialize a JWS using Rhonabwy

The JWS above can be created with the following sample code:

```C
#include <rhonabwy.h>

jws_t * jws = NULL;
jwk_t * jwk_key_symmetric = NULL;
char * token = NULL;
const unsigned char payload[] = "The true sign of intelligence is not knowledge but imagination.";
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0\",\"kid\":\"1\"}";

if (r_jwk_init(&jwk_key_symmetric) == RHN_OK && 
    r_jws_init(&jws) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key_symmetric, jwk_key_symmetric_str) == RHN_OK && 
    r_jws_set_alg(jws, R_JWA_ALG_HS256) == RHN_OK &&
    r_jws_set_payload(jws, payload, sizeof(payload)) == RHN_OK) {
  token = r_jws_serialize(jws, jwk_key_symmetric, 0); // token will store the signed token
}

r_free(token);
r_jws_free(jws);
r_jwk_free(jwk_key_symmetric);
```

### Parse and validate signature of a JWS using Rhonabwy

The JWS above can be parsed and verified using the following sample code:

```C
#include <rhonabwy.h>

jws_t * jws = NULL;
jwk_t * jwk_key_symmetric = NULL;
const char token[] = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ."
"VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u."
"GKxWqRBFr-6X4HfflzGeGvKVsJ8v1-J39Ho2RslC-5o";
const char jwk_key_symmetric_str[] = "{\"kty\":\"oct\",\"alg\":\"HS256\",\"k\":\"c2VjcmV0\",\"kid\":\"1\"}";
const char * payload = NULL;
size_t payload_len = 0;

if (r_jwk_init(&jwk_key_symmetric) == RHN_OK && 
    r_jws_init(&jws) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key_symmetric, jwk_key_symmetric_str) == RHN_OK && 
    r_jws_parse(jws, token, 0) == RHN_OK &&
    r_jws_verify_signature(jws, jwk_key_symmetric, 0) == RHN_OK && 
    (payload = r_jws_get_payload(jws, &payload_len)) != NULL && payload_len > 0) {
    // payload and payload_len will contain the payload data
}

r_jws_free(jws);
r_jwk_free(jwk_key_symmetric);
```

## JWE

A JWE (JSON Web Encryption) is an encrypted content serialized in a compact format that can be easily transferred in HTTP requests.

Basically the payload is encrypted using AES-CBC or AES-GCM and an Initialization Vector (IV), a authentication tag is generated to validate the decryption, and the AES key used to encrypt the payload is encrypted itself using a symmetric or asymmetric encryption algorithm.

The serialized token has the following format:

BASE64URL(UTF8(JWE Protected Header)) || '.' ||
BASE64URL(JWE Encrypted Key) || '.' ||
BASE64URL(JWE Initialization Vector) || '.' ||
BASE64URL(JWE Ciphertext) || '.' ||
BASE64URL(JWE Authentication Tag)

In Rhonabwy library, the supported algorithms are the following:
- Supported Encryption Algorithm (`enc`) for JWE payload encryption: `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A256GCM`
- Supported Cryptographic Algorithms for Key Management: `RSA1_5` (RSAES-PKCS1-v1_5), `dir` (Direct use of a shared symmetric key), `A128GCMKW` and `A256GCMKW`

If you don't specify a Content Encryption Key or an Initialization Vector before the serialization, Rhonabwy will automatically generate one or the other or both depending on the algorithm specified.

### JWE example

In this example, the payload used is the following message:

```
The true sign of intelligence is not knowledge but imagination.
```

The RSA private key associated to this token is:

```JSON
{
  "kty":"RSA",
  "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e":"AQAB",
  "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
  "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
  "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
  "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
  "kid":"2011-04-29"
}

```

The encryption algorithm used is `A128CBC-HS256` and the cryptographic algorithm to encrypt the key is `RSA1_5`

Finally, the complete representation of the JWE is the following:

```
eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0ouvmluqT8kvBCgjMw8mhBFFEI5Rua58WnnATU21RqEQ2f9M6FqGEkgYpJ81ePtTkOyW1l8V-4nxIDxy-xeTHd0v5bDEbxhWKRdOmUHACC018Gt1ZB9EHHJt7k4UYj3up2xVa8qykKbZ3WGF0Gffi6ctfLCfRCWNnXMbAylV02mf4Tfhpad_WC4EeZENNryilXbAKD_9NNje-CoXD0IQK4-z2fkzfyUislwzK7dyz--uNNAC3N6XO3Blr_z61wXWGEHBa62fyHCsQqagAzN_MqTZv6cxOpRpeWM4_SwjjvcyC77rRyVpN0lC9ukyX_pNrGLXW8zH4mH78OcKPoDLPw.o5e-xb5ZzvZA2JYD2qgFbA.YNTPRS7Hv0fqE7ReEUAS_KNM31wMPPldhBGmYuQTzUWVcX8pGqooTbwaV4o_7BBiF4apD_VCGWwQ-fDD0eDofg.uyAjCu7WSo8BeBDFmYfkLA
```

### Serialize a JWE using Rhonabwy

The JWE above can be created with the following sample code:

```C
#include <rhonabwy.h>

jwe_t * jwe = NULL;
jwk_t * jwk_key_rsa = NULL;
char * token = NULL;
const unsigned char payload[] = "The true sign of intelligence is not knowledge but imagination.";
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}",

if (r_jwk_init(&jwk_key_rsa) == RHN_OK && 
    r_jwe_init(&jwe) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key_rsa, jwk_pubkey_rsa_str) == RHN_OK && 
    r_jwe_set_alg(jwe, R_JWA_ALG_RSA1_5) == RHN_OK &&
    r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC) == RHN_OK &&
    r_jwe_set_payload(jwe, payload, sizeof(payload)) == RHN_OK) {
  token = r_jwe_serialize(jwe, jwk_key_rsa, 0); // token will store the encrypted token
}

r_free(token);
r_jwe_free(jwe);
r_jwk_free(jwk_key_rsa);
```

### Parse and decrypt a JWS using Rhonabwy

The JWS above can be parsed and verified using the following sample code:

```C
#include <rhonabwy.h>

jwe_t * jwe = NULL;
jwk_t * jwk_key_rsa = NULL;
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                    "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                    "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                    "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                    "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                    "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                    "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                    "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                    "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                    "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                    "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                    "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                    "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}",
token[] = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.0ouvmluqT8kvBCgjMw8mhBFFEI5Rua58WnnATU21RqEQ2f9M6FqGEkgYpJ81ePtTkOyW1l8V-4nxIDxy-xeTHd0v5bDEbxhWKRdOmUHACC018Gt1ZB9EHHJt7k4UYj3up2xVa8qykKbZ3WGF0Gffi6ctfLCfRCWNnXMbAylV02mf4Tfhpad_WC4EeZENNryilXbAKD_9NNje-CoXD0IQK4-z2fkzfyUislwzK7dyz--uNNAC3N6XO3Blr_z61wXWGEHBa62fyHCsQqagAzN_MqTZv6cxOpRpeWM4_SwjjvcyC77rRyVpN0lC9ukyX_pNrGLXW8zH4mH78OcKPoDLPw.o5e-xb5ZzvZA2JYD2qgFbA.YNTPRS7Hv0fqE7ReEUAS_KNM31wMPPldhBGmYuQTzUWVcX8pGqooTbwaV4o_7BBiF4apD_VCGWwQ-fDD0eDofg.uyAjCu7WSo8BeBDFmYfkLA";
const char * payload = NULL;
size_t payload_len = 0;

if (r_jwk_init(&jwk_key_rsa) == RHN_OK && 
    r_jwe_init(&jwe) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key_rsa, jwk_pubkey_rsa_str) == RHN_OK && 
    r_jwe_parse(jwe, token, 0) == RHN_OK &&
    r_jwe_decrypt(jwe, jwk_key_rsa, 0) == RHN_OK && 
    (payload = r_jwe_get_payload(jwe, &payload_len)) != NULL && payload_len > 0) {
  // payload and payload_len will contain the payload data
}

r_jwe_free(jwe);
r_jwk_free(jwk_key_rsa);
```

## JWT

Finally, a JWT (JSON Web Token) is a JSON content signed and/or encrypted and serialized in a compact format that can be easily transferred in HTTP requests. Technically, a JWT is a JWS or a JWE which payload is a stringified JSON and has the property `"type":"JWT"` in the header.

A JWT can be nested, which means signed and encrypted, in which case the payload is signed as a JWS first, then the seralized signed token is used as the payload in a JWE, or the opposite.

### Verify a list of claims in the JWT

The function int `int r_jwt_validate_claims(jwt_t * jwt, ...)` will help you verify the validity of some claims in the JWT.

Claim types available
- `R_JWT_CLAIM_ISS`: claim `"iss"`, values expected a string or `NULL` to validate the presence of the claim
- `R_JWT_CLAIM_SUB`: claim `"sub"`, values expected a string or `NULL` to validate the presence of the claim
- `R_JWT_CLAIM_AUD`: claim `"aud"`, values expected a string or `NULL` to validate the presence of the claim
- `R_JWT_CLAIM_EXP`: claim `"exp"`, value expected `R_JWT_CLAIM_NOW` or an positive integer value or `R_JWT_CLAIM_PRESENT` to validate the presence of the claim
- `R_JWT_CLAIM_NBF`: claim `"nbf"`, value expected `R_JWT_CLAIM_NOW` or an positive integer value or `R_JWT_CLAIM_PRESENT` to validate the presence of the claim
- `R_JWT_CLAIM_IAT`: claim `"iat"`, value expected `R_JWT_CLAIM_NOW` or an positive integer value or `R_JWT_CLAIM_PRESENT` to validate the presence of the claim
- `R_JWT_CLAIM_JTI`: claim `"jti"`, values expected a string or `NULL` to validate the presence of the claim
- `R_JWT_CLAIM_STR`: the claim name specified must have the string value expected or `NULL` to validate the presence of the claim
- `R_JWT_CLAIM_INT`: the claim name specified must have the integer value expected
- `R_JWT_CLAIM_JSN`: the claim name specified must have the json_t * value expected or `NULL` to validate the presence of the claim

For example, the following code will check the jwt against the claim `iss` has the value `"https://example.com"`, the claim `sub` has the value `"client_1"`, the presence of the claim `aud`, the claim `exp` is after now, the claim `nbf` is before now, the claim `scope` has the value `"scope1"`, the claim `age` has the value `42` and the claim `verified` has the JSON value `true`:

```C
if (r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, "https://example.com", 
                               R_JWT_CLAIM_SUB, "client_1", 
                               R_JWT_CLAIM_AUD, NULL, 
                               R_JWT_CLAIM_EXP, R_JWT_CLAIM_NOW, 
                               R_JWT_CLAIM_NBF, R_JWT_CLAIM_NOW, 
                               R_JWT_CLAIM_STR, "scope", "scope1",
                               R_JWT_CLAIM_INT, "age", 42,
                               R_JWT_CLAIM_JSN, "verified", json_true(),
                               R_JWT_CLAIM_NOP) == RHN_OK)
```

### Serialize a JWT using Rhonabwy

Let's use the following JSON object in a JWT:

```JSON
{
  "iss":"joe",
  "exp":1300819380,
  "http://example.com/is_root":true
}
```

The JWT can be signed using the algorithm `HS256` and the following key:

```JSON
{
  "kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
```

The signed JWT serialized will be the following:

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

#### Signed JWT

The signed JWT above can be created with the following sample code:

```C
#include <rhonabwy.h>

jwt_t * jwt = NULL;
jwk_t * jwk_key = NULL;
const char payload[] = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}",
           jwk_key_str[] = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
char * token = NULL;

if (r_jwk_init(&jwk_key) == RHN_OK && 
    r_jwt_init(&jwt) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key, jwk_key_str) == RHN_OK && 
    r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256) == RHN_OK &&
    r_jwt_set_full_claims_json_str(jwt, payload) == RHN_OK) {
  token = r_jwt_serialize_signed(jwt, jwk_key, 0); // token will store the signed token
}

r_free(token);
r_jwt_free(jwt);
r_jwk_free(jwk_key);
```

The same payload can be encrypted and serialized in an encrypted JWT using `RSA1_5` as key encryption algorithm and `A128CBC-HS256` as content encryption algorithm.

The encrypted JWT of the payload above can be the following:

```
eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ.AxY8DCtDaGlsbGljb3RoZQ.MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.fiK51VwhsxJ-siBMR-YFiA
```

#### Encrypted JWT

An encrypted JWT can be created with Rhonabwy using the following sample code:

```C
#include <rhonabwy.h>

jwt_t * jwt = NULL;
jwk_t * jwk_key = NULL;
const char payload[] = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}",
jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
char * token = NULL;

if (r_jwk_init(&jwk_key) == RHN_OK && 
    r_jwt_init(&jwt) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key, jwk_pubkey_rsa_str) == RHN_OK && 
    r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5) == RHN_OK &&
    r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC) == RHN_OK &&
    r_jwt_set_full_claims_json_str(jwt, payload) == RHN_OK) {
  token = r_jwt_serialize_encrypted(jwt, jwk_key, 0); // token will store the encrypted token
}

r_free(token);
r_jwt_free(jwt);
r_jwk_free(jwk_key);
```

#### Nested JWT

A nested JWT can be created with Rhonabwy using the following sample code:

```C
#include <rhonabwy.h>

jwt_t * jwt = NULL;
jwk_t * jwk_key = NULL, * jwk_key_sign = NULL;
const char payload[] = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}",
jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                      "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                      "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                      ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}",
jwk_key_str[] = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";
char * token = NULL;

if (r_jwk_init(&jwk_key) == RHN_OK && 
    r_jwk_init(&jwk_key_sign) == RHN_OK &&
    r_jwt_init(&jwt) == RHN_OK &&
    r_jwk_import_from_json_str(jwk_key, jwk_pubkey_rsa_str) == RHN_OK && 
    r_jwk_import_from_json_str(jwk_key_sign, jwk_key_str) == RHN_OK && 
    r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5) == RHN_OK &&
    r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC) == RHN_OK &&
    r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256) == RHN_OK &&
    r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256) == RHN_OK &&
    r_jwt_set_full_claims_json_str(jwt, payload) == RHN_OK) {
  token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_key_sign, 0, jwk_key, 0); // token will store the nested token
}

r_free(token);
r_jwt_free(jwt);
r_jwk_free(jwk_key);
```
