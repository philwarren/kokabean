/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ AUTHOR                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/

#include "libc/log/check.h"
#include "libc/mem/mem.h"
#include "libc/serialize.h"
#include "libc/stdio/rand.h"
#include "libc/str/str.h"
#include "libc/str/tab.h"
#include "net/http/escape.h"
#include "third_party/argon2/blake2.h"
#include "third_party/lua/lauxlib.h"
#include "third_party/mbedtls/xchachapoly.h"

/**
 * @fileoverview Paseto (Platform-Agnostic SEcurity TOkens)
 * RFC https://paseto.io/rfc/
 */

#define HEADER_V2_LOCAL  "v2.local."
#define HEADER_V2_PUBLIC "v2.public."
#define NONCE_LEN 24
#define HEADER_V2_LOCAL_LEN  (sizeof HEADER_V2_LOCAL - 1)
#define HEADER_V2_PUBLIC_LEN (sizeof HEADER_V2_PUBLIC - 1)

static char *encode_base64url(const unsigned char *data, size_t len) {
    char *b64 = EncodeBase64((const char *)data, len, NULL);
    if (!b64) return NULL;

    for (char *p = b64; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }

    char *end = b64 + strlen(b64);
    while (end > b64 && end[-1] == '=') {
        end--;
    }
    *end = '\0';

    return b64;
}

static unsigned char *decode_base64url(const char *input, size_t *output_len) {
    if (!input || !output_len) return NULL;

    // Convert base64url back to base64
    size_t input_len = strlen(input);
    char *b64 = malloc(input_len + 4); // +4 for potential padding
    if (!b64) return NULL;

    strcpy(b64, input);

    // Replace base64url chars with base64 chars
    for (char *p = b64; *p; p++) {
        if (*p == '-') *p = '+';
        else if (*p == '_') *p = '/';
    }

    // Add padding if needed
    size_t pad_len = (4 - (input_len % 4)) % 4;
    for (size_t i = 0; i < pad_len; i++) {
        b64[input_len + i] = '=';
    }
    b64[input_len + pad_len] = '\0';

    // Decode using existing base64 decoder (assuming DecodeBase64 exists)
    unsigned char *result = (unsigned char *)DecodeBase64(b64, input_len + pad_len, output_len);
    free(b64);

    return result;
}

// Error codes
typedef enum {
    PASETO_V2_ERROR_SUCCESS = 0,
    PASETO_V2_ERROR_INVALID_KEY_SIZE = 1,
    PASETO_V2_ERROR_INVALID_ENTROPY = 2,
    PASETO_V2_ERROR_OUT_OF_MEMORY = 3,
    PASETO_V2_ERROR_ENTROPY_FAILED = 4,
    PASETO_V2_ERROR_BLAKE2B_FAILED = 5,
    PASETO_V2_ERROR_CRYPTO_FAILED = 6,
    PASETO_V2_ERROR_ENCODING_FAILED = 7,
    PASETO_V2_ERROR_INVALID_KEY_FORMAT = 8
} paseto_v2_error_t;

const char *paseto_v2_error_message(paseto_v2_error_t error_code) {
    switch (error_code) {
        case PASETO_V2_ERROR_SUCCESS:
            return "Success";
        case PASETO_V2_ERROR_INVALID_KEY_SIZE:
            return "Make sure that you provide a 32-byte key";
        case PASETO_V2_ERROR_INVALID_ENTROPY:
            return "Make sure that you provide 24 bytes of entropy";
        case PASETO_V2_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case PASETO_V2_ERROR_ENTROPY_FAILED:
            return "System entropy source unavailable";
        case PASETO_V2_ERROR_BLAKE2B_FAILED:
            return "BLAKE2b operation failed";
        case PASETO_V2_ERROR_CRYPTO_FAILED:
            return "ChaCha20-Poly1305 operation failed";
        case PASETO_V2_ERROR_ENCODING_FAILED:
            return "Base64url encoding failed";
        case PASETO_V2_ERROR_INVALID_KEY_FORMAT:
            return "Invalid key format - expected k2.local.<base64url-data>";
        default:
            return "Unknown error code";
    }
}


// Parse a k2.local.* key and extract the raw key bytes
static paseto_v2_error_t parse_v2_local_key(const char *key_str, uint8_t **key_out, size_t *key_len_out) {
    if (!key_str || !key_out || !key_len_out) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    const char *prefix = "k2.local.";
    size_t prefix_len = strlen(prefix);
    
    if (strncmp(key_str, prefix, prefix_len) != 0) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    const char *encoded_data = key_str + prefix_len;
    size_t decoded_len;
    unsigned char *decoded_key = decode_base64url(encoded_data, &decoded_len);
    
    if (!decoded_key) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    if (decoded_len != 32) {
        free(decoded_key);
        return PASETO_V2_ERROR_INVALID_KEY_SIZE;
    }
    
    *key_out = decoded_key;
    *key_len_out = decoded_len;
    return PASETO_V2_ERROR_SUCCESS;
}

// Generate a new random key for v2.local
paseto_v2_error_t paseto_v2_local_keygen(char **key_out) {
    if (!key_out) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    *key_out = NULL;
    
    // Generate 32 random bytes
    uint8_t raw_key[32];
    if (getentropy(raw_key, 32) != 0) {
        return PASETO_V2_ERROR_ENTROPY_FAILED;
    }
    
    // Encode as base64url
    char *encoded_key = encode_base64url(raw_key, 32);
    if (!encoded_key) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }
    
    // Build final key string: k2.local.<encoded_key>
    size_t key_len = strlen("k2.local.") + strlen(encoded_key) + 1;
    char *key_str = malloc(key_len);
    if (!key_str) {
        free(encoded_key);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }
    
    strcpy(key_str, "k2.local.");
    strcat(key_str, encoded_key);
    free(encoded_key);
    
    *key_out = key_str;
    return PASETO_V2_ERROR_SUCCESS;
}

paseto_v2_error_t paseto_v2_local_encrypt(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *key,
    const uint8_t *footer,
    size_t footer_len,
    const uint8_t *entropy,
    char **token_out
) {
    if (!message || !key || !token_out) {
        return PASETO_V2_ERROR_INVALID_KEY_SIZE; // Reusing for invalid params
    }

    *token_out = NULL;

    // Generate or use provided entropy
    uint8_t entropy_buf[NONCE_LEN];
    if (entropy) {
        memcpy(entropy_buf, entropy, NONCE_LEN);
    } else {
        if (getentropy(entropy_buf, NONCE_LEN) != 0) {
            return PASETO_V2_ERROR_ENTROPY_FAILED;
        }
    }

    // Generate nonce using BLAKE2b
    uint8_t nonce[NONCE_LEN];
    if (blake2b(nonce, NONCE_LEN, message, message_len, entropy_buf, NONCE_LEN) != 0) {
        return PASETO_V2_ERROR_BLAKE2B_FAILED;
    }

    // Calculate PAE length and allocate
    size_t pae_len = 8 + 8 + HEADER_V2_LOCAL_LEN + 8 + NONCE_LEN + 8 + footer_len;
    uint8_t *pae = malloc(pae_len);
    if (!pae) {
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    // Build PAE
    size_t offset = 0;

#define PAE_PUSH(data, data_len) \
    WRITE64LE(pae + offset, data_len); \
    offset += 8; \
    memcpy(pae + offset, data, data_len); \
    offset += data_len;

    WRITE64LE(pae + offset, 3);
    offset += 8;
    PAE_PUSH(HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN);
    PAE_PUSH(nonce, NONCE_LEN);
    if (footer && footer_len > 0) {
        PAE_PUSH(footer, footer_len);
    } else {
        WRITE64LE(pae + offset, 0);
        offset += 8;
    }

    // Allocate ciphertext buffer
    uint8_t *ciphertext = malloc(message_len);
    if (!ciphertext) {
        free(pae);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    // Encrypt with XChaCha20-Poly1305
    uint8_t tag[16];
    int crypto_result = mbedtls_xchachapoly_encrypt_and_tag(
        key, message_len, nonce, pae, offset,
        message, ciphertext, tag);

    if (crypto_result != 0) {
        free(pae);
        free(ciphertext);
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

    // Build payload: nonce + ciphertext + tag
    size_t payload_len = NONCE_LEN + message_len + 16;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        free(pae);
        free(ciphertext);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    memcpy(payload, nonce, NONCE_LEN);
    memcpy(payload + NONCE_LEN, ciphertext, message_len);
    memcpy(payload + NONCE_LEN + message_len, tag, 16);

    free(pae);
    free(ciphertext);

    // Encode payload
    char *encoded = encode_base64url(payload, payload_len);
    free(payload);

    if (!encoded) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }

    // Encode footer if present
    char *footer_encoded = NULL;
    if (footer && footer_len > 0) {
        footer_encoded = encode_base64url(footer, footer_len);
        if (!footer_encoded) {
            free(encoded);
            return PASETO_V2_ERROR_ENCODING_FAILED;
        }
    }

    // Build final token
    size_t token_len = strlen(HEADER_V2_LOCAL) + strlen(encoded) +
                       (footer_encoded ? 1 + strlen(footer_encoded) : 0);
    char *token = malloc(token_len + 1);
    if (!token) {
        free(encoded);
        free(footer_encoded);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    strcpy(token, HEADER_V2_LOCAL);
    strcat(token, encoded);

    if (footer_encoded) {
        strcat(token, ".");
        strcat(token, footer_encoded);
        free(footer_encoded);
    }

    free(encoded);

    *token_out = token;
    return PASETO_V2_ERROR_SUCCESS;
}

#undef PAE_PUSH

paseto_v2_error_t paseto_v2_local_decrypt(
    const char *token,
    const uint8_t *key,
    const uint8_t *expected_footer,
    size_t expected_footer_len,
    uint8_t **message_out,
    size_t *message_len_out
) {
    if (!token || !key || !message_out || !message_len_out) {
        return PASETO_V2_ERROR_INVALID_KEY_SIZE; // Reusing for invalid params
    }

    *message_out = NULL;
    *message_len_out = 0;

    // Check header
    if (strncmp(token, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN) != 0) {
        return PASETO_V2_ERROR_CRYPTO_FAILED; // Invalid token format
    }

    // Find footer separator
    const char *payload_start = token + HEADER_V2_LOCAL_LEN;
    const char *footer_sep = strrchr(payload_start, '.');
    const char *payload_end = footer_sep ? footer_sep : payload_start + strlen(payload_start);

    // Extract actual footer from token
    unsigned char *actual_footer = NULL;
    size_t actual_footer_len = 0;
    
    if (footer_sep) {
        actual_footer = decode_base64url(footer_sep + 1, &actual_footer_len);
        if (!actual_footer) {
            return PASETO_V2_ERROR_ENCODING_FAILED;
        }
    }

    // Verify footer if expected_footer is provided
    if (expected_footer && expected_footer_len > 0) {
        if (!footer_sep) {
            free(actual_footer);
            return PASETO_V2_ERROR_CRYPTO_FAILED; // Expected footer but none found
        }

        int footer_match = (actual_footer_len == expected_footer_len) &&
                          (timingsafe_bcmp(actual_footer, expected_footer, expected_footer_len) == 0);

        if (!footer_match) {
            free(actual_footer);
            return PASETO_V2_ERROR_CRYPTO_FAILED; // Footer mismatch
        }
    }
    // Note: We don't reject tokens with footers when expected_footer is NULL
    // The PASETO spec allows ignoring footers during decryption

    // Decode payload
    size_t payload_str_len = payload_end - payload_start;
    char *payload_str = malloc(payload_str_len + 1);
    if (!payload_str) {
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }
    memcpy(payload_str, payload_start, payload_str_len);
    payload_str[payload_str_len] = '\0';

    size_t payload_len;
    unsigned char *payload = decode_base64url(payload_str, &payload_len);
    free(payload_str);

    if (!payload) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }

    // Payload must be: nonce(24) + ciphertext + tag(16)
    if (payload_len < NONCE_LEN + 16) {
        free(payload);
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

    // Extract components
    uint8_t *nonce = payload;
    size_t ciphertext_len = payload_len - NONCE_LEN - 16;
    uint8_t *ciphertext = payload + NONCE_LEN;
    uint8_t *tag = payload + NONCE_LEN + ciphertext_len;


    // Build PAE for authentication using actual footer from token
    size_t pae_len = 8 + 8 + HEADER_V2_LOCAL_LEN + 8 + NONCE_LEN + 8 + actual_footer_len;
    uint8_t *pae = malloc(pae_len);
    if (!pae) {
        free(payload);
        free(actual_footer);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    size_t offset = 0;
    WRITE64LE(pae + offset, 3);
    offset += 8;

    // Header
    WRITE64LE(pae + offset, HEADER_V2_LOCAL_LEN);
    offset += 8;
    memcpy(pae + offset, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN);
    offset += HEADER_V2_LOCAL_LEN;

    // Nonce
    WRITE64LE(pae + offset, NONCE_LEN);
    offset += 8;
    memcpy(pae + offset, nonce, NONCE_LEN);
    offset += NONCE_LEN;

    // Footer - use actual footer from token
    if (actual_footer && actual_footer_len > 0) {
        WRITE64LE(pae + offset, actual_footer_len);
        offset += 8;
        memcpy(pae + offset, actual_footer, actual_footer_len);
        offset += actual_footer_len;
    } else {
        WRITE64LE(pae + offset, 0);
        offset += 8;
    }

    // Allocate plaintext buffer
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        free(payload);
        free(pae);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    // Decrypt and verify with XChaCha20-Poly1305
    int crypto_result = mbedtls_xchachapoly_auth_decrypt(
        key, ciphertext_len, nonce, pae, offset,
        tag, ciphertext, plaintext);

    free(payload);
    free(pae);
    free(actual_footer);

    if (crypto_result != 0) {
        free(plaintext);
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

    *message_out = plaintext;
    *message_len_out = ciphertext_len;
    return PASETO_V2_ERROR_SUCCESS;
}


// paseto.v2_local_encrypt(message, key, [footer], [entropy])
//     └─→ token
//     └─→ nil, error
static int LuaV2LocalEncrypt(lua_State *L) {
    size_t message_len, footer_len = 0, entropy_len = 0;
    const char *message = luaL_checklstring(L, 1, &message_len);
    const char *key_str = luaL_checkstring(L, 2);
    const char *footer = NULL;
    const char *entropy_raw = NULL;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        footer = luaL_checklstring(L, 3, &footer_len);
    }
    if (lua_gettop(L) >= 4 && !lua_isnil(L, 4)) {
        entropy_raw = luaL_checklstring(L, 4, &entropy_len);
    }

    // Parse key
    uint8_t *key_bin = NULL;
    size_t key_len = 0;
    int parse_result = parse_v2_local_key(key_str, &key_bin, &key_len);
    if (parse_result != PASETO_V2_ERROR_SUCCESS) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v2_error_message(parse_result));
        return 2;
    }

    // Validate entropy length if provided
    if (entropy_raw && entropy_len != 24) {
        free(key_bin);
        lua_pushnil(L);
        lua_pushstring(L, "Make sure that you provide 24 bytes of entropy");
        return 2;
    }

    char *token = NULL;
    int result = paseto_v2_local_encrypt(
        (const uint8_t *)message, message_len,
        key_bin,
        (const uint8_t *)footer, footer_len,
        (const uint8_t *)entropy_raw,
        &token
    );

    // Clean up
    free(key_bin);

    if (result != 0) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v2_error_message(result));
        return 2;
    }

    lua_pushstring(L, token);
    free(token);
    return 1;
}

// paseto.v2_local_decrypt(token, key, [expected_footer])
//     └─→ message
//     └─→ nil, error
static int LuaV2LocalDecrypt(lua_State *L) {
    size_t expected_footer_len = 0;
    const char *token = luaL_checkstring(L, 1);
    const char *key_str = luaL_checkstring(L, 2);
    const char *expected_footer = NULL;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        expected_footer = luaL_checklstring(L, 3, &expected_footer_len);
    }

    // Parse key
    uint8_t *key_bin = NULL;
    size_t key_len = 0;
    int parse_result = parse_v2_local_key(key_str, &key_bin, &key_len);
    if (parse_result != PASETO_V2_ERROR_SUCCESS) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v2_error_message(parse_result));
        return 2;
    }

    uint8_t *message = NULL;
    size_t message_len = 0;

    int result = paseto_v2_local_decrypt(
        token,
        key_bin,
        (const uint8_t *)expected_footer, expected_footer_len,
        &message, &message_len
    );

    // Clean up
    free(key_bin);

    if (result != 0) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v2_error_message(result));
        return 2;
    }

    lua_pushlstring(L, (const char *)message, message_len);
    free(message);
    return 1;
}

// paseto.v2_local_keygen()
//     └─→ key
//     └─→ nil, error
static int LuaV2LocalKeygen(lua_State *L) {
    char *key = NULL;
    int result = paseto_v2_local_keygen(&key);
    
    if (result != PASETO_V2_ERROR_SUCCESS) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v2_error_message(result));
        return 2;
    }
    
    lua_pushstring(L, key);
    free(key);
    return 1;
}

// paseto.unauthenticated_footer(token)
//     └─→ footer_string (or empty string if no footer)
static int LuaV2UnauthenticatedFooter(lua_State *L) {
    const char *token = luaL_checkstring(L, 1);

    // Check header and skip to payload in one step
    const char *payload_start = NULL;
    if (strncmp(token, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN) == 0) {
        payload_start = token + HEADER_V2_LOCAL_LEN;
    } else if (strncmp(token, HEADER_V2_PUBLIC, HEADER_V2_PUBLIC_LEN) == 0) {
        payload_start = token + HEADER_V2_PUBLIC_LEN;
    } else {
        lua_pushstring(L, ""); // Return empty string for invalid tokens
        return 1;
    }

    // Find the last dot separator (footer separator)
    const char *footer_sep = strrchr(payload_start, '.');

    if (!footer_sep) {
        // No footer present
        lua_pushstring(L, "");
        return 1;
    }

    // Decode the footer (base64url)
    size_t footer_decoded_len;
    unsigned char *footer_decoded = decode_base64url(footer_sep + 1, &footer_decoded_len);

    if (!footer_decoded) {
        // Failed to decode footer, return empty string
        lua_pushstring(L, "");
        return 1;
    }

    // Return the decoded footer as a Lua string
    lua_pushlstring(L, (const char *)footer_decoded, footer_decoded_len);
    free(footer_decoded);
    return 1;
}

static const luaL_Reg kLuaPaseto[] = {
    {"v2_local_encrypt",          LuaV2LocalEncrypt},
    {"v2_local_decrypt",          LuaV2LocalDecrypt},
    {"v2_local_keygen",           LuaV2LocalKeygen},
    {"v2_unauthenticated_footer", LuaV2UnauthenticatedFooter},
    {0},
};

int LuaPaseto(lua_State *L) {
  luaL_newlib(L, kLuaPaseto);
  return 1;
}
