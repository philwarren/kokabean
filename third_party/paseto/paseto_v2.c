/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
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

#include "third_party/paseto/paseto_v2.h"
#include "libc/log/check.h"
#include "libc/mem/mem.h"
#include "libc/serialize.h"
#include "libc/stdio/rand.h"
#include "libc/str/str.h"
#include "libc/str/tab.h"
#include "net/http/escape.h"
#include "third_party/argon2/blake2.h"
#include "third_party/mbedtls/xchachapoly.h"

#define HEADER_V2_LOCAL  "v2.local."
#define NONCE_LEN 24
#define HEADER_V2_LOCAL_LEN  (sizeof HEADER_V2_LOCAL - 1)

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
        case PASETO_V2_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        default:
            return "Unknown error code";
    }
}

/**
 * Encodes data as base64url (URL-safe base64 without padding)
 * @param data input data
 * @param len input length
 * @return allocated base64url string or NULL on failure
 */
static char *encode_base64url(const uint8_t *data, size_t len) {
    char *encoded = EncodeBase64((const char *)data, len, NULL);
    if (!encoded) return NULL;

    // Convert to URL-safe alphabet and remove padding
    for (char *p = encoded; *p; p++) {
        if (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }

    // Remove padding
    char *end = encoded + strlen(encoded);
    while (end > encoded && end[-1] == '=') {
        end--;
    }
    *end = '\0';

    return encoded;
}

/**
 * Decodes base64url data
 * @param input base64url string
 * @param output_len receives decoded length
 * @return allocated decoded data or NULL on failure
 */
static uint8_t *decode_base64url(const char *input, size_t *output_len) {
    if (!input || !output_len) return NULL;
    
    // DecodeBase64 handles base64url alphabet natively
    char *decoded = DecodeBase64(input, -1, output_len);
    return (uint8_t *)decoded;
}

paseto_v2_error_t paseto_v2_local_key_to_buffer(const char *key_str, uint8_t *key_buf, size_t buf_size) {
    if (!key_str || !key_buf) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    if (buf_size < 32) {
        return PASETO_V2_ERROR_BUFFER_TOO_SMALL;
    }
    
    const char *prefix = "k2.local.";
    size_t prefix_len = strlen(prefix);
    
    if (strncmp(key_str, prefix, prefix_len) != 0) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    const char *encoded_data = key_str + prefix_len;
    size_t decoded_len;
    uint8_t *decoded_key = decode_base64url(encoded_data, &decoded_len);
    
    if (!decoded_key) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    if (decoded_len != 32) {
        free(decoded_key);
        return PASETO_V2_ERROR_INVALID_KEY_SIZE;
    }
    
    // Copy to caller's buffer and clean up temporary allocation
    memcpy(key_buf, decoded_key, decoded_len);
    free(decoded_key);
    
    return PASETO_V2_ERROR_SUCCESS;
}

paseto_v2_error_t paseto_v2_local_keygen(char **key_out) {
    if (!key_out) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    *key_out = NULL;
    
    uint8_t raw_key[32];
    if (getentropy(raw_key, 32) != 0) {
        return PASETO_V2_ERROR_ENTROPY_FAILED;
    }
    
    char *encoded_key = encode_base64url(raw_key, 32);
    if (!encoded_key) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }
    
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
        return PASETO_V2_ERROR_INVALID_KEY_SIZE;
    }

    *token_out = NULL;

    uint8_t entropy_buf[NONCE_LEN];
    if (entropy) {
        memcpy(entropy_buf, entropy, NONCE_LEN);
    } else {
        if (getentropy(entropy_buf, NONCE_LEN) != 0) {
            return PASETO_V2_ERROR_ENTROPY_FAILED;
        }
    }

    uint8_t nonce[NONCE_LEN];
    if (blake2b(nonce, NONCE_LEN, message, message_len, entropy_buf, NONCE_LEN) != 0) {
        return PASETO_V2_ERROR_BLAKE2B_FAILED;
    }

    size_t pae_len = 8 + 8 + HEADER_V2_LOCAL_LEN + 8 + NONCE_LEN + 8 + footer_len;
    uint8_t *pae = malloc(pae_len);
    if (!pae) {
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

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

    uint8_t *ciphertext = malloc(message_len);
    if (!ciphertext) {
        free(pae);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

    uint8_t tag[16];
    int crypto_result = mbedtls_xchachapoly_encrypt_and_tag(
        key, message_len, nonce, pae, offset,
        message, ciphertext, tag);

    if (crypto_result != 0) {
        free(pae);
        free(ciphertext);
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

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

    char *encoded = encode_base64url(payload, payload_len);
    free(payload);

    if (!encoded) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }

    char *footer_encoded = NULL;
    if (footer && footer_len > 0) {
        footer_encoded = encode_base64url(footer, footer_len);
        if (!footer_encoded) {
            free(encoded);
            return PASETO_V2_ERROR_ENCODING_FAILED;
        }
    }

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
        return PASETO_V2_ERROR_INVALID_KEY_SIZE;
    }

    *message_out = NULL;
    *message_len_out = 0;

    if (strncmp(token, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN) != 0) {
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

    const char *payload_start = token + HEADER_V2_LOCAL_LEN;
    const char *footer_sep = strrchr(payload_start, '.');
    const char *payload_end = footer_sep ? footer_sep : payload_start + strlen(payload_start);

    uint8_t *actual_footer = NULL;
    size_t actual_footer_len = 0;
    
    if (footer_sep) {
        actual_footer = decode_base64url(footer_sep + 1, &actual_footer_len);
        if (!actual_footer) {
            return PASETO_V2_ERROR_ENCODING_FAILED;
        }
    }

    if (expected_footer && expected_footer_len > 0) {
        if (!footer_sep) {
            free(actual_footer);
            return PASETO_V2_ERROR_CRYPTO_FAILED;
        }

        int footer_match = (actual_footer_len == expected_footer_len) &&
                          (timingsafe_bcmp(actual_footer, expected_footer, expected_footer_len) == 0);

        if (!footer_match) {
            free(actual_footer);
            return PASETO_V2_ERROR_CRYPTO_FAILED;
        }
    }

    size_t payload_str_len = payload_end - payload_start;
    char *payload_str = malloc(payload_str_len + 1);
    if (!payload_str) {
        free(actual_footer);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }
    memcpy(payload_str, payload_start, payload_str_len);
    payload_str[payload_str_len] = '\0';

    size_t payload_len;
    uint8_t *payload = decode_base64url(payload_str, &payload_len);
    free(payload_str);

    if (!payload) {
        free(actual_footer);
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }

    if (payload_len < NONCE_LEN + 16) {
        free(payload);
        free(actual_footer);
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }

    uint8_t *nonce = payload;
    size_t ciphertext_len = payload_len - NONCE_LEN - 16;
    uint8_t *ciphertext = payload + NONCE_LEN;
    uint8_t *tag = payload + NONCE_LEN + ciphertext_len;

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

    WRITE64LE(pae + offset, HEADER_V2_LOCAL_LEN);
    offset += 8;
    memcpy(pae + offset, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN);
    offset += HEADER_V2_LOCAL_LEN;

    WRITE64LE(pae + offset, NONCE_LEN);
    offset += 8;
    memcpy(pae + offset, nonce, NONCE_LEN);
    offset += NONCE_LEN;

    if (actual_footer && actual_footer_len > 0) {
        WRITE64LE(pae + offset, actual_footer_len);
        offset += 8;
        memcpy(pae + offset, actual_footer, actual_footer_len);
        offset += actual_footer_len;
    } else {
        WRITE64LE(pae + offset, 0);
        offset += 8;
    }

    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        free(payload);
        free(pae);
        free(actual_footer);
        return PASETO_V2_ERROR_OUT_OF_MEMORY;
    }

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

paseto_v2_error_t paseto_extract_footer(const char *token, uint8_t **footer_out, size_t *footer_len_out) {
    if (!token || !footer_out || !footer_len_out) {
        return PASETO_V2_ERROR_INVALID_KEY_FORMAT;
    }
    
    *footer_out = NULL;
    *footer_len_out = 0;
    
    const char *payload_start = NULL;
    if (strncmp(token, HEADER_V2_LOCAL, HEADER_V2_LOCAL_LEN) == 0) {
        payload_start = token + HEADER_V2_LOCAL_LEN;
    } else {
        return PASETO_V2_ERROR_CRYPTO_FAILED;
    }
    
    const char *footer_sep = strrchr(payload_start, '.');
    if (!footer_sep) {
        return PASETO_V2_ERROR_SUCCESS;
    }
    
    uint8_t *footer_decoded = decode_base64url(footer_sep + 1, footer_len_out);
    if (!footer_decoded) {
        return PASETO_V2_ERROR_ENCODING_FAILED;
    }
    
    *footer_out = footer_decoded;
    return PASETO_V2_ERROR_SUCCESS;
}
