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

#include "third_party/paseto/paseto_v3.h"
#include "libc/mem/mem.h"
#include "libc/str/str.h"
#include "net/http/escape.h"

#define PASETO_V3_KEY_SIZE 32

const char *paseto_v3_error_message(paseto_v3_error_t error_code) {
    switch (error_code) {
        case PASETO_V3_ERROR_SUCCESS:
            return "Success";
        case PASETO_V3_ERROR_NOT_IMPLEMENTED:
            return "PASETO v3 is not yet implemented";
        case PASETO_V3_ERROR_INVALID_KEY_SIZE:
            return "Invalid key size for PASETO v3";
        case PASETO_V3_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case PASETO_V3_ERROR_ENCODING_FAILED:
            return "Encoding failed";
        case PASETO_V3_ERROR_INVALID_KEY_FORMAT:
            return "Invalid key format for PASETO v3";
        default:
            return "Unknown PASETO v3 error code";
    }
}

paseto_v3_error_t paseto_v3_local_keygen(char **key_out) {
    if (!key_out) {
        return PASETO_V3_ERROR_INVALID_KEY_FORMAT;
    }
    
    *key_out = NULL;
    return PASETO_V3_ERROR_NOT_IMPLEMENTED;
}

paseto_v3_error_t paseto_v3_local_encrypt(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *key,
    const uint8_t *footer,
    size_t footer_len,
    const uint8_t *entropy,
    char **token_out
) {
    if (!message || !key || !token_out) {
        return PASETO_V3_ERROR_INVALID_KEY_SIZE;
    }
    
    *token_out = NULL;
    return PASETO_V3_ERROR_NOT_IMPLEMENTED;
}

paseto_v3_error_t paseto_v3_local_decrypt(
    const char *token,
    const uint8_t *key,
    const uint8_t *expected_footer,
    size_t expected_footer_len,
    uint8_t **message_out,
    size_t *message_len_out
) {
    if (!token || !key || !message_out || !message_len_out) {
        return PASETO_V3_ERROR_INVALID_KEY_SIZE;
    }
    
    *message_out = NULL;
    *message_len_out = 0;
    return PASETO_V3_ERROR_NOT_IMPLEMENTED;
}

paseto_v3_error_t paseto_v3_local_key_to_buffer(const char *key_str, uint8_t *key_buf, size_t buf_size) {
    if (!key_str || !key_buf) {
        return PASETO_V3_ERROR_INVALID_KEY_FORMAT;
    }
    
    if (buf_size < PASETO_V3_KEY_SIZE) {
        return PASETO_V3_ERROR_BUFFER_TOO_SMALL;
    }
    
    const char *prefix = "k3.local.";
    size_t prefix_len = strlen(prefix);
    
    if (strncmp(key_str, prefix, prefix_len) != 0) {
        return PASETO_V3_ERROR_INVALID_KEY_FORMAT;
    }
    
    const char *encoded_data = key_str + prefix_len;
    size_t decoded_len;
    char *decoded_key = DecodeBase64(encoded_data, -1, &decoded_len);
    
    if (!decoded_key) {
        return PASETO_V3_ERROR_INVALID_KEY_FORMAT;
    }
    
    if (decoded_len != PASETO_V3_KEY_SIZE) {
        free(decoded_key);
        return PASETO_V3_ERROR_INVALID_KEY_SIZE;
    }
    
    // Copy to caller's buffer and clean up temporary allocation
    memcpy(key_buf, decoded_key, decoded_len);
    free(decoded_key);
    
    return PASETO_V3_ERROR_SUCCESS;
}
