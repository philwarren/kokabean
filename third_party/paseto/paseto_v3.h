#ifndef THIRD_PARTY_PASETO_PASETO_V3_H_
#define THIRD_PARTY_PASETO_PASETO_V3_H_
COSMOPOLITAN_C_START_

/**
 * @fileoverview PASETO v3.local implementation (placeholder)
 */

// Error codes for v3
typedef enum {
    PASETO_V3_ERROR_SUCCESS = 0,
    PASETO_V3_ERROR_NOT_IMPLEMENTED = 1,
    PASETO_V3_ERROR_INVALID_KEY_SIZE = 2,
    PASETO_V3_ERROR_OUT_OF_MEMORY = 3,
    PASETO_V3_ERROR_ENCODING_FAILED = 4,
    PASETO_V3_ERROR_INVALID_KEY_FORMAT = 5,
    PASETO_V3_ERROR_BUFFER_TOO_SMALL = 6
} paseto_v3_error_t;

const char *paseto_v3_error_message(paseto_v3_error_t error_code);

/**
 * Parse a k3.local.* key into a provided buffer
 * 
 * @param key_str Key string in k2.local.<base64url> format
 * @param key_buf Buffer to store key bytes (must be at least 32 bytes)
 * @param buf_size Size of the provided buffer
 * @return Error code
 */
paseto_v3_error_t paseto_v3_local_key_to_buffer(const char *key_str, uint8_t *key_buf, size_t buf_size);

/**
 * Generate a new random key for v3.local (placeholder)
 * 
 * @param key_out Pointer to store allocated key string (must be freed)
 * @return Error code
 */
paseto_v3_error_t paseto_v3_local_keygen(char **key_out);

/**
 * Encrypt a message using PASETO v3.local (placeholder)
 * 
 * @param message Message to encrypt
 * @param message_len Length of message
 * @param key 32-byte encryption key
 * @param footer Optional footer data (can be NULL)
 * @param footer_len Length of footer (0 if no footer)
 * @param entropy Optional entropy (NULL to generate random)
 * @param token_out Pointer to store allocated token string (must be freed)
 * @return Error code
 */
paseto_v3_error_t paseto_v3_local_encrypt(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *key,
    const uint8_t *footer,
    size_t footer_len,
    const uint8_t *entropy,
    char **token_out
);

/**
 * Decrypt a PASETO v3.local token (placeholder)
 * 
 * @param token Token string to decrypt
 * @param key 32-byte decryption key
 * @param expected_footer Expected footer data (can be NULL to ignore)
 * @param expected_footer_len Length of expected footer
 * @param message_out Pointer to store allocated message (must be freed)
 * @param message_len_out Pointer to store message length
 * @return Error code
 */
paseto_v3_error_t paseto_v3_local_decrypt(
    const char *token,
    const uint8_t *key,
    const uint8_t *expected_footer,
    size_t expected_footer_len,
    uint8_t **message_out,
    size_t *message_len_out
);

COSMOPOLITAN_C_END_
#endif /* THIRD_PARTY_PASETO_PASETO_V3_H_ */