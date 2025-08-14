#ifndef THIRD_PARTY_PASETO_PASETO_V2_H_
#define THIRD_PARTY_PASETO_PASETO_V2_H_
COSMOPOLITAN_C_START_

/**
 * @fileoverview PASETO v2.local implementation
 */

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

const char *paseto_v2_error_message(paseto_v2_error_t error_code);

/**
 * Parse a k2.local.* key and extract the raw key bytes
 * 
 * @param key_str Key string in k2.local.<base64url> format
 * @param key_out Pointer to store allocated key bytes (must be freed)
 * @param key_len_out Pointer to store key length
 * @return Error code
 */
paseto_v2_error_t parse_v2_local_key(const char *key_str, uint8_t **key_out, size_t *key_len_out);

/**
 * Generate a new random key for v2.local
 * 
 * @param key_out Pointer to store allocated key string (must be freed)
 * @return Error code
 */
paseto_v2_error_t paseto_v2_local_keygen(char **key_out);

/**
 * Encrypt a message using PASETO v2.local
 * 
 * @param message Message to encrypt
 * @param message_len Length of message
 * @param key 32-byte encryption key
 * @param footer Optional footer data (can be NULL)
 * @param footer_len Length of footer (0 if no footer)
 * @param entropy Optional 24-byte entropy (NULL to generate random)
 * @param token_out Pointer to store allocated token string (must be freed)
 * @return Error code
 */
paseto_v2_error_t paseto_v2_local_encrypt(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *key,
    const uint8_t *footer,
    size_t footer_len,
    const uint8_t *entropy,
    char **token_out
);

/**
 * Decrypt a PASETO v2.local token
 * 
 * @param token Token string to decrypt
 * @param key 32-byte decryption key
 * @param expected_footer Expected footer data (can be NULL to ignore)
 * @param expected_footer_len Length of expected footer
 * @param message_out Pointer to store allocated message (must be freed)
 * @param message_len_out Pointer to store message length
 * @return Error code
 */
paseto_v2_error_t paseto_v2_local_decrypt(
    const char *token,
    const uint8_t *key,
    const uint8_t *expected_footer,
    size_t expected_footer_len,
    uint8_t **message_out,
    size_t *message_len_out
);

/**
 * Extract footer from a PASETO token without authentication
 * 
 * @param token Token string
 * @param footer_out Pointer to store allocated footer (must be freed, NULL if no footer)
 * @param footer_len_out Pointer to store footer length (0 if no footer)
 * @return Error code
 */
paseto_v2_error_t paseto_extract_footer(const char *token, uint8_t **footer_out, size_t *footer_len_out);

COSMOPOLITAN_C_END_
#endif /* THIRD_PARTY_PASETO_PASETO_V2_H_ */