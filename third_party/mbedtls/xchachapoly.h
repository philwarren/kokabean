/* XChaChaPoly for SWI
   Phillip Warren 2025 */

#ifndef MBEDTLS_XCHACHAPOLY_H
#define MBEDTLS_XCHACHAPOLY_H
#include "third_party/mbedtls/config.h"

#define MBEDTLS_ERR_XCHACHAPOLY_BAD_STATE            -0x0058 /*< The requested operation is not permitted in the current state. */
#define MBEDTLS_ERR_XCHACHAPOLY_AUTH_FAILED          -0x005A /*< Authenticated decryption failed: data was not authentic. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           This function performs a complete XChaCha20-Poly1305
 *                  authenticated encryption operation.
 *
 *                  XChaCha20-Poly1305 is a variant of ChaCha20-Poly1305 that
 *                  uses a 192-bit (24 bytes) nonce instead of 96-bit (12 bytes).
 *                  This provides better collision resistance when using random
 *                  nonces.
 *
 *                  The algorithm uses HChaCha20 to derive a subkey from the
 *                  first 16 bytes of the nonce and the key, then uses
 *                  standard ChaCha20-Poly1305 with the derived subkey and
 *                  the remaining 8 bytes of the nonce.
 *
 * \warning         You must never use the same nonce twice with the same key.
 *                  This would void any confidentiality and authenticity
 *                  guarantees for the messages encrypted with the same nonce
 *                  and key.
 *
 * \param key       The 256-bit (32 bytes) encryption key.
 * \param length    The length (in bytes) of the data to encrypt.
 * \param nonce     The 192-bit (24 bytes) nonce/IV to use.
 * \param aad       The buffer containing the additional authenticated
 *                  data (AAD). This pointer can be \c NULL if `aad_len == 0`.
 * \param aad_len   The length (in bytes) of the AAD data to process.
 * \param input     The buffer containing the data to encrypt.
 *                  This pointer can be \c NULL if `length == 0`.
 * \param output    The buffer to where the encrypted data is written.
 *                  This pointer can be \c NULL if `length == 0`.
 * \param tag       The buffer to where the computed 128-bit (16 bytes) MAC
 *                  is written. This must not be \c NULL.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
int mbedtls_xchachapoly_encrypt_and_tag( const unsigned char key[32],
                                         size_t length,
                                         const unsigned char nonce[24],
                                         const unsigned char *aad,
                                         size_t aad_len,
                                         const unsigned char *input,
                                         unsigned char *output,
                                         unsigned char tag[16] );

/**
 * \brief           This function performs a complete XChaCha20-Poly1305
 *                  authenticated decryption operation.
 *
 *                  XChaCha20-Poly1305 is a variant of ChaCha20-Poly1305 that
 *                  uses a 192-bit (24 bytes) nonce instead of 96-bit (12 bytes).
 *                  This provides better collision resistance when using random
 *                  nonces.
 *
 *                  The algorithm uses HChaCha20 to derive a subkey from the
 *                  first 16 bytes of the nonce and the key, then uses
 *                  standard ChaCha20-Poly1305 with the derived subkey and
 *                  the remaining 8 bytes of the nonce.
 *
 * \param key       The 256-bit (32 bytes) encryption key.
 * \param length    The length (in bytes) of the data to decrypt.
 * \param nonce     The 192-bit (24 bytes) nonce/IV to use.
 * \param aad       The buffer containing the additional authenticated data (AAD).
 *                  This pointer can be \c NULL if `aad_len == 0`.
 * \param aad_len   The length (in bytes) of the AAD data to process.
 * \param tag       The buffer holding the authentication tag.
 *                  This must be a readable buffer of length \c 16 bytes.
 * \param input     The buffer containing the data to decrypt.
 *                  This pointer can be \c NULL if `length == 0`.
 * \param output    The buffer to where the decrypted data is written.
 *                  This pointer can be \c NULL if `length == 0`.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_XCHACHAPOLY_AUTH_FAILED
 *                  if the data was not authentic.
 * \return          Another negative error code on other kinds of failure.
 */
int mbedtls_xchachapoly_auth_decrypt( const unsigned char key[32],
                                      size_t length,
                                      const unsigned char nonce[24],
                                      const unsigned char *aad,
                                      size_t aad_len,
                                      const unsigned char tag[16],
                                      const unsigned char *input,
                                      unsigned char *output );

#if defined(MBEDTLS_SELF_TEST)
/**
 * \brief           The XChaCha20-Poly1305 checkup routine.
 *
 * \return          \c 0 on success.
 * \return          \c 1 on failure.
 */
int mbedtls_xchachapoly_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_XCHACHAPOLY_H */
