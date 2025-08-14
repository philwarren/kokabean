/* XChaChaPoly for SWI
   Phillip Warren 2025 */

#include "libc/str/str.h"
#include "libc/serialize.h"
#include "third_party/mbedtls/xchachapoly.h"
#include "third_party/mbedtls/chachapoly.h"
#include "third_party/mbedtls/chk.h"
#include "third_party/mbedtls/common.h"
#include "third_party/mbedtls/error.h"
#include "third_party/mbedtls/platform.h"
__static_yoink("mbedtls_notice");

/**
 * @fileoverview XChaCha20-Poly1305 AEAD construction with extended nonce.
 */

#if defined(MBEDTLS_XCHACHAPOLY_C)

/* Parameter validation macros */
#define XCHACHAPOLY_VALIDATE_RET( cond )                                      \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA )
#define XCHACHAPOLY_VALIDATE( cond )                                          \
    MBEDTLS_INTERNAL_VALIDATE( cond )

static void hchacha20( unsigned char subkey[32], 
                       const unsigned char key[32], 
                       const unsigned char nonce128[16] )
{
    uint32_t state[16];
    int i;
    
    /* Initialize ChaCha state with constants "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    /* Key (8 words) */
    for( i = 0; i < 8; i++ ) {
        state[4 + i] = READ32LE(key + 4 * i);
    }
    
    /* Nonce (4 words, 16 bytes) */
    for( i = 0; i < 4; i++ ) {
        state[12 + i] = READ32LE(nonce128 + 4 * i);
    }
    
    /* Perform 20 rounds (10 iterations of column + diagonal rounds) */
    for( i = 0; i < 10; i++ ) {
        #define ROTL32(value, amount) ((uint32_t)((value) << (amount)) | ((value) >> (32 - (amount))))
        #define QUARTERROUND(a, b, c, d) \
            state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 16); \
            state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 12); \
            state[a] += state[b]; state[d] ^= state[a]; state[d] = ROTL32(state[d], 8); \
            state[c] += state[d]; state[b] ^= state[c]; state[b] = ROTL32(state[b], 7);
        
        /* Column rounds */
        QUARTERROUND(0, 4, 8, 12);
        QUARTERROUND(1, 5, 9, 13);
        QUARTERROUND(2, 6, 10, 14);
        QUARTERROUND(3, 7, 11, 15);
        
        /* Diagonal rounds */
        QUARTERROUND(0, 5, 10, 15);
        QUARTERROUND(1, 6, 11, 12);
        QUARTERROUND(2, 7, 8, 13);
        QUARTERROUND(3, 4, 9, 14);
        
        #undef QUARTERROUND
        #undef ROTL32
    }
    
    /* HChaCha20 returns first and last rows (no addition of initial state) */
    for( i = 0; i < 4; i++ ) {
        WRITE32LE(subkey + 4 * i, state[i]);
        WRITE32LE(subkey + 16 + 4 * i, state[12 + i]);
    }
}

int mbedtls_xchachapoly_encrypt_and_tag( const unsigned char key[32],
                                         size_t length,
                                         const unsigned char nonce[24],
                                         const unsigned char *aad,
                                         size_t aad_len,
                                         const unsigned char *input,
                                         unsigned char *output,
                                         unsigned char tag[16] )
{
    mbedtls_chachapoly_context ctx;
    unsigned char subkey[32];
    unsigned char chacha_nonce[12];
    int ret = MBEDTLS_ERR_THIS_CORRUPTION;
    
    XCHACHAPOLY_VALIDATE_RET( key );
    XCHACHAPOLY_VALIDATE_RET( nonce );
    XCHACHAPOLY_VALIDATE_RET( tag );
    XCHACHAPOLY_VALIDATE_RET( aad || !aad_len );
    XCHACHAPOLY_VALIDATE_RET( input || !length );
    XCHACHAPOLY_VALIDATE_RET( output || !length );
    
    mbedtls_chachapoly_init( &ctx );
    
    /* Derive subkey using HChaCha20 with first 16 bytes of nonce */
    hchacha20( subkey, key, nonce );
    
    /* Set the derived subkey */
    MBEDTLS_CHK( mbedtls_chachapoly_setkey( &ctx, subkey ) );
    
    /* Prepare ChaCha20 nonce: 4 zero bytes + last 8 bytes of XChaCha nonce */
    mbedtls_platform_zeroize( chacha_nonce, 4 );
    memcpy( chacha_nonce + 4, nonce + 16, 8 );
    
    /* Use piecewise API to perform encryption */
    MBEDTLS_CHK( mbedtls_chachapoly_starts( &ctx, chacha_nonce, MBEDTLS_CHACHAPOLY_ENCRYPT ) );
    MBEDTLS_CHK( mbedtls_chachapoly_update_aad( &ctx, aad, aad_len ) );
    MBEDTLS_CHK( mbedtls_chachapoly_update( &ctx, length, input, output ) );
    MBEDTLS_CHK( mbedtls_chachapoly_finish( &ctx, tag ) );

cleanup:
    mbedtls_chachapoly_free( &ctx );
    mbedtls_platform_zeroize( subkey, sizeof( subkey ) );
    return( ret );
}

int mbedtls_xchachapoly_auth_decrypt( const unsigned char key[32],
                                      size_t length,
                                      const unsigned char nonce[24],
                                      const unsigned char *aad,
                                      size_t aad_len,
                                      const unsigned char tag[16],
                                      const unsigned char *input,
                                      unsigned char *output )
{
    mbedtls_chachapoly_context ctx;
    unsigned char subkey[32];
    unsigned char chacha_nonce[12];
    unsigned char check_tag[16];
    size_t i;
    int diff;
    int ret = MBEDTLS_ERR_THIS_CORRUPTION;
    
    XCHACHAPOLY_VALIDATE_RET( key );
    XCHACHAPOLY_VALIDATE_RET( nonce );
    XCHACHAPOLY_VALIDATE_RET( tag );
    XCHACHAPOLY_VALIDATE_RET( aad_len == 0 || aad );
    XCHACHAPOLY_VALIDATE_RET( length == 0 || input );
    XCHACHAPOLY_VALIDATE_RET( length == 0 || output );
    
    mbedtls_chachapoly_init( &ctx );
    
    /* Derive subkey using HChaCha20 with first 16 bytes of nonce */
    hchacha20( subkey, key, nonce );
    
    /* Set the derived subkey */
    MBEDTLS_CHK( mbedtls_chachapoly_setkey( &ctx, subkey ) );
    
    /* Prepare ChaCha20 nonce: 4 zero bytes + last 8 bytes of XChaCha nonce */
    mbedtls_platform_zeroize( chacha_nonce, 4 );
    memcpy( chacha_nonce + 4, nonce + 16, 8 );
    
    /* Use piecewise API to perform decryption and tag computation */
    MBEDTLS_CHK( mbedtls_chachapoly_starts( &ctx, chacha_nonce, MBEDTLS_CHACHAPOLY_DECRYPT ) );
    MBEDTLS_CHK( mbedtls_chachapoly_update_aad( &ctx, aad, aad_len ) );
    MBEDTLS_CHK( mbedtls_chachapoly_update( &ctx, length, input, output ) );
    MBEDTLS_CHK( mbedtls_chachapoly_finish( &ctx, check_tag ) );
    
    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < sizeof( check_tag ); i++ )
        diff |= tag[i] ^ check_tag[i];
        
    if( diff != 0 )
    {
        mbedtls_platform_zeroize( output, length );
        ret = MBEDTLS_ERR_XCHACHAPOLY_AUTH_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_chachapoly_free( &ctx );
    mbedtls_platform_zeroize( subkey, sizeof( subkey ) );
    return( ret );
}

#if defined(MBEDTLS_SELF_TEST)

/* Test vector from draft-irtf-cfrg-xchacha-03 */
static const unsigned char test_key[1][32] =
{
    {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    }
};

static const unsigned char test_nonce[1][24] =
{
    {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    }
};

static const unsigned char test_aad[1][12] =
{
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    }
};

static const size_t test_aad_len[1] =
{
    12U
};

static const unsigned char test_input[1][114] =
{
    {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    }
};

static const unsigned char test_output[1][114] =
{
    {
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b,
        0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9, 0x39,
        0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
        0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb,
        0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44,
        0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
        0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
        0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52,
        0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
        0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e,
        0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f,
        0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
        0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9,
        0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
        0xb5, 0x2e
    }
};

static const size_t test_input_len[1] =
{
    114U
};

static const unsigned char test_mac[1][16] =
{
    {
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79,
        0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49
    }
};

/* Make sure no other definition is already present. */
#undef ASSERT

#define ASSERT( cond, args )            \
    do                                  \
    {                                   \
        if( ! ( cond ) )                \
        {                               \
            if( verbose != 0 )          \
                mbedtls_printf args;    \
                                        \
            return( -1 );               \
        }                               \
    }                                   \
    while( 0 )

int mbedtls_xchachapoly_self_test( int verbose )
{
    unsigned i;
    int ret = MBEDTLS_ERR_THIS_CORRUPTION;
    unsigned char output[200];
    unsigned char mac[16];
    
    for( i = 0U; i < 1U; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  XChaCha20-Poly1305 test %u ", i );
            
        ret = mbedtls_xchachapoly_encrypt_and_tag( test_key[i],
                                                   test_input_len[i],
                                                   test_nonce[i],
                                                   test_aad[i],
                                                   test_aad_len[i],
                                                   test_input[i],
                                                   output,
                                                   mac );
                                                   
        ASSERT( 0 == ret, ( "encrypt_and_tag() error code: %i\n", ret ) );
        ASSERT( 0 == timingsafe_bcmp( output, test_output[i], test_input_len[i] ),
                ( "failure (wrong output)\n" ) );
        ASSERT( 0 == timingsafe_bcmp( mac, test_mac[i], 16U ),
                ( "failure (wrong MAC)\n" ) );
                
        ret = mbedtls_xchachapoly_auth_decrypt( test_key[i],
                                                test_input_len[i],
                                                test_nonce[i],
                                                test_aad[i],
                                                test_aad_len[i],
                                                test_mac[i],
                                                test_output[i],
                                                output );
                                                
        ASSERT( 0 == ret, ( "auth_decrypt() error code: %i\n", ret ) );
        ASSERT( 0 == timingsafe_bcmp( output, test_input[i], test_input_len[i] ),
                ( "failure (wrong plaintext)\n" ) );
                
        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }
    
    if( verbose != 0 )
        mbedtls_printf( "\n" );
        
    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_XCHACHAPOLY_C */
