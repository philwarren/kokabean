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

#include "libc/mem/mem.h"
#include "third_party/lua/lauxlib.h"
#include "third_party/paseto/paseto_v2.h"
#include "third_party/paseto/paseto_v3.h"

#include <errno.h>
#include "libc/serialize.h"
#include "libc/stdio/rand.h"
#include "libc/str/str.h"
#include "net/http/escape.h"
#include "third_party/mbedtls/ctr_drbg.h"
#include "third_party/mbedtls/ecdsa.h"
#include "third_party/mbedtls/entropy.h"
#include "third_party/mbedtls/error.h"
#include "third_party/mbedtls/platform.h"

/**
 * @fileoverview Paseto (Platform-Agnostic SEcurity TOkens) Lua bindings
 * RFC https://paseto.io/rfc/
 */

#define PASETO_V2_KEY_SIZE 32
#define PASETO_V3_KEY_SIZE 32
#define PASETO_V2_ENTROPY_SIZE 24

// paseto.v2_local_keygen()
//     └─→ key
//     └─→ nil, error
static int LuaV2LocalKeygen(lua_State *L) {
    char *key = NULL;
    int result = paseto_v2_local_keygen(&key);
    
    if (result != PASETO_V2_ERROR_SUCCESS) {
        goto error;
    }
    
    // Success path
    lua_pushstring(L, key);
    free(key);
    return 1;

error:
    free(key);
    lua_pushnil(L);
    lua_pushstring(L, paseto_v2_error_message(result));
    return 2;
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
    char *token = NULL;
    uint8_t key_buf[PASETO_V2_KEY_SIZE];
    int result;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        footer = luaL_checklstring(L, 3, &footer_len);
    }
    if (lua_gettop(L) >= 4 && !lua_isnil(L, 4)) {
        entropy_raw = luaL_checklstring(L, 4, &entropy_len);
    }

    // Parse key to stack buffer
    result = paseto_v2_local_key_to_buffer(key_str, key_buf, sizeof(key_buf));
    if (result != PASETO_V2_ERROR_SUCCESS) {
        goto error;
    }

    // Validate entropy length if provided
    if (entropy_raw && entropy_len != PASETO_V2_ENTROPY_SIZE) {
        result = PASETO_V2_ERROR_INVALID_ENTROPY;
        goto error;
    }

    // Main operation
    result = paseto_v2_local_encrypt(
        (const uint8_t *)message, message_len,
        key_buf,
        (const uint8_t *)footer, footer_len,
        (const uint8_t *)entropy_raw,
        &token
    );

    if (result != PASETO_V2_ERROR_SUCCESS) {
        goto error;
    }

    // Success path
    lua_pushstring(L, token);
    free(token);
    return 1;

error:
    free(token);
    lua_pushnil(L);
    lua_pushstring(L, paseto_v2_error_message(result));
    return 2;
}

// paseto.v2_local_decrypt(token, key, [expected_footer])
//     └─→ message
//     └─→ nil, error
static int LuaV2LocalDecrypt(lua_State *L) {
    size_t expected_footer_len = 0;
    const char *token = luaL_checkstring(L, 1);
    const char *key_str = luaL_checkstring(L, 2);
    const char *expected_footer = NULL;
    uint8_t *message = NULL;
    size_t message_len = 0;
    uint8_t key_buf[PASETO_V2_KEY_SIZE];
    int result;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        expected_footer = luaL_checklstring(L, 3, &expected_footer_len);
    }

    // Parse key to stack buffer
    result = paseto_v2_local_key_to_buffer(key_str, key_buf, sizeof(key_buf));
    if (result != PASETO_V2_ERROR_SUCCESS) {
        goto error;
    }

    // Main operation
    result = paseto_v2_local_decrypt(
        token,
        key_buf,
        (const uint8_t *)expected_footer, expected_footer_len,
        &message, &message_len
    );

    if (result != PASETO_V2_ERROR_SUCCESS) {
        goto error;
    }

    // Success path
    lua_pushlstring(L, (const char *)message, message_len);
    free(message);
    return 1;

error:
    free(message);
    lua_pushnil(L);
    lua_pushstring(L, paseto_v2_error_message(result));
    return 2;
}

// paseto.unauthenticated_footer(token)
//     └─→ footer_string (or empty string if no footer)
static int LuaV2UnauthenticatedFooter(lua_State *L) {
    const char *token = luaL_checkstring(L, 1);
    uint8_t *footer = NULL;
    size_t footer_len = 0;
    int result = paseto_extract_footer(token, &footer, &footer_len);

    if (result != PASETO_V2_ERROR_SUCCESS) {
        lua_pushstring(L, "");
        return 1;
    }

    if (!footer) {
        lua_pushstring(L, "");
        return 1;
    }

    // Success path
    lua_pushlstring(L, (const char *)footer, footer_len);
    free(footer);
    return 1;
}


// PAE helpers inspired by https://github.com/authenticvision/libpaseto

struct pae {
    uint8_t *base;
    uint8_t *current;
};
int pae_init(struct pae *pa, size_t num_elements, size_t sizes) {
    size_t num_bytes = (num_elements + 1) * 8 + sizes;
    pa->base = malloc(num_bytes);
    if (!pa->base) return -1;
    WRITE64LE(pa->base, num_elements);
    pa->current = pa->base + 8;
    return 0;
}
void pae_push(struct pae *pa, const uint8_t *data, size_t len) {
    WRITE64LE(pa->current, len);
    pa->current += 8;
    if(len > 0) memcpy(pa->current, data, len);
    pa->current += len;
}

// paseto.v3_local_keygen()
//     └─→ key
static int LuaV3LocalKeygen(lua_State *L) {
        
    char raw_key[32];
    if (getentropy(raw_key, sizeof(raw_key))) {
        return luaL_error(L, "getentropy failed: %s", strerror(errno));
    }
    
    size_t encoded_key_len;
    char *encoded_key = EncodeBase64Url(raw_key, sizeof(raw_key), &encoded_key_len);
    mbedtls_platform_zeroize(raw_key, sizeof(raw_key));

    if (!encoded_key) {
        return luaL_error(L, "EncodeBase64Url failed: %s", strerror(errno));
    }

    lua_pushfstring(L, "k3.local.%s", encoded_key); // may throw
    
    // leaks if we throw above, but that's unlikely.
    mbedtls_platform_zeroize(encoded_key, encoded_key_len);
    free(encoded_key);

    return 1;
}

// paseto.v3_local_encrypt(message, key, [footer], [entropy])
//     └─→ token
//     └─→ nil, error
static int LuaV3LocalEncrypt(lua_State *L) {
    size_t message_len, footer_len = 0, entropy_len = 0;
    const char *message = luaL_checklstring(L, 1, &message_len);
    const char *key_str = luaL_checkstring(L, 2);
    const char *footer = NULL;
    const char *entropy_raw = NULL;
    char *token = NULL;
    uint8_t key_buf[PASETO_V3_KEY_SIZE];
    int result;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        footer = luaL_checklstring(L, 3, &footer_len);
    }
    if (lua_gettop(L) >= 4 && !lua_isnil(L, 4)) {
        entropy_raw = luaL_checklstring(L, 4, &entropy_len);
    }

    // Parse key to stack buffer
    result = paseto_v3_local_key_to_buffer(key_str, key_buf, sizeof(key_buf));
    if (result != PASETO_V3_ERROR_SUCCESS) {
        goto error;
    }

    // Main operation
    result = paseto_v3_local_encrypt(
        (const uint8_t *)message, message_len,
        key_buf,
        (const uint8_t *)footer, footer_len,
        (const uint8_t *)entropy_raw,
        &token
    );

    if (result != PASETO_V3_ERROR_SUCCESS) {
        goto error;
    }

    // Success path
    lua_pushstring(L, token);
    free(token);
    return 1;

error:
    free(token);
    lua_pushnil(L);
    lua_pushstring(L, paseto_v3_error_message(result));
    return 2;
}

// paseto.v3_local_decrypt(token, key, [expected_footer])
//     └─→ message
//     └─→ nil, error
static int LuaV3LocalDecrypt(lua_State *L) {
    size_t expected_footer_len = 0;
    const char *token = luaL_checkstring(L, 1);
    const char *key_str = luaL_checkstring(L, 2);
    const char *expected_footer = NULL;
    uint8_t *message = NULL;
    size_t message_len = 0;
    uint8_t key_buf[PASETO_V3_KEY_SIZE];
    int result;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        expected_footer = luaL_checklstring(L, 3, &expected_footer_len);
    }

    // Parse key to stack buffer
    result = paseto_v3_local_key_to_buffer(key_str, key_buf, sizeof(key_buf));
    if (result != PASETO_V3_ERROR_SUCCESS) {
        goto error;
    }

    // Main operation
    result = paseto_v3_local_decrypt(
        token,
        key_buf,
        (const uint8_t *)expected_footer, expected_footer_len,
        &message, &message_len
    );

    if (result != PASETO_V3_ERROR_SUCCESS) {
        goto error;
    }

    // Success path
    lua_pushlstring(L, (const char *)message, message_len);
    free(message);
    return 1;

error:
    free(message);
    lua_pushnil(L);
    lua_pushstring(L, paseto_v3_error_message(result));
    return 2;
}

// paseto.v3_public_keygen()
//     └─→ public, secret
static int LuaV3PublicKeygen(lua_State *L) {
   
    int mbedtls_ret;
    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    size_t priv_encoded_len = 0;
    char *priv_encoded = NULL;
    char *pub_encoded = NULL;

    char pub_raw[49];
    char priv_raw[48]; // P-384 private key is 48 bytes
    size_t pub_len;

    // Treat ECDSA context as an ECP keypair for public member access
    mbedtls_ecp_keypair *keypair = (mbedtls_ecp_keypair *)&ctx;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const unsigned char pers[] = "paseto-k3-keygen";
    mbedtls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                        &entropy, pers, sizeof(pers) - 1);
    if (mbedtls_ret) goto finish;

    mbedtls_ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP384R1,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
    if(mbedtls_ret) goto finish;

    // Export compressed public key
    mbedtls_ret = mbedtls_ecp_point_write_binary(&keypair->grp, &keypair->Q,
                                                 MBEDTLS_ECP_PF_COMPRESSED,
                                                 &pub_len,
                                                 (unsigned char *)pub_raw, sizeof(pub_raw));
    if (mbedtls_ret) goto finish;

    // Export private scalar
    mbedtls_ret = mbedtls_mpi_write_binary(&keypair->d,
                                           (unsigned char *)priv_raw, sizeof(priv_raw));
    if (mbedtls_ret) goto finish;

    // Encode to Base64URL
    priv_encoded = EncodeBase64Url(priv_raw, sizeof(priv_raw), &priv_encoded_len);
    pub_encoded  = EncodeBase64Url(pub_raw, pub_len, NULL);
    mbedtls_platform_zeroize(priv_raw, sizeof(priv_raw)); // wipe raw priv
    
finish:

   // Clean up mbedtls resources first (these don't throw)
   mbedtls_ctr_drbg_free(&ctr_drbg);
   mbedtls_entropy_free(&entropy);
   mbedtls_ecdsa_free(&ctx);

   // Handle return values and cleanup
   if (mbedtls_ret) {
       char errbuf[128];
       mbedtls_strerror(mbedtls_ret, errbuf, sizeof(errbuf));
       return luaL_error(L, "keygen failed: %s", errbuf);
   } else if (pub_encoded && priv_encoded) {
       lua_pushfstring(L, "k3.public.%s", pub_encoded);  // may throw if OOM
       lua_pushfstring(L, "k3.secret.%s", priv_encoded); // may throw if OOM
       // Clean up after successful push
       // Will leak if the above throws (but that's unlikely to happen)
       mbedtls_platform_zeroize(priv_encoded, priv_encoded_len);
       free(priv_encoded);
       free(pub_encoded);
       return 2;
   } else {
       // Clean up before throwing - one of them may be truthy
       if(priv_encoded) {
           mbedtls_platform_zeroize(priv_encoded, priv_encoded_len);
           free(priv_encoded);
       }
       free(pub_encoded);
       return luaL_error(L, "EncodeBase64Url failed: %s", strerror(errno));
   }
}

#define HEADER_V3_PUBLIC        "v3.public."
#define HEADER_V3_LOCAL         "v3.local."
#define HEADER_V3_PUBLIC_LEN    (sizeof HEADER_V3_PUBLIC - 1)
#define HEADER_V3_LOCAL_LEN     (sizeof HEADER_V3_LOCAL - 1)

// paseto.v3_public_sign(message, secret, [footer], [assertion])
//     └─→ token
//     └─→ nil, error
static int LuaV3PublicSign(lua_State *L) {
    return 0;
//     size_t message_len = 0,
//            footer_len = 0,
//            assertion_len = 0;
   
//     const char *message = luaL_checklstring(L, 1, &message_len);
//     const char *secret  = luaL_checkstring(L, 2);

//     const char *footer = "";
//     const char *assertion = "";

//     if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
//         footer = luaL_checklstring(L, 3, &footer_len);
//     }
//     if (lua_gettop(L) >= 4 && !lua_isnil(L, 4)) {
//         assertion = luaL_checklstring(L, 4, &assertion_len);
//     }

//     char pk[49];
//     // check secret
//     const char *prefix = "k3.secret.";
//     size_t prefix_len = strlen(prefix);
//     if (strncmp(key_str, prefix, prefix_len)) {
//         // TODO: this should raise an error.
//         lua_pushnil(L);
//         lua_pushstring(L, "sign failed: secret should start with \"k3.secret\"");
//         return 2;
//     }

    

    
//     size_t stack_ret = 0;
//     int mbedtls_ret;
    
    
//     struct pae pae = {0};

//     unsigned char hash[48];

//     if(paseto_v3_check_private_key(&pk))

//      // Pack pk, h, m, f, and i together using PAE (pre-authentication encoding).
//     // We'll call this m2.
//     if(pae_init(&pae, 5, sizeof(pk) + HEADER_V3_PUBLIC_LEN + message_len
//                      + footer_len + assertion_len)) {
//         lua_pushnil(L);
//         lua_pushfstring(L, "pae_init failed: %s", strerror(errno));
//         return 2;
//     }
//     pae_push(&pae, pk, sizeof(pk));
//     pae_push(&pae, HEADER_V3_PUBLIC, HEADER_V3_PUBLIC_LEN);
//     pae_push(&pae, message, message_len);
//     pae_push(&pae, footer, footer_len);
//     pae_push(&pae, assertion, assertion_len);

//     // hash
//     unsigned char* m2 = pae.base;
//     size_t m2_len = pae.current - pae.base;
//     mbedtls_ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384), m2, m2_len, hash);
//     if(mbedtls_ret) goto error_mbedtls;

//     // sign
//     mbedtls_ret = mbedtls_ecdsa_sign_det_ext( mbedtls_ecp_group *grp, mbedtls_mpi *r,
//                             mbedtls_mpi *s, const mbedtls_mpi *d,
//                             hash, sizeof(hash),
//                             MBEDTLS_MD_SHA384,
//                             int (*f_rng_blind)(void *, unsigned char *, size_t),
//                             void *p_rng_blind );
//     if(mbedtls_ret) goto error_mbedtls;

//     // Note: pk is the public key corresponding to sk (which MUST use point
//     // compression). pk MUST be 49 bytes long, and the first byte MUST be 0x02
//     // or 0x03 (depending on the least significant bit of Y; section 4.3.6, step
//     // 2.2). The remaining bytes MUST be the X coordinate, using big-endian byte
//     // order.

// error_mbedtls:
//     char errbuf[128];
//     mbedtls_strerror(mbedtls_ret, errbuf, sizeof(errbuf));
//     lua_pushnil(L);
//     lua_pushfstring(L, "sign failed: %s", errbuf);
//     stack = 2;

// free_return:
//     free(pae.base);
//     return stack;
}

// paseto.v3_public_verify(message, secret, [footer], [entropy])
//     └─→ token
//     └─→ nil, error
static int LuaV3PublicVerify(lua_State *L) {
    return 0;
}

static const luaL_Reg kLuaPaseto[] = {
    {"v2_local_encrypt",          LuaV2LocalEncrypt},
    {"v2_local_decrypt",          LuaV2LocalDecrypt},
    {"v2_local_keygen",           LuaV2LocalKeygen},
    {"v2_unauthenticated_footer", LuaV2UnauthenticatedFooter},

    {"v3_local_keygen",           LuaV3LocalKeygen},
    {"v3_local_encrypt",          LuaV3LocalEncrypt},
    {"v3_local_decrypt",          LuaV3LocalDecrypt},

    {"v3_public_keygen",          LuaV3PublicKeygen},
    {"v3_public_sign",            LuaV3PublicSign},
    {"v3_public_verify",          LuaV3PublicVerify},

    {0},
};

int LuaPaseto(lua_State *L) {
  luaL_newlib(L, kLuaPaseto);
  return 1;
}
