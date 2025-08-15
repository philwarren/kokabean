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

// paseto.v3_local_keygen()
//     └─→ key
//     └─→ nil, error
static int LuaV3LocalKeygen(lua_State *L) {
        
    char raw_key[32];
    if (getentropy(raw_key, sizeof(raw_key))) {
        lua_pushnil(L);
        lua_pushfstring(L, "getentropy failed: %s", strerror(errno));
        return 2;
    }
    
    size_t encoded_key_len;
    char *encoded_key = EncodeBase64Url(raw_key, sizeof(raw_key), &encoded_key_len);
    mbedtls_platform_zeroize(raw_key, sizeof(raw_key));

    if (!encoded_key) {
        lua_pushnil(L);
        lua_pushfstring(L, "EncodeBase64Url failed: %s", strerror(errno));
        return 2;
    }

    lua_pushfstring(L, "k3.local.%s", encoded_key);
    mbedtls_platform_zeroize(encoded_key, encoded_key_len);
    free(encoded_key);
    return 1;
}

// paseto.v3_public_keygen()
//     └─→ public, secret
//     └─→ nil, error
static int LuaV3PublicKeygen(lua_State *L) {
   
    int mbedtls_ret;
    mbedtls_ecdsa_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    size_t priv_encoded_len = 0;
    char *priv_encoded = NULL;
    char *pub_encoded = NULL;
    char pub_raw[49]; // 1 byte prefix + 48 bytes for P-384
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
    if (mbedtls_ret) goto error_mbedtls;

    mbedtls_ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP384R1,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
    if(mbedtls_ret) goto error_mbedtls;

    // Export compressed public key
    mbedtls_ret = mbedtls_ecp_point_write_binary(&keypair->grp, &keypair->Q,
                                                 MBEDTLS_ECP_PF_COMPRESSED,
                                                 &pub_len,
                                                 (unsigned char *)pub_raw, sizeof(pub_raw));
    if (mbedtls_ret) goto error_mbedtls;

    // Export private scalar
    mbedtls_ret = mbedtls_mpi_write_binary(&keypair->d,
                                           (unsigned char *)priv_raw, sizeof(priv_raw));
    if (mbedtls_ret) goto error_mbedtls;

    // Encode to Base64URL
    priv_encoded = EncodeBase64Url(priv_raw, sizeof(priv_raw), &priv_encoded_len);
    pub_encoded  = EncodeBase64Url(pub_raw, pub_len, NULL);
    mbedtls_platform_zeroize(priv_raw, sizeof(priv_raw)); // wipe raw priv

    if(!priv_encoded || !pub_encoded) {
        lua_pushnil(L);
        lua_pushfstring(L, "EncodeBase64Url failed: %s", strerror(errno));
        goto free_return;
    }

    lua_pushfstring(L, "k3.public.%s", pub_encoded);
    lua_pushfstring(L, "k3.secret.%s", priv_encoded);
    goto free_return;
    
error_mbedtls:
    char errbuf[128];
    mbedtls_strerror(mbedtls_ret, errbuf, sizeof(errbuf));
    lua_pushnil(L);
    lua_pushfstring(L, "keygen failed: %s", errbuf);

free_return:
    if(priv_encoded) {
        mbedtls_platform_zeroize(priv_encoded, priv_encoded_len);
        free(priv_encoded);
    }
    free(pub_encoded);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecdsa_free(&ctx);
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

static const luaL_Reg kLuaPaseto[] = {
    {"v2_local_encrypt",          LuaV2LocalEncrypt},
    {"v2_local_decrypt",          LuaV2LocalDecrypt},
    {"v2_local_keygen",           LuaV2LocalKeygen},

    {"v3_local_encrypt",          LuaV3LocalEncrypt},
    {"v3_local_decrypt",          LuaV3LocalDecrypt},
    {"v3_local_keygen",           LuaV3LocalKeygen},

    {"v3_public_keygen",          LuaV3PublicKeygen},

    {"v2_unauthenticated_footer", LuaV2UnauthenticatedFooter},
    {0},
};

int LuaPaseto(lua_State *L) {
  luaL_newlib(L, kLuaPaseto);
  return 1;
}
