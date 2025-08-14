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

/**
 * @fileoverview Paseto (Platform-Agnostic SEcurity TOkens) Lua bindings
 * RFC https://paseto.io/rfc/
 */

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

// paseto.v3_local_encrypt(message, key, [footer], [entropy])
//     └─→ token
//     └─→ nil, error
static int LuaV3LocalEncrypt(lua_State *L) {
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

    char *token = NULL;
    int result = paseto_v3_local_encrypt(
        (const uint8_t *)message, message_len,
        (const uint8_t *)key_str, // placeholder - v3 key parsing not implemented
        (const uint8_t *)footer, footer_len,
        (const uint8_t *)entropy_raw,
        &token
    );

    if (result != 0) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v3_error_message(result));
        return 2;
    }

    lua_pushstring(L, token);
    free(token);
    return 1;
}

// paseto.v3_local_decrypt(token, key, [expected_footer])
//     └─→ message
//     └─→ nil, error
static int LuaV3LocalDecrypt(lua_State *L) {
    size_t expected_footer_len = 0;
    const char *token = luaL_checkstring(L, 1);
    const char *key_str = luaL_checkstring(L, 2);
    const char *expected_footer = NULL;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        expected_footer = luaL_checklstring(L, 3, &expected_footer_len);
    }

    uint8_t *message = NULL;
    size_t message_len = 0;

    int result = paseto_v3_local_decrypt(
        token,
        (const uint8_t *)key_str, // placeholder - v3 key parsing not implemented
        (const uint8_t *)expected_footer, expected_footer_len,
        &message, &message_len
    );

    if (result != 0) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v3_error_message(result));
        return 2;
    }

    lua_pushlstring(L, (const char *)message, message_len);
    free(message);
    return 1;
}

// paseto.v3_local_keygen()
//     └─→ key
//     └─→ nil, error
static int LuaV3LocalKeygen(lua_State *L) {
    char *key = NULL;
    int result = paseto_v3_local_keygen(&key);
    
    if (result != PASETO_V3_ERROR_SUCCESS) {
        lua_pushnil(L);
        lua_pushstring(L, paseto_v3_error_message(result));
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

    uint8_t *footer = NULL;
    size_t footer_len = 0;
    int result = paseto_extract_footer(token, &footer, &footer_len);

    if (result != PASETO_V2_ERROR_SUCCESS || !footer) {
        lua_pushstring(L, "");
        return 1;
    }

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
    {"v2_unauthenticated_footer", LuaV2UnauthenticatedFooter},
    {0},
};

int LuaPaseto(lua_State *L) {
  luaL_newlib(L, kLuaPaseto);
  return 1;
}