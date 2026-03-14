/* Wrapper: include real limits.h, then undef INT128 macros that
   cosmopolitan defines as C expressions (casts) — they break kklib's
   #if preprocessor checks.  We're on 64-bit; 128-bit branches are
   never taken. */
#include_next <limits.h>

#undef INT128_MAX
#undef INT128_MIN
#undef UINT128_MAX
#undef UINT128_MIN
