/*---------------------------------------------------------------------------
  kokabean — redbean without Lua, with Koka algebraic effects.

  Follows the redbean-static.c pattern: define preprocessor flags, include
  redbean.c, then define bridge functions AFTER the include so they can
  access redbean's static internals (cpm.outbuf, SetStatus, etc.).
---------------------------------------------------------------------------*/

#define STATIC
#define KOKABEAN
#define REDBEAN "kokabean"

/* kklib — Koka runtime.  Compiled with -I tool/net/kokabean BEFORE the
   system include path so our limits.h wrapper intercepts cosmopolitan's
   INT128_MAX (a C expression) before kklib's #if checks see it. */
#include "kklib.h"

/* Forward-declare Koka-generated entry points */
extern void main_init(kk_context_t* ctx);
extern void main_run(kk_context_t* ctx);
extern void main_done(kk_context_t* ctx);

/* Forward-declare our hook (referenced inside redbean.c via KOKABEAN ifdef) */
static int kokabean_has_handler;
static char *KokabeanOnHttpRequest(void);

/* Pull in redbean */
#include "tool/net/redbean.c"

/* ---------- stubs for symbols redbean references even in STATIC mode ---------- */

void lua_repl_lock(void) {}
void lua_repl_unlock(void) {}
void lua_repl_wock(void) {}
void launch_browser(const char *url) { (void)url; }

/* ---------- handler storage ---------- */

static kk_function_t kokabean_handler;

/* ---------- bridge functions ---------- */

kk_unit_t rb_log(kk_string_t msg) {
  kk_context_t* ctx = kk_get_context();
  const char* s = kk_string_cbuf_borrow(msg, NULL, ctx);
  flogf(kLogInfo, "kokabean", -1, NULL, "%s", s);
  kk_string_drop(msg, ctx);
  return kk_Unit;
}

kk_unit_t rb_write(kk_string_t s) {
  kk_context_t* ctx = kk_get_context();
  size_t len;
  const char* buf = kk_string_cbuf_borrow(s, &len, ctx);
  appendd(&cpm.outbuf, buf, len);
  kk_string_drop(s, ctx);
  return kk_Unit;
}

kk_unit_t rb_on_http_request(kk_function_t handler) {
  kokabean_handler = handler;
  kokabean_has_handler = 1;
  return kk_Unit;
}

static char *KokabeanOnHttpRequest(void) {
  kk_context_t* ctx = kk_get_context();
  kk_function_t h = kk_function_dup(kokabean_handler, ctx);
  kk_function_call(kk_unit_t, (kk_function_t, kk_context_t*),
                    h, (h, ctx), ctx);
  return CommitOutput(SetStatus(200, "OK"));
}

/* ---------- entry point ---------- */

int main(int argc, char *argv[]) {
  kk_context_t* ctx = kk_main_start(argc, argv);
  main_init(ctx);
  main_run(ctx);
  /* After main_run, the Koka handler is registered. Now start redbean. */
  RedBean(argc, argv);
  main_done(ctx);
  kk_main_end(ctx);
  return 0;
}
