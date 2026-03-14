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

/* Forward-declare our hooks (referenced inside redbean.c via KOKABEAN ifdef) */
static int kokabean_has_handler;
static char *KokabeanOnHttpRequest(void);
static void KokabeanApplyConfig(void);

/* Pull in redbean */
#include "tool/net/redbean.c"

/* ---------- stubs for symbols redbean references even in STATIC mode ---------- */

void lua_repl_lock(void) {}
void lua_repl_unlock(void) {}
void lua_repl_wock(void) {}
void launch_browser(const char *url) { (void)url; }

/* ---------- handler + config storage ---------- */

static kk_function_t kokabean_handler;

/* Deferred config: stored during Koka main_run, applied after RedBean
   processes SetDefaults() + GetOpts() via KokabeanApplyConfig(). */
static char *deferred_brand;
static int deferred_uniprocess = -1;  /* -1 = not set */

/* ---------- helpers ---------- */

/* Create a kk_string_t from a C string (may be NULL → empty string). */
static kk_string_t kk_string_from_cstr(const char *s) {
  kk_context_t* ctx = kk_get_context();
  if (!s) return kk_string_empty();
  return kk_string_alloc_from_utf8(s, ctx);
}

/* Create a kk_string_t from a buffer with known length. */
static kk_string_t kk_string_from_buf(const char *s, size_t n) {
  kk_context_t* ctx = kk_get_context();
  if (!s || !n) return kk_string_empty();
  return kk_string_alloc_from_utf8n((kk_ssize_t)n, s, ctx);
}

/* Borrow a C string from a kk_string_t, returning length.  Caller must
   kk_string_drop() after use. */
static const char* kk_borrow(kk_string_t s, size_t *len) {
  return kk_string_cbuf_borrow(s, len, kk_get_context());
}

/* Format an IP address as "x.x.x.x:port". */
static kk_string_t kk_format_addr(int GetAddr(uint32_t *, uint16_t *)) {
  uint32_t ip;
  uint16_t port;
  char buf[32];
  if (GetAddr(&ip, &port)) return kk_string_empty();
  snprintf(buf, sizeof(buf), "%d.%d.%d.%d:%d",
           (ip >> 24) & 0xff, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff, port);
  return kk_string_from_cstr(buf);
}

/* ---------- bridge: logging ---------- */

kk_unit_t rb_log(kk_string_t msg) {
  kk_context_t* ctx = kk_get_context();
  const char* s = kk_string_cbuf_borrow(msg, NULL, ctx);
  flogf(kLogInfo, "kokabean", -1, NULL, "%s", s);
  kk_string_drop(msg, ctx);
  return kk_Unit;
}

/* ---------- bridge: configuration ---------- */

kk_unit_t rb_program_port(kk_integer_t port) {
  ProgramPort(kk_integer_clamp32(port, kk_get_context()));
  return kk_Unit;
}

kk_unit_t rb_program_addr(kk_string_t addr) {
  kk_context_t* ctx = kk_get_context();
  const char* s = kk_string_cbuf_borrow(addr, NULL, ctx);
  ProgramAddr(s);
  kk_string_drop(addr, ctx);
  return kk_Unit;
}

kk_unit_t rb_program_brand(kk_string_t brand) {
  kk_context_t* ctx = kk_get_context();
  const char* s = kk_string_cbuf_borrow(brand, NULL, ctx);
  free(deferred_brand);
  deferred_brand = strdup(s);
  kk_string_drop(brand, ctx);
  return kk_Unit;
}

kk_unit_t rb_program_timeout(kk_integer_t ms) {
  ProgramTimeout(kk_integer_clamp32(ms, kk_get_context()));
  return kk_Unit;
}

kk_unit_t rb_program_cache(kk_integer_t seconds) {
  ProgramCache(kk_integer_clamp32(seconds, kk_get_context()), NULL);
  return kk_Unit;
}

kk_unit_t rb_program_max_payload_size(kk_integer_t n) {
  ProgramMaxPayloadSize(kk_integer_clamp32(n, kk_get_context()));
  return kk_Unit;
}

kk_unit_t rb_program_uniprocess(void) {
  deferred_uniprocess = 1;
  return kk_Unit;
}

kk_unit_t rb_program_content_type(kk_string_t ext, kk_string_t ct) {
  /* Content type registration uses Lua's registry table in redbean,
     which we don't have.  For now, this is a no-op stub. */
  kk_context_t* ctx = kk_get_context();
  kk_string_drop(ext, ctx);
  kk_string_drop(ct, ctx);
  return kk_Unit;
}

kk_unit_t rb_program_header(kk_string_t header) {
  kk_context_t* ctx = kk_get_context();
  const char* s = kk_string_cbuf_borrow(header, NULL, ctx);
  ProgramHeader(s);
  kk_string_drop(header, ctx);
  return kk_Unit;
}

kk_unit_t rb_program_redirect(kk_integer_t code, kk_string_t src, kk_string_t dst) {
  kk_context_t* ctx = kk_get_context();
  int c = kk_integer_clamp32(code, ctx);
  size_t srclen, dstlen;
  const char* sp = kk_borrow(src, &srclen);
  const char* dp = kk_borrow(dst, &dstlen);
  ProgramRedirect(c, strdup(sp), srclen, strdup(dp), dstlen);
  kk_string_drop(src, ctx);
  kk_string_drop(dst, ctx);
  return kk_Unit;
}

/* ---------- bridge: main hook ---------- */

kk_unit_t rb_on_http_request(kk_function_t handler) {
  kokabean_handler = handler;
  kokabean_has_handler = 1;
  return kk_Unit;
}

/* ---------- bridge: request getters ---------- */

kk_string_t rb_get_method(void) {
  char method[9] = {0};
  WRITE64LE(method, cpm.msg.method);
  return kk_string_from_cstr(method);
}

kk_string_t rb_get_path(void) {
  if (url.path.p)
    return kk_string_from_buf(url.path.p, url.path.n);
  return kk_string_empty();
}

kk_string_t rb_get_url(void) {
  size_t n;
  char *p = EncodeUrl(&url, &n);
  kk_string_t s = kk_string_from_buf(p, n);
  free(p);
  return s;
}

kk_string_t rb_get_host(void) {
  if (url.host.n)
    return kk_string_from_buf(url.host.p, url.host.n);
  char buf[16];
  inet_ntop(AF_INET, &serveraddr->sin_addr.s_addr, buf, sizeof(buf));
  return kk_string_from_cstr(buf);
}

kk_integer_t rb_get_port(void) {
  int i, x = 0;
  for (i = 0; i < url.port.n; ++i)
    x = url.port.p[i] - '0' + x * 10;
  if (!x)
    x = ntohs(serveraddr->sin_port);
  return kk_integer_from_int(x, kk_get_context());
}

kk_string_t rb_get_body(void) {
  return kk_string_from_buf(inbuf.p + hdrsize, payloadlength);
}

kk_string_t rb_get_header(kk_string_t name) {
  kk_context_t* ctx = kk_get_context();
  size_t keylen;
  const char* key = kk_borrow(name, &keylen);
  int h;
  kk_string_t result = kk_string_empty();
  if ((h = GetHttpHeader(key, keylen)) != -1) {
    if (cpm.msg.headers[h].a) {
      result = kk_string_from_buf(
          inbuf.p + cpm.msg.headers[h].a,
          cpm.msg.headers[h].b - cpm.msg.headers[h].a);
    }
  } else {
    size_t i;
    for (i = 0; i < cpm.msg.xheaders.n; ++i) {
      if (SlicesEqualCase(
              key, keylen,
              inbuf.p + cpm.msg.xheaders.p[i].k.a,
              cpm.msg.xheaders.p[i].k.b - cpm.msg.xheaders.p[i].k.a)) {
        result = kk_string_from_buf(
            inbuf.p + cpm.msg.xheaders.p[i].v.a,
            cpm.msg.xheaders.p[i].v.b - cpm.msg.xheaders.p[i].v.a);
        break;
      }
    }
  }
  kk_string_drop(name, ctx);
  return result;
}

kk_string_t rb_get_cookie(kk_string_t name) {
  kk_context_t* ctx = kk_get_context();
  const char* cname = kk_string_cbuf_borrow(name, NULL, ctx);
  char *cookie = 0, *cookietmpl, *cookieval;
  kk_string_t result = kk_string_empty();
  cookietmpl = xasprintf(" %s=", cname);
  if (HasHeader(kHttpCookie)) {
    appends(&cookie, " ");
    appendd(&cookie, HeaderData(kHttpCookie), HeaderLength(kHttpCookie));
  }
  if (cookie && (cookieval = strstr(cookie, cookietmpl))) {
    cookieval += strlen(cookietmpl);
    result = kk_string_from_buf(cookieval, strchrnul(cookieval, ';') - cookieval);
  }
  free(cookietmpl);
  if (cookie) free(cookie);
  kk_string_drop(name, ctx);
  return result;
}

kk_string_t rb_get_param(kk_string_t name) {
  kk_context_t* ctx = kk_get_context();
  size_t n;
  const char* s = kk_borrow(name, &n);
  size_t i;
  kk_string_t result = kk_string_empty();
  for (i = 0; i < url.params.n; ++i) {
    if (SlicesEqual(s, n, url.params.p[i].key.p, url.params.p[i].key.n)) {
      if (url.params.p[i].val.p) {
        result = kk_string_from_buf(url.params.p[i].val.p, url.params.p[i].val.n);
      }
      break;
    }
  }
  kk_string_drop(name, ctx);
  return result;
}

kk_integer_t rb_get_http_version(void) {
  return kk_integer_from_int(cpm.msg.version, kk_get_context());
}

bool rb_is_client_using_ssl(void) {
  return usingssl;
}

kk_string_t rb_get_client_addr(void) {
  return kk_format_addr(GetClientAddr);
}

kk_string_t rb_get_server_addr(void) {
  return kk_format_addr(GetServerAddr);
}

kk_string_t rb_get_remote_addr(void) {
  return kk_format_addr(GetRemoteAddr);
}

/* ---------- bridge: response setters ---------- */

kk_unit_t rb_set_status(kk_integer_t code, kk_string_t reason) {
  kk_context_t* ctx = kk_get_context();
  int c = kk_integer_clamp32(code, ctx);
  const char* r = kk_string_cbuf_borrow(reason, NULL, ctx);
  cpm.luaheaderp = SetStatus(c, r);
  kk_string_drop(reason, ctx);
  return kk_Unit;
}

kk_unit_t rb_set_header(kk_string_t name, kk_string_t value) {
  kk_context_t* ctx = kk_get_context();
  size_t keylen, vallen;
  const char* key = kk_borrow(name, &keylen);
  const char* val = kk_borrow(value, &vallen);
  char *eval;
  int h;

  if (!(eval = EncodeHttpHeaderValue(val, vallen, 0))) {
    kk_string_drop(name, ctx);
    kk_string_drop(value, ctx);
    return kk_Unit;
  }

  char *p = GetLuaResponse();
  h = GetHttpHeader(key, keylen);

  /* Grow header buffer if needed */
  while (p - hdrbuf.p + keylen + 2 + strlen(eval) + 2 + 512 > hdrbuf.n) {
    char *q;
    hdrbuf.n += hdrbuf.n >> 1;
    q = xrealloc(hdrbuf.p, hdrbuf.n);
    cpm.luaheaderp = p = q + (p - hdrbuf.p);
    hdrbuf.p = q;
  }

  switch (h) {
    case kHttpConnection:
      connectionclose = SlicesEqualCase(eval, strlen(eval), "close", 5);
      break;
    case kHttpContentType:
      p = AppendContentType(p, eval);
      break;
    case kHttpReferrerPolicy:
      cpm.referrerpolicy = FreeLater(strdup(eval));
      break;
    case kHttpServer:
      cpm.branded = true;
      p = AppendHeader(p, "Server", eval);
      break;
    case kHttpExpires:
    case kHttpCacheControl:
      cpm.gotcachecontrol = true;
      p = AppendHeader(p, key, eval);
      break;
    case kHttpXContentTypeOptions:
      cpm.gotxcontenttypeoptions = true;
      p = AppendHeader(p, key, eval);
      break;
    default:
      p = AppendHeader(p, key, eval);
      break;
  }
  cpm.luaheaderp = p;
  free(eval);

  kk_string_drop(name, ctx);
  kk_string_drop(value, ctx);
  return kk_Unit;
}

kk_unit_t rb_set_cookie(kk_string_t name, kk_string_t value) {
  kk_context_t* ctx = kk_get_context();
  const char* k = kk_string_cbuf_borrow(name, NULL, ctx);
  const char* v = kk_string_cbuf_borrow(value, NULL, ctx);
  char *buf = xasprintf("%s=%s", k, v);
  char *p = GetLuaResponse();
  p = AppendHeader(p, "Set-Cookie", buf);
  cpm.luaheaderp = p;
  free(buf);
  kk_string_drop(name, ctx);
  kk_string_drop(value, ctx);
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

/* ---------- bridge: serving ---------- */

bool rb_route(kk_string_t host, kk_string_t path) {
  kk_context_t* ctx = kk_get_context();
  size_t hostlen, pathlen;
  const char* h = kk_borrow(host, &hostlen);
  const char* p = kk_borrow(path, &pathlen);
  char *r = Route(h, hostlen, p, pathlen);
  if (r) cpm.luaheaderp = r;
  kk_string_drop(host, ctx);
  kk_string_drop(path, ctx);
  return r != NULL;
}

bool rb_serve_asset(kk_string_t path) {
  kk_context_t* ctx = kk_get_context();
  size_t pathlen;
  const char* p = kk_borrow(path, &pathlen);
  struct Asset *a;
  bool found = false;
  if ((a = GetAsset(p, pathlen)) && !S_ISDIR(GetMode(a))) {
    cpm.luaheaderp = ServeAsset(a, p, pathlen);
    found = true;
  }
  kk_string_drop(path, ctx);
  return found;
}

kk_unit_t rb_serve_error(kk_integer_t code, kk_string_t reason) {
  kk_context_t* ctx = kk_get_context();
  int c = kk_integer_clamp32(code, ctx);
  const char* r = kk_string_cbuf_borrow(reason, NULL, ctx);
  cpm.luaheaderp = ServeError(c, r);
  kk_string_drop(reason, ctx);
  return kk_Unit;
}

kk_unit_t rb_serve_redirect(kk_integer_t code, kk_string_t location) {
  kk_context_t* ctx = kk_get_context();
  int c = kk_integer_clamp32(code, ctx);
  size_t loclen;
  const char* loc = kk_borrow(location, &loclen);
  char *eval;
  if ((eval = EncodeHttpHeaderValue(loc, loclen, 0))) {
    cpm.luaheaderp =
        AppendHeader(SetStatus(c, GetHttpReason(c)), "Location", eval);
    free(eval);
  }
  kk_string_drop(location, ctx);
  return kk_Unit;
}

/* ---------- deferred config ---------- */

static void KokabeanApplyConfig(void) {
  if (deferred_brand) {
    ProgramBrand(deferred_brand);
    free(deferred_brand);
    deferred_brand = NULL;
  }
  if (deferred_uniprocess >= 0) {
    uniprocess = deferred_uniprocess;
  }
}

/* ---------- request handler ---------- */

static char *KokabeanOnHttpRequest(void) {
  kk_context_t* ctx = kk_get_context();
  kk_function_t h = kk_function_dup(kokabean_handler, ctx);
  kk_function_call(kk_unit_t, (kk_function_t, kk_context_t*),
                    h, (h, ctx), ctx);
  return CommitOutput(GetLuaResponse());
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
