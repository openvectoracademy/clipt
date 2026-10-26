/* ==========================================================================
   CLIPT — functions/[code].js
   Handles https://clipt.pages.dev/{code}
   Redirect path costs 0 D1 reads on a cache hit, 2 row reads on a miss.
   Click counting is batched (never one D1 write per redirect at high traffic).
   ========================================================================== */

const G = globalThis;
const RESERVED = new Set(['admin', 'abmin', 'api', 'login', 'logout', 'signup', 'signin', 'register', 'dashboard', 'pricing', 'legal', 'terms', 'privacy', 'account', 'settings', 'billing', 'support', 'help', 'about', 'contact', 'static', 'assets', 'images', 'index', 'favicon', 'robots', 'sitemap', 'www', 'app', 'clipt', 'null', 'undefined', 'status', 'health', 'p', 'poll', 'polls']);
const CODE_RE = /^[a-z0-9][a-z0-9_-]{1,30}[a-z0-9]$/;
const BOT_RE = /bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|telegram|curl|wget|python|java|go-http|headless|monitor|uptime|scanner/i;
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' };

/* Best-effort shared rate limiter: per-isolate memory + Cache API counter (per data center). */
async function rl(key, limit, win, peek) {
  const now = Date.now(), b = Math.floor(now / (win * 1000)), k = key + ':' + b;
  const M = G.__rl || (G.__rl = new Map());
  if (M.size > 3000) { for (const x of [...M.keys()]) if (!x.endsWith(':' + b)) M.delete(x); }
  let n = M.get(k) || 0, req = null;
  try {
    req = new Request('https://rl.clipt.internal/' + encodeURIComponent(k));
    const r = await caches.default.match(req);
    if (r) n = Math.max(n, parseInt(await r.text(), 10) || 0);
  } catch { req = null; }
  const retry = Math.max(1, Math.ceil(((b + 1) * win * 1000 - now) / 1000));
  if (peek) return { ok: n < limit, retry, n };
  n++; M.set(k, n);
  if (req) { try { await caches.default.put(req, new Response(String(n), { headers: { 'Cache-Control': 'max-age=' + (win + 1) } })); } catch {} }
  return { ok: n <= limit, retry, n };
}

const LOOKUP_SQL = `SELECT l.url AS url, l.expires_at AS e,
  CASE WHEN u.plan='premium' AND u.plan_until>?2 THEN 1 ELSE 0 END AS d, u.is_blocked AS b
  FROM links l JOIN users u ON u.id=l.user_id WHERE l.code=?1`;

function page(status, title, msg, extra = {}) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${title} · Clipt</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#05080f;color:#f0f4f8;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;padding:24px}
main{max-width:420px;text-align:center}.c{font:600 64px/1 Georgia,'Times New Roman',serif;color:#00d4aa;margin:0 0 12px}h1{font:600 26px/1.2 Georgia,serif;margin:0 0 10px}p{color:#a0adb8;margin:0 0 22px;line-height:1.55}
a{display:inline-block;background:#00d4aa;color:#04110d;font-weight:700;text-decoration:none;padding:11px 20px;border-radius:9px}</style></head><body><main><div class="c">${status}</div><h1>${title}</h1><p>${msg}</p><a href="/">Go to Clipt</a></main></body></html>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SEC, ...extra } });
}

async function lookup(code, env) {
  const now = Date.now();
  const M = G.__rc || (G.__rc = new Map());
  const hit = M.get(code);
  if (hit && hit.t > now) return hit.v;
  const key = new Request('https://r.clipt.internal/' + code);
  try {
    const c = await caches.default.match(key);
    if (c) { const v = await c.json(); M.set(code, { v, t: now + 120e3 }); return v; }
  } catch {}
  const row = await env.CLIPT_DB.prepare(LOOKUP_SQL).bind(code, now).first();
  const v = row && !row.b ? { u: row.url, e: row.e, d: row.d } : { n: 1 };
  let ttl = 600;                                        // seconds
  if (v.n) ttl = 30;                                    // negative cache: alias guessing never hits D1
  else if (v.e && v.e <= now) ttl = 300;                // already expired (served as 410)
  else if (v.e) ttl = Math.max(1, Math.min(600, Math.floor((v.e - now) / 1000)));
  try {
    await caches.default.put(key, new Response(JSON.stringify(v), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=' + ttl } }));
  } catch {}
  if (M.size > 500) { let i = 0; for (const k of [...M.keys()]) { if (i++ < 250) M.delete(k); } }
  M.set(code, { v, t: now + Math.min(ttl, 120) * 1000 });
  return v;
}

/* Batched click tracking: buffer in memory, flush as ONE db.batch every 10 clicks or 30 s. */
function track(ctx, env, code, v, request) {
  const ua = request.headers.get('User-Agent') || '';
  if (!ua || BOT_RE.test(ua)) return;
  const now = Date.now(), day = new Date(now).toISOString().slice(0, 10);
  const B = G.__clk || (G.__clk = { n: 0, t: new Map(), s: new Map() });
  B.n++; B.t.set(code, (B.t.get(code) || 0) + 1);
  if (v.d) {                                            // detailed analytics: premium owners only
    const cc = (request.cf && request.cf.country) || 'XX';
    let ref = 'direct';
    try { const r = request.headers.get('Referer'); if (r) ref = new URL(r).hostname.replace(/^www\./, '').slice(0, 60) || 'direct'; } catch {}
    for (const [kind, val, d] of [['t', '', day], ['c', cc, 'all'], ['r', ref, 'all']]) {
      const k = [code, d, kind, val].join('\u0001');
      B.s.set(k, (B.s.get(k) || 0) + 1);
    }
  }
  if (B.n >= 10 || now - (G.__clkT || 0) >= 30000) ctx.waitUntil(flush(env.CLIPT_DB));
  else if (!G.__clkP) {                                  // low traffic: make sure the tail of the buffer is never lost
    G.__clkP = true;
    const wait = Math.min(25000, Math.max(1000, 30000 - (now - (G.__clkT || 0))));
    ctx.waitUntil(new Promise(r => setTimeout(r, wait)).then(() => { G.__clkP = false; return flush(env.CLIPT_DB); }));
  }
}
async function flush(db) {
  const B = G.__clk;
  if (!B || !B.n) return;
  G.__clk = null; G.__clkT = Date.now();
  const st = [];
  let total = 0;
  for (const [code, n] of B.t) { total += n; st.push(db.prepare('UPDATE links SET clicks=clicks+?1 WHERE code=?2').bind(n, code)); }
  for (const [k, n] of B.s) {
    const [code, day, kind, val] = k.split('\u0001');
    st.push(db.prepare(`INSERT INTO link_stats(code,day,kind,val,n) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS (SELECT 1 FROM links WHERE code=?1)
      ON CONFLICT(code,day,kind,val) DO UPDATE SET n=n+excluded.n`).bind(code, day, kind, val, n));
  }
  st.push(db.prepare("INSERT INTO counters(k,v) VALUES('clicks',?1) ON CONFLICT(k) DO UPDATE SET v=v+excluded.v").bind(total));
  try { await db.batch(st); } catch (e) { console.error('click flush failed', e && e.message); }
}

export async function onRequest(ctx) {
  const { request, env, params } = ctx;
  if (request.method !== 'GET' && request.method !== 'HEAD') return page(405, 'Method not allowed', 'Short links only support GET requests.', { Allow: 'GET, HEAD' });
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const code = String(params.code || '').toLowerCase();

  if (RESERVED.has(code)) return ctx.next();

  const blocked = await rl('bad:' + ip, 10, 60, true);                 // too many invalid attempts? stop before touching D1
  if (!blocked.ok) return page(429, 'Too many attempts', 'Too many invalid short links from your network. Try again in a minute.', { 'Retry-After': String(blocked.retry) });

  const miss = async () => {
    const r = await rl('bad:' + ip, 10, 60);
    return r.ok ? page(404, 'Link not found', 'This short link does not exist or was removed.')
                : page(429, 'Too many attempts', 'Too many invalid short links from your network. Try again in a minute.', { 'Retry-After': String(r.retry) });
  };
  if (!CODE_RE.test(code)) return miss();

  let v;
  try { v = await lookup(code, env); }
  catch (e) { console.error('lookup failed', e && e.message); return page(503, 'Temporarily unavailable', 'We could not load this link right now. Please try again shortly.', { 'Retry-After': '30' }); }

  if (v.n) return miss();
  if (v.e && v.e <= Date.now()) return page(410, 'Link expired', 'This short link has expired and is no longer available.');
  if (!/^https?:\/\//i.test(v.u)) return miss();                       // never redirect to non-http(s) schemes

  if (request.method === 'GET') track(ctx, env, code, v, request);
  return new Response(null, { status: 302, headers: { Location: v.u, ...SEC } });
}
