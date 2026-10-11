/* ==========================================================================
   CLIPT — functions/api/[[route]].js
   Entire backend in one file: auth, user, admin. Cloudflare Pages Function + D1.
   D1 binding: CLIPT_DB   |   Optional env: JWT_SECRET, SETUP_KEY
   ========================================================================== */

const G = globalThis;
const enc = new TextEncoder();
const SCHEMA_V = '1';
const DAY = 864e5;
const PAGE = 25;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Expose-Headers': 'X-New-Token, Retry-After',
  'Access-Control-Max-Age': '86400'
};

const LIM = {
  free:    { links: 15,  daily: 5,   alias: 1,  create: 2,  api: 60  },
  premium: { links: 500, daily: 100, alias: 50, create: 10, api: 120 }
};
const FREE_EXPIRY_DAYS = 90;
const PLANS = {
  monthly: { usd: 2.99, bdt: 299,  days: 30  },
  yearly:  { usd: 29,   bdt: 2990, days: 365 }
};
const RESERVED = new Set(['admin', 'abmin', 'api', 'login', 'logout', 'signup', 'signin', 'register', 'dashboard', 'pricing', 'legal', 'terms', 'privacy', 'account', 'settings', 'billing', 'support', 'help', 'about', 'contact', 'static', 'assets', 'images', 'index', 'favicon', 'robots', 'sitemap', 'www', 'app', 'clipt', 'null', 'undefined', 'status', 'health']);
const DEFAULTS = {
  registration_open: '1', require_approval: '0', one_device: '1', read_only: '0',
  announcement: '', support_email: '', bkash: '', nagad: '', rocket: '', pay_note: '', blocked_domains: ''
};
const EMAIL_RE = /^[^\s@<>]{1,64}@[^\s@<>]{1,200}\.[^\s@<>]{2,}$/;
const ALIAS_RE = /^[a-z0-9][a-z0-9_-]{1,30}[a-z0-9]$/;

/* ---------- helpers ---------- */
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS, ...extra }
  });
}
function err(msg, status = 400, extra = {}) { return json({ error: msg }, status, extra); }
function tooMany(retry, msg) {
  return json({ error: msg || 'Too many requests. Please slow down.', retry_after: retry }, 429, { 'Retry-After': String(retry) });
}
async function sha256(s) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randHex(n) { return [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join(''); }
function randCode() {
  const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (;;) {
    let s = '';
    const a = crypto.getRandomValues(new Uint8Array(5));
    for (const b of a) s += c[b % 36];
    if (!RESERVED.has(s)) return s;
  }
}
function safeEq(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const hashPw = (pw, salt) => sha256(salt + ':' + pw);
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max);
const normEmail = s => String(s || '').trim().toLowerCase().slice(0, 254);
const todayUTC = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);
const isPrem = u => !!(u && u.plan === 'premium' && u.plan_until > Date.now());

/* ---------- JWT (HMAC-SHA256, hand-rolled) ---------- */
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uStr = s => b64u(enc.encode(s));
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const hmacKey = secret => crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

async function signToken(payload, secret) {
  const h = b64uStr(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64uStr(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(h + '.' + p));
  return h + '.' + p + '.' + b64u(sig);
}
async function verifyToken(token, secret) {
  try {
    const [h, p, s] = String(token).split('.');
    if (!h || !p || !s) return null;
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(s), enc.encode(h + '.' + p));
    if (!ok) return null;
    const pl = JSON.parse(new TextDecoder().decode(unb64u(p)));
    if (!pl.exp || pl.exp < Date.now()) return null;
    return pl;
  } catch { return null; }
}
async function getUser(request, secret) {
  const a = request.headers.get('Authorization') || '';
  if (!a.startsWith('Bearer ')) return null;
  return verifyToken(a.slice(7).trim(), secret);
}
/* JWT payload: { id, email, role, exp, pl, pu }  (pl/pu = plan flag + expiry, so rate limits need no DB read) */
function mkToken(u, secret) {
  return signToken({
    id: u.id, email: u.email, role: u.role,
    pl: u.plan === 'premium' ? 1 : 0, pu: u.plan_until || 0,
    exp: Date.now() + 30 * DAY
  }, secret);
}
const pubUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, plan: u.plan, plan_until: u.plan_until });

async function getSecret(db, env) {
  if (env.JWT_SECRET) return String(env.JWT_SECRET);
  if (G.__sec) return G.__sec;
  let r = await db.prepare("SELECT v FROM settings WHERE k='jwt_secret'").first();
  if (!r) {
    await db.prepare("INSERT OR IGNORE INTO settings(k,v) VALUES('jwt_secret',?)").bind(randHex(32)).run();
    r = await db.prepare("SELECT v FROM settings WHERE k='jwt_secret'").first();
  }
  return (G.__sec = r.v);
}

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

/* ---------- schema ---------- */
const TABLES = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
    plan TEXT NOT NULL DEFAULT 'free', plan_until INTEGER NOT NULL DEFAULT 0,
    is_approved INTEGER NOT NULL DEFAULT 1, is_blocked INTEGER NOT NULL DEFAULT 0,
    active_links INTEGER NOT NULL DEFAULT 0, alias_count INTEGER NOT NULL DEFAULT 0,
    daily_count INTEGER NOT NULL DEFAULT 0, daily_date TEXT NOT NULL DEFAULT '',
    device_id TEXT, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS links (
    code TEXT PRIMARY KEY, user_id INTEGER NOT NULL, url TEXT NOT NULL, created_at INTEGER NOT NULL,
    expires_at INTEGER, is_alias INTEGER NOT NULL DEFAULT 0, counted INTEGER NOT NULL DEFAULT 1,
    clicks INTEGER NOT NULL DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id)) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS link_stats (
    code TEXT NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL, val TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (code, day, kind, val)) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, method TEXT NOT NULL,
    trx_id TEXT NOT NULL UNIQUE, sender TEXT NOT NULL, period TEXT NOT NULL, amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', note TEXT, created_at INTEGER NOT NULL, decided_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id))`,
  `CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
    is_read INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))`,
  `CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS counters (k TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS login_fails (ip TEXT PRIMARY KEY, n INTEGER NOT NULL, reset_at INTEGER NOT NULL)`,
  'CREATE INDEX IF NOT EXISTS idx_links_user ON links(user_id, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_users_device ON users(device_id)',
  'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)',
  'CREATE INDEX IF NOT EXISTS idx_pay_status ON payments(status, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_pay_user ON payments(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read)',
  'CREATE INDEX IF NOT EXISTS idx_lf_reset ON login_fails(reset_at)'
];
/* Safe schema updates: each ALTER is attempted once per schema version; failures (column exists) are ignored. */
const migrations = [
  'ALTER TABLE users ADD COLUMN last_login INTEGER'
];
async function ensureTables(db) {
  try {
    const r = await db.prepare("SELECT v FROM settings WHERE k='schema_v'").first();
    if (r && r.v === SCHEMA_V) return;
  } catch {}
  await db.batch(TABLES.map(s => db.prepare(s)));
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch {}
  }
  await db.prepare("INSERT OR REPLACE INTO settings(k,v) VALUES('schema_v',?)").bind(SCHEMA_V).run();
}

/* ---------- settings / small cached lookups ---------- */
async function getSettings(db) {
  const c = G.__set;
  if (c && Date.now() - c.t < 60000) return c.v;
  const rows = await db.prepare("SELECT k,v FROM settings WHERE k NOT IN ('jwt_secret','schema_v')").all();
  const v = { ...DEFAULTS };
  for (const r of rows.results) if (r.k in DEFAULTS) v[r.k] = r.v;
  G.__set = { t: Date.now(), v };
  return v;
}
async function adminExists(db) {
  if (G.__adm) return true;
  const r = await db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();
  if (r) G.__adm = true;
  return !!r;
}

/* ---------- login throttle (D1-backed, writes only on failure) ---------- */
async function loginGate(db, ip) {
  const r = await db.prepare('SELECT n,reset_at FROM login_fails WHERE ip=?').bind(ip).first();
  const now = Date.now();
  if (r && r.reset_at > now && r.n >= 5) return Math.ceil((r.reset_at - now) / 1000);
  return 0;
}
async function loginFail(db, ip) {
  const now = Date.now(), until = now + 10 * 60 * 1000;
  await db.batch([
    db.prepare(`INSERT INTO login_fails(ip,n,reset_at) VALUES(?1,1,?2)
      ON CONFLICT(ip) DO UPDATE SET n=CASE WHEN reset_at<=?3 THEN 1 ELSE n+1 END,
      reset_at=CASE WHEN reset_at<=?3 THEN ?2 ELSE reset_at END`).bind(ip, until, now),
    db.prepare('DELETE FROM login_fails WHERE reset_at<?').bind(now - DAY)
  ]);
}

/* ---------- URL + alias validation ---------- */
function checkUrl(raw, selfHost, blockedCsv) {
  if (typeof raw !== 'string' || !raw.trim()) return { error: 'Enter a destination URL.' };
  raw = raw.trim();
  if (raw.length > 2048) return { error: 'That URL is too long (max 2048 characters).' };
  if (/[\s\u0000-\u001f]/.test(raw)) return { error: 'The URL contains spaces or invalid characters.' };
  let u;
  try { u = new URL(raw); } catch { return { error: 'That is not a valid URL. Start it with http:// or https://' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { error: 'Only http:// and https:// links are allowed.' };
  if (u.username || u.password) return { error: 'URLs with embedded credentials are not allowed.' };
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!h.includes('.') || h.startsWith('[')) return { error: 'Use a public website address.' };
  if (/^(localhost|.*\.(local|localhost|internal|lan|home|corp))$/.test(h)) return { error: 'Local or private addresses are not allowed.' };
  if (/^(0|10|127)\./.test(h) || /^169\.254\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^192\.168\./.test(h) ||
      /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(h) || /^(22[4-9]|2[3-5]\d)\./.test(h))
    return { error: 'Local or private addresses are not allowed.' };
  if (h === selfHost || h.endsWith('.' + selfHost) || h === 'clipt.pages.dev') return { error: 'You cannot shorten a link that points back to this site.' };
  for (const d of String(blockedCsv || '').split(',')) {
    if (d && (h === d || h.endsWith('.' + d))) return { error: 'This destination domain is not allowed.' };
  }
  return { url: u.href };
}
function parseExpiry(v, now) {
  if (v === null || v === undefined || v === '' || v === 'never') return { val: null };
  const n = Number(v);
  if (!Number.isFinite(n)) return { error: 'Invalid expiry date.' };
  if (n < now + 60e3) return { error: 'The expiry date must be in the future.' };
  if (n > now + 3650 * DAY) return { error: 'The expiry date is too far away (max 10 years).' };
  return { val: Math.floor(n) };
}

/* ---------- quotas: one atomic batch ---------- */
const PREM = "(u.plan='premium' AND u.plan_until>?1)";
const COND = `u.id=?2 AND u.is_blocked=0
  AND u.active_links<(CASE WHEN ${PREM} THEN ${LIM.premium.links} ELSE ${LIM.free.links} END)
  AND (CASE WHEN u.daily_date=?3 THEN u.daily_count ELSE 0 END)<(CASE WHEN ${PREM} THEN ${LIM.premium.daily} ELSE ${LIM.free.daily} END)
  AND (?4=0 OR u.alias_count<(CASE WHEN ${PREM} THEN ${LIM.premium.alias} ELSE ${LIM.free.alias} END))`;

/* Un-count expired links (so they stop using quota) and purge ones expired > 30 days ago. */
async function settle(db, uid, now) {
  const res = await db.batch([
    db.prepare('DELETE FROM link_stats WHERE code IN (SELECT code FROM links WHERE user_id=?1 AND counted=0 AND expires_at IS NOT NULL AND expires_at<?2)').bind(uid, now - 30 * DAY),
    db.prepare('DELETE FROM links WHERE user_id=?1 AND counted=0 AND expires_at IS NOT NULL AND expires_at<?2').bind(uid, now - 30 * DAY),
    db.prepare(`UPDATE users SET
      active_links=MAX(0,active_links-(SELECT COUNT(*) FROM links WHERE user_id=?1 AND counted=1 AND expires_at IS NOT NULL AND expires_at<=?2)),
      alias_count=MAX(0,alias_count-(SELECT COUNT(*) FROM links WHERE user_id=?1 AND counted=1 AND is_alias=1 AND expires_at IS NOT NULL AND expires_at<=?2))
      WHERE id=?1`).bind(uid, now),
    db.prepare('UPDATE links SET counted=0 WHERE user_id=?1 AND counted=1 AND expires_at IS NOT NULL AND expires_at<=?2').bind(uid, now)
  ]);
  return res[3].meta.changes || 0;
}

async function purgeCache(code) {
  try { await caches.default.delete(new Request('https://r.clipt.internal/' + code)); } catch {}
  try { G.__rc && G.__rc.delete(code); } catch {}
}

async function deleteLink(db, code, uid) {
  const w = uid ? 'code=?1 AND user_id=?2' : 'code=?1';
  const a = uid ? [code, uid] : [code];
  const res = await db.batch([
    db.prepare(`UPDATE users SET
      active_links=MAX(0,active_links-COALESCE((SELECT counted FROM links WHERE ${w}),0)),
      alias_count=MAX(0,alias_count-COALESCE((SELECT counted*is_alias FROM links WHERE ${w}),0))
      WHERE id=(SELECT user_id FROM links WHERE ${w})`).bind(...a),
    db.prepare(`DELETE FROM link_stats WHERE code=?1 AND EXISTS (SELECT 1 FROM links WHERE ${w})`).bind(...a),
    db.prepare(`DELETE FROM links WHERE ${w}`).bind(...a)
  ]);
  await purgeCache(code);
  return (res[2].meta.changes || 0) > 0;
}

async function createLink(db, x, user, body) {
  const now = Date.now(), day = todayUTC(now);
  const st = await getSettings(db);
  if (st.read_only === '1') return err('Link creation is paused for maintenance. Please try again soon.', 503);
  const tier = (user.pl === 1 && user.pu > now) ? LIM.premium : LIM.free;
  const r = await rl('create:' + user.id, tier.create, 60);
  if (!r.ok) return tooMany(r.retry, 'You are creating links too quickly. Wait a moment and try again.');

  const chk = checkUrl(body.url, x.host, st.blocked_domains);
  if (chk.error) return err(chk.error, 400);

  let alias = '';
  if (body.alias !== undefined && body.alias !== null && String(body.alias).trim() !== '') {
    alias = String(body.alias).trim().toLowerCase();
    if (!ALIAS_RE.test(alias)) return err('Alias must be 3–32 characters: letters, numbers, hyphen or underscore, starting and ending with a letter or number.', 400);
    if (RESERVED.has(alias)) return err('That alias is reserved. Choose another.', 400);
  }
  const ex = parseExpiry(body.expires_at, now);
  if (ex.error) return err(ex.error, 400);

  const freeExp = now + FREE_EXPIRY_DAYS * DAY;
  const isAlias = alias ? 1 : 0;
  let settled = false;
  for (let attempt = 0; attempt < 6; attempt++) {
    const code = alias || randCode();
    try {
      const res = await db.batch([
        db.prepare(`INSERT INTO links(code,user_id,url,created_at,expires_at,is_alias,counted,clicks)
          SELECT ?5,?2,?6,?1,(CASE WHEN ${PREM} THEN ?7 ELSE ?8 END),?4,1,0 FROM users u WHERE ${COND}
          RETURNING expires_at`).bind(now, user.id, day, isAlias, code, chk.url, ex.val, freeExp),
        db.prepare(`UPDATE users AS u SET
          daily_count=CASE WHEN u.daily_date=?3 THEN u.daily_count+1 ELSE 1 END, daily_date=?3,
          active_links=u.active_links+1, alias_count=u.alias_count+?4 WHERE ${COND}`).bind(now, user.id, day, isAlias)
      ]);
      if (res[1].meta.changes === 1) {
        const row = res[0].results && res[0].results[0];
        return json({ ok: true, code, short: x.origin + '/' + code, url: chk.url, expires_at: row ? row.expires_at : null }, 201);
      }
      // quota refused the insert: find out why (single read, failure path only)
      const u = await db.prepare('SELECT plan,plan_until,active_links,alias_count,daily_count,daily_date,is_blocked FROM users WHERE id=?').bind(user.id).first();
      if (!u) return err('Account not found.', 401);
      if (u.is_blocked) return err('This account has been blocked.', 403);
      const prem = isPrem(u), L = prem ? LIM.premium : LIM.free;
      if (u.active_links >= L.links) {
        if (!settled) { settled = true; if (await settle(db, user.id, now)) { attempt--; continue; } }
        return json({ error: `You have reached your limit of ${L.links} active links.` + (prem ? '' : ' Delete a link or upgrade to Premium.'), upgrade: !prem }, 403);
      }
      const used = u.daily_date === day ? u.daily_count : 0;
      if (used >= L.daily) {
        const reset = Math.ceil((Date.parse(day + 'T00:00:00Z') + DAY - now) / 1000);
        return json({ error: `Daily limit reached (${L.daily} links per day). Resets at 00:00 UTC.` + (prem ? '' : ' Premium allows 100 per day.'), upgrade: !prem, retry_after: reset }, 429, { 'Retry-After': String(reset) });
      }
      if (isAlias && u.alias_count >= L.alias) {
        return json({ error: `You have used all ${L.alias} custom alias${L.alias > 1 ? 'es' : ''} on your plan.` + (prem ? '' : ' Delete one or upgrade to Premium.'), upgrade: !prem }, 403);
      }
      return err('Could not create the link. Please try again.', 409);
    } catch (e) {
      if (/UNIQUE|PRIMARY/i.test(String(e && e.message))) {
        if (alias) return err('That alias is already taken. Try another.', 409);
        continue;
      }
      throw e;
    }
  }
  return err('Could not generate a unique code. Please try again.', 503);
}

/* ---------- AUTH  /api/auth/* ---------- */
async function handleAuth(method, path, body, db, x) {
  const gate = await rl('auth:' + x.ip, 40, 60);
  if (!gate.ok) return tooMany(gate.retry);

  if (method === 'GET' && path === '/auth/config') {
    const st = await getSettings(db);
    const methods = [['bkash', 'bKash'], ['nagad', 'Nagad'], ['rocket', 'Rocket']].filter(([k]) => st[k]).map(([k, n]) => ({ id: k, name: n, number: st[k] }));
    return json({ plans: PLANS, limits: LIM, free_expiry_days: FREE_EXPIRY_DAYS, methods, pay_note: st.pay_note, registration_open: st.registration_open === '1', support_email: st.support_email });
  }

  if (method === 'GET' && path === '/auth/admin-status') {
    const setup = await adminExists(db);
    return json({ setup, keyRequired: !setup && !!x.env.SETUP_KEY });
  }

  if (method === 'POST' && path === '/auth/admin-setup') {
    if (await adminExists(db)) return err('The admin account is already set up.', 409);
    const wait = await loginGate(db, x.ip);
    if (wait) return tooMany(wait, 'Too many attempts. Try again later.');
    if (x.env.SETUP_KEY && !safeEq(await sha256(String(body.key || '')), await sha256(String(x.env.SETUP_KEY)))) {
      await loginFail(db, x.ip);
      return err('Invalid setup key.', 403);
    }
    const email = normEmail(body.email), pw = String(body.password || ''), conf = String(body.confirm || '');
    if (!EMAIL_RE.test(email)) return err('Enter a valid email address.');
    if (pw.length < 10 || pw.length > 72) return err('Password must be 10–72 characters.');
    if (pw !== conf) return err('Passwords do not match.');
    const salt = randHex(16);
    try {
      const r = await db.prepare(`INSERT INTO users (name,email,password,salt,role,is_approved,created_at)
        SELECT 'Admin',?1,?2,?3,'admin',1,?4 WHERE NOT EXISTS (SELECT 1 FROM users WHERE role='admin')`)
        .bind(email, await hashPw(pw, salt), salt, Date.now()).run();
      if (!r.meta.changes) return err('The admin account is already set up.', 409);
    } catch (e) {
      if (/UNIQUE/i.test(String(e.message))) return err('That email is already used by a user account. Use a different email.', 409);
      throw e;
    }
    G.__adm = true;
    const u = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    return json({ token: await mkToken(u, x.secret), user: pubUser(u) }, 201);
  }

  if (method === 'POST' && path === '/auth/signup') {
    const st = await getSettings(db);
    if (st.registration_open !== '1') return err('Sign-ups are currently closed.', 403);
    const s = await rl('signup:' + x.ip, 6, 3600);
    if (!s.ok) return tooMany(s.retry, 'Too many sign-ups from this network. Try again later.');
    const name = clean(body.name, 60), email = normEmail(body.email), pw = String(body.password || '');
    const device = /^[A-Za-z0-9-]{16,64}$/.test(String(body.device || '')) ? String(body.device) : null;
    if (name.length < 2) return err('Enter your name (at least 2 characters).');
    if (!EMAIL_RE.test(email)) return err('Enter a valid email address.');
    if (pw.length < 8 || pw.length > 72) return err('Password must be 8–72 characters.');
    if (st.one_device === '1') {
      if (!device) return err('Device check failed. Reload the page and try again.');
      if (await db.prepare('SELECT id FROM users WHERE device_id=? LIMIT 1').bind(device).first())
        return err('An account already exists on this device.', 409);
    }
    const salt = randHex(16), approved = st.require_approval === '1' ? 0 : 1;
    try {                                                // very first account on a fresh database becomes the approved admin
      await db.prepare(`INSERT INTO users (name,email,password,salt,role,is_approved,device_id,created_at)
        SELECT ?1,?2,?3,?4, CASE WHEN c=0 THEN 'admin' ELSE 'user' END, CASE WHEN c=0 THEN 1 ELSE ?5 END, ?6, ?7
        FROM (SELECT COUNT(*) AS c FROM users)`)
        .bind(name, email, await hashPw(pw, salt), salt, approved, device, Date.now()).run();
    } catch (e) {
      if (/UNIQUE/i.test(String(e.message))) return err('That email is already registered.', 409);
      throw e;
    }
    const u = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if (u.role === 'admin') G.__adm = true;
    if (!u.is_approved) return json({ pending: true, message: 'Account created. An admin must approve it before you can log in.' }, 201);
    return json({ token: await mkToken(u, x.secret), user: pubUser(u) }, 201);
  }

  if (method === 'POST' && (path === '/auth/login' || path === '/auth/admin-login')) {
    const admin = path === '/auth/admin-login';
    const wait = await loginGate(db, x.ip);
    if (wait) return tooMany(wait, 'Too many failed attempts. Try again in a few minutes.');
    const email = normEmail(body.email), pw = String(body.password || '');
    const u = email ? await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first() : null;
    const roleOk = u && (admin ? u.role === 'admin' : u.role === 'user');
    if (!roleOk || !safeEq(await hashPw(pw, u.salt), u.password)) {
      await loginFail(db, x.ip);
      return err('Invalid email or password.', 401);
    }
    if (u.is_blocked) return err('This account has been blocked.', 403);
    if (!u.is_approved) return err('Your account is awaiting admin approval.', 403);
    await db.prepare('UPDATE users SET last_login=? WHERE id=?').bind(Date.now(), u.id).run();
    return json({ token: await mkToken(u, x.secret), user: pubUser(u) });
  }

  return err('Not found', 404);
}

/* ---------- USER  /api/user/* ---------- */
async function overview(db, user, x) {
  const now = Date.now(), today = todayUTC(now);
  const page = Math.max(1, Math.min(200, parseInt(x.q.get('page')) || 1));
  let settled = false, u, rows, unread;
  for (;;) {
    const [ur, lr, nr] = await db.batch([
      db.prepare('SELECT id,name,email,role,plan,plan_until,active_links,alias_count,daily_count,daily_date,is_blocked,created_at FROM users WHERE id=?').bind(user.id),
      db.prepare('SELECT code,url,created_at,expires_at,is_alias,clicks,counted FROM links WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(user.id, PAGE + 1, (page - 1) * PAGE),
      db.prepare('SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND is_read=0').bind(user.id)
    ]);
    u = ur.results[0];
    if (!u) return err('Account not found.', 401);
    if (u.is_blocked) return err('This account has been blocked.', 403);
    rows = lr.results; unread = nr.results[0].c;
    if (!settled && rows.some(r => r.counted === 1 && r.expires_at && r.expires_at <= now)) {
      await settle(db, user.id, now); settled = true; continue;
    }
    break;
  }
  const prem = isPrem(u), L = prem ? LIM.premium : LIM.free;
  if (user.pl !== (u.plan === 'premium' ? 1 : 0) || user.pu !== (u.plan_until || 0)) x.newToken = await mkToken(u, x.secret);
  const st = await getSettings(db);
  const hasMore = rows.length > PAGE;
  return json({
    user: { id: u.id, name: u.name, email: u.email, plan: prem ? 'premium' : 'free', plan_until: u.plan_until, created_at: u.created_at },
    limits: L, free_expiry_days: FREE_EXPIRY_DAYS,
    usage: { active: u.active_links, aliases: u.alias_count, daily: u.daily_date === today ? u.daily_count : 0, resets_at: Date.parse(today + 'T00:00:00Z') + DAY },
    links: rows.slice(0, PAGE).map(r => ({ code: r.code, url: r.url, created_at: r.created_at, expires_at: r.expires_at, is_alias: r.is_alias, clicks: r.clicks, expired: !!(r.expires_at && r.expires_at <= now) })),
    page, hasMore, unread, origin: x.origin,
    announcement: st.announcement, support_email: st.support_email
  });
}

async function handleUser(method, path, body, db, user, x) {
  const now = Date.now();
  let m;
  if (method === 'GET' && path === '/user/overview') return overview(db, user, x);

  if (method === 'POST' && path === '/user/links') return createLink(db, x, user, body);

  if (method === 'DELETE' && (m = path.match(/^\/user\/links\/([a-z0-9_-]{2,32})$/))) {
    const ok = await deleteLink(db, m[1], user.id);
    return ok ? json({ ok: true }) : err('Link not found.', 404);
  }

  if (method === 'GET' && (m = path.match(/^\/user\/links\/([a-z0-9_-]{2,32})\/stats$/))) {
    const l = await db.prepare('SELECT l.code,l.url,l.created_at,l.expires_at,l.clicks,u.plan,u.plan_until FROM links l JOIN users u ON u.id=l.user_id WHERE l.code=? AND l.user_id=?').bind(m[1], user.id).first();
    if (!l) return err('Link not found.', 404);
    const out = { code: l.code, url: l.url, created_at: l.created_at, expires_at: l.expires_at, clicks: l.clicks, detailed: false };
    if (isPrem(l)) {
      const since = todayUTC(now - 29 * DAY);
      const rows = (await db.prepare('SELECT day,kind,val,n FROM link_stats WHERE code=? AND day>=?').bind(l.code, since).all()).results;
      const days = {}, cc = {}, rf = {};
      for (const r of rows) {
        if (r.kind === 't') days[r.day] = r.n;
        else if (r.kind === 'c') cc[r.val] = r.n;
        else if (r.kind === 'r') rf[r.val] = r.n;
      }
      const daily = [];
      for (let i = 29; i >= 0; i--) { const d = todayUTC(now - i * DAY); daily.push({ day: d, n: days[d] || 0 }); }
      const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, n]) => ({ k, n }));
      Object.assign(out, { detailed: true, daily, countries: top(cc), referrers: top(rf) });
    }
    return json(out);
  }

  if (method === 'GET' && path === '/user/notifications') {
    const r = await db.prepare('SELECT id,title,body,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 20').bind(user.id).all();
    return json({ notifications: r.results });
  }
  if (method === 'POST' && path === '/user/notifications/read') {
    await db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0').bind(user.id).run();
    return json({ ok: true });
  }

  if (method === 'PUT' && path === '/user/profile') {
    const name = clean(body.name, 60);
    if (name.length < 2) return err('Enter your name (at least 2 characters).');
    await db.prepare('UPDATE users SET name=? WHERE id=?').bind(name, user.id).run();
    return json({ ok: true, name });
  }
  if (method === 'POST' && path === '/user/password') {
    const cur = String(body.current || ''), pw = String(body.password || '');
    if (pw.length < 8 || pw.length > 72) return err('New password must be 8–72 characters.');
    const wait = await loginGate(db, x.ip);
    if (wait) return tooMany(wait, 'Too many failed attempts. Try again later.');
    const u = await db.prepare('SELECT password,salt FROM users WHERE id=?').bind(user.id).first();
    if (!u || !safeEq(await hashPw(cur, u.salt), u.password)) { await loginFail(db, x.ip); return err('Current password is incorrect.', 403); }
    const salt = randHex(16);
    await db.prepare('UPDATE users SET password=?, salt=? WHERE id=?').bind(await hashPw(pw, salt), salt, user.id).run();
    return json({ ok: true });
  }

  if (method === 'GET' && path === '/user/payments') {
    const r = await db.prepare('SELECT id,method,trx_id,period,amount,status,note,created_at FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 20').bind(user.id).all();
    return json({ payments: r.results });
  }
  if (method === 'POST' && path === '/user/payments') {
    const p = await rl('pay:' + user.id, 6, 3600);
    if (!p.ok) return tooMany(p.retry, 'Too many payment submissions. Try again later.');
    const meth = String(body.method || '').toLowerCase(), period = String(body.period || '');
    const trx = String(body.trx_id || '').trim().toUpperCase(), sender = String(body.sender || '').trim();
    if (!['bkash', 'nagad', 'rocket'].includes(meth)) return err('Choose a payment method.');
    if (!PLANS[period]) return err('Choose monthly or yearly.');
    if (!/^[A-Z0-9]{6,32}$/.test(trx)) return err('Enter the transaction ID exactly as shown in your payment confirmation.');
    if (!/^[0-9+ -]{6,20}$/.test(sender)) return err('Enter the number you paid from.');
    try {
      const r = await db.prepare(`INSERT INTO payments(user_id,method,trx_id,sender,period,amount,status,created_at)
        SELECT ?1,?2,?3,?4,?5,?6,'pending',?7 WHERE NOT EXISTS (SELECT 1 FROM payments WHERE user_id=?1 AND status='pending')`)
        .bind(user.id, meth, trx, sender, period, PLANS[period].bdt, now).run();
      if (!r.meta.changes) return err('You already have a payment waiting for review.', 409);
    } catch (e) {
      if (/UNIQUE/i.test(String(e.message))) return err('That transaction ID was already submitted.', 409);
      throw e;
    }
    return json({ ok: true, message: 'Payment submitted. You will be notified once it is reviewed.' }, 201);
  }

  return err('Not found', 404);
}

/* ---------- ADMIN  /api/admin/* ---------- */
function notifyStmt(db, uid, title, body) {
  return db.prepare('INSERT INTO notifications(user_id,title,body,is_read,created_at) VALUES(?,?,?,0,?)').bind(uid, title, body, Date.now());
}
async function handleAdmin(method, path, body, db, user, x) {
  if (user.role !== 'admin') return err('Forbidden', 403);
  if (!(await db.prepare("SELECT id FROM users WHERE id=? AND role='admin' AND is_blocked=0").bind(user.id).first())) return err('Forbidden', 403);
  const now = Date.now();
  const page = Math.max(1, Math.min(1000, parseInt(x.q.get('page')) || 1)), off = (page - 1) * PAGE;
  let m;

  if (method === 'GET' && path === '/admin/stats') {
    if (G.__ast && now - G.__ast.t < 30000) return json(G.__ast.v);
    const dayStart = Date.parse(todayUTC(now) + 'T00:00:00Z');
    const [a, p, c] = await db.batch([
      db.prepare(`SELECT COUNT(*) AS users, COALESCE(SUM(plan='premium' AND plan_until>?1),0) AS premium, COALESCE(SUM(created_at>=?2),0) AS today,
        COALESCE(SUM(is_blocked),0) AS blocked, COALESCE(SUM(is_approved=0),0) AS unapproved, COALESCE(SUM(active_links),0) AS links FROM users WHERE role='user'`).bind(now, dayStart),
      db.prepare("SELECT COALESCE(SUM(status='pending'),0) AS pending, COALESCE(SUM(CASE WHEN status='approved' THEN amount ELSE 0 END),0) AS revenue FROM payments"),
      db.prepare("SELECT v FROM counters WHERE k='clicks'")
    ]);
    const v = { ...a.results[0], pending_payments: p.results[0].pending, revenue: p.results[0].revenue, clicks: c.results[0] ? c.results[0].v : 0 };
    G.__ast = { t: now, v };
    return json(v);
  }

  if (method === 'GET' && path === '/admin/users') {
    const q = clean(x.q.get('q'), 60), f = x.q.get('filter') || 'all';
    let where = "role='user'"; const args = [];
    if (q) { const like = '%' + q.replace(/[%_\\]/g, '') + '%'; where += ' AND (email LIKE ? OR name LIKE ?)'; args.push(like, like); }
    if (f === 'premium') { where += " AND plan='premium' AND plan_until>?"; args.push(now); }
    else if (f === 'pending') where += ' AND is_approved=0';
    else if (f === 'blocked') where += ' AND is_blocked=1';
    const r = await db.prepare(`SELECT id,name,email,plan,plan_until,is_approved,is_blocked,active_links,alias_count,created_at,last_login FROM users WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).bind(...args, PAGE + 1, off).all();
    return json({ users: r.results.slice(0, PAGE), hasMore: r.results.length > PAGE, page });
  }

  if ((m = path.match(/^\/admin\/users\/(\d+)\/(block|approve|plan|password|notify)$/)) && method === 'POST') {
    const id = +m[1], act = m[2];
    const t = await db.prepare("SELECT id,plan_until FROM users WHERE id=? AND role='user'").bind(id).first();
    if (!t) return err('User not found.', 404);
    if (act === 'block') {
      await db.prepare('UPDATE users SET is_blocked=? WHERE id=?').bind(body.blocked ? 1 : 0, id).run();
      return json({ ok: true });
    }
    if (act === 'approve') {
      await db.batch([db.prepare('UPDATE users SET is_approved=1 WHERE id=?').bind(id), notifyStmt(db, id, 'Account approved', 'Your account has been approved. Welcome to Clipt.')]);
      return json({ ok: true });
    }
    if (act === 'plan') {
      if (body.plan === 'free') {
        await db.batch([db.prepare("UPDATE users SET plan='free', plan_until=0 WHERE id=?").bind(id), notifyStmt(db, id, 'Plan changed', 'Your account is now on the Free plan.')]);
        return json({ ok: true });
      }
      const days = Math.floor(Number(body.days));
      if (body.plan !== 'premium' || !(days >= 1 && days <= 3650)) return err('Choose Premium and a duration of 1–3650 days.');
      const until = Math.max(t.plan_until || 0, now) + days * DAY;
      await db.batch([db.prepare("UPDATE users SET plan='premium', plan_until=? WHERE id=?").bind(until, id), notifyStmt(db, id, 'Premium activated', `Premium is active until ${todayUTC(until)}.`)]);
      return json({ ok: true, plan_until: until });
    }
    if (act === 'password') {
      const pw = String(body.password || '');
      if (pw.length < 8 || pw.length > 72) return err('Password must be 8–72 characters.');
      const salt = randHex(16);
      await db.prepare('UPDATE users SET password=?, salt=? WHERE id=?').bind(await hashPw(pw, salt), salt, id).run();
      return json({ ok: true });
    }
    if (act === 'notify') {
      const title = clean(body.title, 80), msg = clean(body.body, 500);
      if (!title) return err('Enter a title.');
      await notifyStmt(db, id, title, msg).run();
      return json({ ok: true });
    }
  }

  if (method === 'DELETE' && (m = path.match(/^\/admin\/users\/(\d+)$/))) {
    const id = +m[1];
    await db.batch([
      db.prepare('DELETE FROM link_stats WHERE code IN (SELECT code FROM links WHERE user_id=?1)').bind(id),
      db.prepare('DELETE FROM links WHERE user_id=?1').bind(id),
      db.prepare('DELETE FROM notifications WHERE user_id=?1').bind(id),
      db.prepare('DELETE FROM payments WHERE user_id=?1').bind(id),
      db.prepare("DELETE FROM users WHERE id=?1 AND role='user'").bind(id)
    ]);
    return json({ ok: true });
  }

  if (method === 'GET' && path === '/admin/links') {
    const q = String(x.q.get('q') || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 32), uid = parseInt(x.q.get('user')) || 0;
    const cols = 'code,url,user_id,created_at,expires_at,clicks,is_alias';
    let r;
    if (uid) r = await db.prepare(`SELECT ${cols} FROM links WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(uid, PAGE + 1, off).all();
    else if (q) {
      const hi = q.slice(0, -1) + String.fromCharCode(q.charCodeAt(q.length - 1) + 1);
      r = await db.prepare(`SELECT ${cols} FROM links WHERE code>=? AND code<? ORDER BY code LIMIT ? OFFSET ?`).bind(q, hi, PAGE + 1, off).all();
    } else return json({ links: [], hasMore: false, page, hint: true });
    return json({ links: r.results.slice(0, PAGE), hasMore: r.results.length > PAGE, page });
  }
  if (method === 'DELETE' && (m = path.match(/^\/admin\/links\/([a-z0-9_-]{2,32})$/))) {
    return (await deleteLink(db, m[1], 0)) ? json({ ok: true }) : err('Link not found.', 404);
  }

  if (method === 'GET' && path === '/admin/payments') {
    const f = x.q.get('status') || 'pending';
    const w = ['pending', 'approved', 'rejected'].includes(f) ? 'WHERE p.status=?' : '';
    const args = w ? [f] : [];
    const r = await db.prepare(`SELECT p.id,p.user_id,p.method,p.trx_id,p.sender,p.period,p.amount,p.status,p.note,p.created_at,u.email,u.name FROM payments p JOIN users u ON u.id=p.user_id ${w} ORDER BY p.created_at DESC LIMIT ? OFFSET ?`).bind(...args, PAGE + 1, off).all();
    return json({ payments: r.results.slice(0, PAGE), hasMore: r.results.length > PAGE, page });
  }
  if (method === 'POST' && (m = path.match(/^\/admin\/payments\/(\d+)\/(approve|reject)$/))) {
    const id = +m[1];
    if (m[2] === 'approve') {
      const pay = await db.prepare("SELECT period FROM payments WHERE id=? AND status='pending'").bind(id).first();
      if (!pay) return err('Payment not found or already reviewed.', 404);
      const ms = PLANS[pay.period].days * DAY;
      const res = await db.batch([
        db.prepare("UPDATE payments SET status='approved', decided_at=?2 WHERE id=?1 AND status='pending'").bind(id, now),
        db.prepare(`UPDATE users SET plan='premium', plan_until=MAX(plan_until,?3)+?4
          WHERE id=(SELECT user_id FROM payments WHERE id=?1 AND status='approved' AND decided_at=?2)`).bind(id, now, now, ms),
        db.prepare(`INSERT INTO notifications(user_id,title,body,is_read,created_at)
          SELECT user_id,'Payment approved','Premium is now active on your account. Thank you!',0,?2 FROM payments WHERE id=?1 AND status='approved' AND decided_at=?2`).bind(id, now)
      ]);
      if (!res[0].meta.changes) return err('Payment was already reviewed.', 409);
      return json({ ok: true });
    }
    const note = clean(body.note, 200);
    const res = await db.batch([
      db.prepare("UPDATE payments SET status='rejected', note=?3, decided_at=?2 WHERE id=?1 AND status='pending'").bind(id, now, note),
      db.prepare(`INSERT INTO notifications(user_id,title,body,is_read,created_at)
        SELECT user_id,'Payment not approved',?3,0,?2 FROM payments WHERE id=?1 AND status='rejected' AND decided_at=?2`).bind(id, now, note || 'We could not verify this payment. Please check the transaction ID and submit again.')
    ]);
    if (!res[0].meta.changes) return err('Payment not found or already reviewed.', 404);
    return json({ ok: true });
  }

  if (method === 'GET' && path === '/admin/settings') {
    const st = await getSettings(db);
    return json({ settings: st });
  }
  if (method === 'PUT' && path === '/admin/settings') {
    const inc = body.settings || {}, rows = [];
    for (const k of Object.keys(DEFAULTS)) {
      if (!(k in inc)) continue;
      let v = inc[k];
      if (['registration_open', 'require_approval', 'one_device', 'read_only'].includes(k)) v = (v === true || v === '1' || v === 1) ? '1' : '0';
      else if (k === 'blocked_domains') v = String(v || '').toLowerCase().split(/[\s,;]+/).map(d => d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '')).filter(Boolean).slice(0, 200).join(',');
      else if (k === 'announcement' || k === 'pay_note') v = clean(v, 300);
      else if (k === 'support_email') { v = normEmail(v); if (v && !EMAIL_RE.test(v)) return err('Enter a valid support email or leave it empty.'); }
      else v = clean(v, 30);
      rows.push(db.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)').bind(k, v));
    }
    if (rows.length) await db.batch(rows);
    G.__set = null;
    return json({ ok: true, settings: await getSettings(db) });
  }

  if (method === 'POST' && path === '/admin/account') {
    const u = await db.prepare('SELECT * FROM users WHERE id=?').bind(user.id).first();
    const wait = await loginGate(db, x.ip);
    if (wait) return tooMany(wait, 'Too many failed attempts. Try again later.');
    if (!safeEq(await hashPw(String(body.current || ''), u.salt), u.password)) { await loginFail(db, x.ip); return err('Current password is incorrect.', 403); }
    const email = body.email ? normEmail(body.email) : u.email, pw = String(body.password || '');
    if (!EMAIL_RE.test(email)) return err('Enter a valid email address.');
    let hash = u.password, salt = u.salt;
    if (pw) {
      if (pw.length < 10 || pw.length > 72) return err('New password must be 10–72 characters.');
      if (pw !== String(body.confirm || '')) return err('New passwords do not match.');
      salt = randHex(16); hash = await hashPw(pw, salt);
    }
    try { await db.prepare('UPDATE users SET email=?, password=?, salt=? WHERE id=?').bind(email, hash, salt, u.id).run(); }
    catch (e) { if (/UNIQUE/i.test(String(e.message))) return err('That email is already in use.', 409); throw e; }
    const nu = { ...u, email };
    return json({ ok: true, token: await mkToken(nu, x.secret), user: pubUser(nu) });
  }

  return err('Not found', 404);
}

/* ---------- main ---------- */
export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  try {
    const db = env.CLIPT_DB;
    if (!db) return err('Database binding CLIPT_DB is not configured.', 500);
    if (!G.__tablesReady) {
      await ensureTables(db);
      G.__tablesReady = true;
    }
    const url = new URL(request.url);
    let path = url.pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
    const method = request.method;
    let body = {};
    if (method !== 'GET' && method !== 'HEAD') { try { body = await request.json(); } catch { body = {}; } }
    if (!body || typeof body !== 'object') body = {};

    const secret = await getSecret(db, env);
    const x = {
      request, env, ctx: context, secret, newToken: null, q: url.searchParams,
      ip: request.headers.get('CF-Connecting-IP') || 'unknown', origin: url.origin, host: url.hostname.toLowerCase()
    };

    let res;
    if (path.startsWith('/auth/')) {
      res = await handleAuth(method, path, body, db, x);
    } else if (path.startsWith('/user/') || path.startsWith('/admin/')) {
      const user = await getUser(request, secret);
      if (!user) return err('Please log in again.', 401);
      const want = path.startsWith('/admin/') ? 'admin' : 'user';
      if (user.role !== want) return err('Forbidden', 403);
      if (user.exp - Date.now() < 15 * DAY) x.newToken = await signToken({ ...user, exp: Date.now() + 30 * DAY }, secret);
      const prem = user.pl === 1 && user.pu > Date.now();
      const lim = await rl('api:' + user.id, want === 'admin' ? 240 : (prem ? LIM.premium.api : LIM.free.api), 60);
      if (!lim.ok) return tooMany(lim.retry, 'Too many requests. Please wait a moment.');
      res = want === 'admin' ? await handleAdmin(method, path, body, db, user, x) : await handleUser(method, path, body, db, user, x);
    } else {
      res = err('Not found', 404);
    }
    if (x.newToken) res.headers.set('X-New-Token', x.newToken);
    return res;
  } catch (e) {
    console.error('API error:', e && e.message ? e.message : e);
    return err('Something went wrong on our side. Please try again.', 500);
  }
}
