/* ==========================================================================
   CLIPT — functions/p/[id].js
   Public poll page:  https://clipt.pages.dev/p/x58op
   Server-renders the head (title + link-preview tags for WhatsApp / Facebook / X)
   and embeds the poll, so the page paints instantly. Voting goes through /api/public/polls/*.
   D1 binding: CLIPT_DB
   ========================================================================== */

const G = globalThis;
const POLL_ID_RE = /^[a-z0-9]{5}$/;
const POLL_COLORS = ['#3b3bf0', '#0f9d6e', '#e11d48', '#b45309', '#0284c7', '#7c3aed', '#334155'];

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

/* Same payload + cache key as /api/public/polls/:id, so page views and API calls share one cached read. */
async function loadPoll(db, id) {
  const key = new Request('https://pp.clipt.internal/' + id);
  try { const c = await caches.default.match(key); if (c) return await c.json(); } catch {}
  const [pr, orr, sr] = await db.batch([
    db.prepare(`SELECT p.title,p.description,p.multiple,p.color,p.ends_at,p.closed,p.blocked,p.voters,p.created_at,u.is_blocked AS ub
      FROM polls p JOIN users u ON u.id=p.user_id WHERE p.id=?`).bind(id),
    db.prepare('SELECT idx,text,votes FROM poll_options WHERE poll_id=? ORDER BY idx').bind(id),
    db.prepare("SELECT v FROM settings WHERE k='support_email'")
  ]);
  const p = pr.results[0];
  let v, ttl = 5;
  if (!p) { v = { gone: 1 }; ttl = 30; }
  else if (p.blocked || p.ub) { v = { gone: 1, removed: 1 }; ttl = 30; }
  else v = {
    id, title: p.title, description: p.description, multiple: !!p.multiple, color: p.color, ends_at: p.ends_at,
    closed: !!p.closed, voters: p.voters, created_at: p.created_at,
    options: orr.results.map(o => ({ id: o.idx, text: o.text, votes: o.votes })),
    support: (sr.results[0] && sr.results[0].v) || ''
  };
  try { await caches.default.put(key, new Response(JSON.stringify(v), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=' + ttl } })); } catch {}
  return v;
}

const pollOver = v => !!(v.closed || (v.ends_at && v.ends_at <= Date.now()));
function hidePoll(v) {
  if (!v || v.gone || pollOver(v)) return v;
  return { ...v, hidden: true, voters: 0, options: v.options.map(o => ({ id: o.id, text: o.text })) };
}
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, '0')).join('');

/* ---------- styles ---------- */
const CSS = `
:root{--bg:#f8f8f6;--surface:#fff;--surface2:#f1f1ed;--border:rgba(20,24,27,.1);--border2:rgba(20,24,27,.22);--ink:#14181b;--gray:#5c646b;--gray2:#3a4147;--green:#1f7a45;--green-dim:rgba(31,122,69,.1);--red:#c4152b;--hover:rgba(20,24,27,.06);--pf:var(--pa);--shadow:0 1px 2px rgba(20,24,27,.04),0 18px 48px -18px rgba(20,24,27,.18)}
:root[data-theme=dark]{--bg:#0d0f11;--surface:#171a1e;--surface2:#1f2328;--border:rgba(255,255,255,.09);--border2:rgba(255,255,255,.2);--ink:#f2f3f1;--gray:#99a1a8;--gray2:#c3c8cc;--green:#4cd387;--green-dim:rgba(76,211,135,.13);--red:#ff6b7d;--hover:rgba(255,255,255,.07);--shadow:0 1px 2px rgba(0,0,0,.4),0 18px 48px -18px rgba(0,0,0,.7)}
@supports (color:color-mix(in srgb,red,blue)){:root[data-theme=dark]{--pf:color-mix(in srgb,var(--pa) 62%,#fff)}}
*{box-sizing:border-box;margin:0}
html{-webkit-text-size-adjust:100%}
body{min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:400 16px/1.6 "Schibsted Grotesk",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
@supports (color:color-mix(in srgb,red,blue)){body{background:radial-gradient(900px 420px at 50% -150px,color-mix(in srgb,var(--pf) 17%,transparent),transparent 72%),var(--bg)}}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
a{color:inherit}
.hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;max-width:720px;width:100%;margin:0 auto;padding:18px 20px}
.logo{display:flex;align-items:center;gap:10px;text-decoration:none;font-weight:700;font-size:21px;letter-spacing:-.04em}
.logo img{width:30px;height:30px;border-radius:8px}
.hdr-r{display:flex;align-items:center;gap:8px}
.ib{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;color:var(--gray2)}
.ib:hover{background:var(--hover)}
.ib .sun{display:none}:root[data-theme=dark] .ib .sun{display:block}:root[data-theme=dark] .ib .moon{display:none}
.cta{display:inline-flex;align-items:center;min-height:40px;padding:0 16px;border-radius:10px;border:1px solid var(--border2);font-weight:600;font-size:14px;text-decoration:none}
.cta:hover{background:var(--hover)}
main{flex:1;width:100%;max-width:720px;margin:0 auto;padding:8px 20px 40px}
.card{background:var(--surface);border:1.5px dashed var(--border2);border-radius:22px;padding:34px 34px 28px;box-shadow:var(--shadow);animation:rise .45s cubic-bezier(.2,.8,.2,1)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.top{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px;font-size:13.5px}
.pill{display:inline-flex;align-items:center;gap:7px;padding:4px 11px 4px 9px;border-radius:99px;font-weight:600;font-size:12.5px}
.pill.live{background:var(--green-dim);color:var(--green)}
.pill.closed{background:var(--surface2);color:var(--gray2)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.live .dot{animation:pulse 1.8s ease-out infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(31,160,90,.5)}100%{box-shadow:0 0 0 7px rgba(31,160,90,0)}}
.muted{color:var(--gray)}
h1{font-weight:700;font-size:clamp(25px,5.2vw,36px);line-height:1.12;letter-spacing:-.03em;overflow-wrap:anywhere}
.desc{color:var(--gray2);margin-top:10px;overflow-wrap:anywhere;white-space:pre-line}
.hint{margin:24px 0 12px;font-size:13.5px;font-weight:600;color:var(--gray)}
.opts{display:grid;gap:10px}
.opt{position:relative;display:flex;align-items:center;gap:14px;padding:15px 18px;background:var(--surface);border:1.5px solid var(--border);border-radius:14px;cursor:pointer;transition:border-color .15s,box-shadow .15s,background .15s,transform .1s;-webkit-tap-highlight-color:transparent}
.opt:hover{border-color:var(--border2)}
.opt:active{transform:scale(.995)}
.opt input{position:absolute;opacity:0;inset:0;width:100%;height:100%;margin:0;cursor:pointer}
.mark{flex:none;width:24px;height:24px;border-radius:50%;border:2px solid var(--border2);display:grid;place-items:center;color:transparent;transition:all .15s}
.multi .mark{border-radius:7px}
.opt.on{border-color:var(--pf);box-shadow:0 0 0 1px var(--pf);background:var(--surface2)}
.opt.on .mark{background:var(--pa);border-color:var(--pf);color:#fff}
.opt input:focus-visible~.mark{outline:2px solid var(--pf);outline-offset:3px}
.otxt{font-weight:500;overflow-wrap:anywhere}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:54px;margin-top:18px;border-radius:14px;background:var(--pa);color:#fff;font-weight:700;font-size:16px;transition:filter .15s,transform .1s,opacity .15s}
.btn:hover:not(:disabled){filter:brightness(1.1)}
.btn:active:not(:disabled){transform:translateY(1px)}
.btn:disabled{opacity:.4;cursor:not-allowed}
.link{display:block;margin:16px auto 0;font-size:14px;font-weight:600;color:var(--gray2);text-decoration:underline;text-underline-offset:3px}
.note{margin-top:8px;padding:12px 14px;border-radius:12px;background:var(--surface2);color:var(--gray2);font-size:14px;text-align:center}
.results{margin-top:26px}
.res{margin-bottom:20px}
.res-top{display:flex;justify-content:space-between;align-items:baseline;gap:14px;margin-bottom:8px}
.res-name{font-weight:500;overflow-wrap:anywhere}
.res.lead .res-name{font-weight:700}
.you{display:inline-flex;align-items:center;gap:4px;margin-left:10px;padding:2px 9px 2px 7px;border-radius:99px;background:var(--surface2);color:var(--gray2);font-size:12px;font-weight:600;vertical-align:1px;white-space:nowrap}
.res-pct{font-weight:700;font-size:18px;letter-spacing:-.02em}
.bar{height:12px;border-radius:99px;background:var(--surface2);overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:99px;background:var(--pf);opacity:.5;transition:width .9s cubic-bezier(.2,.8,.2,1),opacity .3s}
.res.lead .bar i{opacity:1}
.res-n{margin-top:5px;font-size:12.5px;color:var(--gray)}
.share{margin-top:26px;padding-top:22px;border-top:1.5px dashed var(--border2)}
.share-l{display:block;margin-bottom:10px;font-size:13px;font-weight:600;color:var(--gray)}
.url{display:flex;align-items:center;gap:10px;padding:6px 6px 6px 16px;border-radius:12px;background:var(--surface2);border:1px solid var(--border)}
.url code{flex:1;min-width:0;font:500 14px "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.url code b{color:var(--pf);font-weight:700}
.url button{min-height:38px;padding:0 14px;border-radius:9px;background:var(--surface);border:1px solid var(--border2);font-weight:600;font-size:13.5px;display:inline-flex;align-items:center;gap:7px}
.url button:hover{background:var(--hover)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.chip{display:inline-flex;align-items:center;gap:7px;min-height:38px;padding:0 14px;border-radius:99px;border:1px solid var(--border2);font-weight:600;font-size:13.5px;text-decoration:none;color:var(--gray2)}
.chip:hover{background:var(--hover);color:var(--ink)}
.gone{text-align:center;padding:26px 6px 14px}
.gone .big{font-weight:700;font-size:68px;letter-spacing:-.045em;color:var(--pf);line-height:1}
.gone h1{font-size:26px;margin:12px 0 8px}
.gone p{color:var(--gray);margin-bottom:22px}
.gone .btn{display:inline-flex;width:auto;padding:0 26px;text-decoration:none}
.foot{max-width:720px;width:100%;margin:0 auto;padding:6px 20px 30px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px 20px;font-size:13px;color:var(--gray)}
.foot a{color:var(--gray2);font-weight:600}
.toast{position:fixed;left:50%;bottom:22px;transform:translate(-50%,20px);opacity:0;pointer-events:none;background:var(--ink);color:var(--bg);padding:11px 18px;border-radius:12px;font-weight:600;font-size:14px;transition:all .25s;z-index:9;max-width:90vw;text-align:center}
.toast.on{opacity:1;transform:translate(-50%,0)}
.toast.err{background:var(--red);color:#fff}
@media(max-width:520px){.card{padding:24px 18px 20px;border-radius:18px}.url code{font-size:13px}.cta{display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

/* ---------- client (plain DOM, no innerHTML with user data; no backticks or dollar-braces in here) ---------- */
const CLIENT = String.raw`
(function () {
  'use strict';
  var app = document.getElementById('app');
  var ID = app.getAttribute('data-id');
  var S = { poll: null, view: 'vote', picked: [], mine: null, busy: false };
  var toastT = null;

  var ICON = {
    check: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    copy: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>',
    share: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15V3M7 8l5-5 5 5M5 13v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6"/></svg>'
  };

  function $(s, r) { return (r || document).querySelector(s); }
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function fmt(n) { return Number(n || 0).toLocaleString(); }
  function plural(n, w) { return fmt(n) + ' ' + w + (n === 1 ? '' : 's'); }

  function toast(msg, bad) {
    var t = $('#toast');
    t.textContent = msg;
    t.className = 'toast on' + (bad ? ' err' : '');
    clearTimeout(toastT);
    toastT = setTimeout(function () { t.className = 'toast'; }, 2800);
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return false; });
    }
    try {
      var ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;opacity:0';
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand('copy'); ta.remove();
      return Promise.resolve(ok);
    } catch (e) { return Promise.resolve(false); }
  }

  /* voter identity: random id kept in this browser (the server also caps votes per network) */
  function uuid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    var a = new Uint8Array(16); crypto.getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  var memVoter = null;
  function voterId() {
    try {
      var v = localStorage.getItem('clipt_voter');
      if (v && /^[A-Za-z0-9-]{16,64}$/.test(v)) return v;
      v = uuid(); localStorage.setItem('clipt_voter', v); return v;
    } catch (e) { return memVoter || (memVoter = uuid()); }
  }
  function loadMine() {
    try { var v = JSON.parse(localStorage.getItem('clipt_pv_' + ID) || 'null'); return Array.isArray(v) ? v : null; } catch (e) { return null; }
  }
  function saveMine(a) { try { localStorage.setItem('clipt_pv_' + ID, JSON.stringify(a)); } catch (e) {} }

  function isClosed(p) { return !!(p.closed || (p.ends_at && p.ends_at <= Date.now())); }
  function left(ms) {
    var m = Math.floor(ms / 60000);
    if (m < 1) return 'less than a minute';
    if (m < 60) return m + ' min';
    var hr = Math.floor(m / 60);
    if (hr < 48) return hr + (hr === 1 ? ' hour' : ' hours');
    return Math.floor(hr / 24) + ' days';
  }
  function metaText(p) {
    var t = p.hidden ? '' : plural(p.voters, 'vote');
    if (p.hidden && !isClosed(p)) { if (p.ends_at) t = 'closes in ' + left(p.ends_at - Date.now()); return t; }
    if (isClosed(p)) {
      if (p.ends_at && !p.closed) t += ' · ended ' + new Date(p.ends_at).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
    } else if (p.ends_at) t += ' · closes in ' + left(p.ends_at - Date.now());
    return t;
  }

  /* percentages: single-choice results are rounded so they always add up to 100 */
  function percents(p) {
    var tot = p.voters, o = p.options;
    if (!tot) return o.map(function () { return 0; });
    if (p.multiple) return o.map(function (x) { return Math.min(100, Math.round(x.votes * 100 / tot)); });
    var base = o.map(function (x) { return Math.floor(x.votes * 100 / tot); });
    var rem = 100 - base.reduce(function (a, b) { return a + b; }, 0);
    var order = o.map(function (x, i) { return { i: i, r: x.votes * 100 / tot - base[i] }; }).sort(function (a, b) { return b.r - a.r; });
    for (var k = 0; k < rem && k < order.length; k++) base[order[k].i]++;
    return base;
  }
  function maxVotes(p) { return Math.max.apply(null, p.options.map(function (o) { return o.votes; })); }

  /* ---------- views ---------- */
  function voteView(p) {
    var wrap = h('div', 'vote' + (p.multiple ? ' multi' : ''));
    wrap.appendChild(h('p', 'hint', p.multiple ? 'Select all that apply' : 'Choose one'));
    var list = h('div', 'opts');
    list.setAttribute('role', p.multiple ? 'group' : 'radiogroup');
    list.setAttribute('aria-label', p.title);
    var btn = h('button', 'btn', 'Submit vote');
    btn.type = 'button';
    btn.disabled = !S.picked.length;
    p.options.forEach(function (o) {
      var lab = h('label', 'opt' + (S.picked.indexOf(o.id) !== -1 ? ' on' : ''));
      var inp = h('input');
      inp.type = p.multiple ? 'checkbox' : 'radio';
      inp.name = 'opt'; inp.value = o.id;
      inp.checked = S.picked.indexOf(o.id) !== -1;
      var mark = h('span', 'mark'); mark.innerHTML = ICON.check;
      lab.appendChild(inp); lab.appendChild(mark); lab.appendChild(h('span', 'otxt', o.text));
      inp.addEventListener('change', function () {
        if (p.multiple) {
          S.picked = Array.prototype.map.call(list.querySelectorAll('input:checked'), function (i) { return +i.value; });
        } else S.picked = [o.id];
        Array.prototype.forEach.call(list.querySelectorAll('label'), function (l) { l.classList.toggle('on', l.firstChild.checked); });
        btn.disabled = !S.picked.length;
      });
      list.appendChild(lab);
    });
    btn.addEventListener('click', submit);
    wrap.appendChild(list); wrap.appendChild(btn);
    wrap.appendChild(h('p', 'hint', 'Results are shown after you vote.'));
    return wrap;
  }

  function resultsView(p) {
    var wrap = h('div', 'results');
    wrap.setAttribute('aria-live', 'polite');
    var pc = percents(p), max = maxVotes(p);
    p.options.forEach(function (o, i) {
      var row = h('div', 'res' + (max > 0 && o.votes === max ? ' lead' : ''));
      row.setAttribute('data-i', o.id);
      var top = h('div', 'res-top');
      var name = h('span', 'res-name', o.text);
      if (S.mine && S.mine.indexOf(o.id) !== -1) {
        var you = h('span', 'you'); you.innerHTML = ICON.check + 'Your vote'; name.appendChild(you);
      }
      top.appendChild(name); top.appendChild(h('span', 'res-pct', pc[i] + '%'));
      var bar = h('div', 'bar'), fill = h('i'); bar.appendChild(fill);
      row.appendChild(top); row.appendChild(bar); row.appendChild(h('div', 'res-n', plural(o.votes, 'vote')));
      wrap.appendChild(row);
      requestAnimationFrame(function () { requestAnimationFrame(function () { fill.style.width = pc[i] + '%'; }); });
    });
    if (isClosed(p)) {
      wrap.appendChild(h('div', 'note', 'This poll is closed. These are the final results.'));
    } else {
      wrap.appendChild(h('div', 'note', 'Thanks for voting. Results update live.'));
    }
    return wrap;
  }

  function shareView(p) {
    var url = location.origin + '/p/' + ID;
    var box = h('div', 'share');
    box.appendChild(h('span', 'share-l', 'Share this poll'));
    var pill = h('div', 'url');
    var code = h('code'); code.appendChild(document.createTextNode(location.host + '/p/'));
    code.appendChild(h('b', null, ID)); pill.appendChild(code);
    var cp = h('button'); cp.type = 'button'; cp.innerHTML = ICON.copy + '<span>Copy</span>';
    cp.addEventListener('click', function () { copyText(url).then(function (ok) { toast(ok ? 'Link copied' : 'Could not copy the link', !ok); }); });
    pill.appendChild(cp); box.appendChild(pill);
    var chips = h('div', 'chips');
    if (navigator.share) {
      var sh = h('button', 'chip'); sh.type = 'button'; sh.innerHTML = ICON.share + '<span>Share</span>';
      sh.addEventListener('click', function () { navigator.share({ title: p.title, url: url }).catch(function () {}); });
      chips.appendChild(sh);
    }
    [['WhatsApp', 'https://wa.me/?text=' + encodeURIComponent(p.title + ' ' + url)],
     ['Facebook', 'https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url)],
     ['X', 'https://twitter.com/intent/tweet?text=' + encodeURIComponent(p.title) + '&url=' + encodeURIComponent(url)]
    ].forEach(function (c) {
      var a = h('a', 'chip', c[0]); a.href = c[1]; a.target = '_blank'; a.rel = 'noopener noreferrer'; chips.appendChild(a);
    });
    box.appendChild(chips);
    return box;
  }

  function render() {
    var p = S.poll;
    app.textContent = '';
    var card = h('section', 'card');
    var top = h('div', 'top');
    var closed = isClosed(p);
    var pill = h('span', 'pill ' + (closed ? 'closed' : 'live'));
    pill.appendChild(h('i', 'dot')); pill.appendChild(document.createTextNode(closed ? 'Closed' : 'Live'));
    var meta = h('span', 'muted', metaText(p)); meta.id = 'meta';
    top.appendChild(pill); top.appendChild(meta);
    card.appendChild(top);
    card.appendChild(h('h1', null, p.title));
    if (p.description) card.appendChild(h('p', 'desc', p.description));
    card.appendChild(S.view === 'vote' && !closed ? voteView(p) : resultsView(p));
    card.appendChild(shareView(p));
    app.appendChild(card);
    var foot = $('#report');
    if (foot) {
      foot.textContent = '';
      if (p.support) {
        var a = h('a', null, 'Report this poll');
        a.href = 'mailto:' + p.support + '?subject=' + encodeURIComponent('Report poll ' + ID);
        foot.appendChild(a);
      }
    }
  }

  function gone(removed) {
    S.poll = null;
    app.textContent = '';
    var card = h('section', 'card'), g = h('div', 'gone');
    g.appendChild(h('div', 'big', '404'));
    g.appendChild(h('h1', null, removed ? 'This poll was removed' : 'Poll not found'));
    g.appendChild(h('p', null, removed ? 'It no longer follows our rules, so it is not available.' : 'The link may be mistyped, or the poll was deleted by its owner.'));
    var a = h('a', 'btn', 'Create your own poll'); a.href = '/dashboard.html#polls'; g.appendChild(a);
    card.appendChild(g); app.appendChild(card);
  }

  /* ---------- data ---------- */
  function api(method, path, body) {
    var o = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body) o.body = JSON.stringify(body);
    return fetch('/api' + path, o).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { s: r.status, d: d }; }); });
  }
  function accent(p) { if (p && p.color) document.documentElement.style.setProperty('--pa', p.color); }
  function refresh(force) {
    var voted = S.mine || (S.poll && !S.poll.hidden);
    return (voted ? api('POST', '/public/polls/' + ID + '/results', { voter: voterId() }) : api('GET', '/public/polls/' + ID)).then(function (x) {
      if (x.s === 403) { S.mine = null; S.view = 'vote'; if (S.poll) render(); }
      else if (x.s === 200 && x.d.poll) {
        var was = S.poll ? isClosed(S.poll) : null;
        S.poll = x.d.poll;
        if (force || was !== isClosed(S.poll)) { if (isClosed(S.poll)) S.view = 'results'; render(); } else paint();
      } else if (x.s === 404) gone(/removed/.test(x.d.error || ''));
    }).catch(function () {});
  }
  function paint() {
    var p = S.poll, pc = percents(p), max = maxVotes(p);
    p.options.forEach(function (o, i) {
      var row = $('.res[data-i="' + o.id + '"]');
      if (!row) return;
      row.classList.toggle('lead', max > 0 && o.votes === max);
      $('.res-pct', row).textContent = pc[i] + '%';
      $('.res-n', row).textContent = plural(o.votes, 'vote');
      $('.bar i', row).style.width = pc[i] + '%';
    });
    var m = $('#meta'); if (m) m.textContent = metaText(p);
  }

  function submit() {
    if (S.busy || !S.picked.length || !S.poll) return;
    S.busy = true;
    var btn = $('.btn'); if (btn) { btn.disabled = true; btn.textContent = 'Submitting…'; }
    api('POST', '/public/polls/' + ID + '/vote', { voter: voterId(), options: S.picked }).then(function (x) {
      S.busy = false;
      if (x.s === 200 && x.d.poll) {
        S.poll = x.d.poll; S.mine = S.picked.slice(); saveMine(S.mine); S.view = 'results'; render(); toast('Vote recorded. Thank you!');
      } else if (x.s === 409) {
        S.mine = loadMine() || []; S.view = 'results'; toast('You have already voted in this poll.'); refresh(true);
      } else if (x.s === 403 || x.s === 410) {
        toast(x.d.error || 'This poll is closed.', true); S.poll.closed = true; refresh(true);
      } else {
        toast(x.d.error || 'Could not record your vote. Please try again.', true);
        if (btn) { btn.disabled = false; btn.textContent = 'Submit vote'; }
      }
    }).catch(function () {
      S.busy = false; toast('Network error. Please try again.', true);
      if (btn) { btn.disabled = false; btn.textContent = 'Submit vote'; }
    });
  }

  function start(p) {
    S.poll = p; S.mine = loadMine(); S.view = (S.mine || isClosed(p)) ? 'results' : 'vote';
    accent(p);
    if (S.mine && p.hidden) refresh(true); else render();
  }

  var tb = $('#themeBtn');
  if (tb) tb.addEventListener('click', function () {
    var d = document.documentElement, n = d.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    d.setAttribute('data-theme', n);
    try { localStorage.setItem('clipt_theme', n); } catch (e) {}
  });

  setInterval(function () {
    if (document.hidden || !S.poll) return;
    if (S.view === 'results' && !isClosed(S.poll) && !S.poll.hidden) refresh();
    else if (isClosed(S.poll) && S.view === 'vote') { S.view = 'results'; render(); }
    else { var m = $('#meta'); if (m) m.textContent = metaText(S.poll); }
  }, 15000);

  var d = null;
  try { d = JSON.parse($('#pd').textContent); } catch (e) {}
  if (d && d.gone) gone(!!d.removed);
  else if (d && d.id) start(d);
  else api('GET', '/public/polls/' + ID).then(function (x) {
    if (x.s === 200 && x.d.poll) start(x.d.poll);
    else if (x.s === 404) gone(/removed/.test(x.d.error || ''));
    else { app.textContent = ''; var c = h('section', 'card'); c.appendChild(h('p', 'muted', 'Could not load this poll. Please refresh the page.')); app.appendChild(c); }
  }).catch(function () { app.textContent = ''; var c = h('section', 'card'); c.appendChild(h('p', 'muted', 'Network error. Please refresh the page.')); app.appendChild(c); });
})();
`;

function render(origin, id, v, nonce) {
  const ok = v && v.id;
  const color = ok && POLL_COLORS.includes(v.color) ? v.color : POLL_COLORS[0];
  const title = ok ? v.title : 'Poll';
  const desc = ok
    ? (v.description || ('Vote now: ' + v.options.map(o => o.text).join(' · '))).slice(0, 180)
    : 'Vote in this poll on Clipt.';
  const url = origin + '/p/' + id;
  const data = (v ? JSON.stringify(v) : 'null').replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  const t = esc(title + ' · Clipt Poll');
  return `<!doctype html><html lang="en" data-theme="light"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${t}</title>
<meta name="robots" content="noindex,nofollow">
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#f8f8f6">
<meta property="og:type" content="website"><meta property="og:site_name" content="Clipt">
<meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(desc)}">
<meta property="og:url" content="${esc(url)}"><meta property="og:image" content="${esc(origin)}/clipt.png">
<meta name="twitter:card" content="summary"><meta name="twitter:title" content="${esc(title)}"><meta name="twitter:description" content="${esc(desc)}">
<link rel="icon" href="/clipt.png">
<script nonce="${nonce}">try{var t=localStorage.getItem('clipt_theme');document.documentElement.setAttribute('data-theme',t==='dark'?'dark':'light')}catch(e){}</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&family=Schibsted+Grotesk:wght@400;500;600;700&display=swap">
<style nonce="${nonce}">:root{--pa:${color}}${CSS}</style></head>
<body>
<header class="hdr">
  <a class="logo" href="/"><img src="/clipt.png" alt="" width="30" height="30"><span>Clipt</span></a>
  <div class="hdr-r">
    <button class="ib" id="themeBtn" type="button" aria-label="Toggle dark mode">
      <svg class="moon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
      <svg class="sun" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    </button>
    <a class="cta" href="/dashboard.html#polls">Create a poll</a>
  </div>
</header>
<main id="app" data-id="${esc(id)}"><section class="card"><p class="muted">Loading poll…</p></section></main>
<footer class="foot"><span>Made with <a href="/">Clipt</a> · free polls and short links</span><span id="report"></span></footer>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script type="application/json" id="pd">${data}</script>
<script nonce="${nonce}">${CLIENT}</script>
</body></html>`;
}

export async function onRequest(ctx) {
  const { request, env, params } = ctx;
  if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const id = String(params.id || '').toLowerCase();
  const origin = new URL(request.url).origin;

  const blocked = await rl('pbad:' + ip, 15, 60, true);                 // many invalid poll links in a minute: stop before touching D1
  if (!blocked.ok) return new Response('Too many attempts. Try again in a minute.', { status: 429, headers: { 'Retry-After': String(blocked.retry), 'Cache-Control': 'no-store' } });

  let v = null, status = 200;
  if (!POLL_ID_RE.test(id)) v = { gone: 1 };
  else {
    try { v = await loadPoll(env.CLIPT_DB, id); }
    catch (e) { console.error('poll page lookup failed', e && e.message); v = null; }    // tables may not exist yet: the page then loads via /api, which creates them
  }
  v = hidePoll(v);
  if (v && v.gone) { status = v.removed ? 410 : 404; await rl('pbad:' + ip, 15, 60); }

  const nonce = hex(16);
  const csp = `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  return new Response(render(origin, POLL_ID_RE.test(id) ? id : 'xxxxx', v, nonce), {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': csp,
      'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Robots-Tag': 'noindex, nofollow'
    }
  });
}
