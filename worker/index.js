/* WingMan push server (Cloudflare Worker). Free tier is enough.
   - The app sends its flights and push subscription here (POST /sync).
   - A cron trigger (every 10 minutes) checks live flight status and sends Web Push alerts.
   Secrets: ADB_KEY (AeroDataBox key), VAPID_JWK (private key JSON), VAPID_SUBJECT (mailto:...). KV binding: WM. */
const ALLOWED = 'https://imadala1234.github.io';
const enc = new TextEncoder();
const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0)),
};
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; a.forEach((x) => { o.set(x, i); i += x.length; }); return o; };

/* ---------- Web Push: VAPID (RFC 8292) + aes128gcm payload encryption (RFC 8291) ---------- */
async function vapidHeader(endpoint, env, now = Date.now()) {
  const jwk = JSON.parse(env.VAPID_JWK), aud = new URL(endpoint).origin;
  const key = await crypto.subtle.importKey('jwk', { ...jwk, key_ops: ['sign'], ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const head = b64u.enc(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u.enc(enc.encode(JSON.stringify({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'mailto:admin@example.com' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body));
  const pub = b64u.enc(cat(Uint8Array.of(4), b64u.dec(jwk.x), b64u.dec(jwk.y)));
  return 'vapid t=' + head + '.' + body + '.' + b64u.enc(sig) + ', k=' + pub;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encryptPayload(sub, text) {
  const ua = b64u.dec(sub.keys.p256dh), auth = b64u.dec(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, secret, cat(enc.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, cat(enc.encode(text), Uint8Array.of(2))));
  return cat(salt, Uint8Array.of(0, 0, 16, 0, 65), asPub, ct);
}
async function sendPush(sub, payload, env) {
  const body = await encryptPayload(sub, JSON.stringify(payload));
  return fetch(sub.endpoint, { method: 'POST', body, headers: { Authorization: await vapidHeader(sub.endpoint, env), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' } });
}

/* ---------- flight checks ---------- */
const tsOf = (t) => { if (!t) return 0; const u = t.utc || t.scheduledTimeUtc, l = t.local; const x = u ? Date.parse(u.replace(' ', 'T').replace(/Z?$/, 'Z')) : l ? Date.parse(l.replace(' ', 'T')) : 0; return isNaN(x) ? 0 : x; };
const mv = (m) => { m = m || {}; return { s: tsOf(m.scheduledTime || { utc: m.scheduledTimeUtc, local: m.scheduledTimeLocal }), r: tsOf(m.revisedTime || m.predictedTime || { utc: m.revisedTimeUtc, local: m.revisedTimeLocal }) }; };
const hm = (ts, tz) => new Intl.DateTimeFormat('en-AU', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false }).format(ts);
async function fetchStatus(f, env) {
  const date = new Intl.DateTimeFormat('en-CA', { timeZone: f.tz || 'UTC' }).format(f.dep);
  const r = await fetch('https://aerodatabox.p.rapidapi.com/flights/number/' + encodeURIComponent(f.no) + '/' + date + '?withAircraftImage=false&withLocation=false', { headers: { 'X-RapidAPI-Key': env.ADB_KEY, 'X-RapidAPI-Host': 'aerodatabox.p.rapidapi.com' } });
  if (!r.ok) return null;
  const j = await r.json(), x = (Array.isArray(j) ? j : []).find((q) => q.departure && q.departure.airport && String(q.departure.airport.iata).toUpperCase() === f.from);
  if (!x) return null;
  const d = x.departure, dt = mv(d), at = mv(x.arrival), st = x.status || '';
  return { delay: dt.s && dt.r ? Math.round((dt.r - dt.s) / 60000) : 0, gate: d.gate || '', terminal: d.terminal || '', cancelled: /cancel/i.test(st), dep: dt.s || f.dep };
}
function changes(f, old, nw) {
  const out = [], eff = f.dep + nw.delay * 60000;
  if (nw.cancelled && !old.cancelled) out.push({ k: 'x', title: f.no + ' cancelled', body: f.fromName + ' to ' + f.toName + ' has been cancelled.' });
  else if (Math.abs(nw.delay - old.delay) >= 5) out.push({ k: 'd' + nw.delay, title: nw.delay > 0 ? f.no + ' delayed ' + nw.delay + ' min' : f.no + ' is back on time', body: 'New departure ' + hm(eff, f.tz) + ' from ' + f.fromName + '.' });
  if (nw.gate && nw.gate !== old.gate) out.push({ k: 'g' + nw.gate, title: old.gate ? 'Gate change for ' + f.no : 'Gate assigned for ' + f.no, body: old.gate ? 'Gate ' + old.gate + ' is now ' + nw.gate + '.' : 'Gate ' + nw.gate + (nw.terminal ? ', Terminal ' + nw.terminal : '') + '.' });
  else if (nw.terminal && nw.terminal !== old.terminal) out.push({ k: 't' + nw.terminal, title: 'Terminal change for ' + f.no, body: 'Terminal ' + nw.terminal + '.' });
  return out;
}
function reminders(f, st, set, now) {
  const out = [], eff = f.dep + (st.delay || 0) * 60000, M = 60000;
  if (st.cancelled || now > eff) return out;
  const due = (t) => now >= t && now < t + 30 * M;
  if (set.checkin !== false && due(f.dep - (set.checkinHrs || 24) * 3600000)) out.push({ k: 'ci' + f.dep, title: 'Check-in is open for ' + f.no, body: f.fromName + ' to ' + f.toName + '.' });
  if (set.leave !== false && due(eff - ((set.leaveMins || 150) + (f.intl ? 90 : 0)) * M)) out.push({ k: 'lv' + f.dep, title: 'Time to leave for the airport', body: f.no + ' departs ' + hm(eff, f.tz) + (f.gate ? ', gate ' + f.gate : '') + '.' });
  if (set.boarding !== false && due(eff - 40 * M)) out.push({ k: 'bd' + f.dep, title: 'Boarding soon for ' + f.no, body: 'Departs ' + hm(eff, f.tz) + (f.gate ? ' from gate ' + f.gate : '') + '.' });
  return out;
}
async function runDevice(id, rec, env, now) {
  rec.st = rec.st || {}; rec.sent = rec.sent || {}; const pushes = [];
  for (const f of rec.flights || []) {
    const st = (rec.st[f.id] = rec.st[f.id] || { delay: f.delay || 0, gate: f.gate || '', terminal: f.terminal || '', cancelled: !!f.cancelled, chk: 0 });
    const win = f.dep - now, gap = now >= f.dep - 3 * 3600000 ? 9 * 60000 : win < 48 * 3600000 ? 29 * 60000 : Infinity;
    if (env.ADB_KEY && win < 48 * 3600000 && now < f.arr + 3 * 3600000 && now - st.chk >= gap) {
      st.chk = now;
      try { const nw = await fetchStatus(f, env); if (nw) { changes(f, st, nw).forEach((c) => pushes.push(c)); Object.assign(st, { delay: nw.delay, gate: nw.gate || st.gate, terminal: nw.terminal || st.terminal, cancelled: nw.cancelled }); } } catch (e) {}
    }
    reminders(f, st, rec.settings || {}, now).forEach((c) => pushes.push(c));
    pushes.forEach((c) => { c.fid = f.id; });
  }
  let gone = false;
  for (const c of pushes) {
    const key = c.fid + c.k; if (rec.sent[key]) continue; rec.sent[key] = now;
    const r = await sendPush(rec.sub, { title: c.title, body: c.body, tag: key, url: '#alerts' }, env).catch(() => null);
    if (r && (r.status === 404 || r.status === 410)) { gone = true; break; }
  }
  Object.keys(rec.sent).forEach((k) => { if (now - rec.sent[k] > 5 * 86400000) delete rec.sent[k]; });
  return gone;
}

/* ---------- HTTP + cron ---------- */
const cors = (extra = {}) => ({ 'Access-Control-Allow-Origin': ALLOWED, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin', ...extra });
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: cors({ 'Content-Type': 'application/json' }) });
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
    const path = new URL(req.url).pathname;
    if (req.method === 'GET') { const jwk = env.VAPID_JWK ? JSON.parse(env.VAPID_JWK) : null; return json({ ok: true, name: 'wingman-push', publicKey: jwk ? b64u.enc(cat(Uint8Array.of(4), b64u.dec(jwk.x), b64u.dec(jwk.y))) : null, adbKey: !!env.ADB_KEY }); }
    if (req.headers.get('Origin') !== ALLOWED) return json({ error: 'forbidden' }, 403);
    let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
    const id = String(b.id || ''); if (!/^[A-Za-z0-9_-]{16,64}$/.test(id)) return json({ error: 'bad id' }, 400);
    const k = 'dev:' + id; let rec = await env.WM.get(k, 'json');
    if (path === '/off') { await env.WM.delete(k); return json({ ok: true }); }
    if (path === '/sync') {
      const sub = b.sub || (rec && rec.sub); if (!sub || !sub.endpoint || !sub.keys) return json({ error: 'no subscription' }, 400);
      const flights = (Array.isArray(b.flights) ? b.flights : []).slice(0, 40).map((f) => ({ id: String(f.id), no: String(f.no), from: String(f.from), to: String(f.to), dep: +f.dep, arr: +f.arr, tz: String(f.tz || 'UTC'), fromName: String(f.fromName || f.from), toName: String(f.toName || f.to), intl: !!f.intl, delay: +f.delay || 0, gate: String(f.gate || ''), terminal: String(f.terminal || ''), cancelled: !!f.cancelled }));
      const old = (rec && rec.st) || {}, st = {}; flights.forEach((f) => { if (old[f.id]) st[f.id] = old[f.id]; });
      rec = { sub, flights, settings: b.settings || {}, st, sent: (rec && rec.sent) || {}, at: Date.now() };
      await env.WM.put(k, JSON.stringify(rec), { expirationTtl: 60 * 86400 });
      return json({ ok: true, flights: flights.length });
    }
    if (path === '/test') {
      if (!rec) return json({ error: 'not registered' }, 404);
      const r = await sendPush(rec.sub, { title: 'WingMan alerts are on', body: 'You will get delay, gate and reminder alerts here.', tag: 'test', url: '#alerts' }, env);
      return json({ ok: r.ok, status: r.status }, r.ok ? 200 : 502);
    }
    return json({ error: 'not found' }, 404);
  },
  async scheduled(ev, env, ctx) {
    ctx.waitUntil((async () => {
      const now = Date.now(); let cur;
      do {
        const l = await env.WM.list({ prefix: 'dev:', cursor: cur }); cur = l.list_complete ? null : l.cursor;
        for (const { name } of l.keys) {
          const rec = await env.WM.get(name, 'json'); if (!rec) continue;
          const gone = await runDevice(name.slice(4), rec, env, now);
          if (gone) await env.WM.delete(name); else await env.WM.put(name, JSON.stringify(rec), { expirationTtl: 60 * 86400 });
        }
      } while (cur);
    })());
  },
};
export { encryptPayload, vapidHeader, changes, reminders };
