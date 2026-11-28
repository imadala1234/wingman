/* WingMan push server for Google Apps Script.
   The app registers this phone here (doPost). A time trigger (tick) checks live flight status and sends Web Push alerts.
   Web Push needs P-256 and AES-GCM, which Apps Script lacks, so they are implemented below in plain JavaScript (BigInt). */

/* BigInt constants (the Apps Script editor rejects 123n literals) */
var B0 = BigInt(0);
var B1 = BigInt(1);
var B2 = BigInt(2);
var B3 = BigInt(3);
var B4 = BigInt(4);
var B8 = BigInt(8);
var B64 = BigInt(64);
/* ---------- P-256 + AES-GCM + HKDF in plain JS ---------- */
var P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
var N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
var GX = BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
var GY = BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
function mod(a, m) { var r = a % m; return r >= B0 ? r : r + m; }
function powmod(b, e, m) { var r = B1; b = mod(b, m); while (e > B0) { if (e & B1) r = r * b % m; b = b * b % m; e >>= B1; } return r; }
function inv(a, m) { return powmod(a, m - B2, m); }
function pdbl(p) {
  if (!p || p[1] === B0) return null;
  var X = p[0], Y = p[1], Z = p[2], d = Z * Z % P, g = Y * Y % P, b = X * g % P, a = B3 * mod(X - d, P) * ((X + d) % P) % P;
  var X3 = mod(a * a - B8 * b, P), Z3 = mod((Y + Z) * (Y + Z) - g - d, P), Y3 = mod(a * (B4 * b - X3) - B8 * g * g, P);
  return [X3, Y3, Z3];
}
function padd(p, q) {
  if (!p) return q; if (!q) return p;
  var Z1 = p[2], Z2 = q[2], Z1Z1 = Z1 * Z1 % P, Z2Z2 = Z2 * Z2 % P, U1 = p[0] * Z2Z2 % P, U2 = q[0] * Z1Z1 % P, S1 = p[1] * Z2 * Z2Z2 % P, S2 = q[1] * Z1 * Z1Z1 % P;
  if (U1 === U2) { return S1 === S2 ? pdbl(p) : null; }
  var H = mod(U2 - U1, P), I = B4 * H * H % P, J = H * I % P, r = B2 * mod(S2 - S1, P) % P, V = U1 * I % P;
  var X3 = mod(r * r - J - B2 * V, P), Y3 = mod(r * (V - X3) - B2 * S1 * J, P), Z3 = mod(((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) * H, P);
  return [X3, Y3, Z3];
}
function pmul(k, x, y) {
  var q = [x, y, B1], r = null, bits = k.toString(2);
  for (var i = 0; i < bits.length; i++) { r = pdbl(r); if (bits[i] === '1') r = padd(r, q); }
  if (!r) return null; var zi = inv(r[2], P), z2 = zi * zi % P; return [r[0] * z2 % P, r[1] * z2 * zi % P];
}
function b2i(a) { var h = '0x'; a.forEach(function (b) { h += ('0' + b.toString(16)).slice(-2); }); return BigInt(h.length > 2 ? h : '0x0'); }
function i2b(n, len) { var h = n.toString(16); while (h.length < len * 2) h = '0' + h; var o = []; for (var i = 0; i < h.length; i += 2) o.push(parseInt(h.substr(i, 2), 16)); return o; }
function cat() { var o = []; for (var i = 0; i < arguments.length; i++) o = o.concat(Array.prototype.slice.call(arguments[i])); return o; }
function u8(s) { var o = [], e = unescape(encodeURIComponent(s)); for (var i = 0; i < e.length; i++) o.push(e.charCodeAt(i)); return o; }
function b64u(a) { return Utilities.base64EncodeWebSafe(a.map(function (x) { return x > 127 ? x - 256 : x; })).replace(/=+$/, ''); }
function unb64u(s) { return Utilities.base64DecodeWebSafe(s + '===='.slice(s.length % 4 || 4)).map(function (x) { return x & 255; }); }
function hmac(key, data) { return Array.prototype.slice.call(Utilities.computeHmacSha256Signature(data.map(function (x) { return x > 127 ? x - 256 : x; }), key.map(function (x) { return x > 127 ? x - 256 : x; }))).map(function (x) { return x & 255; }); }
function sha256(data) { return Array.prototype.slice.call(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, data.map(function (x) { return x > 127 ? x - 256 : x; }))).map(function (x) { return x & 255; }); }
function hkdf(salt, ikm, info, len) { var prk = hmac(salt, ikm), t = [], o = [], c = 1; while (o.length < len) { t = hmac(prk, cat(t, info, [c++])); o = o.concat(t); } return o.slice(0, len); }
function randBytes(n) { var o = []; while (o.length < n) { o = o.concat(sha256(u8(Utilities.getUuid() + Utilities.getUuid() + Date.now() + Math.random()))); } return o.slice(0, n); }
function randScalar() { for (;;) { var k = b2i(randBytes(32)); if (k > B0 && k < N) return k; } }
function rfc6979(d, h) {
  var x = i2b(d, 32), h1 = i2b(mod(b2i(h), N), 32), V = []; for (var i = 0; i < 32; i++) V.push(1); var K = []; for (i = 0; i < 32; i++) K.push(0);
  K = hmac(K, cat(V, [0], x, h1)); V = hmac(K, V); K = hmac(K, cat(V, [1], x, h1)); V = hmac(K, V);
  for (;;) { V = hmac(K, V); var k = b2i(V); if (k > B0 && k < N) return k; K = hmac(K, cat(V, [0])); V = hmac(K, V); }
}
function ecdsaSign(d, msg) {
  var h = sha256(msg), z = b2i(h);
  for (;;) { var k = rfc6979(d, h), R = pmul(k, GX, GY), r = mod(R[0], N); if (r === B0) continue; var s = mod(inv(k, N) * (z + r * d), N); if (s === B0) continue; return i2b(r, 32).concat(i2b(s, 32)); }
}
var SBOX = (function () { var s = [], p = 1, q = 1; do { p = p ^ ((p << 1) & 255) ^ (p & 128 ? 0x1b : 0); q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 255; if (q & 128) q ^= 0x09; var x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4)); s[p] = (x ^ 0x63) & 255; } while (p !== 1); s[0] = 0x63; return s; })();
function xt(a) { return ((a << 1) ^ (a & 128 ? 0x1b : 0)) & 255; }
function aesKey(key) {
  var w = [], i, t, rc = 1; for (i = 0; i < 16; i++) w.push(key[i]);
  for (i = 16; i < 176; i += 4) { t = w.slice(i - 4, i); if (i % 16 === 0) { t = [SBOX[t[1]] ^ rc, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]; rc = xt(rc); } for (var j = 0; j < 4; j++) w.push(w[i - 16 + j] ^ t[j]); }
  return w;
}
function aesBlock(w, inp) {
  var s = inp.slice(), r, i; for (i = 0; i < 16; i++) s[i] ^= w[i];
  for (r = 1; r <= 10; r++) {
    var t = []; for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
    s = [t[0], t[5], t[10], t[15], t[4], t[9], t[14], t[3], t[8], t[13], t[2], t[7], t[12], t[1], t[6], t[11]];
    if (r < 10) { for (var c = 0; c < 16; c += 4) { var a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3], x = a0 ^ a1 ^ a2 ^ a3; s[c] = a0 ^ x ^ xt(a0 ^ a1); s[c + 1] = a1 ^ x ^ xt(a1 ^ a2); s[c + 2] = a2 ^ x ^ xt(a2 ^ a3); s[c + 3] = a3 ^ x ^ xt(a3 ^ a0); } }
    for (i = 0; i < 16; i++) s[i] ^= w[r * 16 + i];
  }
  return s;
}
function gmul(x, y) { var z = B0, v = y, R = BigInt('0xe1000000000000000000000000000000'); for (var i = 127; i >= 0; i--) { if ((x >> BigInt(i)) & B1) z ^= v; v = (v & B1) ? (v >> B1) ^ R : v >> B1; } return z; }
function gcmEncrypt(key, iv, pt) {
  var w = aesKey(key), H = b2i(aesBlock(w, new Array(16).fill(0))), ct = [], ctr = cat(iv, [0, 0, 0, 1]), j0 = ctr.slice(), n, i;
  for (var off = 0; off < pt.length; off += 16) {
    n = (ctr[15] | (ctr[14] << 8) | (ctr[13] << 16) | (ctr[12] << 24)) + 1 >>> 0; ctr[12] = n >>> 24; ctr[13] = (n >>> 16) & 255; ctr[14] = (n >>> 8) & 255; ctr[15] = n & 255;
    var ks = aesBlock(w, ctr), blk = pt.slice(off, off + 16); for (i = 0; i < blk.length; i++) ct.push(blk[i] ^ ks[i]);
  }
  var X = B0; for (off = 0; off < ct.length; off += 16) { var c = ct.slice(off, off + 16); while (c.length < 16) c.push(0); X = gmul(X ^ b2i(c), H); }
  X = gmul(X ^ ((B0 << B64) | BigInt(ct.length * 8)), H);
  var tag = i2b(X ^ b2i(aesBlock(w, j0)), 16); return ct.concat(tag);
}
/* RFC 8291 aes128gcm Web Push payload */
function encryptPayload(sub, text) {
  var ua = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth), d = randScalar(), A = pmul(d, GX, GY), asPub = cat([4], i2b(A[0], 32), i2b(A[1], 32));
  var S = pmul(d, b2i(ua.slice(1, 33)), b2i(ua.slice(33, 65))), secret = i2b(S[0], 32);
  var ikm = hkdf(auth, secret, cat(u8('WebPush: info\0'), ua, asPub), 32), salt = randBytes(16);
  var cek = hkdf(salt, ikm, u8('Content-Encoding: aes128gcm\0'), 16), nonce = hkdf(salt, ikm, u8('Content-Encoding: nonce\0'), 12);
  return cat(salt, [0, 0, 16, 0, 65], asPub, gcmEncrypt(cek, nonce, cat(u8(text), [2])));
}
function vapidKeys() {
  var props = PropertiesService.getScriptProperties(), d = props.getProperty('VAPID_D');
  if (!d) { d = i2b(randScalar(), 32).map(function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); props.setProperty('VAPID_D', d); }
  var dd = BigInt('0x' + d), Q = pmul(dd, GX, GY); return { d: dd, pub: cat([4], i2b(Q[0], 32), i2b(Q[1], 32)) };
}
function vapidHeader(endpoint) {
  var k = vapidKeys(), aud = endpoint.match(/^https:\/\/[^\/]+/)[0];
  var head = b64u(u8(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))), body = b64u(u8(JSON.stringify({ aud: aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:' + (Session.getEffectiveUser().getEmail() || 'admin@example.com') })));
  return 'vapid t=' + head + '.' + body + '.' + b64u(ecdsaSign(k.d, u8(head + '.' + body))) + ', k=' + b64u(k.pub);
}
function sendPush(sub, payload) {
  var body = encryptPayload(sub, JSON.stringify(payload));
  return UrlFetchApp.fetch(sub.endpoint, { method: 'post', contentType: 'application/octet-stream', payload: body.map(function (x) { return x > 127 ? x - 256 : x; }), muteHttpExceptions: true, headers: { Authorization: vapidHeader(sub.endpoint), 'Content-Encoding': 'aes128gcm', TTL: '86400', Urgency: 'high' } });
}

/* ---------- flight checks ---------- */
function tsOf(t) { if (!t) return 0; var u = t.utc || t.scheduledTimeUtc, l = t.local, x = u ? Date.parse(u.replace(' ', 'T').replace(/Z?$/, 'Z')) : l ? Date.parse(l.replace(' ', 'T')) : 0; return isNaN(x) ? 0 : x; }
function mvT(m) { m = m || {}; return { s: tsOf(m.scheduledTime || { utc: m.scheduledTimeUtc, local: m.scheduledTimeLocal }), r: tsOf(m.revisedTime || m.predictedTime || { utc: m.revisedTimeUtc, local: m.revisedTimeLocal }) }; }
function hm(ts, tz) { return Utilities.formatDate(new Date(ts), tz, 'HH:mm'); }
function fetchStatus(f, key) {
  var date = Utilities.formatDate(new Date(f.dep), f.tz || 'UTC', 'yyyy-MM-dd');
  var r = UrlFetchApp.fetch('https://aerodatabox.p.rapidapi.com/flights/number/' + encodeURIComponent(f.no) + '/' + date + '?withAircraftImage=false&withLocation=false', { muteHttpExceptions: true, headers: { 'X-RapidAPI-Key': key, 'X-RapidAPI-Host': 'aerodatabox.p.rapidapi.com' } });
  if (r.getResponseCode() !== 200) return null;
  var j = JSON.parse(r.getContentText()), x = (Array.isArray(j) ? j : []).filter(function (q) { return q.departure && q.departure.airport && String(q.departure.airport.iata).toUpperCase() === f.from; })[0];
  if (!x) return null; var d = x.departure, dt = mvT(d), st = x.status || '';
  return { delay: dt.s && dt.r ? Math.round((dt.r - dt.s) / 60000) : 0, gate: d.gate || '', terminal: d.terminal || '', cancelled: /cancel/i.test(st) };
}
function changes(f, old, nw) {
  var out = [], eff = f.dep + nw.delay * 60000;
  if (nw.cancelled && !old.cancelled) out.push({ k: 'x', title: f.no + ' cancelled', body: f.fromName + ' to ' + f.toName + ' has been cancelled.' });
  else if (Math.abs(nw.delay - old.delay) >= 5) out.push({ k: 'd' + nw.delay, title: nw.delay > 0 ? f.no + ' delayed ' + nw.delay + ' min' : f.no + ' is back on time', body: 'New departure ' + hm(eff, f.tz) + ' from ' + f.fromName + '.' });
  if (nw.gate && nw.gate !== old.gate) out.push({ k: 'g' + nw.gate, title: old.gate ? 'Gate change for ' + f.no : 'Gate assigned for ' + f.no, body: old.gate ? 'Gate ' + old.gate + ' is now ' + nw.gate + '.' : 'Gate ' + nw.gate + (nw.terminal ? ', Terminal ' + nw.terminal : '') + '.' });
  else if (nw.terminal && nw.terminal !== old.terminal) out.push({ k: 't' + nw.terminal, title: 'Terminal change for ' + f.no, body: 'Terminal ' + nw.terminal + '.' });
  return out;
}
function reminders(f, st, set, now) {
  var out = [], eff = f.dep + (st.delay || 0) * 60000, M = 60000;
  if (st.cancelled || now > eff) return out;
  function due(t) { return now >= t && now < t + 30 * M; }
  if (set.checkin !== false && due(f.dep - (set.checkinHrs || 24) * 3600000)) out.push({ k: 'ci' + f.dep, title: 'Check-in is open for ' + f.no, body: f.fromName + ' to ' + f.toName + '.' });
  if (set.leave !== false && due(eff - ((set.leaveMins || 150) + (f.intl ? 90 : 0)) * M)) out.push({ k: 'lv' + f.dep, title: 'Time to leave for the airport', body: f.no + ' departs ' + hm(eff, f.tz) + (f.gate ? ', gate ' + f.gate : '') + '.' });
  if (set.boarding !== false && due(eff - 40 * M)) out.push({ k: 'bd' + f.dep, title: 'Boarding soon for ' + f.no, body: 'Departs ' + hm(eff, f.tz) + (f.gate ? ' from gate ' + f.gate : '') + '.' });
  return out;
}
function runDevice(rec, now) {
  rec.st = rec.st || {}; rec.sent = rec.sent || {}; var pushes = [], key = PropertiesService.getScriptProperties().getProperty('ADB_KEY');
  (rec.flights || []).forEach(function (f) {
    var st = rec.st[f.id] = rec.st[f.id] || { delay: f.delay || 0, gate: f.gate || '', terminal: f.terminal || '', cancelled: !!f.cancelled, chk: 0 };
    var win = f.dep - now, gap = now >= f.dep - 3 * 3600000 ? 9 * 60000 : win < 48 * 3600000 ? 29 * 60000 : Infinity, mine = [];
    if (key && win < 48 * 3600000 && now < f.arr + 3 * 3600000 && now - st.chk >= gap) {
      st.chk = now;
      try { var nw = fetchStatus(f, key); if (nw) { mine = changes(f, st, nw); st.delay = nw.delay; st.gate = nw.gate || st.gate; st.terminal = nw.terminal || st.terminal; st.cancelled = nw.cancelled; } } catch (e) {}
    }
    mine = mine.concat(reminders(f, st, rec.settings || {}, now)); mine.forEach(function (c) { c.fid = f.id; pushes.push(c); });
  });
  var gone = false;
  pushes.forEach(function (c) {
    var k = c.fid + c.k; if (rec.sent[k] || gone) return; rec.sent[k] = now;
    var r = sendPush(rec.sub, { title: c.title, body: c.body, tag: k, url: '#alerts' }); if (r.getResponseCode() === 404 || r.getResponseCode() === 410) gone = true;
  });
  Object.keys(rec.sent).forEach(function (k) { if (now - rec.sent[k] > 5 * 86400000) delete rec.sent[k]; });
  return gone;
}

/* ---------- web app + trigger ---------- */
function out(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
function doGet() { return out({ ok: true, name: 'wingman-push', publicKey: b64u(vapidKeys().pub) }); }
function doPost(e) {
  var b; try { b = JSON.parse(e.postData.contents); } catch (x) { return out({ error: 'bad json' }); }
  var id = String(b.id || ''); if (!/^[A-Za-z0-9_-]{16,64}$/.test(id)) return out({ error: 'bad id' });
  var props = PropertiesService.getScriptProperties(), k = 'dev:' + id, lock = LockService.getScriptLock(); lock.waitLock(20000);
  try {
    var raw = props.getProperty(k), rec = raw ? JSON.parse(raw) : null;
    if (b.action === '/off') { props.deleteProperty(k); return out({ ok: true }); }
    if (b.action === '/sync') {
      var sub = b.sub || (rec && rec.sub); if (!sub || !sub.endpoint || !sub.keys) return out({ error: 'no subscription' });
      if (!rec && Object.keys(props.getProperties()).filter(function (x) { return x.indexOf('dev:') === 0; }).length >= 5) return out({ error: 'too many devices' });
      if (b.adbKey) props.setProperty('ADB_KEY', String(b.adbKey));
      var flights = (Array.isArray(b.flights) ? b.flights : []).slice(0, 20).map(function (f) { return { id: String(f.id), no: String(f.no), from: String(f.from), to: String(f.to), dep: +f.dep, arr: +f.arr, tz: String(f.tz || 'UTC'), fromName: String(f.fromName || f.from), toName: String(f.toName || f.to), intl: !!f.intl, delay: +f.delay || 0, gate: String(f.gate || ''), terminal: String(f.terminal || ''), cancelled: !!f.cancelled }; });
      var old = (rec && rec.st) || {}, st = {}; flights.forEach(function (f) { if (old[f.id]) st[f.id] = old[f.id]; });
      props.setProperty(k, JSON.stringify({ sub: sub, flights: flights, settings: b.settings || {}, st: st, sent: (rec && rec.sent) || {} }));
      return out({ ok: true, flights: flights.length });
    }
    if (b.action === '/test') {
      if (!rec) return out({ error: 'not registered' });
      var r = sendPush(rec.sub, { title: 'WingMan alerts are on', body: 'You will get delay, gate and reminder alerts here.', tag: 'test', url: '#alerts' });
      return out({ ok: r.getResponseCode() < 300, status: r.getResponseCode(), detail: r.getResponseCode() < 300 ? '' : r.getContentText().slice(0, 200) });
    }
    return out({ error: 'not found' });
  } finally { lock.releaseLock(); }
}
function tick() {
  var props = PropertiesService.getScriptProperties(), all = props.getProperties(), now = Date.now();
  Object.keys(all).filter(function (k) { return k.indexOf('dev:') === 0; }).forEach(function (k) {
    var rec = JSON.parse(all[k]), gone = runDevice(rec, now);
    if (gone) props.deleteProperty(k); else props.setProperty(k, JSON.stringify(rec));
  });
}
/* Run once from the editor: creates the 10-minute trigger and the push keys. */
function setup() {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === 'tick') ScriptApp.deleteTrigger(t); });
  ScriptApp.newTrigger('tick').timeBased().everyMinutes(10).create();
  Logger.log('Ready. Public key: ' + b64u(vapidKeys().pub));
}
