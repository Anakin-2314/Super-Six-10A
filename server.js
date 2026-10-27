// SUPER SIX - zero-knowledge relay.
//  * Main room: the 6 fixed members, log in with a personal ID (members.json).
//  * Guest rooms: members create a link; anyone with it joins by nickname; auto-expire; anyone can burn.
// The server only forwards ciphertext. It never sees keys or plaintext, and stores nothing.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const NAMES = ['TANAY', 'PAVAN', 'HARSHIL', 'AKSHIYAA', 'RIDDHIMA', 'VAIBHAVI'];
const CFG = path.join(__dirname, 'members.json');
const PUBDIR = path.join(__dirname, 'public');
const MAX_BYTES = 12 * 1024 * 1024; // room for files up to ~4 MB after encryption + base64

function rand(n) {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = ''; for (const b of crypto.randomBytes(n)) s += A[b % A.length]; return s;
}
// On a host without a persistent disk, put the whole members.json text in the MEMBERS_JSON environment variable.
const FROM_ENV = !!process.env.MEMBERS_JSON;
if (!FROM_ENV && !fs.existsSync(CFG)) {
  const members = {};
  for (const n of NAMES) members[n] = `${n.replace(/[^A-Z]/g, '').slice(0, 6)}-${rand(4)}-${rand(4)}-${rand(4)}`;
  fs.writeFileSync(CFG, JSON.stringify({ roomKey: crypto.randomBytes(24).toString('base64url'), members }, null, 2), { mode: 0o600 });
  console.log('Created members.json (keep it private).');
}
const cfg = JSON.parse(FROM_ENV ? process.env.MEMBERS_JSON : fs.readFileSync(CFG, 'utf8'));
// Add TURN servers here if calls fail on strict networks, e.g. {"urls":"turn:host:3478","username":"u","credential":"p"}
const ICE = cfg.iceServers || [{ urls: 'stun:stun.l.google.com:19302' }];
const byId = new Map(Object.entries(cfg.members).map(([name, id]) => [id.toUpperCase(), name]));

// ---------- rooms ----------
class Room {
  constructor(o) {
    Object.assign(this, { id: null, fixed: false, names: null, max: 6, owner: null, expires: null }, o);
    this.mem = new Map(); // name -> { ws, pub, tok }
    this.timer = null; this.emptyTimer = null;
  }
  presence() {
    const members = this.fixed
      ? this.names.map(n => ({ name: n, online: this.mem.has(n), pub: this.mem.has(n) ? this.mem.get(n).pub : null }))
      : [...this.mem].map(([n, v]) => ({ name: n, online: true, pub: v.pub }));
    for (const v of this.mem.values()) send(v.ws, { type: 'presence', members });
  }
}
const main = new Room({ fixed: true, names: NAMES, max: 6 });
const guests = new Map(); // id -> Room

const send = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
function burn(room, reason) {
  clearTimeout(room.timer); clearTimeout(room.emptyTimer);
  for (const v of room.mem.values()) { send(v.ws, { type: 'burned', reason }); try { v.ws.close(4005, 'burned'); } catch {} }
  room.mem.clear(); guests.delete(room.id);
}

// ---------- http ----------
const asset = (f, type) => fs.existsSync(path.join(PUBDIR, f)) ? [fs.readFileSync(path.join(PUBDIR, f)), type] : null;
const files = {
  '/logo.jpg': asset('logo.jpg', 'image/jpeg'),
  '/icon-192.png': asset('icon-192.png', 'image/png'),
  '/icon-512.png': asset('icon-512.png', 'image/png'),
  '/manifest.webmanifest': asset('manifest.webmanifest', 'application/manifest+json'),
};
const page = fs.readFileSync(path.join(PUBDIR, 'index.html'));
const SEC = {
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
};
const server = http.createServer((req, res) => {
  const p = req.url.split('?')[0].split('#')[0];
  if (files[p]) { res.writeHead(200, { 'Content-Type': files[p][1], 'Cache-Control': 'public, max-age=3600', ...SEC }); return res.end(files[p][0]); }
  if (p === '/' || /^\/g\/[A-Za-z0-9]{8,32}$/.test(p)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SEC }); return res.end(page);
  }
  res.writeHead(404, SEC); res.end('Not found');
});
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: MAX_BYTES });

const okIv = s => typeof s === 'string' && s.length > 0 && s.length < 64;
const okCt = s => typeof s === 'string' && s.length > 0 && s.length < MAX_BYTES - 1024;

wss.on('connection', (ws) => {
  let room = null, me = null;
  let tokens = 10, last = Date.now(), sigTok = 60, sigLast = Date.now();
  const authTimer = setTimeout(() => { if (!me) ws.close(4002, 'auth timeout'); }, 8000);
  const deny = (type, reason) => setTimeout(() => { send(ws, { type, reason }); ws.close(4003, 'denied'); }, 600);

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }

    // ----- not logged in yet -----
    if (!me) {
      if (m.type === 'auth' && typeof m.id === 'string') {
        const name = byId.get(m.id.trim().toUpperCase());
        if (!name) return deny('denied');
        const old = main.mem.get(name);
        if (old && old.ws !== ws) { send(old.ws, { type: 'replaced' }); old.ws.close(4004, 'replaced'); }
        clearTimeout(authTimer); room = main; me = name;
        main.mem.set(name, { ws, pub: null, tok: null });
        send(ws, { type: 'ok', name, guest: false, ice: ICE });
        main.presence();
      } else if (m.type === 'gjoin') {
        const g = guests.get(String(m.room || '').toUpperCase());
        if (!g) return deny('gdenied', 'Room not found, expired or already burned.');
        let nick = String(m.nick || '').trim();
        if (!/^[\p{L}\p{N} ._-]{1,16}$/u.test(nick)) return deny('gdenied', 'Nickname: 1-16 letters, numbers, space . _ -');
        const tok = String(m.tok || '').slice(0, 64);
        const ex = g.mem.get(nick);
        const same = ex && ex.tok === tok;
        if (!same && g.mem.size >= g.max) return deny('gdenied', 'This room is full.');
        if (ex && !same) { let i = 2; while (g.mem.has(`${nick.slice(0, 13)} ${i}`)) i++; nick = `${nick.slice(0, 13)} ${i}`; }
        if (same) { send(ex.ws, { type: 'replaced' }); ex.ws.close(4004, 'replaced'); }
        clearTimeout(authTimer); clearTimeout(g.emptyTimer); room = g; me = nick;
        g.mem.set(nick, { ws, pub: null, tok });
        send(ws, { type: 'ok', name: nick, guest: true, expires: g.expires, ice: ICE });
        g.presence();
      }
      return;
    }

    // ----- rate limit (calls signalling has its own bucket; big files cost more) -----
    const now = Date.now();
    if (m.type === 'sig') {
      sigTok = Math.min(60, sigTok + (now - sigLast) / 100); sigLast = now;
      if (sigTok < 1) return; sigTok -= 1;
    } else {
      tokens = Math.min(10, tokens + (now - last) / 500); last = now;
      const cost = Math.min(8, 1 + Math.floor(raw.length / 524288));
      if (tokens < cost) return; tokens -= cost;
    }

    if (m.type === 'pub' && typeof m.pub === 'string' && m.pub.length < 300) {
      room.mem.get(me).pub = m.pub; room.presence();
    } else if (m.type === 'group' && okIv(m.iv) && okCt(m.ct)) {
      for (const [n, v] of room.mem) if (n !== me) send(v.ws, { type: 'group', from: me, iv: m.iv, ct: m.ct });
    } else if ((m.type === 'dm' || m.type === 'sig') && typeof m.to === 'string' && m.to !== me && okIv(m.iv) && okCt(m.ct) && (m.type === 'dm' || m.ct.length < 8192)) {
      const t = room.mem.get(m.to);
      if (!t) return send(ws, { type: 'offline', to: m.to });
      send(t.ws, { type: m.type, from: me, iv: m.iv, ct: m.ct });
    } else if (m.type === 'burn' && room !== main) {
      burn(room, 'burned');
    } else if (m.type === 'mkguest' && room === main) {
      const ttl = [15, 60, 240, 1440].includes(+m.ttl) ? +m.ttl : 60;
      const max = Math.min(8, Math.max(2, parseInt(m.max) || 6));
      const mine = [...guests.values()].filter(g => g.owner === me).length;
      if (mine >= 5 || guests.size >= 50) return send(ws, { type: 'guesterr', reason: 'Too many open guest rooms. Burn one first.' });
      const g = new Room({ id: rand(10), max, owner: me, expires: Date.now() + ttl * 60000 });
      g.timer = setTimeout(() => burn(g, 'expired'), ttl * 60000);
      g.emptyTimer = setTimeout(() => burn(g, 'unused'), 10 * 60000); // nobody joined in 10 min
      guests.set(g.id, g);
      send(ws, { type: 'guestroom', id: g.id, expires: g.expires, max });
    } else if (m.type === 'setid' && room === main && typeof m.id === 'string') {
      const id = m.id.trim().toUpperCase();
      if (!/^[A-Z0-9][A-Z0-9 _.-]{5,39}$/.test(id)) return send(ws, { type: 'iderr', reason: 'Use 6-40 letters, numbers, - _ . or spaces.' });
      if (byId.has(id) && byId.get(id) !== me) return send(ws, { type: 'iderr', reason: 'That ID is already taken.' });
      if (FROM_ENV) return send(ws, { type: 'iderr', reason: 'IDs are set on the host (MEMBERS_JSON) and cannot be changed here.' });
      byId.delete(String(cfg.members[me]).toUpperCase());
      byId.set(id, me); cfg.members[me] = id;
      fs.writeFileSync(CFG, JSON.stringify(cfg, null, 2), { mode: 0o600 });
      send(ws, { type: 'idok' });
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (!room || !me) return;
    const v = room.mem.get(me);
    if (!v || v.ws !== ws) return;
    room.mem.delete(me);
    if (!room.fixed && room.mem.size === 0) room.emptyTimer = setTimeout(() => burn(room, 'empty'), 120000);
    else room.presence();
  });
});

server.listen(PORT, () => {
  console.log(`SUPER SIX running on http://localhost:${PORT}`);
  console.log(`Invite link (room key included): http://localhost:${PORT}/#${cfg.roomKey}`);
});
