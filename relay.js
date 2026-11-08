/* MGH Studio relay crypto (browser + Node). Same algorithm as tools/relay_lib.py.
   The PIN never leaves the device. From the PIN we derive: two secret mailbox names (orders in, status out), an encryption key and a signing key.
   Message = "v1." + nonce + "." + ciphertext + "." + tag   (all base64url)
   cipher = plaintext XOR HMAC-SHA256(kEnc, nonce || counter_be32) blocks ; tag = HMAC-SHA256(kMac, "v1" || nonce || ciphertext) */
(function (root) {
  'use strict';
  const enc = new TextEncoder(), dec = new TextDecoder();
  const subtle = (root.crypto || require('crypto').webcrypto).subtle;
  const rnd = (n) => (root.crypto || require('crypto').webcrypto).getRandomValues(new Uint8Array(n));
  const b64 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
  const hex = (u8) => Array.from(u8).map((x) => x.toString(16).padStart(2, '0')).join('');
  const concat = (...a) => { const n = a.reduce((t, x) => t + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
  async function hmac(key, data) {
    const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', k, data));
  }
  async function derive(pin) {
    const km = await subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
    const master = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('mgh-studio-v1'), iterations: 200000 }, km, 256));
    return keysFromMaster(master);
  }
  async function keysFromMaster(master) {
    const lab = async (l) => hex(await hmac(master, enc.encode(l)));
    return {
      topicIn: 'mgh-' + (await lab('topic-in')).slice(0, 32),
      topicOut: 'mgh-' + (await lab('topic-out')).slice(0, 32),
      kEnc: await hmac(master, enc.encode('enc')),
      kMac: await hmac(master, enc.encode('mac')),
    };
  }
  async function keystream(kEnc, nonce, len) {
    const out = new Uint8Array(len);
    for (let i = 0, c = 0; i < len; i += 32, c++) {
      const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, c);
      const blk = await hmac(kEnc, concat(nonce, ctr));
      out.set(blk.subarray(0, Math.min(32, len - i)), i);
    }
    return out;
  }
  async function seal(keys, obj, nonceOverride) {
    const pt = enc.encode(JSON.stringify(obj));
    const nonce = nonceOverride || rnd(16);
    const ks = await keystream(keys.kEnc, nonce, pt.length);
    const ct = new Uint8Array(pt.length); for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
    const tag = await hmac(keys.kMac, concat(enc.encode('v1'), nonce, ct));
    return 'v1.' + b64(nonce) + '.' + b64(ct) + '.' + b64(tag);
  }
  async function open(keys, msg) {
    try {
      const p = String(msg).trim().split('.');
      if (p.length !== 4 || p[0] !== 'v1') return null;
      const nonce = unb64(p[1]), ct = unb64(p[2]), tag = unb64(p[3]);
      const want = await hmac(keys.kMac, concat(enc.encode('v1'), nonce, ct));
      if (want.length !== tag.length) return null;
      let diff = 0; for (let i = 0; i < want.length; i++) diff |= want[i] ^ tag[i];
      if (diff !== 0) return null;
      const ks = await keystream(keys.kEnc, nonce, ct.length);
      const pt = new Uint8Array(ct.length); for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
      return JSON.parse(dec.decode(pt));
    } catch (e) { return null; }
  }
  root.MghRelay = { derive, keysFromMaster, seal, open, rnd, hex };
})(typeof window !== 'undefined' ? window : globalThis);
if (typeof module !== 'undefined') module.exports = globalThis.MghRelay;
