/**
 * AES-256-GCM backend — native (iOS / Android).
 *
 * Wire format everywhere: 12-byte IV, ciphertext with the 16-byte auth tag
 * APPENDED (ct ‖ tag). That's what @noble/ciphers' gcm() emits and what
 * WebCrypto's subtle.encrypt emits, so the three backends are byte-for-byte
 * interchangeable — no data migration across app versions or platforms.
 *
 * react-native-quick-crypto is OpenSSL over JSI — 2–3 orders of magnitude
 * faster than pure-JS noble on Hermes (no JIT), which is what makes multi-MB
 * media decrypts feasible without freezing the JS thread. noble stays as the
 * fallback so a JS-only OTA update landing on a binary built WITHOUT the
 * native module degrades to slow, never to broken (E2EE data must always be
 * reachable).
 */

import { gcm } from '@noble/ciphers/aes';

const TAG_LEN = 16;

type QuickCrypto = typeof import('react-native-quick-crypto').default;

const quick: QuickCrypto | null = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('react-native-quick-crypto');
    const candidate = (mod?.default ?? mod) as QuickCrypto;
    // Probe: constructing a cipher touches the C++ installer, which throws if
    // the native module isn't linked into this binary. Fail once, here, and
    // stay on noble for the whole session.
    candidate.createCipheriv('aes-256-gcm', new Uint8Array(32) as never, new Uint8Array(12) as never);
    return candidate;
  } catch {
    return null;
  }
})();

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

/** Encrypt; returns ct ‖ tag. */
export function gcmEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (quick) {
    const cipher = quick.createCipheriv('aes-256-gcm', key as never, iv as never);
    const head = new Uint8Array(cipher.update(plaintext as never) as ArrayBuffer);
    const tail = new Uint8Array(cipher.final() as ArrayBuffer);
    const tag = new Uint8Array(cipher.getAuthTag());
    return concat(head, tail, tag);
  }
  return gcm(key, iv).encrypt(plaintext);
}

/** Decrypt ct ‖ tag; throws when the auth tag doesn't verify (wrong key/data). */
export function gcmDecrypt(key: Uint8Array, iv: Uint8Array, ctAndTag: Uint8Array): Uint8Array {
  if (quick) {
    if (ctAndTag.length < TAG_LEN) throw new Error('Ciphertext too short');
    const ct = ctAndTag.subarray(0, ctAndTag.length - TAG_LEN);
    const tag = ctAndTag.subarray(ctAndTag.length - TAG_LEN);
    const decipher = quick.createDecipheriv('aes-256-gcm', key as never, iv as never);
    decipher.setAuthTag(tag as never);
    const head = new Uint8Array(decipher.update(ct as never) as ArrayBuffer);
    const tail = new Uint8Array(decipher.final() as ArrayBuffer); // throws on bad tag
    return concat(head, tail);
  }
  return gcm(key, iv).decrypt(ctAndTag);
}

// Async variants exist for the web backend's sake (WebCrypto is async-only);
// on native the work is synchronous either way, but at OpenSSL speed that's
// microseconds-per-100KB — no yielding needed.
export async function gcmEncryptAsync(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return gcmEncrypt(key, iv, plaintext);
}

export async function gcmDecryptAsync(key: Uint8Array, iv: Uint8Array, ctAndTag: Uint8Array): Promise<Uint8Array> {
  return gcmDecrypt(key, iv, ctAndTag);
}
