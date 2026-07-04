/**
 * AES-256-GCM backend — web.
 *
 * Same wire format as the native backend (12-byte IV, ct ‖ 16-byte tag):
 * WebCrypto's AES-GCM appends the tag to the ciphertext exactly like
 * @noble/ciphers' gcm(), so the two paths are byte-for-byte interchangeable.
 *
 * Async paths use crypto.subtle (native browser crypto, and the browser may
 * run it off the main thread). The sync exports have no subtle equivalent —
 * they stay on noble, which browsers JIT well beyond Hermes speeds; callers
 * that move real data (media binaries) all go through the async variants.
 * noble also backstops the async paths for insecure contexts (plain-http dev
 * hosts have no crypto.subtle) — and re-running a failed subtle decrypt
 * through noble keeps the "throws on bad tag" contract intact either way.
 */

import { gcm } from '@noble/ciphers/aes';

export function gcmEncrypt(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return gcm(key, iv).encrypt(plaintext);
}

export function gcmDecrypt(key: Uint8Array, iv: Uint8Array, ctAndTag: Uint8Array): Uint8Array {
  return gcm(key, iv).decrypt(ctAndTag);
}

const subtle: SubtleCrypto | undefined = globalThis.crypto?.subtle;

export async function gcmEncryptAsync(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (subtle) {
    try {
      const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
      return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, k, plaintext));
    } catch {
      // Environment quirk (blocked subtle, detached buffer, …) — noble below.
    }
  }
  return gcm(key, iv).encrypt(plaintext);
}

export async function gcmDecryptAsync(key: Uint8Array, iv: Uint8Array, ctAndTag: Uint8Array): Promise<Uint8Array> {
  if (subtle) {
    try {
      const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
      return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv }, k, ctAndTag));
    } catch {
      // subtle reports a bad auth tag as a bare OperationError —
      // indistinguishable from an environment failure. Re-run through noble:
      // genuinely bad data throws there too (contract preserved), and an
      // environment hiccup still decrypts. Only failure paths pay this.
    }
  }
  return gcm(key, iv).decrypt(ctAndTag);
}
