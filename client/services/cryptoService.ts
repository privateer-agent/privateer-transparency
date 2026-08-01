/**
 * Crypto Service — E2EE Foundation
 *
 * Every account has a 32-byte AES-256 master key, generated client-side at
 * signup, never transmitted to the server. The master key is encrypted with a
 * KEK derived locally from one of two sources:
 *
 *   - Password user → KEK = Argon2id(password, kdfSalt, kdfParams)
 *   - Wallet user   → KEK = HKDF-SHA256(wallet.signMessage("Privateer vault key v2 for <pubkey>"))
 *
 * The wrapped master key (AES-256-GCM ciphertext) is stored on the server and
 * fetched at login. Unwrapping happens locally; the KEK is discarded after use.
 *
 * Forgetting the password = data is permanently inaccessible. There is no
 * recovery path.
 *
 * Local key cache (password users only — wallet users re-derive each cold start):
 *   @privateer/master_key_raw  ← 32-byte AES key (session cache)
 */

import './internal/randomPolyfill';
// AES-GCM backend: react-native-quick-crypto (OpenSSL/JSI) on native,
// crypto.subtle on web, @noble/ciphers as the universal fallback. All three
// share one wire format (12-byte IV, ct ‖ 16-byte tag) — see internal/aesGcm.
import { gcmEncrypt, gcmDecrypt, gcmEncryptAsync, gcmDecryptAsync } from './internal/aesGcm';
import { Buffer } from 'buffer';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { deriveArgon2idHash } from './internal/argon2';
import { secureKv } from './internal/secureKv';
import { brand } from '../config/brand';
import { settleAll } from '../utils/settleAll';

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

const MASTER_KEY_KEY = `${brand.storagePrefix}/master_key_raw`;

// ---------------------------------------------------------------------------
// KDF parameters
// ---------------------------------------------------------------------------

export interface KdfParams {
  algorithm: 'argon2id';
  m: number; // memory in KiB
  t: number; // iterations
  p: number; // parallelism
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  algorithm: 'argon2id',
  m: 65536, // 64 MiB
  t: 3,
  p: 1,
};

// Wallet KEK message — the exact UTF-8 string a Solana wallet must sign to
// produce its KEK. It embeds the wallet's Ed25519 public key (lowercase hex)
// so a signature for account A cannot be reused to derive account B's KEK, and
// a signature any other domain coaxes the wallet into producing over a
// different message is structurally incompatible.

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// Buffer's table-driven codec rather than btoa/atob + char loops: these two
// run on every E2EE payload, including multi-MB media, and on native the atob
// polyfill is itself Buffer-backed (polyfills.js) — the old path decoded to a
// binary string only to walk it back out byte by byte. Output is standard
// padded base64 either way, so nothing on the wire or on disk changes.
export function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength).toString('base64');
}

export function fromBase64(b64: string): Uint8Array {
  const buf = Buffer.from(b64, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

let _masterKey: Uint8Array | null = null;

export function isMasterKeyLoaded(): boolean {
  return _masterKey !== null;
}

export function getMasterKey(): Uint8Array | null {
  return _masterKey;
}

/**
 * Best-effort guarantee that the in-memory master key is available, recovering
 * it from secure storage if a cold-launch race or session churn dropped it.
 * Write paths that must encrypt before persisting (E2EE contract) should call
 * this instead of bare `isMasterKeyLoaded()` so they don't silently fall back
 * to sending plaintext the server will reject.
 */
export async function ensureMasterKeyLoaded(): Promise<boolean> {
  if (_masterKey !== null) return true;
  return loadPersistedKey();
}

// Listeners fire whenever the in-memory master key flips loaded/unloaded.
// Used by UI that mounts before the key is unwrapped (cold-launch races) so
// decrypt effects can retry once the key arrives.
const _keyListeners = new Set<(loaded: boolean) => void>();
function _emitKeyState(): void {
  const loaded = _masterKey !== null;
  _keyListeners.forEach(fn => {
    try { fn(loaded); } catch { /* listener errors are non-fatal */ }
  });
}
export function subscribeMasterKeyState(listener: (loaded: boolean) => void): () => void {
  _keyListeners.add(listener);
  return () => { _keyListeners.delete(listener); };
}

// ---------------------------------------------------------------------------
// Master key generation, wrapping, persistence
// ---------------------------------------------------------------------------

export function generateMasterKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function generateKdfSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Derive a 32-byte KEK from a user password using Argon2id.
 *
 * Backed by react-native-argon2 (native C implementation), 10–60× faster than
 * the pure-JS @noble/hashes path on Hermes. The salt is passed as hex with
 * `saltEncoding: 'hex'` so the native side decodes it back to the exact same
 * raw bytes the JS version used — wire-format compatible with existing
 * accounts.
 */
export async function deriveKekFromPassword(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  if (params.algorithm !== 'argon2id') {
    throw new Error(`Unsupported KDF algorithm: ${params.algorithm}`);
  }
  return deriveArgon2idHash(password, salt, params);
}

/**
 * Derive a 32-byte KEK from a 64-byte Ed25519 signature produced by the user's
 * Solana wallet over WALLET_KEK_MESSAGE. The wallet's private key never leaves
 * the wallet app's secure enclave.
 */
export function deriveKekFromWalletSignature(signatureBytes: Uint8Array): Uint8Array {
  const salt = sha256('privateer-wallet-kek');
  const info = new TextEncoder().encode('aes-256-gcm');
  return hkdf(sha256, signatureBytes, salt, info, 32);
}

/**
 * The exact messages a wallet signs to produce its KEK. Defined in
 * wallets/vaultMessage.ts — dependency-free so they can be unit tested — and
 * re-exported here because cryptoService is the public surface for key
 * operations (CLAUDE.md §5).
 */
export { getWalletKekMessage, getWalletKekMessageV3 } from './wallets/vaultMessage';

/**
 * Wrap a 32-byte master key with a 32-byte KEK using AES-256-GCM.
 * Output format: base64 of (12-byte IV || ciphertext || 16-byte auth tag).
 */
export function wrapMasterKey(masterKey: Uint8Array, kek: Uint8Array): string {
  if (masterKey.length !== 32) throw new Error('Master key must be 32 bytes');
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = gcmEncrypt(kek, iv, masterKey);
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toBase64(out);
}

/**
 * Unwrap a wrapped master key produced by `wrapMasterKey`.
 * Throws if the KEK is wrong (GCM auth tag verification fails).
 */
export function unwrapMasterKey(wrapped: string, kek: Uint8Array): Uint8Array {
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  const blob = fromBase64(wrapped);
  if (blob.length < 12 + 16) throw new Error('Wrapped master key is too short');
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  return gcmDecrypt(kek, iv, ct);
}

/**
 * Store raw master key bytes in memory. When `persist` is true the bytes are
 * also written to EncryptedStorage so subsequent cold starts can skip the
 * unwrap prompt. Both password and wallet accounts persist; the cache is
 * cleared on logout via `clearSessionKeyState`.
 */
export async function setMasterKey(rawBytes: Uint8Array, opts: { persist: boolean }): Promise<void> {
  if (rawBytes.length !== 32) throw new Error('Master key must be 32 bytes');
  _masterKey = rawBytes;
  _emitKeyState();
  if (opts.persist) {
    await secureKv.setItem(MASTER_KEY_KEY, toBase64(rawBytes));
  } else {
    await secureKv.removeItem(MASTER_KEY_KEY).catch(() => {});
  }
}

/** Restore the master key from EncryptedStorage (warm start). */
export async function loadPersistedKey(): Promise<boolean> {
  try {
    const stored = await secureKv.getItem(MASTER_KEY_KEY);
    if (!stored) return false;
    _masterKey = fromBase64(stored);
    _emitKeyState();
    return true;
  } catch {
    return false;
  }
}

export function clearMasterKey(): void {
  _masterKey = null;
  _emitKeyState();
  secureKv.removeItem(MASTER_KEY_KEY).catch(() => {});
}

export async function clearMasterKeyAsync(): Promise<void> {
  _masterKey = null;
  _emitKeyState();
  await secureKv.removeItem(MASTER_KEY_KEY);
}

/**
 * Sign-out wipe. Drops the in-memory master key and the cached raw key so the
 * next session must re-authenticate and re-unwrap.
 */
export async function clearSessionKeyState(): Promise<void> {
  _masterKey = null;
  _emitKeyState();
  await secureKv.removeItem(MASTER_KEY_KEY);
}

/**
 * Full wipe of all key material and local user data. Called when a different
 * user logs in so they cannot see any trace of the previous user's data.
 */
export async function clearAllKeyMaterial(): Promise<void> {
  _masterKey = null;
  _emitKeyState();
  const p = brand.storagePrefix;
  await settleAll([
    secureKv.removeItem(MASTER_KEY_KEY),
    secureKv.removeItem(`${p}/local_chats_index`),
    secureKv.removeItem(`${p}/local_projects_index`),
    secureKv.removeItem(`${p}/project_files_index`),
    secureKv.removeItem(`${p}/cargo_index`),
    secureKv.removeItem(`${p}/memories`),
    secureKv.removeItem(`${p}/personalization`),
    secureKv.removeItem(`${p}/preferred_model_id`),
    secureKv.removeItem(`${p}/preferred_model_name`),
    secureKv.removeItem(`${p}/recent_model_ids`),
    secureKv.removeItem(`${p}/favorite_model_ids`),
    secureKv.removeItem(`${p}/vision_model_id`),
    secureKv.removeItem(`${p}/vision_model_name`),
    secureKv.removeItem(`${p}/image_gen_model_id`),
    secureKv.removeItem(`${p}/image_gen_model_name`),
    secureKv.removeItem(`${p}/video_gen_model_id`),
    secureKv.removeItem(`${p}/video_gen_model_name`),
    secureKv.removeItem(`${p}/balance_cache`),
  ]);
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers (used everywhere user content is encrypted)
// ---------------------------------------------------------------------------

/**
 * Encrypt a UTF-8 string with an explicit 32-byte key. Returns a JSON string:
 * `{ iv, ct }` (both base64). Used by the master-key path (`encryptText`) and
 * by the share-snapshot path, which encrypts under a standalone share key.
 */
export function encryptTextWithKey(plaintext: string, key: Uint8Array): string {
  if (key.length !== 32) throw new Error('Encryption key must be 32 bytes');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = gcmEncrypt(key, iv, new TextEncoder().encode(plaintext));
  return JSON.stringify({ iv: toBase64(iv), ct: toBase64(ct) });
}

export function decryptTextWithKey(payload: string, key: Uint8Array): string {
  if (key.length !== 32) throw new Error('Decryption key must be 32 bytes');
  const { iv, ct } = JSON.parse(payload);
  const plaintext = gcmDecrypt(key, fromBase64(iv), fromBase64(ct));
  return new TextDecoder().decode(plaintext);
}

export function encryptBinaryWithKey(buf: Uint8Array, key: Uint8Array): { iv: string; ct: string } {
  if (key.length !== 32) throw new Error('Encryption key must be 32 bytes');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = gcmEncrypt(key, iv, buf);
  return { iv: toBase64(iv), ct: toBase64(ct) };
}

export function decryptBinaryWithKey(iv: string, ct: string, key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('Decryption key must be 32 bytes');
  return gcmDecrypt(key, fromBase64(iv), fromBase64(ct));
}

/**
 * Encrypt a UTF-8 string. Returns a JSON string: `{ iv, ct }` (both base64).
 *
 * The async master-key helpers below route through the async backend variants
 * (not the sync *WithKey siblings) so web gets crypto.subtle for real
 * payloads; on native both variants hit the same OpenSSL path.
 */
export async function encryptText(plaintext: string): Promise<string> {
  if (!_masterKey) throw new Error('Master key not loaded.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await gcmEncryptAsync(_masterKey, iv, new TextEncoder().encode(plaintext));
  return JSON.stringify({ iv: toBase64(iv), ct: toBase64(ct) });
}

export async function decryptText(payload: string): Promise<string> {
  if (!_masterKey) throw new Error('Master key not loaded.');
  const { iv, ct } = JSON.parse(payload);
  const plaintext = await gcmDecryptAsync(_masterKey, fromBase64(iv), fromBase64(ct));
  return new TextDecoder().decode(plaintext);
}

export async function encryptBinary(buf: Uint8Array): Promise<{ iv: string; ct: string }> {
  if (!_masterKey) throw new Error('Master key not loaded.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await gcmEncryptAsync(_masterKey, iv, buf);
  return { iv: toBase64(iv), ct: toBase64(ct) };
}

export async function decryptBinary(iv: string, ct: string): Promise<Uint8Array> {
  if (!_masterKey) throw new Error('Master key not loaded.');
  return gcmDecryptAsync(_masterKey, fromBase64(iv), fromBase64(ct));
}

export async function decryptBinaryRaw(iv: string, ctBytes: Uint8Array): Promise<Uint8Array> {
  if (!_masterKey) throw new Error('Master key not loaded.');
  return gcmDecryptAsync(_masterKey, fromBase64(iv), ctBytes);
}

// ---------------------------------------------------------------------------
// Share keys — standalone symmetric keys for public chat snapshots.
//
// A shared chat is re-encrypted under a fresh 32-byte key that lives in the
// share URL's #fragment (never sent to the server), so the server keeps storing
// ciphertext only while anyone with the full link can decrypt locally. The
// share key is also wrapped under the owner's master key (`wrapMasterKey`) and
// stored server-side so the owner can re-open/update the snapshot later.
// ---------------------------------------------------------------------------

export function generateShareKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypt binary under an explicit key, returning the raw GCM ciphertext bytes
 * (ct ‖ tag) and a separate base64 IV. This mirrors how media binaries are
 * stored in S3 (object body = raw ciphertext, IV kept alongside as `encIv`),
 * so share media uploads/downloads use the same on-the-wire shape.
 */
export function encryptBinaryRawWithKey(buf: Uint8Array, key: Uint8Array): { iv: string; ct: Uint8Array } {
  if (key.length !== 32) throw new Error('Encryption key must be 32 bytes');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = gcmEncrypt(key, iv, buf);
  return { iv: toBase64(iv), ct };
}

export function decryptBinaryRawWithKey(iv: string, ctBytes: Uint8Array, key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new Error('Decryption key must be 32 bytes');
  return gcmDecrypt(key, fromBase64(iv), ctBytes);
}

/** Base64url (no padding) — safe to drop into a URL fragment. */
export function shareKeyToFragment(key: Uint8Array): string {
  return toBase64(key).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function shareKeyFromFragment(fragment: string): Uint8Array {
  const b64 = fragment.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const key = fromBase64(padded);
  if (key.length !== 32) throw new Error('Invalid share key');
  return key;
}
