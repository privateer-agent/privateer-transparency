// Web shim for react-native-encrypted-storage.
//
// On native, EncryptedStorage maps to iOS Keychain / Android Keystore — hardware
// backed, isolated from app process memory. The browser has no equivalent. We
// store values in IndexedDB and wrap them with a non-extractable AES-GCM
// CryptoKey kept in the same IDB. This is not protection against XSS in the
// origin (an attacker with script execution can call decrypt with the handle
// just like we can) — it only prevents passive disclosure of raw bytes from
// disk-level IDB exports. Real defenses are origin isolation, CSP, and not
// running untrusted code.
//
// The store is per-origin and per-browser-profile; the user-visible consequence
// is documented in the storage backend "decide before starting" item in the
// web port plan.

const DB_NAME = 'privateer-secure-kv';
const DB_VERSION = 1;
const STORE_META = 'meta';
const STORE_KV = 'kv';
const KEY_HANDLE_ID = 'wrap-key';

interface WrappedValue {
  iv: Uint8Array;
  ct: Uint8Array;
}

let _dbPromise: Promise<IDBDatabase> | null = null;
let _keyPromise: Promise<CryptoKey> | null = null;

function openDb(): Promise<IDBDatabase> {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_META)) db.createObjectStore(STORE_META);
      if (!db.objectStoreNames.contains(STORE_KV)) db.createObjectStore(STORE_KV);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return _dbPromise;
}

function tx<T>(
  store: string,
  mode: IDBTransactionMode,
  fn: (s: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openDb().then(
    db =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(store, mode);
        const req = fn(t.objectStore(store));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      }),
  );
}

async function getOrCreateWrapKey(): Promise<CryptoKey> {
  if (_keyPromise) return _keyPromise;
  _keyPromise = (async () => {
    const existing = (await tx<CryptoKey | undefined>(STORE_META, 'readonly', s =>
      s.get(KEY_HANDLE_ID),
    )) as CryptoKey | undefined;
    if (existing) return existing;
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable — handle persists in IDB, raw bytes never reach JS
      ['encrypt', 'decrypt'],
    );
    await tx(STORE_META, 'readwrite', s => s.put(key, KEY_HANDLE_ID));
    return key;
  })();
  return _keyPromise;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

async function encryptValue(plaintext: string): Promise<WrappedValue> {
  const key = await getOrCreateWrapKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext)),
  );
  return { iv, ct };
}

async function decryptValue(wrapped: WrappedValue): Promise<string> {
  const key = await getOrCreateWrapKey();
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrapped.iv as BufferSource }, key, wrapped.ct as BufferSource);
  return dec.decode(pt);
}

export const secureKv = {
  async getItem(key: string): Promise<string | null> {
    const wrapped = (await tx<WrappedValue | undefined>(STORE_KV, 'readonly', s =>
      s.get(key),
    )) as WrappedValue | undefined;
    if (!wrapped) return null;
    try {
      return await decryptValue(wrapped);
    } catch {
      // Wrap key rotated or value corrupted — drop the stale entry.
      await tx(STORE_KV, 'readwrite', s => s.delete(key));
      return null;
    }
  },

  async setItem(key: string, value: string): Promise<void> {
    const wrapped = await encryptValue(value);
    await tx(STORE_KV, 'readwrite', s => s.put(wrapped, key));
  },

  async removeItem(key: string): Promise<void> {
    await tx(STORE_KV, 'readwrite', s => s.delete(key));
  },
};
