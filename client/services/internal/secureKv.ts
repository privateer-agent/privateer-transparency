// The ONLY sanctioned door to secure key-value storage. Import this, never
// `react-native-encrypted-storage` directly: metro.config.js resolves that
// package to a Proxy no-op on web (WEB_NATIVE_STUBS), so a direct importer
// reads back null and writes into the void — silently, with no error to catch.
// secureKv.web.ts backs the same three-method API with IndexedDB + AES-GCM.
import EncryptedStorage from 'react-native-encrypted-storage';

export const secureKv = {
  getItem: (key: string): Promise<string | null> => EncryptedStorage.getItem(key),
  // Presence, independent of whether the value can be read right now. Native
  // getItem already throws on a store failure rather than answering null, so
  // null here really means absent; the web shim is where the two differ.
  hasItem: async (key: string): Promise<boolean> => (await EncryptedStorage.getItem(key)) !== null,
  setItem: (key: string, value: string): Promise<void> => EncryptedStorage.setItem(key, value),
  // EncryptedStorage.removeItem rejects when the key was never set (Keychain/
  // Keystore surface "not found" as an error instead of a no-op). Callers here
  // always mean "ensure this is gone", so swallow that case to keep the
  // contract idempotent, matching the web IndexedDB shim.
  removeItem: (key: string): Promise<void> =>
    EncryptedStorage.removeItem(key).catch(() => undefined),
};
