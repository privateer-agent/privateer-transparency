// The ONLY sanctioned door to secure key-value storage. Import this, never
// `react-native-encrypted-storage` directly: metro.config.js resolves that
// package to a Proxy no-op on web (WEB_NATIVE_STUBS), so a direct importer
// reads back null and writes into the void — silently, with no error to catch.
// secureKv.web.ts backs the same three-method API with IndexedDB + AES-GCM.
import EncryptedStorage from 'react-native-encrypted-storage';

export const secureKv = {
  getItem: (key: string): Promise<string | null> => EncryptedStorage.getItem(key),
  setItem: (key: string, value: string): Promise<void> => EncryptedStorage.setItem(key, value),
  removeItem: (key: string): Promise<void> => EncryptedStorage.removeItem(key),
};
