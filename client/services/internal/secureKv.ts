import EncryptedStorage from 'react-native-encrypted-storage';

export const secureKv = {
  getItem: (key: string): Promise<string | null> => EncryptedStorage.getItem(key),
  setItem: (key: string, value: string): Promise<void> => EncryptedStorage.setItem(key, value),
  removeItem: (key: string): Promise<void> => EncryptedStorage.removeItem(key),
};
