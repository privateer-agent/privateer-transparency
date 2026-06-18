import argon2 from 'react-native-argon2';
import type { KdfParams } from '../cryptoService';

export async function deriveArgon2idHash(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  const saltHex = Array.from(salt, b => b.toString(16).padStart(2, '0')).join('');
  const { rawHash } = await argon2(password, saltHex, {
    mode: 'argon2id',
    memory: params.m,
    iterations: params.t,
    parallelism: params.p,
    hashLength: 32,
    saltEncoding: 'hex',
  });
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(rawHash.substr(i * 2, 2), 16);
  }
  return out;
}
