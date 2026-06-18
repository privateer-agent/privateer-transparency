import { argon2idAsync } from '@noble/hashes/argon2';
import type { KdfParams } from '../cryptoService';

export async function deriveArgon2idHash(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    m: params.m,
    t: params.t,
    p: params.p,
    dkLen: 32,
  });
}
