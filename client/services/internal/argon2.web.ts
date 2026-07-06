import type { KdfParams } from '../cryptoService';

// WASM-backed Argon2id (hash-wasm) — ~100-300ms for the default 64 MiB / t=3
// params, vs multiple seconds for the pure-JS @noble/hashes path, whose long
// synchronous chunks freeze the main thread and make login appear hung.
// Wire-format compatible: same UTF-8 password encoding, raw salt bytes, and
// parameters produce the same 32-byte KEK as the noble and native paths.
//
// noble stays as a fallback for environments where WebAssembly is unavailable
// or blocked by CSP (instantiation rejected without `wasm-unsafe-eval`).
let wasmUnavailable = false;

export async function deriveArgon2idHash(
  password: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  if (!wasmUnavailable) {
    try {
      const { argon2id } = await import('hash-wasm');
      return await argon2id({
        password,
        salt,
        iterations: params.t,
        memorySize: params.m,
        parallelism: params.p,
        hashLength: 32,
        outputType: 'binary',
      });
    } catch (err) {
      wasmUnavailable = true;
      console.warn('[argon2] WASM derivation unavailable, falling back to pure JS:', err);
    }
  }
  const { argon2idAsync } = await import('@noble/hashes/argon2');
  return argon2idAsync(password, salt, {
    m: params.m,
    t: params.t,
    p: params.p,
    dkLen: 32,
  });
}
