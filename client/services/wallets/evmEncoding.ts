/**
 * EVM encoding helpers — pure, so every transport shares one implementation and
 * it can be unit tested without a browser or a wallet.
 *
 * The two that matter for correctness:
 *
 *   - `bytesToHex` produces the `0x…` payload handed to `personal_sign`. Passing
 *     the message as hex rather than a UTF-8 string removes any question of how
 *     a wallet interprets a string that happens to look like hex.
 *   - `toChecksumAddress` is EIP-55. It's display normalization only — two
 *     addresses differing in case are the same account, so comparisons are
 *     always done lowercase — but the checksummed form is what wallets and
 *     explorers show, so it's what the sign prompt must show too.
 */

import { keccak_256 } from '@noble/hashes/sha3';

/** `0x`-prefixed lowercase hex for a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/** Parse `0x`-prefixed (or bare) hex into bytes. Throws on malformed input. */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') throw new Error('Wallet returned a malformed signature');
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Wallet returned a malformed signature');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * EIP-55 mixed-case checksum. Input is 40 lowercase hex chars, no prefix;
 * output is the `0x`-prefixed checksummed address.
 */
export function toChecksumAddress(lowerHex40: string): string {
  if (!/^[0-9a-f]{40}$/.test(lowerHex40)) {
    throw new Error('Expected 40 lowercase hex characters');
  }
  const hash = Array.from(keccak_256(new TextEncoder().encode(lowerHex40)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  let out = '';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lowerHex40[i].toUpperCase() : lowerHex40[i];
  }
  return `0x${out}`;
}

/**
 * Normalize a wallet-supplied address into a WalletAccount's two forms.
 * Throws if it isn't a 20-byte hex address.
 */
export function parseEvmAddress(raw: string): { address: string; idHex: string } {
  if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(raw)) {
    throw new Error('Wallet did not return a valid address');
  }
  const idHex = raw.slice(2).toLowerCase();
  return { address: toChecksumAddress(idHex), idHex };
}

/**
 * Pull the address out of a CAIP-10 account string (`eip155:1:0xabc…`), which
 * is the form a WalletConnect session reports. The chain id is discarded on
 * purpose: one EVM address is the same Privateer account on every EVM network,
 * so binding the identity to a chain id would make a user's vault underivable
 * the moment they switched networks.
 */
export function addressFromCaip10(caip10: string): { address: string; idHex: string } {
  const parts = String(caip10).split(':');
  if (parts.length !== 3 || parts[0] !== 'eip155') {
    throw new Error(`Unexpected account format from wallet: ${caip10}`);
  }
  return parseEvmAddress(parts[2]);
}
