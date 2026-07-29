/**
 * Vault-KEK messages — the exact strings a wallet signs to produce the key that
 * unwraps its master key.
 *
 * These are the highest-consequence literals in the codebase. The signature
 * over one of them IS the KEK input (cryptoService.deriveKekFromWalletSignature),
 * so changing a single character of a message an account already enrolled with
 * makes that account's data permanently unreadable — Privateer has no password
 * recovery and no server-side copy of the key.
 *
 * They live here, dependency-free, so they can be unit tested directly;
 * cryptoService re-exports them as the public surface for key operations.
 *
 * Two forms exist, and which one a wallet signs follows from its chain:
 *
 *   v2 — `Privateer vault key v2 for <64-hex pubkey>`. Solana, and Solana
 *        forever. Every wallet account that exists today derived its KEK from
 *        this. It is frozen.
 *   v3 — `Privateer vault key v3 for <namespace>:<hex>`. Every chain added
 *        since. The namespace prefix is the load-bearing part: Ethereum and
 *        Tron derive the same 20 address bytes from one key and both sign with
 *        secp256k1, so a bare-hex message would hand two separate accounts the
 *        same KEK.
 */

/**
 * The v2 message. Embeds the wallet's Ed25519 public key (lowercase hex) so a
 * signature is structurally bound to one account and cannot be replayed to
 * derive another's KEK.
 */
export function getWalletKekMessage(pubkeyHex: string): string {
  if (!pubkeyHex || !/^[0-9a-fA-F]{64}$/.test(pubkeyHex)) {
    throw new Error('Pubkey (64 hex chars) is required for the wallet vault message');
  }
  return `Privateer vault key v2 for ${pubkeyHex.toLowerCase()}`;
}

/**
 * The v3, namespace-scoped message. `scope` is
 * `<namespace>:<lowercase unprefixed hex identity>` — see chains.ts → chainScope().
 */
export function getWalletKekMessageV3(scope: string): string {
  if (!/^[a-z0-9]+:[0-9a-f]+$/.test(scope)) {
    throw new Error('Vault scope must be "<namespace>:<lowercase hex identity>"');
  }
  return `Privateer vault key v3 for ${scope}`;
}
