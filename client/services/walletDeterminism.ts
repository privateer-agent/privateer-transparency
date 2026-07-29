/**
 * Vault-signature determinism gate.
 *
 * The vault KEK is HKDF over the wallet's signature of a fixed message (see
 * cryptoService.deriveKekFromWalletSignature), so unlocking an account depends
 * on that wallet producing the *same signature bytes* every time it signs those
 * bytes. Ed25519 (RFC 8032) derives its nonce from the key and message, and
 * ECDSA implementations follow RFC 6979 by convention, which is why this holds
 * for an ordinary self-custody wallet. It does NOT hold for:
 *
 *   - MPC / threshold wallets, where the nonce is jointly sampled and so cannot
 *     be derived from key + message. This includes Ed25519 threshold schemes,
 *     which means the failure is reachable on Solana today — it is not a
 *     hypothetical about chains we haven't added yet.
 *   - smart-contract and passkey accounts (ERC-1271 / WebAuthn), which return a
 *     wrapper the wallet decorates rather than a raw fixed-length signature.
 *   - any wallet that simply chooses a fresh random nonce.
 *
 * With such a wallet the first sign-in looks perfectly healthy: a master key is
 * generated, wrapped under a KEK, and stored. Every later sign-in derives a
 * different KEK, fails to unwrap, and — because Privateer has no password
 * recovery — the account's data is gone for good. The failure is silent at the
 * moment it is caused and unrecoverable by the time it is visible.
 *
 * So before an account's vault is ever created, we ask the wallet to sign the
 * vault message a second time and require the two signatures to match. It costs
 * one extra prompt, exactly once in an account's lifetime, on the enrollment
 * path only; an established account still re-derives from a single signature.
 *
 * This module is deliberately dependency-free so it can be unit-tested
 * standalone (see ./walletDeterminism.test.ts) and imported from any platform.
 */

/** Structured code callers branch on — never match on the message text. */
export const WALLET_NON_DETERMINISTIC = 'WALLET_NON_DETERMINISTIC';

/**
 * The connected wallet cannot produce a stable signature, so it cannot hold an
 * encrypted vault. Thrown before any master key is generated or stored.
 *
 * The message avoids the words `isWalletCancellation` treats as a user backing
 * out ("cancel", "reject", "declin", "dismiss", "4001") — this is a hard stop
 * that must reach the user, not a soft retry nudge.
 */
export class WalletNonDeterministicError extends Error {
  code = WALLET_NON_DETERMINISTIC;

  constructor(message = 'This wallet produces a different signature each time, so it cannot secure an account.') {
    super(message);
    this.name = 'WalletNonDeterministicError';
  }
}

/**
 * Byte equality for two signatures over the same message.
 *
 * Both values are locally-held secrets belonging to the same user, so there is
 * no attacker to time against and a plain compare is fine. The length floor is
 * the load-bearing part: a wallet that returns empty (or absurdly short) bytes
 * twice would otherwise "match" and be enrolled with a KEK derived from
 * nothing. Real signatures are 64 bytes (Ed25519) or 65 (secp256k1 ECDSA).
 */
export function signaturesMatch(first: Uint8Array, second: Uint8Array): boolean {
  if (!(first instanceof Uint8Array) || !(second instanceof Uint8Array)) return false;
  if (first.length < 32 || second.length < 32) return false;
  if (first.length !== second.length) return false;
  for (let i = 0; i < first.length; i++) {
    if (first[i] !== second[i]) return false;
  }
  return true;
}

/**
 * Throw unless the wallet signed the vault message identically twice. Call this
 * on the enrollment path *before* generating or wrapping a master key.
 */
export function assertDeterministicVaultSignature(first: Uint8Array, second: Uint8Array): void {
  if (!signaturesMatch(first, second)) {
    throw new WalletNonDeterministicError();
  }
}
