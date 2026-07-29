/**
 * Canonical auth-message assembly — pure, dependency-free, so it can be unit
 * tested without pulling in @solana/web3.js or the crypto stack.
 *
 * This format is a wire protocol: `parseCanonicalAuthMessage` in
 * server/routes/auth.js pins the exact line set and rejects anything else, so a
 * signature obtained in some other context can't be replayed as a sign-in.
 * Change a character here and sign-in breaks; the tests on both sides
 * (services/wallets/authMessage.test.ts and server/test/walletAuthMessage.test.js)
 * assert the same literals for exactly that reason.
 */

import { WalletAccount, getChain } from './chains';

export interface AuthMessageParams {
  brandName: string;
  domain: string;
  account: WalletAccount;
  nonce: string;
  /** ISO-8601 timestamp. Injected rather than read here so tests are stable. */
  issuedIso: string;
}

/**
 * Build the canonical auth-message lines.
 *
 * Solana produces the original five lines and must keep doing so forever —
 * older clients and every existing account verify against that shape. Chains
 * added later carry a `Chain:` line, which is what makes a signature
 * namespace-specific rather than liftable from one chain to another.
 *
 * The `Wallet:` line carries the canonical address (base58 / EIP-55) because
 * the user reads this in their wallet's sign prompt and should recognize it.
 */
export function buildAuthMessageLines(params: AuthMessageParams): string[] {
  const { brandName, domain, account, nonce, issuedIso } = params;

  // Callers used to pass raw pubkey bytes here. Anything without a namespace and
  // an address would otherwise sail past `getChain` with an opaque error, or
  // worse produce a message bound to `undefined` — so reject it by shape, with a
  // message that names the actual mistake.
  if (!account || typeof account !== 'object' || !account.namespace || !account.address) {
    throw new Error('buildAuthMessage expects a WalletAccount ({ namespace, address, idHex })');
  }

  const chain = getChain(account.namespace);

  const lines = [
    `Sign in to ${brandName}`,
    `Domain: ${domain}`,
    `Wallet: ${account.address}`,
  ];
  if (chain.includesChainLine) lines.push(`Chain: ${account.namespace}`);
  lines.push(`Nonce: ${nonce}`);
  lines.push(`Issued: ${issuedIso}`);
  return lines;
}

export function buildAuthMessageText(params: AuthMessageParams): string {
  return buildAuthMessageLines(params).join('\n');
}
