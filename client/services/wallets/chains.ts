/**
 * Chain descriptors — the client's half of multi-chain wallet auth.
 *
 * One entry per CAIP-2 namespace we can sign in with. Everything that differs
 * between chains lives here; walletAuthShared and the transports stay generic.
 *
 * The two things that actually differ:
 *
 *   1. **Identity shape.** Solana's identity IS a 32-byte Ed25519 public key.
 *      An EVM or Tron identity is a 20-byte address the signature is recovered
 *      to — no public key is ever transmitted.
 *   2. **Display form.** base58 vs EIP-55 mixed-case hex vs base58check. The
 *      auth message shows this, so the user can verify it against their wallet
 *      at a glance.
 *
 * Which vault-KEK message a chain signs is NOT a field here: it follows from
 * the namespace, and walletAuthShared selects it directly. Solana signs the
 * original bare-hex message and always will — that exact string is what every
 * existing wallet vault was derived from, and there is no recovery if it
 * changes. Every other chain signs the namespace-scoped form.
 *
 * `idHex` is the lowercase, unprefixed hex identity used for message binding
 * and the KEK message — never displayed. `address` is the canonical form users
 * and explorers recognize.
 */

export type ChainNamespace = 'solana' | 'eip155' | 'sui' | 'tron';

/** A connected account, normalized across chains. */
export interface WalletAccount {
  namespace: ChainNamespace;
  /**
   * Canonical, user-recognizable address (base58 | EIP-55 hex | 0x sui hex |
   * base58check "T…").
   */
  address: string;
  /**
   * Lowercase unprefixed hex: 64 chars (solana pubkey), 40 chars (evm address),
   * 64 chars (sui address), 40 chars (tron address). Solana and Sui are the same
   * width, and Tron's 20 bytes are literally the same bytes as its EVM twin —
   * which is exactly why the vault message is namespace-scoped rather than bare
   * hex.
   */
  idHex: string;
}

export interface ChainDescriptor {
  namespace: ChainNamespace;
  /** Brand proper noun — never translated (CLAUDE.md §7). */
  label: string;
  /**
   * Whether the canonical auth message carries a `Chain:` line. Solana's
   * message predates multi-chain and stays at its original five lines so older
   * clients and existing accounts keep verifying; every other chain is
   * explicitly scoped.
   */
  includesChainLine: boolean;
  /** Expected raw signature length in bytes. */
  signatureLength: number;
  /**
   * The identity string sent to `/auth/wallet/verify` as `walletPublicKey`.
   * Solana keeps sending unprefixed hex — the exact wire form older clients
   * already use — while EVM sends the 0x-prefixed address the server's
   * eip155 parser expects.
   */
  wireIdentity(account: WalletAccount): string;
}

export const CHAINS: Record<ChainNamespace, ChainDescriptor> = {
  solana: {
    namespace: 'solana',
    label: 'Solana',
    includesChainLine: false,
    signatureLength: 64,
    wireIdentity: (account) => account.idHex,
  },
  eip155: {
    namespace: 'eip155',
    label: 'Ethereum',
    // An EVM address is the same account on every EVM chain, so the namespace
    // is the scope — deliberately no chain id. Switching networks in MetaMask
    // must not look like switching accounts.
    includesChainLine: true,
    signatureLength: 65,
    wireIdentity: (account) => `0x${account.idHex}`,
  },
  sui: {
    namespace: 'sui',
    label: 'Sui',
    includesChainLine: true,
    // Sui returns a SERIALIZED signature: flag(1) || ed25519 sig(64) ||
    // public key(32). The key travels inside the signature — the address is a
    // hash of it, so there is nothing to recover from and nothing else to send.
    // Only the Ed25519 flag is accepted (see wallets/suiEncoding.ts).
    signatureLength: 97,
    wireIdentity: (account) => `0x${account.idHex}`,
  },
  tron: {
    namespace: 'tron',
    label: 'Tron',
    includesChainLine: true,
    // secp256k1 ECDSA, same 65-byte r‖s‖v as EVM: Tron's signMessageV2 differs
    // from personal_sign only in the prefix inside the digest.
    signatureLength: 65,
    // The only chain whose wire identity is not hex. A Tron address is a
    // base58check string over `0x41 ‖ idHex`, and its 4-byte checksum is the
    // only thing standing between a corrupted address and a vault enrolled
    // under bytes the user never saw — so the checked form is what travels, and
    // the server decodes it rather than trusting a hex spelling.
    wireIdentity: (account) => account.address,
  },
};

/**
 * Display name for whichever chain an account belongs to, or null when it isn't
 * a wallet account. Accepts the legacy shape too: accounts created before
 * multi-chain sign-in carry only `solanaPublicKey`, and reading `walletChain`
 * alone would report them as having no wallet.
 */
export function walletChainLabel(
  user?: { walletChain?: string | null; solanaPublicKey?: string | null } | null,
): string | null {
  const namespace = user?.walletChain || (user?.solanaPublicKey ? 'solana' : null);
  if (!namespace) return null;
  return CHAINS[namespace as ChainNamespace]?.label ?? null;
}

/**
 * The account's canonical address, whichever chain it is on. Falls back to the
 * legacy field so pre-multi-chain Solana accounts still resolve.
 */
export function walletAddressOf(
  user?: { walletAddress?: string | null; solanaPublicKey?: string | null } | null,
): string | null {
  return user?.walletAddress || user?.solanaPublicKey || null;
}

/**
 * Is `address` — a canonical address in its own chain's encoding, as the server
 * stores and serves it — the same account as `account`?
 *
 * The comparison is per-encoding, not per-string. EIP-55 carries its checksum
 * in the letter case of an otherwise case-insensitive hex address, so an
 * all-lowercase spelling of an EVM (or Sui) address is the SAME account and must
 * match. Base58 is not case-insensitive — 'a' and 'A' are distinct characters —
 * so Solana and Tron compare exactly.
 */
export function isSameAccountAddress(address: string, account: WalletAccount): boolean {
  const hexEncoded = account.namespace === 'eip155' || account.namespace === 'sui';
  return hexEncoded
    ? address.toLowerCase() === account.address.toLowerCase()
    : address === account.address;
}

/**
 * Truncated address for display — enough to recognize which account you are
 * signed into, which is all any of these surfaces need.
 *
 * The `0x` chains (EVM, Sui) keep their prefix plus two bytes; that is the form
 * every wallet UI shows, and dropping the prefix would make the address read as
 * some other kind of identifier. Base58 has no prefix to preserve, so it splits
 * evenly.
 */
export function shortWalletAddress(
  user?: { walletAddress?: string | null; solanaPublicKey?: string | null } | null,
): string | null {
  const address = walletAddressOf(user);
  if (!address) return null;
  const head = address.startsWith('0x') ? 6 : 4;
  // Anything this short is already readable whole — truncating it would only
  // lose characters without shortening the line.
  if (address.length <= head + 5) return address;
  return `${address.slice(0, head)}…${address.slice(-4)}`;
}

export function getChain(namespace: ChainNamespace): ChainDescriptor {
  const chain = CHAINS[namespace];
  if (!chain) throw new Error(`Unsupported wallet chain: ${namespace}`);
  return chain;
}

/** The CAIP-2-style scope string embedded in v3 vault messages. */
export function chainScope(account: WalletAccount): string {
  return `${account.namespace}:${account.idHex}`;
}
