/**
 * Chain descriptors — the client's half of multi-chain wallet auth.
 *
 * One entry per CAIP-2 namespace we can sign in with. Everything that differs
 * between chains lives here; walletAuthShared and the transports stay generic.
 *
 * The two things that actually differ:
 *
 *   1. **Identity shape.** Solana's identity IS a 32-byte Ed25519 public key.
 *      An EVM identity is a 20-byte address the signature is recovered to — no
 *      public key is ever transmitted.
 *   2. **Display form.** base58 vs EIP-55 mixed-case hex. The auth message
 *      shows this, so the user can verify it against their wallet at a glance.
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

export type ChainNamespace = 'solana' | 'eip155';

/** A connected account, normalized across chains. */
export interface WalletAccount {
  namespace: ChainNamespace;
  /** Canonical, user-recognizable address (base58 | EIP-55 hex). */
  address: string;
  /** Lowercase unprefixed hex: 64 chars (solana pubkey) | 40 chars (evm address). */
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

export function getChain(namespace: ChainNamespace): ChainDescriptor {
  const chain = CHAINS[namespace];
  if (!chain) throw new Error(`Unsupported wallet chain: ${namespace}`);
  return chain;
}

/** The CAIP-2-style scope string embedded in v3 vault messages. */
export function chainScope(account: WalletAccount): string {
  return `${account.namespace}:${account.idHex}`;
}
