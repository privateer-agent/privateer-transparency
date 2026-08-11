/**
 * Wallet Auth — shared, platform-agnostic core.
 *
 * Everything here is identical for native (Mobile Wallet Adapter) and web
 * (injected browser wallet). The only difference between platforms is *how* the
 * wallet is asked to sign — the message bytes, the server round-trips, and the
 * master-key enroll/unwrap logic are all here so the two transports stay in
 * lockstep.
 *
 * Why this matters: the vault KEK is HKDF over the wallet's Ed25519 signature of
 * `getWalletKekMessage(pubkey)`. Ed25519 signatures are deterministic (RFC
 * 8032), so the same wallet signing the same bytes produces the same KEK whether
 * the signature came from MWA on Android or Phantom in a browser. As long as
 * both platforms sign the byte-identical messages built here, a wallet user who
 * enrolled on native unlocks the same master key on web, and vice versa.
 *
 * The server (`/auth/wallet/{verify,master-key}`, `/auth/me`) is transport-blind:
 * it only verifies a signature over the canonical message and checks the nonce,
 * so no server change is needed to add the web path.
 */

import { PublicKey } from '@solana/web3.js';
import { getServerUrl } from '../config/environment';
import { brand } from '../config/brand';
import {
  setMasterKey,
  generateMasterKey,
  deriveKekFromWalletSignature,
  getWalletKekMessage,
  getWalletKekMessageV3,
  wrapMasterKey,
  unwrapMasterKey,
  clearMasterKeyAsync,
} from './cryptoService';
import {
  WalletAccount,
  ChainNamespace,
  getChain,
  chainScope,
  walletAddressOf,
  isSameAccountAddress,
} from './wallets/chains';
import { buildAuthMessageText } from './wallets/authMessage';
import authService, { VaultPayload } from './authService';
import { assertDeterministicVaultSignature, WALLET_NON_DETERMINISTIC } from './walletDeterminism';
import { Sentry } from './sentryService';
import { sessionDeviceMeta } from '../utils/sessionDevice';

export { WALLET_NON_DETERMINISTIC, WalletNonDeterministicError } from './walletDeterminism';

const API_BASE = getServerUrl();

export interface WalletUser {
  id: string;
  email?: string;
  profileImage?: string;
  solanaPublicKey?: string | null;
  kekSource?: 'password' | 'wallet' | null;
}

export interface WalletAuthResult {
  accessToken: string;
  refreshToken: string;
  user: WalletUser;
}

/**
 * True when a wallet sign-in failure is just the user backing out — closing the
 * wallet app, dismissing the picker, or declining a sign prompt — rather than a
 * real error. Callers should treat this as a soft "try again" cue, not a
 * failure. Covers MWA's Android `CancellationException`, wallet "user
 * rejected/declined/dismissed" strings, and the EIP-1193-style `4001` code that
 * browser wallets (Phantom/Solflare/Backpack) return on user rejection.
 */
export function isWalletCancellation(err: unknown): boolean {
  const msg = ((err as any)?.message ?? String(err ?? '')).toLowerCase();
  return (
    msg.includes('cancel') ||          // cancelled / canceled / cancellation / CancellationException
    msg.includes('reject') ||          // user rejected
    msg.includes('declin') ||          // declined
    msg.includes('dismiss') ||         // wallet UI dismissed
    msg.includes('did not approve') ||
    msg.includes('not approved') ||
    msg.includes('4001')               // EIP-1193-style user-rejection code
  );
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------------------------------------------------------------------------
// Canonical message construction — the single source of truth for both
// platforms. Change the wire format here and native + web stay in sync.
// ---------------------------------------------------------------------------

export interface WalletMessages {
  pubkeyHex: string;
  /** UTF-8 bytes of the nonce-bound auth message the server verifies. */
  authMessage: Uint8Array;
  /** UTF-8 bytes of the deterministic vault message whose signature → KEK. */
  vaultMessage: Uint8Array;
}

/** Normalize a raw 32-byte Ed25519 public key into a Solana WalletAccount. */
export function solanaAccount(pubkeyBytes: Uint8Array): WalletAccount {
  return {
    namespace: 'solana',
    address: new PublicKey(pubkeyBytes).toBase58(),
    idHex: toHex(pubkeyBytes),
  };
}

/**
 * Same, from the lowercase hex form. Used by the desktop hand-off, where the
 * browser page signs and only the hex identity comes back over the wire.
 */
export function solanaAccountFromHex(pubkeyHex: string): WalletAccount {
  const bytes = new Uint8Array(pubkeyHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(pubkeyHex.slice(i * 2, i * 2 + 2), 16);
  }
  return solanaAccount(bytes);
}

/**
 * Build the two messages a wallet must sign.
 *
 * The auth message shows the address in its canonical form — base58 on Solana,
 * EIP-55 hex on EVM — the form users recognize from their wallet and
 * explorers, so the sign prompt is verifiable at a glance. The server
 * normalizes whatever appears on the `Wallet:` line back to lowercase hex
 * before binding it to the claimed identity.
 *
 * Chains other than Solana add a `Chain:` line. Solana's message keeps its
 * original five lines forever: the server's parser pins that exact shape, and
 * existing accounts + older clients must keep verifying against it.
 */
export function buildWalletMessages(account: WalletAccount, nonce: string): WalletMessages {
  const chain = getChain(account.namespace);

  const authText = buildAuthMessageText({
    brandName: brand.name,
    domain: brand.domain,
    account,
    nonce,
    issuedIso: new Date().toISOString(),
  });

  // Solana signs the original bare-hex message, forever: it is what every
  // existing wallet vault was derived from and there is no way back if it
  // changes. Every other chain signs the namespace-scoped form, which is what
  // keeps two secp256k1 chains that share an address derivation (Ethereum and
  // Tron, say) from deriving one another's key.
  const vaultText = account.namespace === 'solana'
    ? getWalletKekMessage(account.idHex)
    : getWalletKekMessageV3(chainScope(account));

  return {
    pubkeyHex: account.idHex,
    authMessage: new TextEncoder().encode(authText),
    vaultMessage: new TextEncoder().encode(vaultText),
  };
}

// ---------------------------------------------------------------------------
// Server round-trips
// ---------------------------------------------------------------------------

export async function fetchNonce(): Promise<{ nonce: string; nonceId: string }> {
  const res = await fetch(`${API_BASE}/auth/wallet/nonce`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { message?: string };
    throw new Error(body.message || 'Failed to fetch nonce');
  }
  return res.json() as Promise<{ nonce: string; nonceId: string }>;
}

async function verifyWithServer(
  account: WalletAccount,
  signature: Uint8Array,
  signedMessage: Uint8Array,
  nonceId: string,
  recover = false,
): Promise<WalletAuthResult & { vault: VaultPayload | null; needsMasterKeySetup: boolean }> {
  const res = await fetch(`${API_BASE}/auth/wallet/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      walletPublicKey: getChain(account.namespace).wireIdentity(account),
      // Omitted for Solana so the request stays byte-identical to what older
      // clients send; the server defaults an absent `chain` to solana.
      ...(account.namespace === 'solana' ? {} : { chain: account.namespace }),
      signature: toHex(signature),
      signedMessage: toHex(signedMessage),
      nonceId,
      // Lift a pending 30-day deletion on an otherwise valid wallet sign-in.
      // Sent only after the user confirms the recovery prompt (see LoginScreen).
      ...(recover ? { recover: true } : {}),
      // Names this sign-in in the linked-device list (display metadata only).
      ...sessionDeviceMeta(),
    }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { message?: string; code?: string };
    // Preserve the structured code (e.g. ACCOUNT_PENDING_DELETION) so callers
    // can branch — the recovery prompt keys off it, not the localized message.
    const err: any = new Error(body.message || 'Wallet verification failed');
    err.code = body.code;
    throw err;
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Post-signature finishers — shared between native and web. Each platform's
// job is reduced to "collect the two signatures", then hand off here.
// ---------------------------------------------------------------------------

export interface CollectedSignatures {
  /** The connected account, including which chain it belongs to. */
  account: WalletAccount;
  /** Signature over `authMessage`. */
  authSignature: Uint8Array;
  /** The exact auth-message bytes that were signed. */
  authMessage: Uint8Array;
  /** Signature over the v2 vault message — its HKDF is the KEK. */
  vaultSignature: Uint8Array;
  nonceId: string;
}

export interface CompleteWalletLoginOptions {
  /** Lift a pending 30-day deletion (see verifyWithServer). */
  recover?: boolean;
  /**
   * Ask the *same* wallet account to sign the vault message once more.
   *
   * Called only when this sign-in is about to create the account's vault, so
   * the enrollment signature can be checked for reproducibility before a master
   * key exists to lose (see ./walletDeterminism). Established accounts never
   * hit it, which is why the extra prompt is a once-per-account cost rather
   * than a per-login one — and why it can't be collected up front alongside the
   * other two signatures: whether we're enrolling is only known after the
   * server responds.
   *
   * Implementations MUST re-sign with the account already in `sigs.account` —
   * re-prompting a picker that lets the user switch accounts would compare two
   * unrelated signatures and fail the honest wallet.
   */
  resignVault?: () => Promise<Uint8Array>;
}

/**
 * Enrollment-only guard: the wallet must sign the vault message to the same
 * bytes twice before we build an account around that signature. A wallet that
 * fails this — MPC/threshold, smart-contract, passkey — would enroll happily
 * and then be unable to unwrap on every later sign-in, which under Privateer's
 * no-recovery rule is permanent data loss. See ./walletDeterminism.
 *
 * On any failure the freshly-minted session is torn down. An authenticated user
 * with no vault cannot encrypt anything, so leaving them signed in would only
 * move the failure somewhere harder to explain. This also covers the user
 * simply dismissing the second prompt: nothing was created, so there is nothing
 * to keep.
 */
async function assertWalletCanEnroll(
  sigs: CollectedSignatures,
  resignVault?: () => Promise<Uint8Array>,
): Promise<void> {
  if (!resignVault) {
    // Every shipping transport supplies this; reaching here means a caller was
    // added without one, and enrolling blind is the one thing we must not do.
    await authService.logout().catch(() => { /* teardown is best-effort */ });
    throw new Error('This app cannot set up a wallet vault yet. Please update to the latest version.');
  }

  try {
    const second = await resignVault();
    assertDeterministicVaultSignature(sigs.vaultSignature, second);
  } catch (err) {
    await authService.logout().catch(() => { /* teardown is best-effort */ });
    if ((err as any)?.code === WALLET_NON_DETERMINISTIC) {
      // Worth knowing how often real wallets trip this, and which ones.
      Sentry.captureException(err, { level: 'warning', tags: { op: 'wallet_enroll_determinism' } });
    }
    throw err;
  }
}

/**
 * Verify the auth signature with the server, then either enroll a fresh master
 * key (first sign-in for this wallet account) or unwrap the server-stored vault
 * — both keyed off the vault signature collected in the same session. On
 * success the in-memory master key is loaded and the user is authenticated.
 */
export async function completeWalletLogin(
  sigs: CollectedSignatures,
  opts?: CompleteWalletLoginOptions,
): Promise<WalletAuthResult> {
  const result = await verifyWithServer(
    sigs.account, sigs.authSignature, sigs.authMessage, sigs.nonceId, opts?.recover === true,
  );

  // Sync auth state (tokens + user) into authService.
  await authService.updateAuthData(result.accessToken, result.refreshToken, result.user);

  if (result.needsMasterKeySetup || !result.vault) {
    // First wallet sign-in for this account — generate a master key and enroll
    // it, wrapped under the vault signature from this same session. Before that
    // key exists to be lost, prove the wallet signs reproducibly.
    await assertWalletCanEnroll(sigs, opts?.resignVault);

    const kek = deriveKekFromWalletSignature(sigs.vaultSignature);
    const masterKey = generateMasterKey();
    const wrapped = wrapMasterKey(masterKey, kek);
    const accepted = await authService.setWalletMasterKey(wrapped);
    if (!accepted) {
      throw new Error('Account already has a master key registered. Try signing in again.');
    }
    await setMasterKey(masterKey, { persist: true });
    return { accessToken: result.accessToken, refreshToken: result.refreshToken, user: result.user };
  }

  if (result.vault.kekSource !== 'wallet') {
    throw new Error('This account does not use wallet sign-in.');
  }

  const kek = deriveKekFromWalletSignature(sigs.vaultSignature);
  let masterKey: Uint8Array;
  try {
    masterKey = unwrapMasterKey(result.vault.wrappedMasterKey, kek);
  } catch (err) {
    Sentry.captureException(err, { level: 'warning', tags: { op: 'wallet_unwrap_key' } });
    throw new Error('Could not unlock your data with this wallet.');
  }
  await setMasterKey(masterKey, { persist: true });

  return { accessToken: result.accessToken, refreshToken: result.refreshToken, user: result.user };
}

export interface WalletVault extends VaultPayload {
  /**
   * Canonical address of the account this vault was enrolled on, in the form
   * the server stores: base58 on Solana and Tron, EIP-55 hex on EVM, 0x-hex on
   * Sui. Null only from a server older than multi-chain sign-in.
   */
  walletAddress?: string | null;
}

/**
 * Fetch the authenticated wallet user's vault so its wrapped master key can be
 * unwrapped. Used by `loadDerivedKey` when the on-device cache is empty.
 */
export async function fetchWalletVault(): Promise<WalletVault> {
  const meRes = await authService.makeAuthenticatedRequest('/auth/me');
  if (!meRes.ok) throw new Error('Failed to fetch vault from server');
  const meData = await meRes.json() as {
    vault: VaultPayload | null;
    user?: { walletAddress?: string | null; solanaPublicKey?: string | null };
  };
  if (!meData.vault || meData.vault.kekSource !== 'wallet') {
    throw new Error('Account is missing a wallet vault.');
  }
  // walletAddressOf falls back to the legacy field, so an account made before
  // multi-chain sign-in still binds rather than silently skipping the check.
  return { ...meData.vault, walletAddress: walletAddressOf(meData.user) };
}

/**
 * Refuse to derive a KEK from an account that is not the one this vault was
 * enrolled on.
 *
 * Every unlock re-prompts a wallet that may hold several accounts, and nothing
 * in that prompt says which one is wanted. Signing with the wrong one derives a
 * key that cannot unwrap, and the failure surfaces as "could not unlock your
 * data" — the wording for a lost vault, on an account that is perfectly fine.
 * Worse, it is reported as a broken vault rather than as a wrong pick.
 *
 * A server that doesn't say which account was enrolled leaves the check off
 * rather than blocking the unlock. This is a diagnosis, not a gate: the unwrap
 * itself is what actually decides.
 */
export function assertVaultAccount(vault: WalletVault, account: WalletAccount): void {
  const enrolled = vault.walletAddress;
  if (!enrolled) return;
  if (!isSameAccountAddress(enrolled, account)) {
    throw new Error('A different wallet account signed. Choose the account this Privateer account was created with, then try again.');
  }
}

/**
 * Unwrap the vault with a fresh vault signature and load the master key into
 * memory. Shared tail of `loadDerivedKey` for both platforms.
 */
export async function completeLoadDerivedKey(vault: VaultPayload, vaultSignature: Uint8Array): Promise<void> {
  const kek = deriveKekFromWalletSignature(vaultSignature);
  let masterKey: Uint8Array;
  try {
    masterKey = unwrapMasterKey(vault.wrappedMasterKey, kek);
  } catch (err) {
    Sentry.captureException(err, { level: 'warning', tags: { op: 'wallet_masterkey_setup' } });
    throw new Error('Could not unlock your data with this wallet.');
  }
  await setMasterKey(masterKey, { persist: true });
}

export async function clearDerivedKey(): Promise<void> {
  await clearMasterKeyAsync();
}
