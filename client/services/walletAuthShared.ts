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
  wrapMasterKey,
  unwrapMasterKey,
  clearMasterKeyAsync,
} from './cryptoService';
import authService, { VaultPayload } from './authService';
import { Sentry } from './sentryService';
import { sessionDeviceMeta } from '../utils/sessionDevice';

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
  /** UTF-8 bytes of the deterministic v2 vault message whose signature → KEK. */
  vaultMessage: Uint8Array;
}

/**
 * Build the two messages a wallet must sign, given its raw 32-byte Ed25519
 * public key. The auth message shows the address in base58 — the form users
 * recognize from their wallet/explorers — so the sign prompt is verifiable at a
 * glance; the server accepts either base58 or hex on the `Wallet:` line. The
 * vault message is version-locked v2 and stays hex.
 */
export function buildWalletMessages(pubkeyBytes: Uint8Array, nonce: string): WalletMessages {
  const pubkeyHex = toHex(pubkeyBytes);
  const pubkeyBase58 = new PublicKey(pubkeyBytes).toBase58();

  const authMessageText =
    `Sign in to ${brand.name}\n` +
    `Domain: ${brand.domain}\n` +
    `Wallet: ${pubkeyBase58}\n` +
    `Nonce: ${nonce}\n` +
    `Issued: ${new Date().toISOString()}`;

  return {
    pubkeyHex,
    authMessage: new TextEncoder().encode(authMessageText),
    vaultMessage: new TextEncoder().encode(getWalletKekMessage(pubkeyHex)),
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
  walletPubkeyHex: string,
  signature: Uint8Array,
  signedMessage: Uint8Array,
  nonceId: string,
): Promise<WalletAuthResult & { vault: VaultPayload | null; needsMasterKeySetup: boolean }> {
  const res = await fetch(`${API_BASE}/auth/wallet/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      walletPublicKey: walletPubkeyHex,
      signature: toHex(signature),
      signedMessage: toHex(signedMessage),
      nonceId,
      // Names this sign-in in the linked-device list (display metadata only).
      ...sessionDeviceMeta(),
    }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { message?: string };
    throw new Error(body.message || 'Wallet verification failed');
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Post-signature finishers — shared between native and web. Each platform's
// job is reduced to "collect the two signatures", then hand off here.
// ---------------------------------------------------------------------------

export interface CollectedSignatures {
  pubkeyHex: string;
  /** Signature over `authMessage`. */
  authSignature: Uint8Array;
  /** The exact auth-message bytes that were signed. */
  authMessage: Uint8Array;
  /** Signature over the v2 vault message — its HKDF is the KEK. */
  vaultSignature: Uint8Array;
  nonceId: string;
}

/**
 * Verify the auth signature with the server, then either enroll a fresh master
 * key (first sign-in for this wallet account) or unwrap the server-stored vault
 * — both keyed off the vault signature collected in the same session. On
 * success the in-memory master key is loaded and the user is authenticated.
 */
export async function completeWalletLogin(sigs: CollectedSignatures): Promise<WalletAuthResult> {
  const result = await verifyWithServer(sigs.pubkeyHex, sigs.authSignature, sigs.authMessage, sigs.nonceId);

  // Sync auth state (tokens + user) into authService.
  await authService.updateAuthData(result.accessToken, result.refreshToken, result.user);

  if (result.needsMasterKeySetup || !result.vault) {
    // First wallet sign-in for this account — generate a master key and enroll
    // it, wrapped under the vault signature from this same session.
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

/**
 * Fetch the authenticated wallet user's vault so its wrapped master key can be
 * unwrapped. Used by `loadDerivedKey` when the on-device cache is empty.
 */
export async function fetchWalletVault(): Promise<VaultPayload> {
  const meRes = await authService.makeAuthenticatedRequest('/auth/me');
  if (!meRes.ok) throw new Error('Failed to fetch vault from server');
  const meData = await meRes.json() as { vault: VaultPayload | null };
  if (!meData.vault || meData.vault.kekSource !== 'wallet') {
    throw new Error('Account is missing a wallet vault.');
  }
  return meData.vault;
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
