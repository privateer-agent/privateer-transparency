/**
 * Wallet Auth Service — WEB (browser) via injected wallet provider.
 *
 * Mirror of the native (MWA) service for the browser. Metro auto-prefers this
 * `.web` extension when bundling for web, so the Android-only Mobile Wallet
 * Adapter import in ./walletAuthService.ts never loads in a browser.
 *
 *   1. POST /auth/wallet/nonce
 *   2. connect() the injected wallet, then signMessage() the auth message and
 *      the vault message — two prompts in the same wallet extension. The wallet
 *      stays connected across both, mirroring the single native transact()
 *      session. Auth state is only persisted after both signatures land, so a
 *      user cancel leaves no partial state behind.
 *   3. Hand the two signatures to the shared core (./walletAuthShared), which
 *      verifies, enrolls/unwraps the master key, and authenticates.
 *
 * The signed bytes are byte-identical to the native path (built by the shared
 * `buildWalletMessages`), so a wallet user who enrolled on native unlocks the
 * same E2EE master key here, and the server's `/auth/wallet/verify` is unchanged.
 */

import {
  WalletAuthResult,
  buildWalletMessages,
  fetchNonce,
  completeWalletLogin,
  fetchWalletVault,
  completeLoadDerivedKey,
} from './walletAuthShared';
import { connectBrowserWallet } from './browserWalletProvider.web';
import { canLinkWalletViaBrowser, linkWalletViaBrowser } from './desktopWalletLink';

// Re-export the platform-agnostic surface so existing imports from
// '../services/walletAuthService' keep working unchanged on web.
export {
  isWalletCancellation,
  clearDerivedKey,
} from './walletAuthShared';
export type { WalletUser, WalletAuthResult } from './walletAuthShared';

/**
 * Sign in via a browser Solana wallet. After this resolves, the in-memory
 * master key is loaded and the user is authenticated.
 */
export async function solanaLogin(): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  // Electron desktop: no extension is injected here, so the signing happens in
  // the user's real browser and only the signatures come back. Everything after
  // that — verify, enroll/unwrap, session — still runs on this side.
  if (canLinkWalletViaBrowser()) {
    const linked = await linkWalletViaBrowser('login', nonce);
    return completeWalletLogin({
      pubkeyHex: linked.pubkeyHex,
      authSignature: linked.authSignature!,
      authMessage: linked.authMessage!,
      vaultSignature: linked.vaultSignature,
      nonceId,
    });
  }

  const wallet = await connectBrowserWallet();
  const { pubkeyHex, authMessage, vaultMessage } = buildWalletMessages(wallet.pubkeyBytes, nonce);

  const authSignature = await wallet.signMessage(authMessage);
  const vaultSignature = await wallet.signMessage(vaultMessage);

  return completeWalletLogin({ pubkeyHex, authSignature, authMessage, vaultSignature, nonceId });
}

/**
 * Re-derive the master key for an authenticated wallet user by prompting the
 * browser wallet for a fresh vault signature. Used when the on-device cache is
 * empty (first sign-in on this device, after logout, or after REAUTH_REQUIRED).
 */
export async function loadDerivedKey(): Promise<void> {
  const vault = await fetchWalletVault();

  // Desktop: same browser hand-off as sign-in, but only the vault signature is
  // needed — there's no nonce-bound auth message to re-sign for an already
  // authenticated user.
  if (canLinkWalletViaBrowser()) {
    const linked = await linkWalletViaBrowser('unlock', '');
    await completeLoadDerivedKey(vault, linked.vaultSignature);
    return;
  }

  const wallet = await connectBrowserWallet();
  const { vaultMessage } = buildWalletMessages(wallet.pubkeyBytes, '');
  const vaultSignature = await wallet.signMessage(vaultMessage);

  await completeLoadDerivedKey(vault, vaultSignature);
}
