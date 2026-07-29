/**
 * Wallet Auth Service — NATIVE (iOS/Android) via Mobile Wallet Adapter.
 *
 *   1. POST /auth/wallet/nonce
 *   2. Single transact(): authorize() + signMessages([authMsg]) + signMessages([vaultMsg])
 *      — both signatures collected in one MWA session, both from the same
 *      authorized account. One Android intent, one wallet picker, two sign
 *      prompts in the same wallet UI flow.
 *   3. Hand the two signatures to the shared core (see ./walletAuthShared),
 *      which verifies, enrolls/unwraps the master key, and authenticates.
 *
 * Why two signMessages calls instead of one with two payloads:
 *   Phantom (and most wallets) caps signMessages to 1 payload per call. Two
 *   sequential signMessages calls within a single transact session is the
 *   reliable shape. Auth state is only persisted after both signatures are
 *   collected, so a user cancel leaves no partial state behind.
 *
 * Web uses ./walletAuthService.web.ts instead — Metro auto-prefers the `.web`
 * extension in the browser, so the Android-only MWA import below never loads
 * there. All non-transport logic lives in ./walletAuthShared and is identical
 * across platforms.
 */

import {
  transact,
  Web3MobileWallet,
} from '@solana-mobile/mobile-wallet-adapter-protocol-web3js';
import { brand } from '../config/brand';
import {
  WalletAuthResult,
  buildWalletMessages,
  fetchNonce,
  completeWalletLogin,
  fetchWalletVault,
  completeLoadDerivedKey,
  solanaAccount,
  base64ToBytes,
} from './walletAuthShared';

/**
 * EVM sign-in has no transport in the native app yet.
 *
 * Mobile Wallet Adapter is Solana-specific, and there is no injected EIP-1193
 * provider inside an Android app. WalletConnect was built here and removed: its
 * relay is metered per monthly active user, which is the wrong shape of
 * dependency for a sign-in path — the cost scales with exactly the thing you
 * want to grow, and it puts a third party between the app and the wallet.
 *
 * The vendor-free replacement is the browser hand-off this app already uses on
 * desktop (services/desktopWalletLink.ts): borrow a browser that *does* have
 * the wallet, sign there, seal the signatures back. On Android that browser is
 * the wallet's own in-app browser and the return channel is the `privateer://`
 * scheme rather than desktop's loopback listener.
 *
 * Until that exists, the LoginScreen only offers Ethereum on web.
 */
export async function evmLogin(): Promise<never> {
  throw new Error('Ethereum wallet sign-in is not supported on this platform yet.');
}

// Re-export the platform-agnostic surface so existing imports from
// '../services/walletAuthService' keep working unchanged.
export {
  isWalletCancellation,
  clearDerivedKey,
} from './walletAuthShared';
export type { WalletUser, WalletAuthResult } from './walletAuthShared';

const IDENTITY = {
  name: brand.name,
  uri: `https://${brand.domain}`,
  icon: brand.walletIcon,
};

/**
 * Sign in via Solana wallet. After this resolves, the in-memory master key is
 * loaded and the user is authenticated.
 */
export async function solanaLogin(opts?: { recover?: boolean }): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  // One MWA session signs the auth message + the vault message, both from the
  // same authorized account. No second session, no version branching — the
  // vault message is always v2.
  const { account, authSignature, authMessage, vaultSignature } = await transact(async (wallet: Web3MobileWallet) => {
    const authResult = await wallet.authorize({
      identity: IDENTITY,
      chain: 'solana:mainnet',
    });

    const address = authResult.accounts[0].address;
    const account = solanaAccount(base64ToBytes(address));
    const { authMessage, vaultMessage } = buildWalletMessages(account, nonce);

    const authSigResult = await wallet.signMessages({
      addresses: [address],
      payloads: [authMessage],
    });
    const vaultSigResult = await wallet.signMessages({
      addresses: [address],
      payloads: [vaultMessage],
    });

    return {
      account,
      authSignature: authSigResult[0],
      authMessage,
      vaultSignature: vaultSigResult[0],
    };
  });

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    // Enrollment only: a second MWA session, because the one above is closed by
    // the time the server tells us this sign-in is creating the vault.
    resignVault: () => signVaultMessage(account.idHex),
  });
}

/**
 * Open an MWA session and sign the vault message. `expectedPubkeyHex` binds the
 * result to a known account — authorize() reconnects whatever the wallet has
 * authorized, and on the enrollment re-sign we must be comparing signatures
 * from the same account or an honest wallet would fail the determinism gate.
 */
async function signVaultMessage(expectedPubkeyHex?: string): Promise<Uint8Array> {
  return transact(async (wallet: Web3MobileWallet) => {
    const authResult = await wallet.authorize({
      identity: IDENTITY,
      chain: 'solana:mainnet',
    });
    const address = authResult.accounts[0].address;
    const account = solanaAccount(base64ToBytes(address));
    const { vaultMessage } = buildWalletMessages(account, '');
    if (expectedPubkeyHex && account.idHex !== expectedPubkeyHex) {
      throw new Error('A different wallet account signed the second time. Use the same account to finish setting up.');
    }
    const results = await wallet.signMessages({
      addresses: [address],
      payloads: [vaultMessage],
    });
    return results[0];
  });
}

/**
 * Re-derive the master key for an authenticated wallet user by prompting the
 * wallet for a fresh vault signature. Used when the on-device cache is empty
 * (first sign-in on this device, after logout, or after a REAUTH_REQUIRED
 * response from the server).
 */
export async function loadDerivedKey(): Promise<void> {
  const vault = await fetchWalletVault();

  // An account enrolled on another chain can't be unlocked here: prompting
  // Mobile Wallet Adapter would derive a different KEK and report "could not
  // unlock your data" on a perfectly healthy account. Say what's actually wrong
  // instead. (Reachable today only by enrolling on web, then installing the
  // Android app — there is no native EVM sign-in to create one from.)
  if (vault.walletChain && vault.walletChain !== 'solana') {
    throw new Error('This account signs in with an Ethereum wallet. Use the web app to unlock it on this device.');
  }

  await completeLoadDerivedKey(vault, await signVaultMessage());
}
