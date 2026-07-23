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
  base64ToBytes,
} from './walletAuthShared';

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
  const { pubkeyHex, authSignature, authMessage, vaultSignature } = await transact(async (wallet: Web3MobileWallet) => {
    const authResult = await wallet.authorize({
      identity: IDENTITY,
      chain: 'solana:mainnet',
    });

    const address = authResult.accounts[0].address;
    const { pubkeyHex, authMessage, vaultMessage } = buildWalletMessages(base64ToBytes(address), nonce);

    const authSigResult = await wallet.signMessages({
      addresses: [address],
      payloads: [authMessage],
    });
    const vaultSigResult = await wallet.signMessages({
      addresses: [address],
      payloads: [vaultMessage],
    });

    return {
      pubkeyHex,
      authSignature: authSigResult[0],
      authMessage,
      vaultSignature: vaultSigResult[0],
    };
  });

  return completeWalletLogin({ pubkeyHex, authSignature, authMessage, vaultSignature, nonceId }, opts);
}

/**
 * Re-derive the master key for an authenticated wallet user by prompting the
 * wallet for a fresh vault signature. Used when the on-device cache is empty
 * (first sign-in on this device, after logout, or after a REAUTH_REQUIRED
 * response from the server).
 */
export async function loadDerivedKey(): Promise<void> {
  const vault = await fetchWalletVault();

  const vaultSignature = await transact(async (wallet: Web3MobileWallet) => {
    const authResult = await wallet.authorize({
      identity: IDENTITY,
      chain: 'solana:mainnet',
    });
    const address = authResult.accounts[0].address;
    const { vaultMessage } = buildWalletMessages(base64ToBytes(address), '');
    const results = await wallet.signMessages({
      addresses: [address],
      payloads: [vaultMessage],
    });
    return results[0];
  });

  await completeLoadDerivedKey(vault, vaultSignature);
}
