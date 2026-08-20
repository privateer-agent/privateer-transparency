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
import { signatureFromSignedPayload } from './wallets/mwaSignedPayload';
import { ChainNamespace, WalletAccount } from './wallets/chains';
import {
  WalletAuthResult,
  buildWalletMessages,
  fetchNonce,
  completeWalletLogin,
  fetchWalletVault,
  completeLoadDerivedKey,
  assertVaultAccount,
  solanaAccount,
  solanaAccountFromHex,
  base64ToBytes,
} from './walletAuthShared';
// The reply shape is the shared one both hand-off transports return
// (wallets/walletLinkPayload.ts), not something this transport defines.
import type { LinkedSignatures } from './wallets/walletLinkPayload';
import {
  InAppBrowserWallet,
  canHandoffToWalletBrowser,
  linkWalletViaWalletBrowser,
  cancelWalletHandoff,
  preferredWalletBrowser,
  rememberWalletBrowser,
  walletBrowsersFor,
} from './walletHandoffLink';

// ---------------------------------------------------------------------------
// Wallet-browser hand-off — every chain except Solana
//
// Mobile Wallet Adapter is Solana-specific, and there is no injected provider
// of any kind inside an Android app: no EIP-1193 for EVM, no window for Sui's
// Wallet Standard events to fire in, no `tronLink`. WalletConnect was built
// here and removed — its relay is metered per monthly active user, which is the
// wrong shape of dependency for a sign-in path, because the cost scales with
// exactly the thing you want to grow and it puts a third party between the app
// and the wallet.
//
// The vendor-free replacement is the browser hand-off this app already uses on
// desktop, with the wallet's OWN in-app browser standing in for the user's
// default browser and the `privateer://` scheme standing in for the loopback
// listener. Mechanics and the security argument: ./walletHandoffLink.ts.
//
// Solana deliberately does NOT go through it. MWA is a better experience (no
// browser, one wallet picker, both prompts in one session) and it is the path
// that is actually verified on devices.
// ---------------------------------------------------------------------------

/**
 * Back out of a wallet sign-in the user dismissed.
 *
 * Platform-resolved, like the logins themselves, so the sign-in UI has one name
 * to call: here it abandons a pending hand-off, on web it releases the desktop
 * loopback listener, and on iOS there is nothing to cancel. Nothing can recall
 * a request another app already owns — this abandons the *wait*.
 */
export function cancelWalletSignIn(): void {
  cancelWalletHandoff();
}

/** Options every hand-off login accepts. `wallet` is the user's pick, if asked. */
export interface HandoffLoginOptions {
  recover?: boolean;
  /**
   * Which wallet's browser to sign in. The sign-in screen asks (there is no
   * "default wallet app" on Android the way there is a default browser); when
   * it doesn't, the last one used on this device is reused.
   */
  wallet?: InAppBrowserWallet;
}

/** Rebuild the connected account from what the wallet's browser handed back. */
function accountFromLink(linked: LinkedSignatures): WalletAccount {
  // Solana is the one chain whose canonical address is derivable from the hex
  // identity alone. It cannot reach here today (MWA owns that path), but the
  // hand-off is chain-generic and this keeps it honest if that ever changes.
  if (linked.namespace === 'solana' && !linked.address) return solanaAccountFromHex(linked.idHex);
  return { namespace: linked.namespace, address: linked.address!, idHex: linked.idHex };
}

/**
 * Resolve which wallet browser to use, or refuse in a way that says why.
 *
 * A chain with no wallet browser we can address is not a failure to report as
 * "something went wrong" — it is a capability this build genuinely lacks, and
 * config/billingMode.ts hides its tile for exactly this reason. Reaching here
 * means something bypassed the gate.
 */
async function resolveWalletBrowser(
  chain: ChainNamespace,
  picked?: InAppBrowserWallet,
): Promise<InAppBrowserWallet> {
  // A pick from a stale screen is checked rather than trusted: it becomes a
  // deeplink, and an unknown wallet builds one that opens nothing.
  if (picked && (walletBrowsersFor(chain) as string[]).includes(picked)) return picked;
  const wallet = await preferredWalletBrowser(chain);
  if (!wallet) {
    throw new Error(`${chain} wallet sign-in is not supported on this platform yet.`);
  }
  return wallet;
}

/**
 * Full sign-in through the wallet-browser hand-off, for any chain.
 *
 * Identical for all of them, because everything chain-specific — which provider
 * to connect, which vault message to sign, how the identity is encoded —
 * happens on the browser side and arrives here already normalized.
 */
async function handoffLogin(
  chain: ChainNamespace,
  opts?: HandoffLoginOptions,
): Promise<WalletAuthResult> {
  const wallet = await resolveWalletBrowser(chain, opts?.wallet);
  const { nonce, nonceId } = await fetchNonce();
  const linked = await linkWalletViaWalletBrowser('login', nonce, chain, wallet);

  // Only after a signature actually came back. Remembering a wallet the user
  // never completed a sign-in with would send the silent unlock path to it.
  void rememberWalletBrowser(chain, wallet);

  return completeWalletLogin({
    account: accountFromLink(linked),
    authSignature: linked.authSignature!,
    authMessage: linked.authMessage!,
    vaultSignature: linked.vaultSignature,
    nonceId,
  }, {
    ...opts,
    // Enrollment only, once in an account's lifetime. Unlike desktop there is
    // no tab still holding the wallet to ask (linked.resign() is null by
    // construction here), so this is a whole second trip: back into the same
    // wallet's browser, reconnect, one prompt. 'unlock' mode signs only the
    // vault message.
    resignVault: async () => {
      const same = await linked.resign();
      if (same) return same;

      const again = await linkWalletViaWalletBrowser('unlock', '', chain, wallet);
      // A fresh hand-off is a fresh wallet session the user could have switched
      // accounts in, and two signatures from two different accounts would fail
      // the determinism gate for the wrong reason.
      if (again.idHex !== linked.idHex) {
        throw new Error('A different wallet account signed the second time. Use the same account to finish setting up.');
      }
      return again.vaultSignature;
    },
  });
}

/**
 * Sign in via an Ethereum (or any EVM) wallet, through its in-app browser.
 * After this resolves the in-memory master key is loaded and the user is
 * authenticated — the same end state as the MWA path below.
 */
export async function evmLogin(opts?: HandoffLoginOptions): Promise<WalletAuthResult> {
  return handoffLogin('eip155', opts);
}

/**
 * Sign in via a Sui wallet, through Slush's in-app browser.
 *
 * The only chain whose deeplink is a ROUTE rather than a parameter
 * (`browse/:url`), which is worth knowing here because it means the target is
 * encoded into a path — see wallets/inAppBrowserLinks.ts.
 */
export async function suiLogin(opts?: HandoffLoginOptions): Promise<WalletAuthResult> {
  return handoffLogin('sui', opts);
}

/** Sign in via TronLink, through its in-app browser. */
export async function tronLogin(opts?: HandoffLoginOptions): Promise<WalletAuthResult> {
  return handoffLogin('tron', opts);
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

    // signMessages answers with signed *payloads* — the message with the
    // signature appended — not with signatures. See wallets/mwaSignedPayload.
    return {
      account,
      authSignature: signatureFromSignedPayload(authSigResult[0], authMessage),
      authMessage,
      vaultSignature: signatureFromSignedPayload(vaultSigResult[0], vaultMessage),
    };
  });

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    // Enrollment only: a second MWA session, because the one above is closed by
    // the time the server tells us this sign-in is creating the vault.
    resignVault: () => signVaultMessage((signer) => {
      if (signer.idHex !== account.idHex) {
        throw new Error('A different wallet account signed the second time. Use the same account to finish setting up.');
      }
    }),
  });
}

/**
 * Open an MWA session and sign the vault message.
 *
 * `check` binds the result to the account the caller means, because authorize()
 * reconnects whatever the wallet has authorized, which need not be that one:
 *
 *   - enrolling, we must be comparing two signatures from the *same* account or
 *     an honest wallet would fail the determinism gate;
 *   - unlocking, a signature from the wrong account derives a KEK that cannot
 *     unwrap this vault (see walletAuthShared.assertVaultAccount).
 *
 * It runs before signMessages so a wrong pick costs no prompt.
 */
async function signVaultMessage(check?: (account: WalletAccount) => void): Promise<Uint8Array> {
  return transact(async (wallet: Web3MobileWallet) => {
    const authResult = await wallet.authorize({
      identity: IDENTITY,
      chain: 'solana:mainnet',
    });
    const address = authResult.accounts[0].address;
    const account = solanaAccount(base64ToBytes(address));
    const { vaultMessage } = buildWalletMessages(account, '');
    check?.(account);
    const results = await wallet.signMessages({
      addresses: [address],
      payloads: [vaultMessage],
    });
    return signatureFromSignedPayload(results[0], vaultMessage);
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

  // An account enrolled on another chain can't be unlocked through MWA:
  // prompting it would derive a different KEK and report "could not unlock your
  // data" on a perfectly healthy account. The vault message is namespace-scoped,
  // so the chain that enrolled is the only one that can unwrap.
  if (vault.walletChain && vault.walletChain !== 'solana') {
    const chain = vault.walletChain as ChainNamespace;

    // Same hand-off as sign-in, minus the auth message — an already
    // authenticated user has no nonce to bind. There is no UI to ask which
    // wallet from here (this runs on a cleared key cache or a REAUTH_REQUIRED),
    // which is why the sign-in remembers the answer.
    if (canHandoffToWalletBrowser(chain)) {
      const wallet = await resolveWalletBrowser(chain);
      const linked = await linkWalletViaWalletBrowser('unlock', '', chain, wallet);
      // The one branch that can't check before signing: the hand-off returns a
      // signature and the identity that made it in one answer.
      assertVaultAccount(vault, accountFromLink(linked));
      await completeLoadDerivedKey(vault, linked.vaultSignature);
      return;
    }

    // A chain we can reach no wallet for on this device (Sui today). Say what's
    // actually wrong rather than failing as a decryption error.
    throw new Error('This account signs in with a wallet on another chain. Use the web app to unlock it on this device.');
  }

  // Bound to the enrolled account, for the same reason enrollment binds to the
  // first signature: the wallet picker can offer several accounts and only one
  // of them derives the KEK that unwraps this vault.
  await completeLoadDerivedKey(vault, await signVaultMessage((signer) => assertVaultAccount(vault, signer)));
}
