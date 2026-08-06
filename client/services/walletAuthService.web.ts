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
  solanaAccount,
  solanaAccountFromHex,
  fetchNonce,
  completeWalletLogin,
  fetchWalletVault,
  completeLoadDerivedKey,
} from './walletAuthShared';
import { connectBrowserWallet } from './browserWalletProvider.web';
import { connectEvmWallet } from './evmWalletProvider.web';
import { connectSuiWallet } from './suiWalletProvider.web';
import { connectTronWallet } from './tronWalletProvider.web';
import { canLinkWalletViaBrowser, linkWalletViaBrowser, LinkedSignatures } from './desktopWalletLink';
import { ChainNamespace, WalletAccount } from './wallets/chains';

// Re-export the platform-agnostic surface so existing imports from
// '../services/walletAuthService' keep working unchanged on web.
export {
  isWalletCancellation,
  clearDerivedKey,
} from './walletAuthShared';
export type { WalletUser, WalletAuthResult } from './walletAuthShared';

// ---------------------------------------------------------------------------
// Desktop browser hand-off
//
// Electron loads no extensions, so there is no injected wallet of any kind in
// the desktop renderer. Signing happens in the user's real browser and only the
// signatures come back; everything after that — verify, enroll/unwrap, session
// — still runs on this side. See ./desktopWalletLink.ts.
// ---------------------------------------------------------------------------

/** Rebuild the connected account from what the browser handed back. */
function accountFromLink(linked: LinkedSignatures): WalletAccount {
  // Solana is the one chain whose canonical address is derivable from the hex
  // identity, which is all a pre-multi-chain page sends back.
  if (linked.namespace === 'solana' && !linked.address) return solanaAccountFromHex(linked.idHex);
  return { namespace: linked.namespace, address: linked.address!, idHex: linked.idHex };
}

/**
 * Full sign-in through the browser hand-off, for any chain.
 *
 * Identical for all four because the chain-specific parts — which provider to
 * connect, which vault message to sign, how the identity is encoded — all
 * happen on the browser side and arrive here already normalized.
 */
async function handoffLogin(
  chain: ChainNamespace,
  nonce: string,
  nonceId: string,
  opts?: { recover?: boolean },
): Promise<WalletAuthResult> {
  const linked = await linkWalletViaBrowser('login', nonce, chain);
  return completeWalletLogin({
    account: accountFromLink(linked),
    authSignature: linked.authSignature!,
    authMessage: linked.authMessage!,
    vaultSignature: linked.vaultSignature,
    nonceId,
  }, {
    ...opts,
    // Enrollment only: a second hand-off to the same browser. 'unlock' mode
    // re-signs just the vault message, and we re-check the identity because a
    // fresh hand-off is a fresh wallet session the user could switch accounts in.
    resignVault: async () => {
      const again = await linkWalletViaBrowser('unlock', '', chain);
      if (again.idHex !== linked.idHex) {
        throw new Error('A different wallet account signed the second time. Use the same account to finish setting up.');
      }
      return again.vaultSignature;
    },
  });
}

/**
 * Sign in via a browser Solana wallet. After this resolves, the in-memory
 * master key is loaded and the user is authenticated.
 */
export async function solanaLogin(opts?: { recover?: boolean }): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  if (canLinkWalletViaBrowser()) return handoffLogin('solana', nonce, nonceId, opts);

  const wallet = await connectBrowserWallet();
  const account = solanaAccount(wallet.pubkeyBytes);
  const { authMessage, vaultMessage } = buildWalletMessages(account, nonce);

  const authSignature = await wallet.signMessage(authMessage);
  const vaultSignature = await wallet.signMessage(vaultMessage);

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    // Enrollment only. Re-signs through the handle we're already connected to,
    // so it's the same account by construction — no second picker.
    resignVault: () => wallet.signMessage(vaultMessage),
  });
}

/**
 * Sign in via a browser EVM wallet (MetaMask, Rabby, Coinbase, …).
 *
 * Structurally identical to solanaLogin — connect, sign the auth message, sign
 * the vault message, hand both to the shared core — because everything that
 * differs between the chains is in wallets/chains.ts and the provider module.
 * One EVM address is the same account on every EVM network, so there is no
 * network to pick here and switching networks in the wallet changes nothing.
 *
 * Gated by multiChainWalletsEnabled(); callers must not reach this otherwise.
 */
export async function evmLogin(opts?: { recover?: boolean }): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  if (canLinkWalletViaBrowser()) return handoffLogin('eip155', nonce, nonceId, opts);

  const wallet = await connectEvmWallet();
  const { account } = wallet;
  const { authMessage, vaultMessage } = buildWalletMessages(account, nonce);

  const authSignature = await wallet.signMessage(authMessage);
  const vaultSignature = await wallet.signMessage(vaultMessage);

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    resignVault: () => wallet.signMessage(vaultMessage),
  });
}

/**
 * Sign in via a browser Sui wallet (Slush, Suiet, Nightly, …).
 *
 * Same three steps as the other two chains. What differs is entirely inside the
 * provider: Sui wallets announce themselves over the Wallet Standard instead of
 * injecting a global, and `sui:signPersonalMessage` returns a serialized
 * `flag || sig || pubkey` rather than a bare signature. A Sui address is the
 * same account on mainnet, testnet and devnet, so — as with EVM — there is no
 * network to pick.
 *
 * Gated by suiWalletEnabled(); callers must not reach this otherwise.
 */
export async function suiLogin(opts?: { recover?: boolean }): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  if (canLinkWalletViaBrowser()) return handoffLogin('sui', nonce, nonceId, opts);

  const wallet = await connectSuiWallet();
  const { account } = wallet;
  const { authMessage, vaultMessage } = buildWalletMessages(account, nonce);

  const authSignature = await wallet.signMessage(authMessage);
  const vaultSignature = await wallet.signMessage(vaultMessage);

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    resignVault: () => wallet.signMessage(vaultMessage),
  });
}

/**
 * Sign in via a browser Tron wallet (TronLink, OKX, Bitget, …).
 *
 * Same three steps again. Tron's differences are all inside the provider and the
 * verifier: the wallet is a `tronLink`-shaped injected object rather than an
 * announced one, `signMessageV2` frames the digest with Tron's own prefix, and
 * the identity travels as the base58check "T…" address instead of hex. The
 * signature itself is the same 65-byte secp256k1 shape as EVM's — which is also
 * why one key's Tron and Ethereum accounts must stay apart, and do: the v3 vault
 * message is scoped by namespace.
 *
 * Gated by tronWalletEnabled(); callers must not reach this otherwise.
 */
export async function tronLogin(opts?: { recover?: boolean }): Promise<WalletAuthResult> {
  const { nonce, nonceId } = await fetchNonce();

  if (canLinkWalletViaBrowser()) return handoffLogin('tron', nonce, nonceId, opts);

  const wallet = await connectTronWallet();
  const { account } = wallet;
  const { authMessage, vaultMessage } = buildWalletMessages(account, nonce);

  const authSignature = await wallet.signMessage(authMessage);
  const vaultSignature = await wallet.signMessage(vaultMessage);

  return completeWalletLogin({ account, authSignature, authMessage, vaultSignature, nonceId }, {
    ...opts,
    resignVault: () => wallet.signMessage(vaultMessage),
  });
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
  // authenticated user. The chain has to be the one the account enrolled on for
  // the same reason it does on the branches below: the vault message is
  // namespace-scoped, so the wrong chain derives a KEK that cannot unwrap.
  if (canLinkWalletViaBrowser()) {
    const chain: ChainNamespace = vault.walletChain ?? 'solana';
    const linked = await linkWalletViaBrowser('unlock', '', chain);
    await completeLoadDerivedKey(vault, linked.vaultSignature);
    return;
  }

  // Re-derive with the chain the account actually enrolled on. An EVM vault
  // was wrapped under a v3 message signed by an EVM wallet; prompting the
  // Solana provider here would derive a different KEK and surface as "could not
  // unlock your data" on an account that is perfectly healthy. Accounts that
  // predate multi-chain have no walletChain, and Solana is correct for them.
  if (vault.walletChain === 'eip155') {
    const evm = await connectEvmWallet();
    const { vaultMessage } = buildWalletMessages(evm.account, '');
    await completeLoadDerivedKey(vault, await evm.signMessage(vaultMessage));
    return;
  }

  if (vault.walletChain === 'sui') {
    const sui = await connectSuiWallet();
    const { vaultMessage } = buildWalletMessages(sui.account, '');
    await completeLoadDerivedKey(vault, await sui.signMessage(vaultMessage));
    return;
  }

  if (vault.walletChain === 'tron') {
    const tron = await connectTronWallet();
    const { vaultMessage } = buildWalletMessages(tron.account, '');
    await completeLoadDerivedKey(vault, await tron.signMessage(vaultMessage));
    return;
  }

  const wallet = await connectBrowserWallet();
  const { vaultMessage } = buildWalletMessages(solanaAccount(wallet.pubkeyBytes), '');
  const vaultSignature = await wallet.signMessage(vaultMessage);

  await completeLoadDerivedKey(vault, vaultSignature);
}
