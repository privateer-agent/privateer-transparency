/**
 * Wallet Auth Service — iOS stub.
 *
 * Mobile Wallet Adapter is Android-only (it relies on Android Intents).
 * The LoginScreen already hides the Solana sign-in button on iOS
 * (`Platform.OS !== 'ios'` guard), so solanaLogin/loadDerivedKey should
 * never be called here. This file exists solely so that the top-level
 * import in AuthContext doesn't try to load the MWA TurboModule on iOS
 * at startup, which would crash immediately.
 */

export {
  isWalletCancellation,
  clearDerivedKey,
} from './walletAuthShared';
export type { WalletUser, WalletAuthResult } from './walletAuthShared';

export async function solanaLogin(_opts?: { recover?: boolean }): Promise<never> {
  throw new Error('Solana wallet login is not supported on iOS.');
}

/**
 * Never reachable: walletAuthEnabled() is hard-false on iOS (config/
 * billingMode.ts), so no wallet entry point renders. Present so the shared
 * import surface type-checks across platforms.
 */
export async function evmLogin(_opts?: { recover?: boolean }): Promise<never> {
  throw new Error('Wallet login is not supported on iOS.');
}

export async function suiLogin(_opts?: { recover?: boolean }): Promise<never> {
  throw new Error('Wallet login is not supported on iOS.');
}

export async function loadDerivedKey(): Promise<never> {
  throw new Error('Solana wallet login is not supported on iOS.');
}
