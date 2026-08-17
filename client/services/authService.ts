import { Platform } from 'react-native';
import { secureKv } from './internal/secureKv';
import { getServerUrl } from '../config/environment';
import {
  loadPersistedKey,
  setMasterKey,
  isMasterKeyLoaded,
  clearAllKeyMaterial,
  clearSessionKeyState,
  fromBase64,
  toBase64,
  generateMasterKey,
  generateKdfSalt,
  deriveKekFromPassword,
  wrapMasterKey,
  unwrapMasterKey,
  DEFAULT_KDF_PARAMS,
  KdfParams,
  subscribeMasterKeyState,
} from './cryptoService';
import { syncOutboxPublicKey, resetOutboxKeyState } from './outboxKeyService';
import { clearOutboxResults } from './outboxService';
import { clearAccountModelsCache } from './accountModelsService';
import { clearTrustedTerminalKeys } from './terminalTrustService';
import { clearCargoContentCache } from './internal/cargoContentCache';
import { setAccountScope } from './internal/accountScope';
import { installLegacyLocalDataAdoption } from './internal/legacyLocalData';
import { Sentry } from './sentryService';
import { sessionDeviceMeta } from '../utils/sessionDevice';

const API_BASE_URL = getServerUrl();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UserData {
  id: string;
  email?: string;
  profileImage?: string;
  /** Legacy Solana-only identity. Null for wallet accounts on other chains. */
  solanaPublicKey?: string | null;
  /** Canonical address for any chain — prefer this over solanaPublicKey. */
  walletAddress?: string | null;
  walletChain?: 'solana' | 'eip155' | 'sui' | 'tron' | null;
  kekSource?: 'password' | 'wallet' | null;
}

interface VaultPayload {
  wrappedMasterKey: string;
  kekSource: 'password' | 'wallet';
  kdfSalt: string | null;
  kdfParams: KdfParams | null;
  /**
   * Which chain this wallet vault was enrolled on. The client picks both the
   * wallet provider and the vault message from this. Absent on accounts
   * created before multi-chain sign-in, where Solana is correct.
   */
  walletChain?: 'solana' | 'eip155' | 'sui' | 'tron' | null;
}

interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: UserData;
  vault: VaultPayload | null;
}

// ---------------------------------------------------------------------------
// AuthService
// ---------------------------------------------------------------------------

class AuthService {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private user: UserData | null = null;
  private refreshingPromise: Promise<boolean> | null = null;
  private tokenExpirationCallbacks: Array<() => void> = [];

  private reauthPromise: Promise<void> | null = null;
  private reauthResolve: (() => void) | null = null;
  private reauthReject: ((err: Error) => void) | null = null;
  private reauthCallbacks: Array<() => void> = [];

  constructor() {
    // Publish the account outbox public key once BOTH the master key and a
    // session token exist. Their load order varies (password login sets the key
    // first, wallet/warm-start set the token first), so we trigger from both the
    // key-load event here and the token-store path (storeAuthData / initialize).
    // trySyncOutboxKey guards on both and syncOutboxPublicKey dedups per session.
    subscribeMasterKeyState((loaded) => {
      if (loaded) this.trySyncOutboxKey();
    });
  }

  // Fire-and-forget publish; no-ops until both key and token are present.
  private trySyncOutboxKey(): void {
    if (!this.accessToken) return;
    void syncOutboxPublicKey(this.makeAuthenticatedRequest.bind(this));
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  async initialize(): Promise<boolean> {
    try {
      const [storedAccess, storedRefresh, storedUser] = await Promise.all([
        secureKv.getItem('accessToken'),
        secureKv.getItem('refreshToken'),
        secureKv.getItem('user')
      ]);

      if (storedAccess && storedRefresh && storedUser) {
        this.accessToken = storedAccess;
        this.refreshToken = storedRefresh;
        this.user = JSON.parse(storedUser);
        // Point the on-device stores at this account before anything can read
        // them — an unscoped read would find nothing, a wrong-scoped one would
        // find somebody else's rows.
        setAccountScope(this.user?.id ?? null);
        // Warm start restores the token here (not via storeAuthData); publish
        // if the cached master key is already loaded, else the key-load event will.
        this.trySyncOutboxKey();
        return true;
      }
      return false;
    } catch (error) {
      console.error('Auth initialization error:', error);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Email / password
  // ---------------------------------------------------------------------------

  /**
   * Register a new email/password account.
   *
   * The caller has already generated a master key, derived a KEK from the
   * password, and wrapped the master key. The server stores ciphertext only;
   * it never sees the password-derived KEK or the master key.
   */
  async register(args: {
    email: string;
    password: string;
    wrappedMasterKey: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    // Aggregate analytics only: this device used guest mode before signing
    // up, so the server counts the signup as a guest conversion.
    fromGuest?: boolean;
  }): Promise<{ message: string; requiresVerification: boolean; email: string }> {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(args),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Registration failed');
    return data;
  }

  /**
   * Sign up flow used by SignupScreen: generate master key, derive KEK from
   * password, wrap the master key, register the account on the server.
   *
   * After this returns successfully, the caller still needs to verify their
   * email before they can log in.
   */
  async signupWithPassword(email: string, password: string): Promise<{ requiresVerification: boolean; email: string }> {
    const masterKey = generateMasterKey();
    const kdfSalt = generateKdfSalt();
    const kdfParams = DEFAULT_KDF_PARAMS;
    const kek = await deriveKekFromPassword(password, kdfSalt, kdfParams);
    const wrappedMasterKey = wrapMasterKey(masterKey, kek);

    // Guest-conversion signal (analytics only). Dynamic import to avoid a
    // static cycle with the chat/graph service graph; never blocks signup.
    let fromGuest = false;
    try {
      const { hasGuestChatsToImport } = await import('./guestConversionService');
      fromGuest = await hasGuestChatsToImport();
    } catch {
      // Signal is best-effort only.
    }

    const result = await this.register({
      email,
      password,
      wrappedMasterKey,
      kdfSalt: toBase64(kdfSalt),
      kdfParams,
      fromGuest,
    });

    return { requiresVerification: result.requiresVerification, email: result.email };
  }

  /**
   * Sign in with email/password. Unwraps the master key locally and caches it
   * in EncryptedStorage so subsequent app opens skip the password prompt.
   */
  async loginWithPassword(email: string, password: string, opts?: { recover?: boolean }): Promise<AuthResponse> {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // Tag the session with the surface signing in, so the account's linked-
      // device list names this row ("iPhone" / "Desktop app on macOS") instead
      // of showing an anonymous "App". Display metadata only.
      // `recover: true` asks the server to lift a pending 30-day deletion on an
      // otherwise valid password login (sent only after the user confirms the
      // "account scheduled for deletion — recover?" prompt).
      body: JSON.stringify({ email, password, ...(opts?.recover ? { recover: true } : {}), ...sessionDeviceMeta() }),
    });

    const data = await response.json();
    if (!response.ok) {
      // Preserve structured signals so callers can branch without matching on
      // the (now localized) message text.
      const err: any = new Error(data.message || 'Login failed');
      err.code = data.code;
      err.requiresVerification = data.requiresVerification;
      throw err;
    }

    if (!data.vault) {
      throw new Error('Account is missing a vault. Contact support.');
    }
    if (data.vault.kekSource !== 'password' || !data.vault.kdfSalt || !data.vault.kdfParams) {
      throw new Error('This account uses a different sign-in method.');
    }

    const kek = await deriveKekFromPassword(password, fromBase64(data.vault.kdfSalt), data.vault.kdfParams);
    let masterKey: Uint8Array;
    try {
      masterKey = unwrapMasterKey(data.vault.wrappedMasterKey, kek);
    } catch (err) {
      Sentry.captureException(err, { level: 'warning', tags: { op: 'password_unwrap_key' } });
      throw new Error('Could not unlock your data. Try again.');
    }
    await setMasterKey(masterKey, { persist: true });

    await this.storeAuthData(data.accessToken, data.refreshToken, data.user);
    return data;
  }

  // ---------------------------------------------------------------------------
  // Email verification
  // ---------------------------------------------------------------------------

  async verifyEmail(token: string): Promise<{ message: string }> {
    const response = await fetch(`${API_BASE_URL}/auth/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Email verification failed');
    return data;
  }

  async resendVerification(email: string): Promise<{ message: string }> {
    const response = await fetch(`${API_BASE_URL}/auth/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Failed to resend verification');
    return data;
  }

  // ---------------------------------------------------------------------------
  // Password change (re-wraps master key under a new KEK)
  // ---------------------------------------------------------------------------

  /**
   * Change the account password. Unwraps the existing master key with the old
   * password's KEK, re-wraps it under a new KEK, and submits both halves to
   * the server. The master key itself never changes — only its wrapping does.
   *
   * On success, all existing sessions are revoked server-side; the caller must
   * sign in again.
   */
  async changePassword(args: { currentPassword: string; newPassword: string }): Promise<void> {
    if (!this.user) throw new Error('Not signed in');
    if (!isMasterKeyLoaded()) throw new Error('Vault is locked');

    const meRes = await this.makeAuthenticatedRequest('/auth/me');
    if (!meRes.ok) throw new Error('Failed to fetch current vault');
    const meData = await meRes.json() as { vault: VaultPayload | null };
    if (!meData.vault || meData.vault.kekSource !== 'password' || !meData.vault.kdfSalt || !meData.vault.kdfParams) {
      throw new Error('This account does not use a password.');
    }

    const oldKek = await deriveKekFromPassword(
      args.currentPassword,
      fromBase64(meData.vault.kdfSalt),
      meData.vault.kdfParams,
    );
    let masterKey: Uint8Array;
    try {
      masterKey = unwrapMasterKey(meData.vault.wrappedMasterKey, oldKek);
    } catch (err) {
      Sentry.captureException(err, { level: 'warning', tags: { op: 'password_change_unwrap' } });
      throw new Error('Current password is incorrect');
    }

    const newSalt = generateKdfSalt();
    const newParams = DEFAULT_KDF_PARAMS;
    const newKek = await deriveKekFromPassword(args.newPassword, newSalt, newParams);
    const newWrapped = wrapMasterKey(masterKey, newKek);

    const res = await this.makeAuthenticatedRequest('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        currentPassword: args.currentPassword,
        newPassword: args.newPassword,
        wrappedMasterKey: newWrapped,
        kdfSalt: toBase64(newSalt),
        kdfParams: newParams,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { message?: string };
      throw new Error(err.message || 'Failed to change password');
    }

    // Server revoked all sessions — clean up locally and force re-login.
    await this.handleTokenExpiration();
  }

  // ---------------------------------------------------------------------------
  // Account deletion
  // ---------------------------------------------------------------------------

  // Initiates the 30-day grace-period deletion on the server. The server
  // revokes all sessions, so we tear down local session/key state afterward to
  // force a clean signed-out state. The account can be recovered by signing in
  // again before the grace period elapses.
  async requestAccountDeletion(): Promise<{ hardDeleteAt?: string }> {
    if (!this.user) throw new Error('Not signed in');

    const res = await this.makeAuthenticatedRequest('/auth/account/delete-request', {
      method: 'POST',
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as { message?: string };
      throw new Error(err.message || 'Failed to delete account');
    }

    const data = await res.json().catch(() => ({})) as { hardDeleteAt?: string };

    // Server already revoked sessions — clear everything locally.
    await Promise.all([
      secureKv.removeItem('accessToken'),
      secureKv.removeItem('refreshToken'),
      secureKv.removeItem('user'),
    ]);
    await clearSessionKeyState();
    clearCargoContentCache();
    this.accessToken = null;
    this.refreshToken = null;
    this.user = null;
    setAccountScope(null);

    return data;
  }

  // ---------------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------------

  async logout(): Promise<void> {
    if (this.accessToken) {
      try {
        await fetch(`${API_BASE_URL}/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${this.accessToken}` }
        });
      } catch (_) { /* non-fatal */ }
    }

    await Promise.all([
      secureKv.removeItem('accessToken'),
      secureKv.removeItem('refreshToken'),
      secureKv.removeItem('user'),
    ]);
    await clearSessionKeyState();
    this.accessToken = null;
    this.refreshToken = null;
    this.user = null;
    // Signed out: the on-device stores address nobody until the next sign-in.
    // The data stays on disk under the account's namespace — local-backend
    // content has no server copy, so signing out must not destroy it.
    setAccountScope(null);
    resetOutboxKeyState();
    // Drop the account model catalog cache so a different account signing in on this
    // device doesn't briefly see the previous account's model list.
    clearAccountModelsCache();
    // Wipe caught-up outbox results — they're decrypted plaintext tied to the
    // account and must not survive sign-out on a shared device.
    void clearOutboxResults();
    // …and the briefs written over them, which are the same plaintext condensed.
    // Imported lazily: inboxBriefService reaches inference, which reaches back
    // here, and this module must not sit in that cycle at load time.
    void import('./inboxBriefService').then((m) => m.clearInboxBriefs()).catch(() => {});
    // Drop pinned terminal keys — they belong to this account's terminals; a
    // different account signing in on this device must not inherit their trust.
    void clearTrustedTerminalKeys();
    // Decrypted artifact content held for the preview path — same rule as the
    // outbox results above: plaintext must not survive sign-out.
    clearCargoContentCache();
  }

  // ---------------------------------------------------------------------------
  // Token refresh
  // ---------------------------------------------------------------------------

  async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken) return false;
    if (this.refreshingPromise) return this.refreshingPromise;

    this.refreshingPromise = this._doRefresh();
    try {
      return await this.refreshingPromise;
    } finally {
      this.refreshingPromise = null;
    }
  }

  /** POST /auth/refresh with one specific token. Non-2xx returns its status. */
  private async _postRefresh(
    refreshToken: string,
  ): Promise<{ ok: true; data: { accessToken: string; refreshToken: string } } | { ok: false; status: number }> {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    if (!response.ok) return { ok: false, status: response.status };
    return { ok: true, data: await response.json() };
  }

  private async _doRefresh(): Promise<boolean> {
    try {
      // Rotate the freshest token on disk, not whichever one this instance
      // booted with. The store is shared but each instance caches its own copy
      // in memory — web runs several tabs against one IndexedDB, and each holds
      // the token it read at init. Once any tab rotates, every other tab's copy
      // is spent, and replaying a spent token outside the server's 30s grace
      // window reads as theft: rotateRefreshToken revokes the whole device
      // family, so the next request from ANY tab 401s and the session dies with
      // no message (on web, straight out to the marketing landing).
      const stored = await secureKv.getItem('refreshToken').catch(() => null);
      if (stored && stored !== this.refreshToken) this.refreshToken = stored;

      const sent = this.refreshToken;
      if (!sent) return false;
      let result = await this._postRefresh(sent);

      if (!result.ok && result.status === 401) {
        // Another tab may have rotated between our read above and this reply —
        // that leaves us holding a spent token through no fault of the session.
        // Retry once with whatever is on disk now; only a 401 on the CURRENT
        // stored token means the session is genuinely gone.
        const latest = await secureKv.getItem('refreshToken').catch(() => null);
        if (latest && latest !== sent) {
          this.refreshToken = latest;
          result = await this._postRefresh(latest);
        }
      }

      if (!result.ok) {
        if (result.status === 401) {
          await this.handleTokenExpiration();
        }
        return false;
      }

      await this.storeAuthData(result.data.accessToken, result.data.refreshToken, this.user!);
      return true;
    } catch (err) {
      Sentry.captureException(err, { level: 'warning', tags: { op: 'refresh_token' } });
      return false;
    }
  }

  async updateAuthData(accessToken: string, refreshToken: string, user: UserData): Promise<void> {
    await this.storeAuthData(accessToken, refreshToken, user);
  }

  async validateToken(): Promise<{ valid: boolean; reason?: 'expired' | 'server_error' | 'network_error'; user?: UserData }> {
    try {
      if (!this.accessToken) return { valid: false, reason: 'expired' };

      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${this.accessToken}` }
      });

      if (response.status === 401) {
        const refreshed = await this.refreshAccessToken();
        if (!refreshed) return { valid: false, reason: 'expired' };

        const retryResponse = await fetch(`${API_BASE_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${this.accessToken}` }
        });
        if (!retryResponse.ok) {
          await this.handleTokenExpiration();
          return { valid: false, reason: 'expired' };
        }
        const retryData = await retryResponse.json();
        this.user = retryData.user;
        return { valid: true, user: retryData.user };
      }

      if (!response.ok) {
        if (response.status >= 500) {
          return { valid: !!this.accessToken, reason: 'server_error', user: this.user ?? undefined };
        }
        // A non-401, non-5xx failure (e.g. 403 on a grace_period account) means
        // this session is no longer usable. Tear down authService's own token
        // state here — not just React state in the caller — so the two don't
        // desync into a zombie session where useAuth() reports signed-out while
        // makeAuthenticatedRequest still attaches the stale token and it
        // survives relaunch.
        await this.handleTokenExpiration();
        return { valid: false, reason: 'expired' };
      }

      const data = await response.json();
      if (data.user) {
        this.user = data.user;
        await secureKv.setItem('user', JSON.stringify(data.user));
      }
      return { valid: true, user: data.user };
    } catch (_) {
      return { valid: !!this.accessToken, reason: 'network_error' };
    }
  }

  // ---------------------------------------------------------------------------
  // Authenticated requests
  // ---------------------------------------------------------------------------

  async makeAuthenticatedRequest(
    endpoint: string,
    options: RequestInit = {},
    abortSignal?: AbortSignal
  ): Promise<Response> {
    const hadTokenAtStart = !!this.accessToken;
    const isFormData = options.body instanceof FormData;
    const headers: Record<string, string> = {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...(this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {}),
      // Web has no EncryptedStorage / on-device FS, so the 'local' storage
      // backend is non-functional there and the client coerces it to 'cloud'
      // at read time (effectiveStorageBackend). Tell the server so its
      // requireCloudBackend guard applies the same coercion — otherwise a
      // local-pref user on web is blocked from the cloud path the client is
      // forced to take. Read-time only; the stored pref is never mutated.
      ...(Platform.OS === 'web' ? { 'X-Client-Platform': 'web' } : {}),
      ...(options.headers as Record<string, string> | undefined)
    };

    const url = `${API_BASE_URL}${endpoint}`;
    let response = await fetch(url, { ...options, headers, signal: abortSignal });

    if (response.status === 401) {
      const errorData = await response.json().catch(() => ({})) as { code?: string };

      if (errorData.code === 'REAUTH_REQUIRED') {
        await this.triggerReauth();
        const retryHeaders = { ...headers, Authorization: `Bearer ${this.accessToken}` };
        return fetch(url, { ...options, headers: retryHeaders, signal: abortSignal });
      }

      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        const retryHeaders = { ...headers, Authorization: `Bearer ${this.accessToken}` };
        response = await fetch(url, { ...options, headers: retryHeaders, signal: abortSignal });
      }

      if (response.status === 401) {
        // Only treat this as a session expiry if we actually had a token going
        // in. For guest sessions (no token at all), a 401 just means the caller
        // hit an authenticated endpoint without auth — surface that as an
        // unauthorized error without clearing state or firing the expiration
        // callbacks (which log "Token expired" and look like a real signout).
        if (hadTokenAtStart) {
          await this.handleTokenExpiration();
          throw new Error('Your session has expired. Please sign in again.');
        }
        throw new Error('Not authenticated.');
      }
    }

    return response;
  }

  // ---------------------------------------------------------------------------
  // Wallet master-key setup (called once after first wallet auth)
  // ---------------------------------------------------------------------------

  /**
   * Submit the wrapped master key for a wallet account on first sign-in.
   * Returns true if accepted, false if a different wrapped key is already on
   * file (in which case the caller should fall back to fetching it via /auth/me
   * and the existing wallet KEK).
   */
  async setWalletMasterKey(
    wrappedMasterKey: string,
  ): Promise<boolean> {
    const res = await this.makeAuthenticatedRequest('/auth/wallet/master-key', {
      method: 'POST',
      body: JSON.stringify({ wrappedMasterKey }),
    });

    if (res.ok) return true;
    if (res.status === 409) return false;
    const err = await res.json().catch(() => ({})) as { message?: string };
    throw new Error(err.message || 'Failed to register master key');
  }

  // ---------------------------------------------------------------------------
  // Accessors
  // ---------------------------------------------------------------------------

  getAuthState() {
    return {
      token: this.accessToken,
      accessToken: this.accessToken,
      user: this.user,
      isAuthenticated: !!this.accessToken
    };
  }

  getAuthHeader(): { Authorization: string } | Record<string, never> {
    return this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {};
  }

  isMasterKeyReady(): boolean {
    return isMasterKeyLoaded();
  }

  /** Try to restore the master key from EncryptedStorage on cold start. */
  async loadCachedMasterKey(): Promise<boolean> {
    return loadPersistedKey();
  }

  // ---------------------------------------------------------------------------
  // Token expiration callbacks
  // ---------------------------------------------------------------------------

  onTokenExpiration(callback: () => void): () => void {
    this.tokenExpirationCallbacks.push(callback);
    return () => {
      const index = this.tokenExpirationCallbacks.indexOf(callback);
      if (index > -1) this.tokenExpirationCallbacks.splice(index, 1);
    };
  }

  // ---------------------------------------------------------------------------
  // Re-auth
  // ---------------------------------------------------------------------------

  onReauthRequired(callback: () => void): () => void {
    this.reauthCallbacks.push(callback);
    return () => {
      const idx = this.reauthCallbacks.indexOf(callback);
      if (idx > -1) this.reauthCallbacks.splice(idx, 1);
    };
  }

  triggerReauth(): Promise<void> {
    if (this.reauthPromise) return this.reauthPromise;
    this.reauthPromise = new Promise<void>((resolve, reject) => {
      this.reauthResolve = resolve;
      this.reauthReject = reject;
    });
    this.reauthCallbacks.forEach(cb => { try { cb(); } catch (_) {} });
    return this.reauthPromise;
  }

  resolveReauth(): void {
    this.reauthResolve?.();
    this.reauthPromise = null;
    this.reauthResolve = null;
    this.reauthReject = null;
  }

  rejectReauth(): void {
    const err = new Error('Re-authentication cancelled.');
    this.reauthReject?.(err);
    this.reauthPromise = null;
    this.reauthResolve = null;
    this.reauthReject = null;
    this.handleTokenExpiration();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async storeAuthData(accessToken: string, refreshToken: string, user: UserData | null): Promise<void> {
    await Promise.all([
      secureKv.setItem('accessToken', accessToken),
      secureKv.setItem('refreshToken', refreshToken),
      user ? secureKv.setItem('user', JSON.stringify(user)) : Promise.resolve()
    ]);
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    if (user) this.user = user;
    setAccountScope(this.user?.id ?? null);
    this.trySyncOutboxKey();
  }

  private async handleTokenExpiration(): Promise<void> {
    try {
      await Promise.all([
        secureKv.removeItem('accessToken'),
        secureKv.removeItem('refreshToken'),
        secureKv.removeItem('user'),
      ]);
      await clearAllKeyMaterial();
      this.accessToken = null;
      this.refreshToken = null;
      this.user = null;
      setAccountScope(null);
      resetOutboxKeyState();
      void clearOutboxResults();
      void import('./inboxBriefService').then((m) => m.clearInboxBriefs()).catch(() => {});
      this.tokenExpirationCallbacks.forEach(cb => {
        try { cb(); } catch (_) {}
      });
    } catch (error) {
      console.error('Error handling token expiration:', error);
    }
  }
}

export const authService = new AuthService();
export default authService;

// Hand any pre-namespace on-device data to the account that can prove it owns
// it. Runs once both the session and the master key are known — see
// internal/legacyLocalData.ts.
installLegacyLocalDataAdoption();

export type { UserData, VaultPayload };
