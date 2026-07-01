# End-to-End Encryption Architecture — Privateer

> Version: 3.0 | Date: 2026-05-06

---

## Threat model

Privateer is end-to-end encrypted: the server stores ciphertext only, and the
encryption key never leaves the user's device. Even a full server compromise
yields no readable user content.

What this protects against:
- Server compromise (DB dump, S3 access, server-side code execution).
- Privateer employees and operators.
- Network observers (TLS plus E2EE).

What this does **not** protect against:
- Compromise of the user's device or wallet.
- Exposure during AI inference. The plaintext message and response transit
  the inference provider (OpenRouter) for model execution. We use Zero Data
  Retention providers where available.
- Loss of the user's password or wallet — there is no recovery path.

## Identity model

Each account has a single Mongo `User._id`. There is no separate
`privateerPublicKey` and no multi-key system; data ownership is keyed by
`userId`.

Auth methods:
- **Email + password** — bcrypt hash on the server for auth, password used
  locally as the encryption key derivation input.
- **Solana wallet** — wallet signature over a fixed message produces the
  encryption KEK; no password.

## Master key wrapping

Every account holds a randomly generated 32-byte AES-256 master key. The
master key is never sent to the server in plaintext. It is wrapped with a KEK
derived locally, and only the wrapped blob is stored on the server.

Per-user `User` document fields:
- `wrappedMasterKey: String` — base64 of `IV ‖ ciphertext ‖ GCM auth tag`.
- `kekSource: 'password' | 'wallet'`.
- `kdfSalt: String` — base64 of 16 random bytes (password users only).
- `kdfParams: { algorithm: 'argon2id', m, t, p }` (password users only).

### KEK derivation — password users
```
KEK = Argon2id(passwordBytes, salt = kdfSalt, m, t, p, dkLen = 32)
```
Default parameters: m = 65536 (64 MiB), t = 3, p = 1. Tuned for ~500 ms on
mid-range mobile devices; can be increased per-user without breaking older
clients (clients honor the `kdfParams` field returned by the server).

### KEK derivation — wallet users
The vault-key message is a single, pubkey-bound string. There is no version
negotiation — v1 was never released, so there is no legacy account class.
```
msg = "Privateer vault key v2 for " + lowercase(hex(walletPubkey))

sig = wallet.signMessage(msg)                          // 64 bytes, deterministic
KEK = HKDF-SHA256(sig, salt = SHA256("privateer-wallet-kek"),
                       info = "aes-256-gcm", length = 32)
```
The auth signature and the vault signature are collected in a single MWA
`transact()` session from the same authorized account — one wallet picker, two
sign prompts, no second session. The server stores `kekMessageVersion: 2` on
enrollment but it is never branched on; the client always signs the v2 string.

### Wrap / unwrap
- AES-256-GCM with a 12-byte random IV per wrap, 128-bit auth tag.
- Wrap: `out = IV || GCM_encrypt(KEK, IV, masterKey)` → base64.
- Unwrap: parse, GCM-decrypt; auth tag failure surfaces as "wrong password".

## Local persistence

### Password users
- Master key cached in `EncryptedStorage` under `@privateer/master_key_raw` so
  cold starts skip the password prompt.
- Password change: client unwraps with old KEK, re-wraps with new KEK from a
  fresh salt, posts to `/auth/change-password`. Master key bytes are unchanged.

### Wallet users
- Master key is cached in `EncryptedStorage` under `@privateer/master_key_raw`
  after the first successful sign-in on the device, identically to password
  users. Cold starts read the cache and decrypt content without any wallet
  interaction.
- The wallet is prompted only when the cache is empty: first sign-in on a
  given device, after logout, after a fresh install, or when the server
  forces a re-auth (`REAUTH_REQUIRED`). In each of those flows the wallet
  signs the vault message, the KEK is re-derived, and the unwrapped master
  key is written back to the cache.
- Threat model: a stolen-and-unlocked device exposes the master key for
  both wallet and password accounts (EncryptedStorage is the only barrier
  in either case). The wallet remains the durable cross-device backup —
  losing the device or wiping the app is OK as long as the user still has
  the wallet, since the server holds the wrapped blob and the wallet
  re-derives the KEK on the next sign-in.

## Content encryption

All user content (messages, AI responses, image and video metadata, image
binaries, project names and instructions, memories, chat titles) is encrypted
client-side with the master key.

Wire format: a JSON string `{"iv":"<base64 12B>","ct":"<base64 ct ‖ tag>"}`.

Plaintext fields on the server schemas (`content`, `aiResponse`, `title`,
`prompt`) are kept optional only for legacy data that predates E2EE.

## AI inference flow

1. Client decrypts conversation history locally.
2. Client sends plaintext message + history to `POST /api/chat/stream`.
3. Server forwards plaintext to the inference provider.
4. Server streams the plaintext AI response back over SSE.
5. Client encrypts the response and persists it via `POST /api/chat/...`.

The server never writes the AI response to the database in plaintext. The
plaintext exists in memory on the server only for the duration of the request.

## Auth endpoints

- `POST /auth/register` — email/password signup. Body includes the
  client-generated `wrappedMasterKey`, `kdfSalt`, `kdfParams`.
- `POST /auth/login` — email/password. Returns tokens plus `vault: { … }`.
- `POST /auth/wallet/nonce` / `POST /auth/wallet/verify` — SIWS auth. Verify
  returns `vault | null` plus `needsMasterKeySetup`.
- `POST /auth/wallet/master-key` — wallet account first-sign-in master key
  registration. Idempotent: 200 if matches, 409 if a different key is on file.
- `POST /auth/change-password` — re-wrap the master key under a new KEK.
- `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/verify-email`,
  `POST /auth/resend-verification` — standard.

## What is intentionally absent

- No password reset endpoints. Forgetting the password is permanent.
- No Google sign-in. OAuth provides no user secret, and bolting on a separate
  encryption password defeats the convenience that drives OAuth conversions.
- No recovery phrase / BIP39 / SLIP-0010. Replaced entirely by the wrapped
  master key.
- No multi-key vault, no key ring, no `X-Privateer-Key` header. Each account
  has exactly one master key.

## Data ownership

Every content model carries `userId: ObjectId(User)` and queries scope by it.
Content models: `Chat`, `ChatGraph`, `ChatNode`, `ChatEdge`, `Message`,
`Project`, `ProjectFile`, `UserMemory`, `LibraryVideo`, `BugReport`,
`SupportTicket`, `UserStoragePrefs`.

## Key file map

Client:
- `client/services/cryptoService.ts` — KDF, wrap/unwrap, encrypt/decrypt.
- `client/services/authService.ts` — login, register, password change, refresh.
- `client/services/walletAuthShared.ts` + `walletAuthService.{web,android,ios}.ts` — SIWS + wallet KEK derivation (shared HKDF-from-signature core, with per-platform signing adapters).
- `client/contexts/AuthContext.tsx` — auth state, lifecycle.
- `client/screens/LoginScreen.tsx`, `SignupScreen.tsx`, `SecurityScreen.tsx`.

Server:
- `server/models/userModel.js` — User schema with `wrappedMasterKey` fields.
- `server/routes/auth.js` — auth endpoints.
- `server/middleware/auth.js` — JWT verification.

## Limitations

- No server-side full-text search (we cannot read ciphertext).
- AI provider sees plaintext during inference.
- No forward secrecy — an attacker who captures the wrapped master key and the
  user's password can decrypt all historical content.
- Metadata in the clear: timestamps, document IDs, projectId associations,
  S3 key shape (random suffix, no semantic content).
- Forgetting the password = permanent data loss. This is by design.

## Web platform threat model

The React-Native-Web build (`expo export -p web`) runs the *same* E2EE code as
native, in a browser. The cryptography is identical — AES-256-GCM, Argon2id /
HKDF KEK derivation, client-side wrap/unwrap — but the browser changes the trust
model in ways that do **not** apply to the store-signed native binary. Read this
before shipping or changing the web build.

### Code-delivery trust (the fundamental difference)

The native app is a signed, store-reviewed binary; its code changes only through
a reviewed update. The web app **re-fetches its JavaScript from the host on every
load**. Anyone who can control the served JS can serve code that reads
`getMasterKey()` and exfiltrates all decrypted content and tokens:

- the hosting provider / CDN,
- a successful XSS in the app origin,
- a network MITM if the bundle is ever served without HTTPS.

This is inherent to browser-delivered E2EE and cannot be fully eliminated. We
shrink it to "trust the origin + HTTPS" via:

- **HTTPS + HSTS** (`includeSubDomains; preload`) — closes the MITM/downgrade path.
- **A strict CSP** (`default-src 'self'`, no `unsafe-inline`/`unsafe-eval` in
  `script-src`, `connect-src` limited to self + the API origin) — the second
  line of defense if any XSS slips through, and it blocks beaconing data out.
- **A locked-down static host**, HTTPS-only.

The header set lives on the web host (`render.yaml`, service `privateer-app`).
Verify with `curl -I` after every deploy.

### Key & token at rest in the browser

On native, `EncryptedStorage` is the iOS Keychain / Android Keystore (hardware
backed, isolated from the app process). The browser has no equivalent. The web
shim `client/services/internal/secureKv.web.ts` persists the master key and JWTs
in **IndexedDB, wrapped with a non-extractable AES-GCM `CryptoKey`**. This
protects only against *passive disk-level IndexedDB dumps*. It is **not**
protection against script running in the app origin — any such script can call
the same decrypt path, exactly as the app does. (Metro stubs the native
`react-native-encrypted-storage` module on web, but that stub is unused: the
relative `./secureKv` import resolves to the `.web.ts` shim above.)

The master key also lives in memory in the `_masterKey` singleton in
`cryptoService.ts`, reachable by any code in the origin. Same as native — but
native has OS process isolation; the browser does not. This is why the
origin/XSS controls above are load-bearing on web.

### HTML rendering — sanitize everything (sink inventory)

AI responses and user/file content are attacker-influenceable (directly, or via
indirect prompt injection). Any HTML built from that content and placed in a
**same-origin** browsing context is an XSS → key-exfil path. Rules:

- All markdown renders through `renderMarkdown()` in
  `client/components/markdownHtml.ts`, which runs `marked` output through
  **DOMPurify** (`sanitizeMarkup`) — `marked` does not sanitize. The link
  renderer must never interpolate unescaped `href`/`title`.
- The web markdown iframe (`MarkdownWebView.web.tsx`) is sandboxed
  **without `allow-same-origin`** (opaque origin → no access to parent
  IndexedDB / master key) and carries an in-document CSP (`script-src 'nonce-…'`,
  `connect-src 'none'`). Parent→frame updates go over `postMessage`, not `eval`.
  Do not re-add `allow-same-origin`.
- `DocumentViewerModal.tsx` renders docx/csv/code/pdf inside
  `react-native-webview` (an isolated context, not the app document), and its
  file reads use `expo-file-system`, which is **stubbed on web** — so the viewer
  does not render on web at all and is outside the web key-exfil surface. If web
  file viewing is ever enabled, route its HTML through `sanitizeMarkup` and
  sandbox the iframe (opaque origin) before shipping.
- `PolicyScreen.web.tsx` renders first-party policy markdown in an iframe with
  **no `allow-scripts`** (scripts never execute); it shares `buildHtml`, so it is
  sanitized for free.

Any new `innerHTML` / `srcDoc` / `dangerouslySetInnerHTML` sink that can carry
user, AI, or file content **must** go through `sanitizeMarkup` and, on web, an
opaque-origin sandbox. Grep for these sinks during review.

### Token hygiene

Auth is `Authorization: Bearer` (no auth cookies → no CSRF). The email
verification token must not sit in the URL query string (leaks via `Referer`,
history, proxy/CDN logs). The verification email links to
`CLIENT_URL/verify-email#token=…` (fragment, not query). The web verify page
reads the token from the fragment (falling back to the query string for legacy
links) and strips it from history immediately via `history.replaceState`.

### Residual / by-design risks on web

- **No recovery**: forgetting the password/wallet is permanent data loss.
- **Web Argon2 is slow**: KDF params are stored per account and must match across
  platforms, so they cannot be lowered for web. Password login on web is simply
  slow (`@noble/hashes` argon2, pure JS); do not weaken the KDF to fix UX.
- **Plaintext metadata** and **inference plaintext exposure**: unchanged from the
  Limitations section above.
