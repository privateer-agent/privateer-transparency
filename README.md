# Privateer — Verify Us, Don't Trust Us

**Privateer** ([privateer.pro](https://privateer.pro)) is an end-to-end-encrypted AI
chat app. This repository is the **transparency mirror** of Privateer's *privacy trust
boundary* — the exact code that defines our privacy guarantee — published so anyone can
audit the claim instead of taking our word for it.

> "Private AI" is a crowded category. The honest way to stand out isn't a louder promise —
> it's letting people **read the code that makes the promise**.

## The claim you can verify here

1. **Your content is encrypted on your device before it ever leaves it.** Every account
   has one 32-byte AES-256 master key, generated client-side, wrapped by a key derived
   locally from your password (Argon2id) or your Solana wallet signature (HKDF). The
   server only ever receives the *wrapped* blob — never the key, never the password.
2. **The server stores and forwards ciphertext only.** It cannot read your messages,
   titles, images, or memories even under full compromise. The content models and routes
   here show every persisted field is an `encrypted*` field.
3. **AI inference goes only to Zero-Data-Retention providers.** Prompts are plaintext for
   the few seconds a model needs to run, at the inference provider — never written to our
   database in plaintext. The inference layer here shows how requests are pinned to ZDR
   providers and how confidential-compute (TEE) models are attested.

There is **no password recovery**. Forgetting your password/wallet means the data is
permanently unreadable — including to us. That is the cost of real E2EE, and it's by
design.

### Why our model is a step beyond enclave attestation

Some excellent privacy-AI products (Maple/OpenSecret, Confer) decrypt your data
server-side *inside an attested secure enclave*, and open-source the enclave code so you
can verify it. **Privateer's server never decrypts content at all** — there is no
server-side plaintext to attest away. Our equivalent of "the enclave" is the client-side
crypto + the wire format + the inference routing in this repo.

## What's in this repo

| Area | Files | What it proves |
|---|---|---|
| **Client crypto core** | [`client/services/cryptoService.ts`](client/services/cryptoService.ts) | KDF/KEK derivation, master-key wrap/unwrap, `encryptText`/`encryptBinary` — the heart of the claim |
| **Wallet auth + KEK** | [`client/services/walletAuthService.ts`](client/services/walletAuthService.ts), [`walletAuthShared.ts`](client/services/walletAuthShared.ts), [`internal/argon2.ts`](client/services/internal/argon2.ts), [`internal/secureKv.ts`](client/services/internal/secureKv.ts) | wallet-signature → key derivation; on-device secure storage |
| **Auth/vault flow** | [`client/services/authService.ts`](client/services/authService.ts) | register/login/password-change never send the key or password-derived KEK |
| **Sharing** | [`client/services/shareService.ts`](client/services/shareService.ts) | E2EE-preserving public shares via a URL-fragment key |
| **Confidential models** | [`client/components/AttestationSheet.tsx`](client/components/AttestationSheet.tsx) | how TEE attestation is surfaced to users |
| **Server vault + auth** | [`server/models/userModel.js`](server/models/userModel.js), [`server/routes/auth.js`](server/routes/auth.js), [`server/middleware/auth.js`](server/middleware/auth.js) | server stores only the *wrapped* master key |
| **Ciphertext-only storage** | content models + [`server/routes/`](server/routes/) (chat, graph, projects, images, share) | every persisted content field is `encrypted*` |
| **ZDR inference routing** | [`server/services/inferenceService.js`](server/services/inferenceService.js), [`server/services/nearAiService.js`](server/services/nearAiService.js) | two-key ZDR enforcement + NEAR AI TEE attestation |
| **Specs** | [`docs/E2EE_ARCHITECTURE.md`](docs/E2EE_ARCHITECTURE.md), [`docs/CONTENT_ENCRYPTION.md`](docs/CONTENT_ENCRYPTION.md) | threat model, KEK derivation, wire format `{"iv":…,"ct":…}` |

**Recommended reading order:** `docs/E2EE_ARCHITECTURE.md` → `client/services/cryptoService.ts`
→ a server content model (e.g. `server/models/messageModel.js`) → `server/services/inferenceService.js`.

## What's deliberately *not* here (and why that's correct)

This is an **excerpt, not a runnable build.** Keeping the trust boundary *small* is the
whole point — the less code that touches plaintext, the easier the privacy claim is to
verify. The following are part of Privateer's closed codebase because they only ever see
**ciphertext, account IDs, and metadata** — opening them adds risk with zero
auditability gain (this mirrors what Maple/OpenSecret and Proton's Lumo keep closed):

- **Billing / payments** — Stripe, Solana RPC proxy, top-ups, price oracles, markup logic.
- **Subscription / entitlement** — tiers, credit accounting, quota enforcement.
- **Account / infra** — rate limiting, Redis, email, object storage wiring, deploy config.
- **All secrets** — never published. `process.env.*` references here are variable *names*
  only (see [`.env.example`](.env.example)); values live in our deployment environment.

Where closed logic was interleaved with in-scope code, it is stubbed inline and marked
`TRANSPARENCY REPO OMISSION`, and each server file carries a header explaining the excerpt.

## Roadmap

- [ ] **Third-party cryptography audit** of the wire format + key handling, published here.
- [ ] **Reproducible client builds** so users can verify the shipped app matches this source.

## Security

Found something? See [`SECURITY.md`](SECURITY.md). License: [MIT](LICENSE).
