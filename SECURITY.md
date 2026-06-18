# Security Policy

Privateer's privacy guarantee rests on the code in this repository, so we take reports
about it seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Email **security@privateer.pro** with:
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the file(s) / commit involved.

We aim to acknowledge reports within 72 hours and will keep you updated on remediation.
Coordinated disclosure is appreciated; we're happy to credit you once a fix ships.

## In scope

This repo is the **trust boundary** of an end-to-end-encrypted app. The highest-value
reports concern:

- **Cryptography** — key derivation (Argon2id / HKDF), master-key wrap/unwrap, the
  content wire format, IV/nonce handling, anything that could weaken AES-256-GCM usage.
- **Key handling** — any path where a master key, KEK, password, or wrapped blob could
  leak to the server, logs, or an attacker.
- **Ciphertext-only invariant** — any server path that could persist or transmit user
  *plaintext* content.
- **Inference routing** — any path that could send prompts to a non–Zero-Data-Retention
  provider when ZDR is required.
- **Web key-exfil surface** — XSS/CSP/sandbox issues in the browser build that could
  reach the in-memory master key (see the web threat model in `docs/E2EE_ARCHITECTURE.md`).

## Out of scope

This is an **excerpt**, not a runnable application. Reports that depend on the omitted
closed components (billing, entitlement, infra) or on this excerpt "not compiling" are
out of scope — those modules never touch plaintext. Findings about deliberately stubbed
`TRANSPARENCY REPO OMISSION` blocks are also out of scope.

## A note on recovery

By design there is **no password/wallet recovery path**. Forgetting credentials means
permanent data loss. This is an intended property, not a vulnerability.
