# How Content Is Encrypted — Privateer

> Companion to [`E2EE_ARCHITECTURE.md`](./E2EE_ARCHITECTURE.md)

This document covers the **content data path**: what gets encrypted, where in the
code it happens, the on-the-wire format, and the rules that keep plaintext off
the server. For the master-key lifecycle (generation, wrapping, KDF, wallet vs.
password unlock), see [`E2EE_ARCHITECTURE.md`](./E2EE_ARCHITECTURE.md).

---

## 1. The one key that does everything

All user content is encrypted with a single per-account **32-byte AES-256
master key**. It is generated client-side, never sent to the server in
plaintext, and lives in module memory in
`client/services/cryptoService.ts` (`_masterKey`). Cloud or local backend makes
no difference to the algorithm — only to *where the ciphertext is stored*.

If `_masterKey` is null, every encrypt/decrypt call throws
`"Master key not loaded."` — encryption is never silently skipped.

---

## 2. Primitive: AES-256-GCM

Every content operation goes through four helpers in `cryptoService.ts`
(`cryptoService.ts:296–325`):

| Function | Input | Output |
|----------|-------|--------|
| `encryptText(plaintext)` | UTF-8 string | JSON string `{"iv","ct"}` (both base64) |
| `decryptText(payload)` | that JSON string | UTF-8 string |
| `encryptBinary(buf)` | `Uint8Array` | `{ iv, ct }` (base64) — for image/video bytes |
| `decryptBinary(iv, ct)` / `decryptBinaryRaw(iv, ctBytes)` | base64 / raw bytes | `Uint8Array` |

Properties of every operation:

- **AES-256-GCM** via `@noble/ciphers/aes`.
- **Fresh 12-byte random IV per call** (`crypto.getRandomValues`) — never reused.
- **128-bit GCM auth tag** appended to the ciphertext (`ct = ciphertext ‖ tag`).
  Tampering or a wrong key fails decryption loudly rather than returning garbage.

### Wire format

Text content is persisted as a **JSON string**:

```json
{ "iv": "<base64, 12 bytes>", "ct": "<base64, ciphertext ‖ 16-byte tag>" }
```

Binary content stores `iv` and `ct` as separate base64 fields on the model.

---

## 3. What is encrypted, and where

Encryption happens in the **client services**, immediately before the API call
that persists the data. The server only ever receives ciphertext for these
fields.

| Content | Encrypted field(s) | Produced in |
|---------|-------------------|-------------|
| Chat / graph titles | `encryptedTitle` | `graphService.ts:57, 231, 682` |
| Node prompt & AI response | `encryptedPrompt`, `encryptedAiResponse` | `graphService.ts:301–305` |
| Message body | `encryptedContent` | `graphService.ts:574, 621, 722` |
| Sources, weather, compose, generation options | `encryptedSources`, `encryptedWeatherData`, `encryptedComposeData`, `encryptedGenerationOptions` | `graphService.ts` (JSON-stringified, then `encryptText`) |
| Note bodies | `encryptedNoteBody` | `graphService.ts:315, 414` |
| Image / video binaries | `iv` + `ct` (binary) | `chatService.ts:777, 868, 976`, `nodeFilesService.ts:175`, `nodeVideosService.ts:82` |
| Image / video / file metadata (filename, mime) | `encryptedMetadata` | `chatService.ts:780`, `nodeFilesService.ts:180`, `nodeVideosService.ts:63` |
| Project name & instructions | `encryptedName`, `encryptedInstructions` | `projectService.ts:96–97, 171–172` |
| User memories | `encryptedContent` | `memoryService.ts:73` |
| Personalization profile | `encryptedPersonalization` | `personalizationService.ts:128, 151` |
| Local-backend chats / projects | whole record JSON, `encryptText`'d | `localChatService.ts:150`, `localProjectService.ts:125` |

**Rule:** structured data (sources, options, metadata) is `JSON.stringify`'d
first, then passed through `encryptText`. There is no separate binary codec for
structured fields.

### Server schema fields

Encrypted content lives in `encrypted*` columns. The plaintext twins
(`content`, `prompt`, `aiResponse`, `title`) are **optional and legacy-only** —
they hold pre-E2EE data and must never be written for new content. Data
ownership is keyed by `userId` on every content model (`Chat`, `ChatGraph`,
`ChatNode`, `ChatEdge`, `Message`, `Project`, `ProjectFile`, `UserMemory`, …).

> **Decryption gotcha:** when projecting `ChatNode` with Mongoose `.select()`,
> you must include `encryptedPrompt` / `encryptedAiResponse`. Omitting them
> yields blank node cards after reload — the ciphertext simply wasn't fetched.

---

## 4. The one place plaintext is allowed: AI inference

Inference cannot run on ciphertext, so there is a single, deliberate exception:

1. Client **decrypts** conversation history locally.
2. Client sends **plaintext** message + history to `POST /api/chat/stream`.
3. Server forwards plaintext to the inference provider (OpenRouter / Gemini).
4. Server streams the **plaintext** AI response back over SSE.
5. Client **encrypts** the response (`encryptText`) and only then persists it.

The server holds plaintext **in memory for the duration of the request only**
and never writes the AI response to the database in plaintext. Plaintext also
transits the inference provider — this is called out in the threat model in
`E2EE_ARCHITECTURE.md`. ZDR providers are used where available.

---

## 5. Defenses that keep plaintext from leaking

- **Sentry scrubbing** — `sentryService.ts` denylists `encryptedContent`,
  `encryptedPrompt`, `encryptedAiResponse`, `encryptedTitle`,
  `encryptedPersonalization`, the plaintext twins (`content`, `prompt`,
  `aiResponse`, `title`), `messages`, `images`, `imageData`, plus all key
  material (`wrappedMasterKey`, `masterKey`, `kdfSalt`, `signature`). Neither
  ciphertext nor plaintext nor keys reach error telemetry.
- **Master-key gating** — every `encrypt*`/`decrypt*` throws if the master key
  isn't loaded; no fallback to plaintext writes.
- **Per-call random IV** — no IV reuse across operations, so identical
  plaintexts produce different ciphertexts.
- **Storage-backend rule** — for `local` backend, content is encrypted with the
  same master key and stored on-device via `EncryptedStorage` /
  `expo-file-system`; nothing is sent to the server.

---

## 6. Key invariants for contributors

1. **Never** write user content to a server endpoint without encrypting it
   first via `cryptoService.encryptText()` / `encryptBinary()`.
2. **Never** populate the legacy plaintext fields (`content`, `prompt`,
   `aiResponse`, `title`) for new data.
3. Structured payloads → `JSON.stringify` → `encryptText`. Don't invent a
   parallel format.
4. `cryptoService.ts` is the **single source of truth** for crypto. Do not
   inline AES calls elsewhere.
5. If you add a new encrypted field, add it to the Sentry denylist in
   `sentryService.ts`.
6. If you add a `ChatNode` query, include every `encrypted*` field you intend
   to decrypt in the `.select()` projection.

---

## 7. File map

- `client/services/cryptoService.ts` — all encrypt/decrypt + key handling.
- `client/services/graphService.ts` — chat/graph/message/node content.
- `client/services/chatService.ts`, `nodeFilesService.ts`,
  `nodeVideosService.ts` — image/video binaries + metadata.
- `client/services/projectService.ts` — project name/instructions.
- `client/services/memoryService.ts`,
  `client/services/personalizationService.ts` — memories & profile.
- `client/services/localChatService.ts`,
  `client/services/localProjectService.ts` — local-backend whole-record
  encryption.
- `client/services/sentryService.ts` — telemetry scrub denylist.
