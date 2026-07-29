/*
 * ───────────────────────────────────────────────────────────────────────────
 * Privateer — Transparency Excerpt (server)
 *
 * This file is published from Privateer's otherwise-closed server so anyone can
 * verify our core privacy claim: the server stores and forwards CIPHERTEXT
 * ONLY, never user plaintext, and routes AI inference exclusively to
 * Zero-Data-Retention providers.
 *
 * It is an EXCERPT, not a runnable build. Imports of modules that are NOT part
 * of this transparency repo (e.g. billing/pricing, entitlement/quota, S3/object
 * storage, email, rate limiting, Redis, Sentry wiring, logging) are left in
 * place so the code reads truthfully, but those modules are intentionally
 * omitted — they only ever see ciphertext, account IDs, and metadata, so they
 * add nothing to the privacy audit. Some such logic is stubbed inline with a
 * clearly marked "TRANSPARENCY REPO OMISSION" note.
 *
 * No secrets or credentials appear here; `process.env.*` reads reference public
 * variable NAMES only (documented in .env.example). See docs/E2EE_ARCHITECTURE.md.
 * ───────────────────────────────────────────────────────────────────────────
 */

/**
 * Wallet signature verifiers, keyed by CAIP-2 namespace.
 *
 * `/auth/wallet/verify` used to call `nacl.sign.detached.verify` inline, which
 * baked three Solana-shaped assumptions into the auth route:
 *
 *   1. the account identity IS an Ed25519 public key,
 *   2. it is 32 bytes and arrives from the client alongside the signature,
 *   3. base58 is its canonical form.
 *
 * None of the three survives contact with a second chain. An EVM identity is a
 * 20-byte address that is *recovered from* the signature and never sent, its
 * canonical form is EIP-55 mixed-case hex, and the bytes that get hashed are
 * wrapped in the EIP-191 prefix rather than signed raw. So the per-chain parts
 * live here behind two functions and the route keeps only the parts that are
 * genuinely chain-independent (nonce, message binding, session issuance).
 *
 * Adding a chain means adding one entry to VERIFIERS. It does NOT mean the
 * chain can hold an E2EE vault — that additionally requires the wallet to sign
 * deterministically, which is enforced client-side at enrollment (see
 * client/services/walletDeterminism.ts).
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');
const { blake2b } = require('@noble/hashes/blake2b');
const { base58Decode, base58DecodeVar, base58Encode } = require('../utils/base58');

/** Thrown for a namespace we have no verifier for. Callers map this to a 400. */
class UnsupportedChainError extends Error {
  constructor(namespace) {
    super(`Unsupported wallet chain: ${namespace}`);
    this.name = 'UnsupportedChainError';
    this.code = 'UNSUPPORTED_CHAIN';
  }
}

/** Thrown when the claimed identity is malformed for its namespace. */
class InvalidWalletIdentityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidWalletIdentityError';
    this.code = 'INVALID_WALLET_IDENTITY';
  }
}

// ---------------------------------------------------------------------------
// Solana — ed25519 over the raw message bytes
// ---------------------------------------------------------------------------

const solana = {
  namespace: 'solana',
  signatureScheme: 'ed25519',
  signatureLength: 64,

  /**
   * Accepts base58 (what users and explorers show) or 64-char hex (what legacy
   * clients send). Canonical storage form is base58 — unchanged from before
   * this module existed, so existing accounts keep matching.
   */
  parseIdentity(raw) {
    if (typeof raw !== 'string') {
      throw new InvalidWalletIdentityError('Invalid walletPublicKey encoding');
    }
    const isHex = /^[0-9a-fA-F]{64}$/.test(raw);
    let buf;
    try {
      buf = isHex ? Buffer.from(raw, 'hex') : base58Decode(raw);
    } catch {
      throw new InvalidWalletIdentityError('Invalid walletPublicKey encoding');
    }
    if (buf.length !== 32) {
      throw new InvalidWalletIdentityError('Invalid walletPublicKey length');
    }
    const canonical = base58Encode(buf);
    // base58Decode left-pads to 32 bytes, so a short string like "abc" decodes
    // "successfully" to a padded key that is not the address anyone typed.
    // Requiring the base58 form to already be canonical closes that off. Real
    // addresses round-trip exactly, including ones with leading zero bytes
    // (which encode as leading '1's).
    if (!isHex && canonical !== raw) {
      throw new InvalidWalletIdentityError('Invalid walletPublicKey encoding');
    }
    return {
      namespace: 'solana',
      canonical,
      // Lowercase hex is the form the signed message binds to and the form the
      // client's vault-KEK message embeds. Never displayed.
      hex: buf.toString('hex'),
      verifyKey: buf,
    };
  },

  verify({ identity, message, signature }) {
    if (signature.length !== 64) return false;
    return nacl.sign.detached.verify(
      new Uint8Array(message),
      new Uint8Array(signature),
      new Uint8Array(identity.verifyKey),
    );
  },
};

// ---------------------------------------------------------------------------
// EVM (eip155) — secp256k1 ECDSA over the EIP-191 personal_sign digest
// ---------------------------------------------------------------------------

/**
 * EIP-55 mixed-case checksum. Two addresses differing only in case are the same
 * account, so this is a display/storage normalization, never a security check —
 * comparisons below are done lowercase.
 */
function toChecksumAddress(lowerHex40) {
  const hash = Buffer.from(keccak_256(Buffer.from(lowerHex40, 'utf8'))).toString('hex');
  let out = '';
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lowerHex40[i].toUpperCase() : lowerHex40[i];
  }
  return `0x${out}`;
}

/** keccak256 of the EIP-191 "personal sign" framing of `message`. */
function personalSignDigest(message) {
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${message.length}`, 'utf8');
  return keccak_256(Buffer.concat([prefix, message]));
}

/**
 * Recover the 20-byte signer address from a 65-byte `r ‖ s ‖ v` signature over
 * `digest`, as lowercase hex. Returns null for anything that isn't a recoverable
 * signature — a bad recovery byte, out-of-range r/s, a truncated buffer.
 *
 * Shared by eip155 and tron: both are secp256k1 ECDSA recovered to
 * `keccak256(pubkey)[-20:]`. Only the digest framing and how those 20 bytes are
 * *displayed* differ, which is the whole reason Tron is a cheap namespace to add
 * and also the reason the v3 vault message is namespace-scoped — the same key
 * yields the same 20 bytes on both chains.
 */
function recoverSecp256k1Address(signature, digest) {
  if (signature.length !== 65) return null;

  // Wallets return v as 27/28 (yellow-paper convention) or, less often, the raw
  // 0/1 recovery bit. Anything else is not a personal_sign signature.
  const v = signature[64];
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) return null;

  let recovered;
  try {
    recovered = secp256k1.Signature
      .fromCompact(signature.subarray(0, 64))
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest)
      .toRawBytes(false);
  } catch {
    // Malformed r/s (out of range, zero) — noble throws rather than recovering
    // a bogus point.
    return null;
  }

  // Address = last 20 bytes of keccak256(uncompressed pubkey minus its 0x04 tag).
  return Buffer.from(keccak_256(recovered.slice(1))).toString('hex').slice(-40);
}

const eip155 = {
  namespace: 'eip155',
  signatureScheme: 'secp256k1-ecdsa',
  signatureLength: 65,

  parseIdentity(raw) {
    if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(raw)) {
      throw new InvalidWalletIdentityError('Invalid wallet address (expected 0x + 40 hex chars)');
    }
    const lower = raw.slice(2).toLowerCase();
    return {
      namespace: 'eip155',
      canonical: toChecksumAddress(lower),
      hex: lower,
      // There is no public key to verify against — the address is recovered
      // from the signature and compared. This is the structural difference
      // from Solana that the registry exists to absorb.
      verifyKey: null,
    };
  },

  /**
   * Recover the signer and compare to the claimed address. An account is only
   * authenticated if the signature *produces* the address it claims, so a
   * mismatched or replayed-from-elsewhere signature simply recovers to some
   * other address and fails.
   */
  verify({ identity, message, signature }) {
    const addr = recoverSecp256k1Address(signature, personalSignDigest(message));
    return addr !== null && addr === identity.hex;
  },
};

// ---------------------------------------------------------------------------
// Sui — ed25519 over the BLAKE2b-256 digest of an intent-wrapped message
// ---------------------------------------------------------------------------

/**
 * Sui never signs a message directly. `sui:signPersonalMessage` signs
 *
 *   BLAKE2b-256( intent || BCS(message) )
 *
 * where `intent` is the three bytes [scope, version, appId] — PersonalMessage
 * (3), V0 (0), Sui (0) — and BCS encoding of a `vector<u8>` is a ULEB128 length
 * followed by the bytes. That domain separator is why a Sui signature can't be
 * replayed as a transaction approval, and why the digest has to be rebuilt here
 * exactly rather than verified against the raw message.
 *
 * Mirrors @mysten/sui: cryptography/intent.ts + keypair.ts → signWithIntent.
 */
const SUI_INTENT_PERSONAL_MESSAGE = Buffer.from([3, 0, 0]);

/** BCS/ULEB128 length prefix. Auth messages are ~200 bytes, so this is 2 bytes. */
function uleb128(value) {
  const out = [];
  let n = value;
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n > 0) byte |= 0x80;
    out.push(byte);
  } while (n > 0);
  return Buffer.from(out);
}

function suiPersonalMessageDigest(message) {
  const intentMessage = Buffer.concat([
    SUI_INTENT_PERSONAL_MESSAGE,
    uleb128(message.length),
    message,
  ]);
  return Buffer.from(blake2b(intentMessage, { dkLen: 32 }));
}

/**
 * Sui address = BLAKE2b-256(flag || pubkey), hex, 0x-prefixed. The flag is part
 * of the preimage, so the same Ed25519 key enrolled under a different scheme
 * flag is a different account — which is what makes comparing the derived
 * address to the claimed one a complete check.
 */
function suiAddressFromPublicKey(flag, publicKey) {
  const digest = blake2b(Buffer.concat([Buffer.from([flag]), publicKey]), { dkLen: 32 });
  return Buffer.from(digest).toString('hex');
}

/** Ed25519, the flag every mainstream Sui wallet issues by default. */
const SUI_FLAG_ED25519 = 0x00;
/** flag(1) + signature(64) + public key(32) */
const SUI_ED25519_SIGNATURE_LENGTH = 97;

const sui = {
  namespace: 'sui',
  signatureScheme: 'ed25519',
  signatureLength: SUI_ED25519_SIGNATURE_LENGTH,

  /**
   * A Sui address is 32 bytes of hash output — 0x + 64 hex, no checksum case to
   * preserve, so lowercase is canonical. Deliberately strict about the `0x`:
   * bare 64-hex is the legacy *Solana* form, and accepting both here would make
   * one string mean two different accounts depending on the chain field.
   */
  parseIdentity(raw) {
    if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(raw)) {
      throw new InvalidWalletIdentityError('Invalid Sui address (expected 0x + 64 hex chars)');
    }
    const lower = raw.slice(2).toLowerCase();
    return {
      namespace: 'sui',
      canonical: `0x${lower}`,
      hex: lower,
      // Like EVM: the key arrives inside the signature, and the address is
      // derived from it and compared.
      verifyKey: null,
    };
  },

  /**
   * Sui wallets return `flag || signature || publicKey`. Verify the Ed25519
   * signature over the intent digest, then re-derive the address from the
   * public key it carries and require it to be the address being claimed —
   * otherwise any valid signature from any Sui account would authenticate any
   * other.
   *
   * Only the Ed25519 flag is accepted. MultiSig (0x03), zkLogin (0x05) and
   * Passkey (0x06) can't hold a Privateer vault at all — they have no single
   * reproducible signature — and Secp256k1/r1 (0x01/0x02) are rejected because
   * this build has never verified one against a real wallet; a sign-in path
   * that can't be tested is worse than one that isn't offered. Any of them
   * fails here as "invalid signature" rather than being trusted blind.
   */
  verify({ identity, message, signature }) {
    if (signature.length !== SUI_ED25519_SIGNATURE_LENGTH) return false;
    if (signature[0] !== SUI_FLAG_ED25519) return false;

    const sig = signature.subarray(1, 65);
    const publicKey = signature.subarray(65);

    const ok = nacl.sign.detached.verify(
      new Uint8Array(suiPersonalMessageDigest(message)),
      new Uint8Array(sig),
      new Uint8Array(publicKey),
    );
    if (!ok) return false;

    return suiAddressFromPublicKey(SUI_FLAG_ED25519, publicKey) === identity.hex;
  },
};

// ---------------------------------------------------------------------------
// Tron — secp256k1 ECDSA over the TIP-191 digest, base58check identity
// ---------------------------------------------------------------------------

/**
 * Tron is eip155's twin below the surface and its opposite above it.
 *
 * Same curve, same recovery, same `keccak256(pubkey)[-20:]` address bytes — so a
 * single private key controls the same 20 bytes on both chains. What differs:
 *
 *   1. The signed digest is framed with Tron's own prefix (TIP-191), not
 *      Ethereum's, so a signature cannot be lifted between the two chains even
 *      though the recovery math is identical.
 *   2. The address is *displayed* as base58check over `0x41 ‖ 20 bytes` — the
 *      "T…" string every Tron wallet and explorer shows. There is no EIP-55
 *      case checksum; the 4-byte SHA-256d checksum inside the encoding is what
 *      catches a mistyped address.
 *
 * `identity.hex` stays the bare 20 bytes (matching eip155) because that is what
 * the auth message binds to, and the v3 vault message scopes it as
 * `tron:<hex>` — without that namespace prefix an Ethereum account and a Tron
 * account backed by the same key would derive the same KEK.
 */
const TRON_ADDRESS_PREFIX = 0x41;
/** 0x41 ‖ 20 address bytes ‖ 4 checksum bytes. */
const TRON_ADDRESS_BYTES = 25;

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

/** base58check-encode `0x41 ‖ address` into the canonical "T…" form. */
function tronAddressFromHex(hex20) {
  const payload = Buffer.concat([Buffer.from([TRON_ADDRESS_PREFIX]), Buffer.from(hex20, 'hex')]);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  return base58Encode(Buffer.concat([payload, checksum]));
}

/**
 * Decode a canonical "T…" address to its bare 20-byte hex. Throws on a bad
 * character, a wrong length, a foreign version byte, or a failed checksum —
 * every one of which means the string is not the address someone intended.
 */
function tronAddressToHex(address) {
  const decoded = base58DecodeVar(address);
  if (decoded.length !== TRON_ADDRESS_BYTES) throw new Error('Invalid Tron address length');
  if (decoded[0] !== TRON_ADDRESS_PREFIX) throw new Error('Invalid Tron address prefix');
  const payload = decoded.subarray(0, 21);
  const expected = sha256(sha256(payload)).subarray(0, 4);
  if (!expected.equals(decoded.subarray(21))) throw new Error('Invalid Tron address checksum');
  return payload.subarray(1).toString('hex');
}

/**
 * keccak256 of Tron's personal-message framing (TIP-191), which is EIP-191 with
 * a different magic string. This is what `tronWeb.trx.signMessageV2` hashes, and
 * the byte count — not the character count — is what goes in the prefix.
 */
function tronPersonalSignDigest(message) {
  const prefix = Buffer.from(`\x19TRON Signed Message:\n${message.length}`, 'utf8');
  return keccak_256(Buffer.concat([prefix, message]));
}

const tron = {
  namespace: 'tron',
  signatureScheme: 'secp256k1-ecdsa',
  signatureLength: 65,

  /**
   * Only the base58check form is accepted. Tron wallets also carry a
   * `41…` hex form internally, but accepting it here would give one account two
   * spellings on the wire — and a 42-char hex string is exactly what a
   * mis-scoped EVM address would look like after a naive prefix. The checksum
   * inside base58check is doing real work: a corrupted address fails to decode
   * instead of enrolling a vault under bytes the user never saw.
   */
  parseIdentity(raw) {
    if (typeof raw !== 'string' || !/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(raw)) {
      throw new InvalidWalletIdentityError('Invalid Tron address (expected a base58check "T…" address)');
    }
    let hex;
    try {
      hex = tronAddressToHex(raw);
    } catch {
      throw new InvalidWalletIdentityError('Invalid Tron address (expected a base58check "T…" address)');
    }
    return {
      namespace: 'tron',
      canonical: raw,
      hex,
      // Like EVM: nothing to verify against up front, the address is recovered
      // from the signature and compared.
      verifyKey: null,
    };
  },

  verify({ identity, message, signature }) {
    const addr = recoverSecp256k1Address(signature, tronPersonalSignDigest(message));
    return addr !== null && addr === identity.hex;
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const VERIFIERS = { solana, eip155, sui, tron };

/** CAIP-2 namespaces this build can verify. */
const SUPPORTED_NAMESPACES = Object.keys(VERIFIERS);

function isSupportedNamespace(namespace) {
  return Object.prototype.hasOwnProperty.call(VERIFIERS, namespace);
}

function getVerifier(namespace) {
  if (!isSupportedNamespace(namespace)) throw new UnsupportedChainError(namespace);
  return VERIFIERS[namespace];
}

/**
 * Normalize a client-supplied identity into its canonical storage form.
 * Throws InvalidWalletIdentityError / UnsupportedChainError.
 */
function parseWalletIdentity(namespace, raw) {
  return getVerifier(namespace).parseIdentity(raw);
}

/**
 * True when `signature` proves control of `identity` over `message`.
 *
 * `message` and `signature` are Buffers; `identity` is the object returned by
 * parseWalletIdentity. Never throws for bad signature material — a malformed
 * signature is an authentication failure, not a server error.
 */
function verifyWalletSignature({ namespace, identity, message, signature }) {
  const verifier = getVerifier(namespace);
  if (!Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) return false;
  if (identity.namespace !== namespace) return false;
  return verifier.verify({ identity, message, signature });
}

module.exports = {
  SUPPORTED_NAMESPACES,
  isSupportedNamespace,
  getVerifier,
  parseWalletIdentity,
  verifyWalletSignature,
  toChecksumAddress,
  personalSignDigest,
  suiPersonalMessageDigest,
  suiAddressFromPublicKey,
  tronPersonalSignDigest,
  tronAddressFromHex,
  tronAddressToHex,
  UnsupportedChainError,
  InvalidWalletIdentityError,
};
