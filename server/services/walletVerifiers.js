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

const nacl = require('tweetnacl');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');
const { blake2b } = require('@noble/hashes/blake2b');
const { base58Decode, base58Encode } = require('../utils/base58');

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
    if (signature.length !== 65) return false;

    // Wallets return v as 27/28 (yellow-paper convention) or, less often, the
    // raw 0/1 recovery bit. Anything else is not a personal_sign signature.
    const v = signature[64];
    const recovery = v >= 27 ? v - 27 : v;
    if (recovery !== 0 && recovery !== 1) return false;

    let recovered;
    try {
      recovered = secp256k1.Signature
        .fromCompact(signature.subarray(0, 64))
        .addRecoveryBit(recovery)
        .recoverPublicKey(personalSignDigest(message))
        .toRawBytes(false);
    } catch {
      // Malformed r/s (out of range, zero) — noble throws rather than
      // recovering a bogus point.
      return false;
    }

    // Address = last 20 bytes of keccak256(uncompressed pubkey minus its 0x04 tag).
    const addr = Buffer.from(keccak_256(recovered.slice(1))).toString('hex').slice(-40);
    return addr === identity.hex;
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
// Registry
// ---------------------------------------------------------------------------

const VERIFIERS = { solana, eip155, sui };

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
  UnsupportedChainError,
  InvalidWalletIdentityError,
};
