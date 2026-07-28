/**
 * Harbor client-side AMD SEV-SNP chain verification — GO-LIVE GATE 1.
 *
 * This is the check that makes a Harbor attestation mean something against a
 * MALICIOUS OR COMPROMISED SERVER — the exact party attestation exists to
 * constrain. harborAttestation.ts (the outer verifier) checks key-binding,
 * measurement, and freshness against the report bytes, but until now it TRUSTED
 * the server's `chainVerified` boolean for "are these bytes a genuine AMD-signed
 * report at all". A server that shapes our JSON response could set that to true
 * over a forged buffer. This module removes that trust: it re-derives the verdict
 * from the raw certificates the server relays, rooted in an ARK fingerprint PINNED
 * IN THE APP BINARY (never fetched), so a hostile server cannot substitute its own
 * root.
 *
 * WHAT IT PROVES (all four, fail-closed):
 *   1. VCEK signed report[0:0x2A0]     — ECDSA P-384 over SHA-384         (@noble/curves)
 *   2. ASK signed the VCEK certificate — RSA-4096 RSASSA-PSS / SHA-384
 *   3. ARK signed the ASK certificate  — RSA-4096 RSASSA-PSS / SHA-384
 *   4. sha256(ARK DER) === PINNED_ARK_SHA256, and the ARK is self-signed
 * (2)+(3) are what tie the chip-specific VCEK to AMD's root; (4) is what ties that
 * root to AMD rather than to whatever self-signed root a hostile relay invented.
 *
 * PURE JS BY DESIGN. React Native's `react-native-quick-crypto` is stubbed on web
 * (metro.config.js WEB_NATIVE_STUBS) and absent from the standalone test harness, so
 * we do NOT lean on node/native crypto for X.509. AMD's chain is RSA-PSS + ECDSA:
 *   - @noble/curves/p384 does the ECDSA math (report signature).
 *   - RSA verification is s^e mod n via native BigInt, then EMSA-PSS-VERIFY with
 *     MGF1/SHA-384 (@noble/hashes) — RFC 8017 §9.1.2.
 *   - A minimal DER reader extracts tbsCertificate, the signature, and the SPKI.
 * No network. Unit-tested against a SYNTHETIC AMD-shaped chain (a generated RSA-4096
 * root+intermediate and an EC P-384 leaf signing a synthetic report) so the math is
 * pinned without shipping AMD material into the test — see harborChainVerify.test.ts.
 *
 * NATIVE-ONLY MEANING: on web the server ships this very file, so a malicious server
 * edits the verifier; the guarantee is real only where the store-signed binary is
 * outside server control (native). harborAttestation.ts records that and gates the
 * strength of the posture on platform accordingly.
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512';
import { p384 } from '@noble/curves/p384';

// ── SEV-SNP report signature layout (mirror harborAttestation.ts / attest.js) ──
const OFF_SIGNATURE = 0x2a0;      // signature block; everything BEFORE it is signed
const ECDSA_FIELD = 0x48;         // 72-byte r/s fields (P-384 uses the low 48, LE)
const P384_LEN = 48;

// ── The pinned AMD root. sha256 of the DER of AMD's self-signed SEV ARK. ────────
// Milan (harbor-cvm-0 is an n2d = AMD Milan). Read off AMD's KDS cert_chain root
// (kdsintf.amd.com/vcek/v1/Milan/cert_chain, 2nd cert, CN=ARK-Milan, self-signed).
// This is the client mirror of the server's HARBOR_AMD_ARK_SHA256 (config.js);
// both must name the SAME root. Genoa/other generations need their own pin keyed
// by processor before Harbor runs on that silicon.
//
// ⚠ CROSS-CHECK BEFORE GO-LIVE: this value was derived from a single TLS fetch of
// AMD's KDS on a dev machine. Confirm it independently against AMD's published ARK
// (the SEV cert on developer.amd.com) so the pin cannot encode a fetch-time MITM.
export const PINNED_ARK_SHA256: Record<string, string> = {
  milan: '69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd',
};

export interface ChainVerifyInput {
  reportBytes: Uint8Array;     // full raw SEV-SNP report (>= 0x4A0 bytes)
  vcekDer: Uint8Array;         // leaf: the chip+TCB VCEK certificate (DER)
  askDer: Uint8Array;          // intermediate: AMD SEV signing key (DER)
  arkDer: Uint8Array;          // root: AMD SEV root key, self-signed (DER)
  processor?: string;          // 'milan' (default) — selects the pinned ARK
}

export interface ChainVerifyResult {
  ok: boolean;
  reason: string | null;       // machine hint on the first failing step
}

const fail = (reason: string): ChainVerifyResult => ({ ok: false, reason });

/**
 * The whole Gate-1 check. Fail-closed: the FIRST step that does not hold returns
 * ok:false with a reason; only all four holding returns ok:true. Any thrown error
 * (malformed DER, wrong key type, bad length) is a failure, never an exception the
 * caller must handle — attestation of adversarial input must not crash the app.
 */
export function verifyReportChain(input: ChainVerifyInput): ChainVerifyResult {
  try {
    const { reportBytes, vcekDer, askDer, arkDer } = input;
    const processor = (input.processor || 'milan').toLowerCase();

    const pinnedArk = PINNED_ARK_SHA256[processor];
    if (!pinnedArk) return fail('ark-unpinned-processor');

    // (4a) The ARK we were handed must be AMD's, by pinned fingerprint. Do this
    // FIRST — it is the cheapest check and the one that anchors everything else.
    const arkFp = toHex(sha256(arkDer));
    if (arkFp !== pinnedArk.toLowerCase()) return fail('ark-pin-mismatch');

    const ark = parseCertificate(arkDer);
    const ask = parseCertificate(askDer);
    const vcek = parseCertificate(vcekDer);

    // (4b) The ARK is a self-signed root: its own key signed its own body. Without
    // this a matching sha256 over an unparsed blob would be trusted structurally.
    if (!verifyCertSignature(ark, ark)) return fail('ark-not-self-signed');

    // (3) ARK signed ASK.
    if (!verifyCertSignature(ask, ark)) return fail('ask-not-signed-by-ark');

    // (2) ASK signed VCEK.
    if (!verifyCertSignature(vcek, ask)) return fail('vcek-not-signed-by-ask');

    // (1) VCEK signed the report body.
    if (!verifyReportSignature(reportBytes, vcek)) return fail('report-not-signed-by-vcek');

    return { ok: true, reason: null };
  } catch (err) {
    return fail(`chain-verify-error:${(err as Error)?.message || 'unknown'}`);
  }
}

// ───────────────────────── report signature (ECDSA P-384) ─────────────────────

/**
 * Verify report[0:0x2A0] was signed by the VCEK's P-384 key over SHA-384. The r/s
 * fields sit little-endian in 72-byte slots (low 48 bytes each) — reverse to
 * big-endian and concatenate into IEEE-P1363 r‖s, exactly as the server does.
 * lowS:false: AMD does not canonicalise S, and rejecting a high-S but valid AMD
 * signature would be a false negative.
 */
function verifyReportSignature(reportBytes: Uint8Array, vcek: Certificate): boolean {
  if (reportBytes.length < OFF_SIGNATURE + ECDSA_FIELD * 2) return false;
  if (vcek.spki.kind !== 'ec') return false;

  const signedBody = reportBytes.subarray(0, OFF_SIGNATURE);
  const rBE = reverse(reportBytes.subarray(OFF_SIGNATURE, OFF_SIGNATURE + P384_LEN));
  const sBE = reverse(reportBytes.subarray(OFF_SIGNATURE + ECDSA_FIELD, OFF_SIGNATURE + ECDSA_FIELD + P384_LEN));
  const sig = concat(rBE, sBE); // 96-byte compact r‖s
  const msgHash = sha384(signedBody);
  try {
    return p384.verify(sig, msgHash, vcek.spki.point, { lowS: false });
  } catch {
    return false;
  }
}

// ───────────────────────── certificate signatures (RSA-PSS) ───────────────────

/**
 * Verify `cert` was signed by `issuer`. Both AMD ASK and ARK are RSA-4096 keys and
 * every AMD SEV cert is signed with RSASSA-PSS / SHA-384 / MGF1-SHA-384 / salt 48.
 * We require exactly that shape (rsassaPss OID) — refusing an unexpected algorithm
 * is safer than trying to interpret it.
 */
function verifyCertSignature(cert: Certificate, issuer: Certificate): boolean {
  if (issuer.spki.kind !== 'rsa') return false;      // AMD issuers are RSA
  if (cert.sigAlg !== 'rsapss-sha384') return false; // AMD SEV certs are PSS/SHA-384
  return rsaPssVerifySha384(issuer.spki.n, issuer.spki.e, cert.tbs, cert.signature);
}

/**
 * RSASSA-PSS-VERIFY with SHA-384, MGF1-SHA-384, salt length 48 (RFC 8017 §8.1.2,
 * §9.1.2). `message` is the tbsCertificate DER; `signature` is the raw signature
 * octets. Returns false on any inconsistency — never throws to the chain caller.
 */
function rsaPssVerifySha384(n: bigint, e: bigint, message: Uint8Array, signature: Uint8Array): boolean {
  const hLen = 48;   // SHA-384 output
  const sLen = 48;   // salt length (AMD uses 0x30)
  const k = byteLen(n);
  if (signature.length !== k) return false;

  // RSAVP1: m = s^e mod n, then I2OSP to emLen. emBits = modBits - 1.
  const s = osToInt(signature);
  if (s >= n) return false;
  const m = modPow(s, e, n);

  const modBits = bitLen(n);
  const emBits = modBits - 1;
  const emLen = Math.ceil(emBits / 8);
  let em: Uint8Array;
  try {
    em = intToOs(m, emLen);
  } catch {
    return false; // integer too large for emLen — inconsistent
  }

  // EMSA-PSS-VERIFY.
  const mHash = sha384(message);
  if (emLen < hLen + sLen + 2) return false;
  if (em[emLen - 1] !== 0xbc) return false;

  const maskedDB = em.subarray(0, emLen - hLen - 1);
  const H = em.subarray(emLen - hLen - 1, emLen - 1);

  // Leftmost (8*emLen - emBits) bits of maskedDB must be zero.
  const zeroBits = 8 * emLen - emBits; // = 1 for RSA-4096
  if (zeroBits > 0 && (maskedDB[0] & (0xff << (8 - zeroBits))) !== 0) return false;

  const dbMask = mgf1Sha384(H, emLen - hLen - 1);
  const db = xor(maskedDB, dbMask);
  // Clear the same leftmost bits in DB.
  if (zeroBits > 0) db[0] &= 0xff >> zeroBits;

  // DB = PS(0x00..) || 0x01 || salt. PS length = emLen - hLen - sLen - 2.
  const psLen = emLen - hLen - sLen - 2;
  for (let i = 0; i < psLen; i++) if (db[i] !== 0x00) return false;
  if (db[psLen] !== 0x01) return false;
  const salt = db.subarray(db.length - sLen);

  // H' = Hash(0x00*8 || mHash || salt).
  const mPrime = concat(new Uint8Array(8), mHash, salt);
  const hPrime = sha384(mPrime);
  return timingSafeEqual(H, hPrime);
}

/** MGF1 with SHA-384 (RFC 8017 B.2.1). */
function mgf1Sha384(seed: Uint8Array, maskLen: number): Uint8Array {
  const hLen = 48;
  const out = new Uint8Array(maskLen);
  const counter = new Uint8Array(4);
  let off = 0;
  for (let i = 0; off < maskLen; i++) {
    counter[0] = (i >>> 24) & 0xff;
    counter[1] = (i >>> 16) & 0xff;
    counter[2] = (i >>> 8) & 0xff;
    counter[3] = i & 0xff;
    const block = sha384(concat(seed, counter));
    const n = Math.min(hLen, maskLen - off);
    out.set(block.subarray(0, n), off);
    off += n;
  }
  return out;
}

// ───────────────────────── minimal X.509 / DER ────────────────────────────────

type Spki =
  | { kind: 'rsa'; n: bigint; e: bigint }
  | { kind: 'ec'; point: Uint8Array }   // 0x04 || X || Y uncompressed
  | { kind: 'other' };

interface Certificate {
  tbs: Uint8Array;          // raw tbsCertificate DER (what the signature covers)
  sigAlg: string;           // 'rsapss-sha384' | 'ecdsa-sha384' | 'other'
  signature: Uint8Array;    // raw signature octets (BIT STRING contents, sans unused-bits byte)
  spki: Spki;               // this cert's own public key
}

// OIDs we recognise, as dotted strings.
const OID_RSA_PSS = '1.2.840.113549.1.1.10';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';

/**
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature BIT STRING }.
 * We keep the tbsCertificate's raw encoding (header included) because that exact byte
 * string is what the issuer signed.
 */
function parseCertificate(der: Uint8Array): Certificate {
  const cert = readSeq(der, 0);
  const tbsTlv = readTlv(cert.content, 0);
  const tbs = cert.content.subarray(tbsTlv.start, tbsTlv.end); // full TLV of tbsCertificate

  const sigAlgTlv = readTlv(cert.content, tbsTlv.end);
  const sigAlg = parseSigAlg(cert.content.subarray(sigAlgTlv.start, sigAlgTlv.end));

  const sigTlv = readTlv(cert.content, sigAlgTlv.end);
  if (sigTlv.tag !== 0x03) throw new Error('signature is not a BIT STRING');
  // BIT STRING: first content byte is the unused-bits count (0 for a signature).
  const sigContent = cert.content.subarray(sigTlv.cstart, sigTlv.end);
  const signature = sigContent.subarray(1);

  const spki = parseSpkiFromTbs(tbs);
  return { tbs, sigAlg, signature, spki };
}

/** Map an AlgorithmIdentifier SEQUENCE to a short signature-scheme tag. */
function parseSigAlg(algSeq: Uint8Array): string {
  const seq = readSeq(algSeq, 0);
  const oidTlv = readTlv(seq.content, 0);
  const oid = readOid(seq.content.subarray(oidTlv.cstart, oidTlv.end));
  if (oid === OID_RSA_PSS) return 'rsapss-sha384';   // AMD only ever uses SHA-384 PSS
  if (oid === OID_ECDSA_SHA384) return 'ecdsa-sha384';
  return 'other';
}

/**
 * Pull the SubjectPublicKeyInfo out of a tbsCertificate. tbs ::= SEQUENCE {
 *   [0] version, serial, sigAlg, issuer, validity, subject, SPKI, ... }
 * SPKI is the first (and only) child that is itself a SEQUENCE whose first child is
 * an OID we recognise as a key algorithm — we locate it structurally rather than
 * counting optional/tagged fields, which vary.
 */
function parseSpkiFromTbs(tbs: Uint8Array): Spki {
  const seq = readSeq(tbs, 0);
  let off = 0;
  while (off < seq.content.length) {
    const tlv = readTlv(seq.content, off);
    if (tlv.tag === 0x30) {
      // Is this SEQUENCE an SPKI? Its first child must be a SEQUENCE(algorithm)
      // whose first child is a key-algorithm OID.
      const maybe = trySpki(seq.content.subarray(tlv.start, tlv.end));
      if (maybe) return maybe;
    }
    // Guarantee forward progress. readTlv now yields end > off for any valid TLV, but a
    // stray zero/negative advance would loop forever on hostile bytes — refuse instead.
    if (tlv.end <= off) throw new Error('DER: non-advancing TLV');
    off = tlv.end;
  }
  return { kind: 'other' };
}

function trySpki(spkiDer: Uint8Array): Spki | null {
  try {
    const spki = readSeq(spkiDer, 0);
    const algTlv = readTlv(spki.content, 0);
    if (algTlv.tag !== 0x30) return null;
    const alg = readSeq(spki.content.subarray(algTlv.start, algTlv.end), 0);
    const algOidTlv = readTlv(alg.content, 0);
    if (algOidTlv.tag !== 0x06) return null;
    const algOid = readOid(alg.content.subarray(algOidTlv.cstart, algOidTlv.end));

    const bitTlv = readTlv(spki.content, algTlv.end);
    if (bitTlv.tag !== 0x03) return null;
    const keyBits = spki.content.subarray(bitTlv.cstart + 1, bitTlv.end); // drop unused-bits byte

    if (algOid === OID_RSA_ENCRYPTION) {
      // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
      const rsaSeq = readSeq(keyBits, 0);
      const nTlv = readTlv(rsaSeq.content, 0);
      const eTlv = readTlv(rsaSeq.content, nTlv.end);
      const n = osToInt(stripLeadingZero(rsaSeq.content.subarray(nTlv.cstart, nTlv.end)));
      const e = osToInt(stripLeadingZero(rsaSeq.content.subarray(eTlv.cstart, eTlv.end)));
      return { kind: 'rsa', n, e };
    }
    if (algOid === OID_EC_PUBLIC_KEY) {
      // keyBits is the uncompressed point 0x04 || X || Y.
      return { kind: 'ec', point: keyBits.slice() };
    }
    return null;
  } catch {
    return null;
  }
}

// ── DER primitives ──

interface Tlv {
  tag: number;
  start: number;   // index of the tag byte, within the parent slice
  cstart: number;  // index where content begins
  end: number;     // index one past the content
}

/** Read one TLV at `off` within `buf`. Supports short + long-form definite length. */
function readTlv(buf: Uint8Array, off: number): Tlv {
  const start = off;
  const tag = buf[off++];
  if (tag === undefined) throw new Error('DER: tag past end');
  let len = buf[off++];
  if (len === undefined) throw new Error('DER: length past end');
  if (len & 0x80) {
    const nBytes = len & 0x7f;
    if (nBytes === 0 || nBytes > 4) throw new Error('DER: unsupported length form');
    // UNSIGNED accumulation: `len = (len << 8) | b` is 32-bit SIGNED in JS, so a 4-byte
    // length with the high bit set (e.g. 84 80 00 00 00) would go NEGATIVE, making
    // `end = cstart + len` negative and slipping past the `end > buf.length` guard —
    // then subarray(cstart, negative) slices from the end and offsets can move backward,
    // hanging the parser on adversarial cert bytes. `* 0x100 + b` stays a safe positive
    // integer (max 0xFFFFFFFF < 2^53).
    len = 0;
    for (let i = 0; i < nBytes; i++) {
      const b = buf[off++];
      if (b === undefined) throw new Error('DER: length bytes past end');
      len = len * 0x100 + b;
    }
  }
  const cstart = off;
  const end = cstart + len;
  if (end > buf.length) throw new Error('DER: content past end');
  return { tag, start, cstart, end };
}

function readSeq(buf: Uint8Array, off: number): { content: Uint8Array } {
  const tlv = readTlv(buf, off);
  if (tlv.tag !== 0x30) throw new Error(`DER: expected SEQUENCE, got tag 0x${tlv.tag.toString(16)}`);
  return { content: buf.subarray(tlv.cstart, tlv.end) };
}

/** Decode an OBJECT IDENTIFIER's content octets to a dotted string. */
function readOid(content: Uint8Array): string {
  if (content.length === 0) return '';
  const parts: number[] = [];
  const first = content[0];
  parts.push(Math.floor(first / 40), first % 40);
  let val = 0;
  for (let i = 1; i < content.length; i++) {
    const b = content[i];
    val = (val << 7) | (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join('.');
}

// ── bigint / byte helpers ──

function stripLeadingZero(b: Uint8Array): Uint8Array {
  // DER INTEGERs are signed; a leading 0x00 guards the sign bit of a positive value.
  return b.length > 1 && b[0] === 0x00 ? b.subarray(1) : b;
}

function osToInt(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function intToOs(x: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = x;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('integer does not fit in requested length');
  return out;
}

function bitLen(x: bigint): number {
  return x.toString(2).length;
}

function byteLen(x: bigint): number {
  return Math.ceil(bitLen(x) / 8);
}

/** m = base^exp mod mod, square-and-multiply. exp is small (65537) but keep it general. */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function reverse(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function toHex(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, '0');
  return out;
}

// Test-only surface. Exposes the certificate primitives so harborChainVerify.test.ts
// can exercise RSA-PSS verification against real AMD ASK/ARK material (which has no
// accompanying VCEK/report to run through the full public verifyReportChain). Not for
// production callers — the supported entry point is verifyReportChain.
export const __internal = { parseCertificate, verifyCertSignature };
