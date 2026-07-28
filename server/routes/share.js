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
 * Public chat sharing routes.
 *
 * Mounted at /api/share in server.js.
 *
 *   POST   /api/share/assets/presign  → (auth) presigned S3 PUT URLs for media
 *   POST   /api/share                 → (auth) create/update a snapshot
 *   GET    /api/share/source?sourceId=→ (auth) existing share token for a source
 *   GET    /api/share/source/:sourceId→ (auth) same, path form (older clients)
 *   GET    /api/share/:token          → (public) fetch a snapshot to render
 *   DELETE /api/share/:token          → (auth) revoke + purge media
 *
 * E2EE: every snapshot stores ciphertext only. The decryption (share) key never
 * reaches the server — it travels in the share URL's #fragment. See
 * shareSnapshotModel.js for the full design.
 */

const crypto = require('crypto');
const logger = require('../utils/logger');
const express = require('express');
const router = express.Router();

const { authenticate } = require('../middleware/auth');
const { publicShareViewLimiter } = require('../middleware/rateLimiter');
const {
  generateSignedUrl,
  generateSignedUploadUrl,
  deletePrefixFromS3,
  bucketTypeFromKey,
} = require('../services/cloud-services');

const ShareSnapshot = require('../models/shareSnapshotModel');
const Chat = require('../models/chatModel');
const ChatGraph = require('../models/chatGraphModel');
const Cargo = require('../models/cargoModel');
const LibraryAudio = require('../models/libraryAudioModel');

const { validateCargoPayload } = require('../utils/shareCargoValidation');
const { validateAudioPayload } = require('../utils/shareAudioValidation');

const MAX_ASSETS = 200;
const SHARE_ASSET_CONTENT_TYPE = 'application/octet-stream';
const SHARE_SOURCE_TYPES = ['chat', 'graph', 'cargo', 'audio'];

function newToken() {
  return crypto.randomBytes(16).toString('base64url');
}

// Verify the authenticated user owns the chat/graph/cargo/clip being shared. Local sources
// live only on the owner's device — there's nothing to verify against, and
// ownership is implicit (the snapshot is keyed to req.user), so allow them.
async function assertOwnsSource(userId, sourceType, sourceId, sourceBackend) {
  if (sourceBackend === 'local') return true;
  if (sourceType === 'audio') return assertOwnsAudio(userId, sourceId);
  if (sourceType === 'chat') {
    const chat = await Chat.findOne({ _id: sourceId, userId }).select('_id').lean();
    return !!chat;
  }
  if (sourceType === 'graph') {
    const graph = await ChatGraph.findOne({ _id: sourceId, userId }).select('_id').lean();
    return !!graph;
  }
  if (sourceType === 'cargo') {
    const cargo = await Cargo.findOne({ _id: sourceId, userId }).select('_id').lean();
    return !!cargo;
  }
  return false;
}

/**
 * Ownership for an audio clip. `sourceId` is the clip's `storageRef`, not a row
 * id — the same handle libraryDeletion.deleteFile keys on, and for the same
 * reason: a chat-attached clip's Library row id is positional
 * (`<chatId>_<msgIdx>_<fileIdx>`), so it neither survives an edit to the
 * conversation nor proves anything about who owns the bytes.
 *
 * A clip has exactly one home — a LibraryAudio row (Audio studio) or a chat
 * message's fileAttachments (audio that arrived in a conversation) — so the two
 * lookups are a fall-through, not a tiebreak.
 */
async function assertOwnsAudio(userId, storageRef) {
  if (!storageRef || typeof storageRef !== 'string') return false;
  const clip = await LibraryAudio.findOne({ userId, storageRef, deleted: { $ne: true } })
    .select('_id').lean();
  if (clip) return true;
  const chat = await Chat.findOne({
    userId, isActive: true, 'messages.fileAttachments.storageRef': storageRef,
  }).select('_id').lean();
  return !!chat;
}

// ── POST /api/share/assets/presign ───────────────────────────────────────────
// Ensures a snapshot stub exists for (owner, source) and returns presigned PUT
// URLs for re-encrypted media. On a re-share the previous media is purged first
// so finalize replaces everything wholesale.
router.post('/assets/presign', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const { sourceType, sourceId, count, sourceBackend = 'cloud' } = req.body || {};

    if (!SHARE_SOURCE_TYPES.includes(sourceType) || typeof sourceId !== 'string' || !sourceId) {
      return res.status(400).json({ message: 'sourceType and sourceId are required' });
    }
    if (!['cloud', 'local'].includes(sourceBackend)) {
      return res.status(400).json({ message: 'invalid sourceBackend' });
    }
    const n = Number.isInteger(count) ? count : 0;
    if (n < 0 || n > MAX_ASSETS) {
      return res.status(400).json({ message: `count must be between 0 and ${MAX_ASSETS}` });
    }
    if (!(await assertOwnsSource(userId, sourceType, sourceId, sourceBackend))) {
      return res.status(404).json({ message: 'Chat not found' });
    }

    // Find-or-create the snapshot stub; mint the token only on insert so a
    // re-share keeps the same public URL.
    const snapshot = await ShareSnapshot.findOneAndUpdate(
      { ownerUserId: userId, sourceId },
      { $setOnInsert: { token: newToken(), sourceType, sourceBackend, ownerUserId: userId, sourceId } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    // Purge any media from a previous share of this source — finalize will
    // attach a fresh manifest.
    try {
      await deletePrefixFromS3(`shares/${snapshot.token}/`, 'user_uploads');
    } catch (e) {
      logger.warn('[share/presign] prefix purge failed (non-fatal):', e.message);
    }

    const uploads = [];
    for (let i = 0; i < n; i++) {
      const assetId = crypto.randomUUID();
      const s3Key = `shares/${snapshot.token}/${assetId}`;
      const uploadUrl = await generateSignedUploadUrl(s3Key, SHARE_ASSET_CONTENT_TYPE, 'user_uploads', 900);
      uploads.push({ s3Key, uploadUrl, contentType: SHARE_ASSET_CONTENT_TYPE });
    }

    res.json({ token: snapshot.token, uploads });
  } catch (err) {
    logger.error('[share/assets/presign] error:', err);
    res.status(500).json({ message: 'Failed to prepare share upload' });
  }
});

// ── POST /api/share ──────────────────────────────────────────────────────────
// Finalize: write the full ciphertext snapshot. Idempotent on (owner, source);
// re-sharing overwrites the prior content and clears any revocation.
router.post('/', authenticate, async (req, res) => {
  try {
    const userId = req.user._id;
    const {
      token,
      sourceType,
      sourceId,
      sourceBackend = 'cloud',
      wrappedShareKey,
      encryptedTitle = null,
      messages = [],
      nodes = [],
      edges = [],
      entryNodeIds = [],
      cargo = null,
      audio = null,
    } = req.body || {};

    if (!token || !SHARE_SOURCE_TYPES.includes(sourceType) || typeof sourceId !== 'string' || !sourceId || !wrappedShareKey) {
      return res.status(400).json({ message: 'token, sourceType, sourceId and wrappedShareKey are required' });
    }
    if (sourceType === 'cargo') {
      const invalid = validateCargoPayload(cargo);
      if (invalid) return res.status(invalid.status).json({ message: invalid.message });
    }
    if (sourceType === 'audio') {
      const invalid = validateAudioPayload(audio, token);
      if (invalid) return res.status(invalid.status).json({ message: invalid.message });
    }
    if (!['cloud', 'local'].includes(sourceBackend)) {
      return res.status(400).json({ message: 'invalid sourceBackend' });
    }
    if (!(await assertOwnsSource(userId, sourceType, sourceId, sourceBackend))) {
      return res.status(404).json({ message: 'Chat not found' });
    }

    const snapshot = await ShareSnapshot.findOne({ token, ownerUserId: userId });
    if (!snapshot || String(snapshot.sourceId) !== String(sourceId)) {
      return res.status(404).json({ message: 'Share not found' });
    }

    snapshot.sourceType = sourceType;
    snapshot.sourceBackend = sourceBackend;
    snapshot.wrappedShareKey = wrappedShareKey;
    snapshot.encryptedTitle = encryptedTitle;
    snapshot.messages = sourceType === 'chat' ? messages : [];
    snapshot.nodes = sourceType === 'graph' ? nodes : [];
    snapshot.edges = sourceType === 'graph' ? edges : [];
    snapshot.entryNodeIds = sourceType === 'graph' ? entryNodeIds : [];
    snapshot.cargo = sourceType === 'cargo'
      ? { encryptedMeta: cargo.encryptedMeta, encryptedContent: cargo.encryptedContent }
      : null;
    snapshot.audio = sourceType === 'audio'
      ? {
          encryptedMeta: audio.encryptedMeta,
          // Name, mime and length all ride inside encryptedMeta — the plaintext
          // asset fields the image/video shape carries are left null rather
          // than duplicated, so the server holds only an opaque key + IV.
          asset: {
            kind: 'audio',
            s3Key: audio.asset.s3Key,
            encIv: audio.asset.encIv,
            mimeType: null,
            fileName: null,
            width: null,
            height: null,
            durationMs: null,
          },
        }
      : null;
    snapshot.revokedAt = null;
    await snapshot.save();

    res.json({ token: snapshot.token });
  } catch (err) {
    logger.error('[share/finalize] error:', err);
    res.status(500).json({ message: 'Failed to save share' });
  }
});

// ── GET /api/share/source ────────────────────────────────────────────────────
// Owner-scoped lookup so the share sheet can show "copy existing link".
// wrappedShareKey (share key sealed under the owner's master key — useless
// without it) lets the client reuse the same share key on re-share, so
// previously distributed links keep decrypting. Owner-only route; the public
// GET never returns it.
//
// Two forms, one handler. The query form is what the client uses: an audio
// share's sourceId is an S3 key, and a path segment can't carry the slashes
// (proxies and Express disagree about whether %2F stays encoded). The path form
// stays for clients shipped before the query form existed.
async function lookupBySourceId(req, res) {
  try {
    const sourceId = req.params.sourceId ?? req.query.sourceId;
    if (typeof sourceId !== 'string' || !sourceId) {
      return res.status(400).json({ message: 'sourceId is required' });
    }
    const snapshot = await ShareSnapshot.findOne({
      ownerUserId: req.user._id,
      sourceId,
    }).lean();
    if (!snapshot || snapshot.revokedAt) return res.json({ token: null });
    res.json({ token: snapshot.token, wrappedShareKey: snapshot.wrappedShareKey || null });
  } catch (err) {
    logger.error('[share/source] error:', err);
    res.status(500).json({ message: 'Failed to look up share' });
  }
}

router.get('/source', authenticate, lookupBySourceId);
router.get('/source/:sourceId', authenticate, lookupBySourceId);

// ── GET /api/share/:token ─────────────────────────────────────────────────────
// Public, unauthenticated. Returns the ciphertext snapshot plus short-lived
// signed GET URLs for media. Never exposes wrappedShareKey.
router.get('/:token', publicShareViewLimiter, async (req, res) => {
  try {
    const snapshot = await ShareSnapshot.findOne({ token: req.params.token });
    if (!snapshot || !snapshot.isViewable()) {
      return res.status(404).json({ message: 'This link is no longer available.' });
    }

    const signAssets = async (attachments = []) =>
      Promise.all(
        attachments.map(async (a) => {
          let url = null;
          try {
            url = await generateSignedUrl(a.s3Key, bucketTypeFromKey(a.s3Key), 3600);
          } catch {
            /* leave url null — viewer skips the asset */
          }
          return {
            kind: a.kind,
            encIv: a.encIv,
            mimeType: a.mimeType,
            fileName: a.fileName,
            width: a.width,
            height: a.height,
            durationMs: a.durationMs,
            url,
          };
        })
      );

    // Document attachments carry metadata only (no bytes) — pass through as-is.
    const mapFiles = (files = []) =>
      files.map((f) => ({ type: f.type, encryptedFileName: f.encryptedFileName, mimeType: f.mimeType }));

    const out = {
      sourceType: snapshot.sourceType,
      encryptedTitle: snapshot.encryptedTitle,
      createdAt: snapshot.createdAt,
    };

    if (snapshot.sourceType === 'chat') {
      out.messages = await Promise.all(
        snapshot.messages.map(async (m) => ({
          role: m.role,
          encryptedContent: m.encryptedContent,
          encryptedSources: m.encryptedSources,
          attachments: await signAssets(m.attachments),
          files: mapFiles(m.files),
        }))
      );
    } else if (snapshot.sourceType === 'cargo') {
      out.cargo = snapshot.cargo
        ? { encryptedMeta: snapshot.cargo.encryptedMeta, encryptedContent: snapshot.cargo.encryptedContent }
        : null;
    } else if (snapshot.sourceType === 'audio') {
      const [asset] = snapshot.audio ? await signAssets([snapshot.audio.asset]) : [];
      out.audio = snapshot.audio
        ? { encryptedMeta: snapshot.audio.encryptedMeta, asset: asset || null }
        : null;
    } else {
      out.nodes = await Promise.all(
        snapshot.nodes.map(async (nd) => ({
          clientNodeId: nd.clientNodeId,
          type: nd.type,
          encryptedPrompt: nd.encryptedPrompt,
          encryptedAiResponse: nd.encryptedAiResponse,
          encryptedNoteBody: nd.encryptedNoteBody,
          position: nd.position,
          attachments: await signAssets(nd.attachments),
          files: mapFiles(nd.files),
        }))
      );
      out.edges = snapshot.edges.map((e) => ({
        sourceNodeId: e.sourceNodeId,
        targetNodeId: e.targetNodeId,
        edgeType: e.edgeType,
      }));
      out.entryNodeIds = snapshot.entryNodeIds;
    }

    // Best-effort view counter; never block the response on it.
    ShareSnapshot.updateOne({ _id: snapshot._id }, { $inc: { viewCount: 1 } }).catch(() => {});

    res.json({ snapshot: out });
  } catch (err) {
    logger.error('[share/get] error:', err);
    res.status(500).json({ message: 'Failed to load shared chat' });
  }
});

// ── DELETE /api/share/:token ──────────────────────────────────────────────────
// Owner revoke: mark revoked and purge media so the link goes dead.
router.delete('/:token', authenticate, async (req, res) => {
  try {
    const snapshot = await ShareSnapshot.findOne({ token: req.params.token, ownerUserId: req.user._id });
    if (!snapshot) return res.status(404).json({ message: 'Share not found' });

    try {
      await deletePrefixFromS3(`shares/${snapshot.token}/`, 'user_uploads');
    } catch (e) {
      logger.warn('[share/delete] prefix purge failed (non-fatal):', e.message);
    }

    await ShareSnapshot.deleteOne({ _id: snapshot._id });
    res.json({ success: true });
  } catch (err) {
    logger.error('[share/delete] error:', err);
    res.status(500).json({ message: 'Failed to revoke share' });
  }
});

module.exports = router;
