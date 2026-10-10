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

const express = require('express');
const logger = require('../utils/logger');
const router = express.Router();
const { pipeline } = require('stream');
const { streamFromS3, bucketTypeFromKey } = require('../services/cloud-services');
const { authenticate } = require('../middleware/auth');
const ChatNode = require('../models/chatNodeModel');
const Chat = require('../models/chatModel');

// All media requests require authentication
router.use(authenticate);

/**
 * GET /api/media/:storageRef*
 * Proxies cloud images from S3 with JWT auth and ownership verification.
 * storageRef format: {userId}/{path}
 */
router.get('*', async (req, res) => {
  try {
    const storageRef = req.path.substring(1); // strip leading slash

    if (!storageRef || storageRef.trim() === '') {
      return res.status(400).json({ message: 'Invalid media reference' });
    }

    // Ownership check: storageRef starts with the requesting user's id
    const userId = req.user._id.toString();
    if (!storageRef.startsWith(userId + '/')) {
      // Fallback: verify ownership by looking up the ref in DB
      const hasAccess = await verifyOwnership(storageRef, userId);
      if (!hasAccess) {
        return res.status(403).json({ message: 'Access denied' });
      }
    }

    // Which bucket holds it, from the key's own path. Shared with the Library
    // and the deletion path rather than kept as a private copy — this route had
    // the only version that knew about `/videos/`, and the versions that didn't
    // were pointing reads (and deletes) at the wrong bucket.
    const bucketType = bucketTypeFromKey(storageRef);

    // Look up attachment metadata to check if client-encrypted
    const attachmentMeta = await findAttachmentMeta(storageRef, req.user._id.toString());

    // Streamed, never buffered: this route serves videos up to 100MB, and
    // holding each one whole for the length of the response is what ran the
    // 512MB instance out of memory. `streamFromS3` HEADs first, so a ref that
    // is not in the bucket throws here — before any header is written — and is
    // a 404, not the 500 the catch below would report.
    let result;
    try {
      result = await streamFromS3(storageRef, bucketType);
    } catch (dlErr) {
      logger.warn('Media proxy: object unavailable', { storageRef, bucketType, error: dlErr.message });
      return res.status(404).json({ message: 'Media not found' });
    }

    const isEncrypted = !!(attachmentMeta?.encIv);
    const headers = {
      'Content-Type': isEncrypted ? 'application/octet-stream' : (result.contentType || 'image/jpeg'),
      'Content-Length': result.contentLength,
      'Cache-Control': 'private, max-age=3600',
    };
    if (isEncrypted) {
      headers['X-Enc-IV'] = attachmentMeta.encIv;
      if (attachmentMeta.encryptedMetadata) {
        headers['X-Encrypted-Metadata'] = attachmentMeta.encryptedMetadata;
      }
    }
    res.set(headers);
    // pipeline tears down the S3 read when the client goes away mid-download.
    // Headers are already out by the time the stream can fail, so a failure
    // here can only cut the response short, never change its status.
    pipeline(result.stream, res, (streamErr) => {
      if (streamErr && streamErr.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
        logger.warn('Media proxy: stream failed mid-response', { storageRef, error: streamErr.message });
      }
    });
  } catch (error) {
    logger.error('Media proxy error:', error);
    res.status(500).json({ message: 'Failed to retrieve image' });
  }
});

/**
 * Verify a storageRef belongs to a user by checking ChatNode/Chat records.
 * ChatNode uses 's3Key'; Chat model uses 'storageRef'.
 */
async function verifyOwnership(storageRef, userId) {
  const [nodeMatch, chatMatch, messageVideoMatch] = await Promise.all([
    ChatNode.exists({
      userId,
      'imageAttachments.s3Key': storageRef
    }),
    Chat.exists({
      userId,
      $or: [
        { 'messages.imageAttachments.s3Key': storageRef },
        { 'messages.imageAttachments.storageRef': storageRef },
        { 'messages.videoAttachments.storageRef': storageRef },
      ],
    }),
    require('../models/messageModel').exists({
      userId,
      'videoAttachments.storageRef': storageRef,
    }),
  ]);
  return !!(nodeMatch || chatMatch || messageVideoMatch);
}

/**
 * Return attachment subdoc for the given storageRef/s3Key (contains encIv, encryptedMetadata).
 * Returns null if not found.
 * Note: ChatNode uses 's3Key'; Chat model uses 'storageRef' for the same concept.
 */
async function findAttachmentMeta(storageRef, userId) {
  const node = await ChatNode.findOne(
    { userId, 'imageAttachments.s3Key': storageRef },
    { 'imageAttachments.$': 1 }
  ).lean();
  if (node?.imageAttachments?.[0]) return node.imageAttachments[0];

  // Chat model stores the S3 key as 'storageRef', not 's3Key'
  const chat = await Chat.findOne(
    { userId, 'messages.imageAttachments.storageRef': storageRef },
    { 'messages.$': 1 }
  ).lean();
  if (chat?.messages?.[0]?.imageAttachments) {
    const att = chat.messages[0].imageAttachments.find(a => a.storageRef === storageRef);
    if (att) return att;
  }

  // Generated videos live in the same proxy but in a different subdoc array.
  // Without this arm an encrypted video is served as `image/jpeg` with no
  // X-Enc-IV, so a client that has lost the IV has no way to recover it.
  const videoChat = await Chat.findOne(
    { userId, 'messages.videoAttachments.storageRef': storageRef },
    { 'messages.$': 1 }
  ).lean();
  if (videoChat?.messages?.[0]?.videoAttachments) {
    const att = videoChat.messages[0].videoAttachments.find(a => a.storageRef === storageRef);
    if (att) return att;
  }

  const msg = await require('../models/messageModel').findOne(
    { userId, 'videoAttachments.storageRef': storageRef },
    { 'videoAttachments.$': 1 }
  ).lean();
  if (msg?.videoAttachments?.[0]) return msg.videoAttachments[0];

  return null;
}

module.exports = router;
