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
const { downloadFromS3, S3_CONFIG } = require('../services/cloud-services');
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

    // Determine bucket from key path structure
    let bucketType = 'user_uploads';
    if (
      storageRef.includes('/generated/') ||
      storageRef.includes('/edited/') ||
      storageRef.includes('/videos/') ||
      storageRef.includes('ai_generated/')
    ) {
      bucketType = 'ai_generated';
    }

    // Look up attachment metadata to check if client-encrypted
    const attachmentMeta = await findAttachmentMeta(storageRef, req.user._id.toString());

    const result = await downloadFromS3(storageRef, bucketType);

    if (!result.success) {
      return res.status(404).json({ message: 'Image not found' });
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
    res.send(result.buffer);
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
  return null;
}

module.exports = router;
