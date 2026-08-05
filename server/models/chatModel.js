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

const mongoose = require('mongoose');

/**
 * Chat model for standalone chat sessions
 * These are simple chat sessions that don't use the graph structure
 */
const chatSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    title: {
      type: String,
      trim: true,
      maxlength: 100
      // Not required — encrypted chats use encryptedTitle instead
    },
    // E2EE: encrypted chat title. JSON string: { "iv": "<base64>", "ct": "<base64>" }
    encryptedTitle: { type: String, default: null },
    // E2EE: the chat's Stage — what it keeps in front of the model across turns.
    // Decrypts to a JSON array of { kind, id, title, role, isLocal?, pinnedAt?,
    // text?, file? } (client types/stage.ts, PersistedStagedItem).
    //
    // Deliberately POINTERS, not payloads: the resolved text is rebuilt per turn
    // by client stageService, so an artifact edited in the Cargo editor is seen
    // at its current version rather than the copy frozen into history. That also
    // keeps this field small — it is chat-level state, not per-message, unlike
    // messages[].encryptedContextRefs which is a historical record of one turn.
    //
    // The title inside is decrypted user content, which is why the whole array
    // is one ciphertext blob rather than a plain subdocument.
    encryptedStage: { type: String, default: null },
    // Chat messages stored inline for simplicity (no separate Message model needed)
    messages: [{
      role: {
        type: String,
        enum: ['user', 'assistant', 'system'],
        required: true
      },
      content: {
        type: String,
        trim: true
        // Not required — encrypted messages use encryptedContent instead
      },
      // E2EE: AES-256-GCM encrypted content. JSON string: { "iv": "<base64>", "ct": "<base64>" }
      encryptedContent: { type: String, default: null },
      // E2EE: encrypted web search sources. Decrypts to JSON array of { title, url, description }
      encryptedSources: { type: String, default: null },
      // E2EE: encrypted context references — chats/projects the user attached to
      // this message via the composer. Decrypts to JSON array of
      // { kind: 'chat'|'project', id, title, isLocal? }. The title is user
      // content, which is why the whole array is encrypted rather than stored
      // as a plain subdocument.
      encryptedContextRefs: { type: String, default: null },
      // E2EE: encrypted Deep Research step trail (JSON array of {stage,label,query?,sources?,gap?,at}).
      encryptedResearchTrail: { type: String, default: null },
      // E2EE: encrypted Visual-mode media ({images:[],videos:[]}) for the answer's
      // Images / Videos sections. The URLs are public search results, but WHICH
      // ones an answer surfaced is as revealing as the answer, so it's encrypted
      // client-side like sources. Deliberately its own field rather than folded
      // into encryptedSources: that blob decrypts to a bare array and an older
      // client would lose its sources row if the shape changed underneath it.
      encryptedMedia: { type: String, default: null },
      // E2EE: encrypted live weather snapshot (open-meteo) attached to assistant responses.
      // Decrypts to the WeatherData JSON shape consumed by WeatherCard.
      encryptedWeatherData: { type: String, default: null },
      // E2EE: encrypted compose-text payload (toned message variations) attached to
      // assistant responses. Decrypts to the ComposeData shape consumed by ComposeCard.
      encryptedComposeData: { type: String, default: null },
      // E2EE: encrypted JSON snapshot of the user's image/video generation selections at send time.
      encryptedGenerationOptions: { type: String, default: null },
      // PII redaction metadata (non-sensitive): true when the user's turn had PII
      // redacted before it was sent to the AI provider. Drives the "Redacted" badge.
      // `piiCategories` holds generic category labels (e.g. "EMAIL") — not the PII itself.
      piiRedacted: { type: Boolean, default: false },
      piiCategories: { type: [String], default: undefined },
      timestamp: {
        type: Date,
        default: Date.now
      },
      tokensUsed: {
        type: Number,
        default: 0
      },
      modelUsed: {
        type: String,
        default: null
      },
      imageAttachments: [{
        type: {
          type: String,
          enum: ['user_upload', 'ai_generated', 'ai_edited'],
          required: true
        },
        // Canonical storage key: S3 object key for cloud images, local fileId for local images.
        // Legacy documents may have this value stored under `storageRef` — read both.
        s3Key: {
          type: String,
          get: function(v) { return v || this.storageRef || ''; }
        },
        s3Url: { type: String, default: '' },
        storageType: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
        // E2EE: encrypted { fileName, mimeType, size } JSON string
        encryptedMetadata: { type: String, default: null },
        // IV for decrypting the image binary
        encIv: { type: String, default: null },
        // Encrypted ~320px thumbnail companion. Library grid fetches+decrypts
        // ~20KB instead of the full-res image. Backfilled lazily for older
        // attachments that lack these fields.
        thumbS3Key: { type: String, default: null },
        thumbEncIv: { type: String, default: null },
        fileName: { type: String },
        fileSize: { type: Number },
        mimeType: { type: String },
        encryptedSize: { type: Number },
        dimensions: {
          width: { type: Number },
          height: { type: Number }
        },
        metadata: {
          prompt: { type: String },
          uploadedAt: { type: Date, default: Date.now },
          originalFileName: { type: String },
          intent: { type: String, enum: ['generate', 'edit', null], default: null },
          generatedByModel: { type: String, default: null },
          originalImage: {
            _id: { type: String, default: null },
            storageType: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
            storageRef: { type: String, default: null },
            s3Key: { type: String },
            s3Url: { type: String, default: '' },
            fileName: { type: String },
            // E2EE: encrypted { fileName, mimeType, prompt } JSON for the original
            // image so the modal can show a real title under "View original".
            encryptedMetadata: { type: String, default: null },
            encIv: { type: String, default: null }
          }
        },
        // Soft-delete: image removed from library but message preserved in chat history
        deleted: { type: Boolean, default: false },
      }],
      // File attachments (pdf/audio/docx/csv/code). Binary bytes are encrypted
      // client-side and stored in S3 as ciphertext (storageRef + encIv); only
      // encryptedMetadata (filename/mimeType/size) is persisted, never plaintext.
      // Mirrors the shape ChatNode.fileAttachments already uses so the Library
      // and re-fetch paths are uniform. Legacy docs carry plaintext
      // filename/mimeType and no storageRef — read-only fallback.
      fileAttachments: [{
        type: { type: String, enum: ['pdf', 'audio', 'video', 'docx', 'csv', 'code'], required: true },
        storageType: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
        // S3 object key for cloud ciphertext, or local fileId for on-device bytes.
        storageRef: { type: String, default: null },
        s3Url: { type: String, default: '' },
        // E2EE: encrypted { filename, mimeType, size } JSON string
        encryptedMetadata: { type: String, default: null },
        // IV for decrypting the file binary
        encIv: { type: String, default: null },
        fileSize: { type: Number },
        // Legacy plaintext fields (pre-E2EE file uploads) — read-only fallback.
        filename: { type: String },
        mimeType: { type: String },
        // Soft-delete tombstone, matching image/video attachments. Set when the
        // file is deleted from the Library; GET /api/library/files skips these.
        deleted: { type: Boolean, default: false },
      }],
      // AI-generated video attachments — mirrors messageModel videoAttachments
      videoAttachments: [{
        jobId:             { type: String, index: true },
        status:            { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
        storageType:       { type: String, enum: ['cloud', 'local'], default: 'cloud' },
        storageRef:        { type: String, default: null },
        encryptedMetadata: { type: String, default: null },
        encIv:             { type: String, default: null },
        mimeType:          { type: String, default: null },
        fileName:          { type: String, default: null },
        modelId:           { type: String, default: null },
        duration:          { type: Number, default: null },
        aspectRatio:       { type: String, default: null },
        style:             { type: String, default: null },
        composition:       { type: String, default: null },
        mode:              { type: String, enum: ['text', 'imageToVideo', 'startEndFrame'], default: 'text' },
        // Soft-delete: video removed from library but attachment preserved in history
        deleted:           { type: Boolean, default: false },
      }],
    }],
    isActive: {
      type: Boolean,
      default: true
    },
    lastActivity: {
      type: Date,
      default: Date.now,
      index: true
    },
    totalMessages: {
      type: Number,
      default: 0,
      min: 0
    },
    tokensUsed: {
      type: Number,
      default: 0,
      min: 0
    },
    pinned: {
      type: Boolean,
      default: false,
      index: true
    },
    // Optional: group this chat under a project
    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      default: null,
      index: true
    },
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: () => new Map()
    }
  },
  { 
    timestamps: true 
  }
);

// Indexes
chatSchema.index({ userId: 1, lastActivity: -1 });
chatSchema.index({ userId: 1, createdAt: -1 });
chatSchema.index({ userId: 1, isActive: 1 });
// Storage-handle lookups — see the matching indexes on messageModel. Attachment
// ids in the Library API are positional (`chatId_msgIdx_attIdx`), so the S3 key
// / storage ref is the only stable way to address one.
chatSchema.index({ userId: 1, 'messages.imageAttachments.s3Key': 1 });
chatSchema.index({ userId: 1, 'messages.fileAttachments.storageRef': 1 });
chatSchema.index({ userId: 1, 'messages.videoAttachments.storageRef': 1 });

// E2EE fence: any new or modified save nulls out the legacy plaintext
// `title` field and the plaintext `messages[].content`. The encrypted
// variants (`encryptedTitle`, `messages[].encryptedContent`) are the only
// persistent surface for user content.
chatSchema.pre('save', function(next) {
  if (this.isNew || this.isModified('title')) this.title = null;
  if (Array.isArray(this.messages)) {
    for (const msg of this.messages) {
      if (msg && msg.content != null) msg.content = null;
    }
  }
  next();
});

// $push / $set / $addToSet may bypass the document pre('save') hook above
// when callers use findOneAndUpdate. Strip plaintext from any update payload
// that targets `title` or message bodies.
function fenceUpdatePlaintext(next) {
  const update = this.getUpdate?.();
  if (!update) return next();
  const stripPlaintext = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    if ('title' in obj) obj.title = null;
    if ('messages.$.content' in obj) obj['messages.$.content'] = null;
    if (obj.messages && Array.isArray(obj.messages)) {
      for (const m of obj.messages) {
        if (m && m.content != null) m.content = null;
      }
    }
    if (obj.messages && typeof obj.messages === 'object' && !Array.isArray(obj.messages) && obj.messages.content != null) {
      obj.messages.content = null;
    }
  };
  stripPlaintext(update);
  stripPlaintext(update.$set);
  stripPlaintext(update.$push);
  next();
}
chatSchema.pre('findOneAndUpdate', fenceUpdatePlaintext);
chatSchema.pre('updateOne', fenceUpdatePlaintext);
chatSchema.pre('updateMany', fenceUpdatePlaintext);

// Static method to create a new chat. E2EE: callers must supply
// `encryptedTitle` (or omit a title entirely) — the server no longer derives
// a plaintext title from message content.
chatSchema.statics.createChat = async function(userId, firstMessage, projectId = null) {
  const chatDoc = {
    userId,
    messages: [firstMessage],
    totalMessages: 1,
    tokensUsed: firstMessage.tokensUsed || 0,
    lastActivity: new Date(),
    projectId: projectId || null
  };
  if (firstMessage.encryptedTitle) chatDoc.encryptedTitle = firstMessage.encryptedTitle;

  const chat = await this.create(chatDoc);
  return chat;
};

// Static method to add a message to chat
chatSchema.statics.addMessage = async function(chatId, message) {
  const chat = await this.findByIdAndUpdate(
    chatId,
    {
      $push: { messages: message },
      $inc: { 
        totalMessages: 1,
        tokensUsed: message.tokensUsed || 0
      },
      $set: { lastActivity: new Date() }
    },
    { new: true }
  );
  return chat;
};

// Static method to get user's chats with pagination
chatSchema.statics.getUserChats = async function(userId, options = {}) {
  const {
    page = 1,
    limit = 20,
    search = ''
  } = options;

  const skip = (page - 1) * limit;

  // E2EE: server can no longer search by title (titles are ciphertext). The
  // `search` argument is accepted for API compatibility but ignored — clients
  // do title search locally over decrypted titles.
  const query = { userId, isActive: true };

  const [chats, totalCount] = await Promise.all([
    this.find(query)
      .sort({ lastActivity: -1 })
      .skip(skip)
      .limit(limit)
      .select('title encryptedTitle totalMessages lastActivity createdAt messages')
      .lean()
      .then(chats => chats.map(chat => ({
        ...chat,
        // Preview is left blank — message bodies are ciphertext server-side.
        preview: ''
      }))),
    this.countDocuments(query)
  ]);

  return {
    chats,
    pagination: {
      currentPage: page,
      totalPages: Math.ceil(totalCount / limit),
      totalCount,
      hasMore: page < Math.ceil(totalCount / limit),
      limit
    }
  };
};

const Chat = mongoose.model('Chat', chatSchema);

module.exports = Chat;
