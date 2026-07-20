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

const messageSchema = new mongoose.Schema(
  {
    graphId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatGraph',
      required: true,
      index: true
    },
    nodeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatNode',
      required: true,
      index: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    role: {
      type: String,
      enum: ['user', 'assistant', 'system'],
      required: true,
      index: true
    },
    content: {
      type: String,
      trim: true
      // Not required — encrypted messages use encryptedContent instead
    },
    // E2EE: AES-256-GCM encrypted content. Present instead of `content` for all
    // new messages. Payload is a JSON string: { "iv": "<base64>", "ct": "<base64>" }
    encryptedContent: {
      type: String,
      default: null
    },
    // E2EE: encrypted JSON snapshot of the user's image/video generation selections at send time.
    encryptedGenerationOptions: {
      type: String,
      default: null
    },
    // E2EE: encrypted Deep Research step trail (JSON array of {stage,label,query?,sources?,gap?,at}).
    // Plaintext contains user queries and lines of inquiry, so it's encrypted client-side
    // alongside the message content. Include in any projection that returns message content.
    encryptedResearchTrail: {
      type: String,
      default: null
    },
    // Image attachments and generated images
    imageAttachments: [{
      type: {
        type: String,
        enum: ['user_upload', 'ai_generated', 'ai_edited'],
        required: true
      },
      storageType: {
        type: String,
        enum: ['cloud', 'local'],
        default: 'cloud'
      },
      s3Key: {
        type: String,
        required: true // S3 key for cloud, fileId for local
      },
      s3Url: {
        type: String,
        default: '' // Empty for local images
      },
      // E2EE: encrypted { fileName, mimeType, size, prompt } JSON string
      encryptedMetadata: { type: String, default: null },
      // IV used when encrypting the image binary (needed by client for decryption)
      encIv: { type: String, default: null },
      // Encrypted ~320px thumbnail companion. Library grid fetches+decrypts
      // ~20KB instead of the full-res image. Backfilled lazily — older
      // attachments may have null values until the user views them.
      thumbS3Key: { type: String, default: null },
      thumbEncIv: { type: String, default: null },
      fileName: {
        type: String
      },
      fileSize: {
        type: Number
      },
      mimeType: {
        type: String
      },
      dimensions: {
        width: { type: Number },
        height: { type: Number }
      },
      metadata: {
        prompt: { type: String },
        uploadedAt: { type: Date, default: Date.now },
        originalFileName: { type: String },
        compressionApplied: { type: Boolean, default: false },
        intent: { type: String, enum: ['generate', 'edit', null], default: null },
        generatedByModel: { type: String, default: null },
        originalImage: {
          _id: { type: String },
          storageType: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
          storageRef: { type: String, default: null },
          s3Key: { type: String },
          s3Url: { type: String },
          fileName: { type: String },
          // E2EE: encrypted { fileName, mimeType, prompt } JSON for the original
          // image. Needed so the modal can show a real title when the user
          // toggles "View original" — the plaintext fileName is stripped by
          // the attachment sanitizer per E2EE contract.
          encryptedMetadata: { type: String, default: null },
          encIv: { type: String, default: null }
        }
      },
      // Soft-delete: image removed from library but message preserved in chat history
      deleted: { type: Boolean, default: false },
    }],
    // AI-generated video attachments
    videoAttachments: [{
      jobId:             { type: String, index: true },
      status:            { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
      storageType:       { type: String, enum: ['cloud', 'local'], default: 'cloud' },
      storageRef:        { type: String, default: null },
      // E2EE: encrypted { fileName, mimeType } JSON string
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
      createdAt:         { type: Date, default: Date.now },
    }],
    originalContent: {
      type: String,
      trim: true // Store original content if message was edited
    },
    // Token transaction tracking
    tokenTransactionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'TokenTransaction',
      default: null // Links to the token transaction for this message
    },
    tokensUsed: {
      type: Number,
      default: 0,
      min: 0
    },
    // Message metadata
    messageType: {
      type: String,
      enum: ['text', 'system', 'branch_creation', 'summary', 'image_upload', 'image_generation', 'video_generation', 'mixed'],
      default: 'text'
    },
    sequenceNumber: {
      type: Number,
      required: true,
      min: 1 // Order within the conversation node
    },
    // Text selection tracking (for messages that can be selected for branching)
    isSelectable: {
      type: Boolean,
      default: true
    },
    selectionRanges: [{
      start: { type: Number, required: true },
      end: { type: Number, required: true },
      branchNodeId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'ChatNode'
      },
      selectedText: { type: String, required: true }
    }], // Track what parts of this message have been selected for branching
    // Response metadata (for assistant messages)
    geminiMetadata: {
      model: { type: String, default: 'deepseek/deepseek-v4-flash' },
      responseTime: { type: Number }, // milliseconds
      promptTokens: { type: Number, default: 0 },
      completionTokens: { type: Number, default: 0 },
      totalTokens: { type: Number, default: 0 },
      imageModel: { type: String }, // For image generation: 'gemini-2.5-flash-image-preview'
      imagePrompt: { type: String }, // The prompt used for image generation
      imageTokens: { type: Number, default: 0 } // Tokens used specifically for image operations
    },
    // Message state
    isEdited: {
      type: Boolean,
      default: false
    },
    isDeleted: {
      type: Boolean,
      default: false
    },
    editHistory: [{
      content: { type: String, required: true },
      editedAt: { type: Date, default: Date.now },
      reason: { type: String, maxlength: 200 }
    }],
    // Reactions and interactions
    reactions: {
      likes: { type: Number, default: 0 },
      dislikes: { type: Number, default: 0 },
      useful: { type: Boolean, default: false },
      flagged: { type: Boolean, default: false }
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

// Indexes for efficient querying
messageSchema.index({ nodeId: 1, sequenceNumber: 1 });
messageSchema.index({ userId: 1, createdAt: -1 });
messageSchema.index({ role: 1, createdAt: -1 });
messageSchema.index({ isDeleted: 1, createdAt: -1 });
messageSchema.index({ graphId: 1, createdAt: 1 }); // For conversation history
messageSchema.index({ messageType: 1, createdAt: -1 }); // For filtering by message type
messageSchema.index({ 'imageAttachments.type': 1, createdAt: -1 }); // For image queries
// Storage-handle lookups. Library deletes and folder hydration both resolve an
// attachment by its S3 key / storage ref rather than by _id — the ids the
// Library API hands out for embedded attachments are positional and shift when
// an earlier sibling is soft-deleted.
messageSchema.index({ userId: 1, 'imageAttachments.s3Key': 1 });
messageSchema.index({ userId: 1, 'videoAttachments.storageRef': 1 });

// Virtual for message display data
messageSchema.virtual('displayData').get(function() {
  return {
    id: this._id,
    content: this.isDeleted ? '[Message deleted]' : this.content,
    role: this.role,
    timestamp: this.createdAt,
    isEdited: this.isEdited,
    tokensUsed: this.tokensUsed,
    selectionRanges: this.selectionRanges,
    reactions: this.reactions,
    messageType: this.messageType,
    imageAttachments: this.imageAttachments || [],
    hasImages: this.imageAttachments && this.imageAttachments.length > 0
  };
});

// Virtual for text selection data
messageSchema.virtual('selectionData').get(function() {
  return {
    messageId: this._id,
    content: this.content,
    isSelectable: this.isSelectable && !this.isDeleted,
    existingSelections: this.selectionRanges.map(range => ({
      start: range.start,
      end: range.end,
      text: range.selectedText,
      branchId: range.branchNodeId
    }))
  };
});

// Method to add a text selection that created a branch
messageSchema.methods.addSelection = async function(selectionData) {
  const { start, end, selectedText, branchNodeId } = selectionData;
  
  // Validate selection range
  if (start < 0 || end > this.content.length || start >= end) {
    throw new Error('Invalid selection range');
  }
  
  // Allow overlapping selections - users should be able to create multiple branches from the same text
  // This enables exploring different aspects of the same content
  
  // Add the selection
  this.selectionRanges.push({
    start,
    end,
    selectedText,
    branchNodeId
  });
  
  await this.save();
  return this;
};

// Method to add image attachment
messageSchema.methods.addImageAttachment = async function(imageData) {
  const { 
    type, 
    s3Key, 
    s3Url, 
    fileName, 
    fileSize, 
    mimeType, 
    dimensions = {}, 
    metadata = {} 
  } = imageData;
  
  // Validate required fields (s3Url is optional for local storage)
  if (!type || !s3Key || !fileName || !fileSize || !mimeType) {
    throw new Error('Missing required image data fields');
  }
  
  // Validate type
  if (!['user_upload', 'ai_generated', 'ai_edited'].includes(type)) {
    throw new Error('Invalid image attachment type');
  }
  
  // Add the image attachment
  this.imageAttachments.push({
    type,
    s3Key,
    s3Url,
    fileName,
    fileSize,
    mimeType,
    dimensions,
    metadata: {
      ...metadata,
      uploadedAt: new Date()
    }
  });
  
  // Update message type if it was just text
  if (this.messageType === 'text') {
    this.messageType = type === 'user_upload' ? 'image_upload' : 'image_generation';
  } else if (this.messageType !== 'mixed') {
    this.messageType = 'mixed';
  }
  
  await this.save();
  return this;
};

// Method to add a video attachment (pending status on job submission)
messageSchema.methods.addVideoAttachment = async function(videoData) {
  const { jobId, modelId, duration, aspectRatio, style, composition, mode } = videoData;
  if (!jobId) throw new Error('jobId is required for video attachment');
  this.videoAttachments.push({ jobId, status: 'pending', modelId, duration, aspectRatio, style, composition, mode: mode || 'text' });
  if (this.messageType === 'text') this.messageType = 'video_generation';
  else if (this.messageType !== 'mixed') this.messageType = 'mixed';
  await this.save();
  return this;
};

// Method to update video attachment after polling completes
messageSchema.methods.updateVideoAttachment = async function(jobId, fields) {
  const attachment = this.videoAttachments.find(v => v.jobId === jobId);
  if (!attachment) throw new Error(`Video attachment ${jobId} not found on message`);
  Object.assign(attachment, fields);
  await this.save();
  return this;
};

// Method to edit message content
messageSchema.methods.editContent = async function(newContent, reason = 'User edit') {
  if (this.isDeleted) {
    throw new Error('Cannot edit deleted message');
  }
  
  // Save current content to edit history
  this.editHistory.push({
    content: this.content,
    reason
  });
  
  // Update content
  if (!this.originalContent) {
    this.originalContent = this.content;
  }
  this.content = newContent;
  this.isEdited = true;
  
  await this.save();
  return this;
};

// Method to soft delete message
messageSchema.methods.softDelete = async function() {
  this.isDeleted = true;
  await this.save();
  return this;
};

// Static method to create a new message with token tracking
messageSchema.statics.createWithTokens = async function(data) {
  const {
    graphId,
    nodeId,
    userId,
    role,
    content,
    tokensUsed = 0,
    tokenTransactionId,
    geminiMetadata = {},
    imageAttachments = []
  } = data;
  
  // Check if MongoDB supports transactions
  const useTransactions = process.env.NODE_ENV === 'production' || process.env.USE_TRANSACTIONS === 'true';
  
  if (useTransactions) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Get the next sequence number for this node
      const lastMessage = await this.findOne({ nodeId })
        .sort({ sequenceNumber: -1 })
        .session(session);
      
      const sequenceNumber = lastMessage ? lastMessage.sequenceNumber + 1 : 1;
      
      // Create the message
      const message = await this.create([{
        graphId,
        nodeId,
        userId,
        role,
        content,
        tokensUsed,
        tokenTransactionId,
        sequenceNumber,
        geminiMetadata,
        imageAttachments: imageAttachments || []
      }], { session });
      
      // Update node and tree statistics
      const ChatNode = mongoose.model('ChatNode');
      const ChatTree = mongoose.model('ChatTree');
      
      await ChatNode.findByIdAndUpdate(
        nodeId,
        { 
          $inc: { messageCount: 1 },
          lastActivity: new Date()
        },
        { session }
      );
      
      await ChatTree.findByIdAndUpdate(
        graphId,
        { 
          $inc: { totalMessages: 1 },
          lastActivity: new Date()
        },
        { session }
      );
      
      await session.commitTransaction();
      return message[0];
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } else {
    // Fallback for local development without replica set
    try {
      // Get the next sequence number for this node
      const lastMessage = await this.findOne({ nodeId })
        .sort({ sequenceNumber: -1 });
      
      const sequenceNumber = lastMessage ? lastMessage.sequenceNumber + 1 : 1;
      
      // Create the message
      const message = await this.create({
        graphId,
        nodeId,
        userId,
        role,
        content,
        tokensUsed,
        tokenTransactionId,
        sequenceNumber,
        geminiMetadata,
        imageAttachments: imageAttachments || []
      });
      
      // Update node and tree statistics
      const ChatNode = mongoose.model('ChatNode');
      const ChatTree = mongoose.model('ChatTree');
      
      await ChatNode.findByIdAndUpdate(
        nodeId,
        { 
          $inc: { messageCount: 1 },
          lastActivity: new Date()
        }
      );
      
      await ChatTree.findByIdAndUpdate(
        graphId,
        { 
          $inc: { totalMessages: 1 },
          lastActivity: new Date()
        }
      );
      
      return message;
    } catch (error) {
      throw error;
    }
  }
};

// Static method to get conversation history for a node
messageSchema.statics.getNodeHistory = async function(nodeId, options = {}) {
  const {
    limit = 50,
    offset = 0,
    includeDeleted = false
  } = options;
  
  const query = { nodeId };
  if (!includeDeleted) {
    query.isDeleted = false;
  }
  
  return await this.find(query)
    .sort({ sequenceNumber: 1 })
    .skip(offset)
    .limit(limit)
    .populate('tokenTransactionId', 'amount action createdAt')
    .exec();
};

// Static method to get messages for text selection
messageSchema.statics.getSelectableMessages = async function(nodeId) {
  return await this.find({
    nodeId,
    isSelectable: true,
    isDeleted: false,
    role: { $in: ['user', 'assistant'] } // Only user and assistant messages are selectable
  })
  .sort({ sequenceNumber: 1 })
  .select('content encryptedContent selectionRanges createdAt sequenceNumber')
  .exec();
};

// Static method to search messages
messageSchema.statics.searchMessages = async function(userId, query, options = {}) {
  const {
    graphId = null,
    limit = 20,
    offset = 0
  } = options;
  
  const searchQuery = {
    userId,
    isDeleted: false,
    content: { $regex: query, $options: 'i' }
  };
  
  if (graphId) {
    searchQuery.graphId = graphId;
  }
  
  return await this.find(searchQuery)
    .sort({ createdAt: -1 })
    .skip(offset)
    .limit(limit)
    .populate('nodeId', 'summary')
    .populate('graphId', 'title')
    .exec();
};

// Pre-save middleware to validate content
messageSchema.pre('save', function(next) {
  // E2EE fence: the legacy plaintext `content` field is read-only — any new
  // or modified save nulls it out. Encrypted variants (`encryptedContent`)
  // are the only persistent surface for message bodies.
  if (this.isNew || this.isModified('content')) this.content = null;

  // Non-deleted messages must have either encrypted content or attachments
  // (image-only / file-only turns legitimately omit a body).
  const hasEncrypted = !!this.encryptedContent;
  const hasAttachments =
    (this.imageAttachments && this.imageAttachments.length > 0) ||
    (this.videoAttachments && this.videoAttachments.length > 0) ||
    (this.fileAttachments && this.fileAttachments.length > 0);
  if (!this.isDeleted && !hasEncrypted && !hasAttachments) {
    return next(new Error('Message content cannot be empty'));
  }

  // Update gemini metadata totals
  if (this.geminiMetadata.promptTokens && this.geminiMetadata.completionTokens) {
    this.geminiMetadata.totalTokens = this.geminiMetadata.promptTokens + this.geminiMetadata.completionTokens;
  }

  next();
});

// Enable virtuals when converting to JSON
messageSchema.set('toJSON', { virtuals: true });
messageSchema.set('toObject', { virtuals: true });

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;