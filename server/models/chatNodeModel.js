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
const logger = require('../utils/logger');

const chatNodeSchema = new mongoose.Schema(
  {
    graphId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatGraph',
      required: true,
      index: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    // Graph structure fields
    connectedEdgeIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatEdge'
    }],
    nodeType: {
      // 'drawing' is the canvas ink layer, not a card: one per graph, holding
      // every freehand stroke as an encrypted JSON blob on encryptedNoteBody.
      // The client renders it above the cards and keeps it out of the node
      // array entirely (see InkLayer), so it never lays out, drags, or counts.
      type: String,
      enum: ['entry', 'standard', 'note', 'file', 'drawing'],
      default: 'standard',
      required: true
    },
    // Graph node prompt/response fields
    prompt: {
      type: String,
      trim: true
      // Not required — encrypted nodes use encryptedPrompt
    },
    aiResponse: {
      type: String,
      trim: true
      // Not required — encrypted nodes use encryptedAiResponse
    },
    // E2EE fields — JSON strings: { "iv": "<base64>", "ct": "<base64>" }
    encryptedPrompt: { type: String, default: null },
    encryptedAiResponse: { type: String, default: null },
    encryptedSources: { type: String, default: null },
    // E2EE: encrypted Deep Research step trail (JSON array of {stage,label,query?,sources?,gap?,at}).
    // Plaintext contains user queries and lines of inquiry, so it's encrypted client-side
    // alongside the AI response. Include in any projection that returns node content.
    encryptedResearchTrail: { type: String, default: null },
    // E2EE: encrypted Visual-mode media ({images:[],videos:[]}) — see chatModel.
    encryptedMedia: { type: String, default: null },
    // E2EE: encrypted live weather snapshot (open-meteo) attached to weather-intent
    // assistant responses. Decrypts to the WeatherData JSON shape consumed by WeatherCard.
    encryptedWeatherData: { type: String, default: null },
    // Note nodes: encrypted markdown body (user-authored content, no AI inference)
    encryptedNoteBody: { type: String, default: null },
    // E2EE: a short description of whatever picture or clip this node carries,
    // written once when the media landed on the chart (client-side vision call)
    // so that branches off the node have something true to reason from — the
    // ancestor walk that builds a child's context can only read text, and an
    // uploaded photo has none. User content, so ciphertext only.
    encryptedMediaDescription: { type: String, default: null },
    // File attachments for file/note nodes — binaries are stored either in S3 (cloud)
    // or on-device (local); only encrypted metadata/refs live here.
    fileAttachments: [{
      fileType:          { type: String, enum: ['text', 'pdf', 'docx', 'csv', 'code', 'audio', 'video'] },
      storageType:       { type: String, enum: ['cloud', 'local'], default: 'cloud' },
      s3Key:             { type: String, default: '' },
      s3Url:             { type: String, default: '' },
      storageRef:        { type: String, default: null },
      // E2EE: encrypted { filename, mimeType, size, fileType } JSON string
      encryptedMetadata: { type: String, default: null },
      // IV for decrypting the file binary
      encIv:             { type: String, default: null },
      encryptedSize:     { type: Number },
      fileSize:          { type: Number },
      createdAt:         { type: Date, default: Date.now },
    }],
    // Image fields for AI-generated images
    imageUrl: {
      type: String,
      trim: true
    },
    imageAttachments: [{
      type: { type: String, enum: ['user_upload', 'ai_generated', 'ai_edited'] },
      // Canonical key field — matches Message and Chat models.
      // Legacy documents may have this stored as `storageRef`.
      s3Key: {
        type: String,
        get: function(v) { return v || this.storageRef || ''; }
      },
      s3Url: { type: String, default: '' },
      storageType: { type: String, enum: ['cloud', 'local'], default: 'cloud' },
      // E2EE: encrypted { fileName, mimeType, size, prompt } JSON string
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
        originalImage: {
          s3Key: { type: String },
          s3Url: { type: String, default: '' },
          fileName: { type: String },
          // E2EE: encrypted { fileName, mimeType, prompt } JSON for the original
          // image so the modal can show a real title under "View original".
          encryptedMetadata: { type: String, default: null },
          encIv: { type: String, default: null }
        }
      },
      // Soft-delete: image removed from library but message preserved in node history
      deleted: { type: Boolean, default: false },
    }],
    // AI-generated video attachments — mirrors messageModel videoAttachments
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
      mode:              { type: String, enum: ['text', 'imageToVideo', 'startEndFrame', 'reference'], default: 'text' },
      errorMessage:      { type: String, default: null },
      // Soft-delete: video removed from library but attachment preserved in node history
      deleted:           { type: Boolean, default: false },
      createdAt:         { type: Date, default: Date.now },
    }],
    // Connection creation context
    selectedText: {
      type: String,
      trim: true,
      maxlength: 500
    },
    selectedMessageId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Message',
      default: null
    },
    selectionStartIndex: {
      type: Number,
      default: null
    },
    selectionEndIndex: {
      type: Number,
      default: null
    },
    connectionContext: {
      type: String,
      trim: true,
      maxlength: 200
    },
    messageCount: {
      type: Number,
      default: 0,
      min: 0
    },
    lastActivity: {
      type: Date,
      default: Date.now,
      index: true
    },
    isActive: {
      type: Boolean,
      default: true
    },
    // Visualization metadata for graph rendering
    visualMetadata: {
      nodeSize: {
        type: String,
        enum: ['small', 'medium', 'large'],
        default: 'medium'
      },
      position: {
        x: { type: Number, default: 0 },
        y: { type: Number, default: 0 }
      },
      color: {
        type: String,
        default: '#4F46E5'
      },
      width: {
        type: Number,
        default: 220
      },
      height: {
        type: Number,
        default: 120
      },
      // True once the user has dragged the card's corner grip. Node creation
      // seeds a nominal width/height, so those numbers alone can't tell a real
      // resize from a default — this flag is what tells the client the stored
      // box is deliberate and the card should stop hugging its content.
      userSized: {
        type: Boolean,
        default: false
      },
      emoji: {
        type: String,
        default: ''
      },
      promptVisible: {
        type: Boolean,
        default: true
      },
      // Body-text size multiplier chosen by resizing the card. A wider/taller
      // card scales its content up so a resized node reads as full rather than
      // sparse. Persisted (not derivable from width/height alone) so the scale
      // survives reloads. 1 = default content size.
      fontScale: {
        type: Number,
        default: 1
      },
      // Composer mode pill the node was created with (Create Image / Create
      // Video / Deep Research / Multi-Node). '' → plain prompt, no pill.
      modePill: {
        type: String,
        enum: ['', 'image', 'video', 'research', 'multi'],
        default: ''
      },
      // How the client renders the AI response: '' / 'markdown' (default) or
      // 'html' (a model-authored rich-HTML fragment). Non-content metadata.
      renderMode: {
        type: String,
        enum: ['', 'markdown', 'html'],
        default: ''
      },
      // A dropped sprite sheet's animation grid, so the card can PLAY the sheet
      // rather than show it as one flat picture of a dozen poses.
      //
      // Plaintext, and deliberately: this is the same fence libraryFileModel
      // draws around a sprite row, for the same reason — a sprite animates, so
      // the renderer needs the cell size and the frame rate before it can
      // decrypt anything. Nothing here says what the sprite IS; the name, the
      // prompt and the facing list stay sealed in the bundle's own metadata.
      // Absent → the node is an ordinary picture, which is what a sheet was
      // before this existed.
      sprite: {
        type: {
          frameCount: { type: Number },
          frameWidth: { type: Number },
          frameHeight: { type: Number },
          columns: { type: Number },
          rows: { type: Number },
          fps: { type: Number },
          loop: { type: Boolean },
          directionCount: { type: Number },
          animIndex: { type: Number }
        },
        default: null,
        _id: false
      }
    },
    // Token usage tracking
    tokensUsed: {
      type: Number,
      default: 0,
      min: 0
    },
    // Resolved model id that produced this node's AI response (e.g. "near/…",
    // "openai/gpt-4o"). Non-sensitive metadata — NOT user content — so stored
    // plaintext; drives the client ZDR/TEE privacy shield on the node card.
    modelId: {
      type: String,
      default: null
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
chatNodeSchema.index({ graphId: 1 });
chatNodeSchema.index({ userId: 1, lastActivity: -1 });
chatNodeSchema.index({ isActive: 1, lastActivity: -1 });
// Storage-handle lookups — see the matching indexes on messageModel.
chatNodeSchema.index({ userId: 1, 'imageAttachments.s3Key': 1 });
chatNodeSchema.index({ userId: 1, 'videoAttachments.storageRef': 1 });

// Virtual for connection creation summary
chatNodeSchema.virtual('connectionOrigin').get(function() {
  if (!this.selectedText) return null;
  
  return {
    selectedText: this.selectedText,
    sourceMessageId: this.selectedMessageId,
    selectionRange: {
      start: this.selectionStartIndex,
      end: this.selectionEndIndex
    },
    context: this.connectionContext
  };
});

// Virtual for graph node data
chatNodeSchema.virtual('graphNodeData').get(function() {
  return {
    id: this._id,
    prompt: this.prompt,
    aiResponse: this.aiResponse,
    messageCount: this.messageCount,
    nodeType: this.nodeType,
    position: this.visualMetadata.position,
    size: {
      width: this.visualMetadata.width,
      height: this.visualMetadata.height
    },
    userSized: this.visualMetadata.userSized,
    fontScale: this.visualMetadata.fontScale,
    color: this.visualMetadata.color,
    sprite: this.visualMetadata.sprite || null,
    edgeCount: this.connectedEdgeIds ? this.connectedEdgeIds.length : 0,
    lastActivity: this.lastActivity,
    connectionOrigin: this.connectionOrigin,
    imageUrl: this.imageUrl,
    imageAttachments: this.imageAttachments,
    videoAttachments: this.videoAttachments,
    fileAttachments: this.fileAttachments,
    encryptedNoteBody: this.encryptedNoteBody,
    encryptedMediaDescription: this.encryptedMediaDescription
  };
});

// Method to add an edge connection
chatNodeSchema.methods.addEdge = async function(edgeId) {
  if (!this.connectedEdgeIds) {
    this.connectedEdgeIds = [];
  }
  if (!this.connectedEdgeIds.includes(edgeId)) {
    this.connectedEdgeIds.push(edgeId);
    await this.save();
  }
  return this;
};

// Method to remove an edge connection
chatNodeSchema.methods.removeEdge = async function(edgeId) {
  if (this.connectedEdgeIds) {
    this.connectedEdgeIds = this.connectedEdgeIds.filter(id => !id.equals(edgeId));
    await this.save();
  }
  return this;
};

// Method to update node position
chatNodeSchema.methods.updatePosition = async function(x, y) {
  this.visualMetadata.position.x = x;
  this.visualMetadata.position.y = y;
  await this.save();
  return this;
};

// Method to get all connected nodes via edges
chatNodeSchema.methods.getConnectedNodes = async function() {
  if (!this.connectedEdgeIds || this.connectedEdgeIds.length === 0) {
    return [];
  }
  
  const ChatEdge = mongoose.model('ChatEdge');
  const edges = await ChatEdge.find({
    _id: { $in: this.connectedEdgeIds },
    isActive: true
  });
  
  const connectedNodeIds = new Set();
  edges.forEach(edge => {
    if (edge.sourceNodeId.toString() !== this._id.toString()) {
      connectedNodeIds.add(edge.sourceNodeId.toString());
    }
    if (edge.targetNodeId.toString() !== this._id.toString()) {
      connectedNodeIds.add(edge.targetNodeId.toString());
    }
  });
  
  const ChatNode = mongoose.model('ChatNode');
  return ChatNode.find({
    _id: { $in: Array.from(connectedNodeIds) },
    isActive: true
  });
};

// Method to update node statistics
chatNodeSchema.methods.updateStats = async function() {
  const Message = mongoose.model('Message');
  
  try {
    const messageCount = await Message.countDocuments({ nodeId: this._id });
    
    this.messageCount = messageCount;
    this.lastActivity = new Date();
    
    // Update visual metadata based on activity
    if (messageCount > 20) {
      this.visualMetadata.nodeSize = 'large';
    } else if (messageCount > 5) {
      this.visualMetadata.nodeSize = 'medium';
    } else {
      this.visualMetadata.nodeSize = 'small';
    }
    
    await this.save();
    return this;
  } catch (error) {
    logger.error('Error updating node stats:', error);
    throw error;
  }
};

// Static method to create a graph node at a specific position
chatNodeSchema.statics.createGraphNode = async function(data) {
  const {
    graphId,
    userId,
    position = { x: 0, y: 0 },
    size = null,
    nodeType = 'standard',
    encryptedPrompt = null,
    encryptedAiResponse = null,
    encryptedSources = null,
    encryptedResearchTrail = null,
    encryptedMedia = null,
    encryptedWeatherData = null,
    encryptedNoteBody = null,
    encryptedMediaDescription = null,
    imageUrl = null,
    imageAttachments = null,
    videoAttachments = null,
    fileAttachments = null,
    modelId = null,
    modePill = null,
    renderMode = null,
    sprite = null
  } = data;

  const colorByType = {
    entry: '#10B981',
    standard: '#4F46E5',
    note: '#F59E0B',
    file: '#6366F1',
    // Never rendered as a card — each stroke carries its own colour.
    drawing: '#64748B'
  };

  const node = await this.create({
    graphId,
    userId,
    nodeType,
    encryptedPrompt,
    encryptedAiResponse,
    encryptedSources,
    encryptedResearchTrail,
    encryptedMedia,
    encryptedWeatherData,
    encryptedNoteBody,
    encryptedMediaDescription,
    imageUrl,
    imageAttachments: imageAttachments || [],
    videoAttachments: videoAttachments || [],
    fileAttachments: fileAttachments || [],
    modelId,
    visualMetadata: {
      position,
      color: colorByType[nodeType] || '#4F46E5',
      // Persist the card dimensions the client laid out so the graph renders
      // identically on revisit. Falls back to the legacy compact default when
      // a caller doesn't send a size.
      width: size?.width ?? 220,
      height: size?.height ?? 120,
      // Which composer pill created this node — kept through the pending →
      // finished swap so the card can keep showing it after reloads.
      modePill: typeof modePill === 'string' ? modePill : '',
      renderMode: renderMode === 'html' || renderMode === 'markdown' ? renderMode : '',
      // Already whitelisted and clamped by the controller; null for every node
      // that is not a sprite, which is nearly all of them.
      sprite: sprite || null
    }
  });
  
  // Update graph's node count
  const ChatGraph = mongoose.model('ChatGraph');
  await ChatGraph.findByIdAndUpdate(graphId, {
    $inc: { totalNodes: 1 },
    lastActivity: new Date()
  });
  
  return node;
};

// Static method to get all nodes for a graph
chatNodeSchema.statics.getNodesForGraph = async function(graphId) {
  return this.find({ graphId, isActive: true })
    .populate('connectedEdgeIds')
    .exec();
};

// Static method to get node with its graph structure
chatNodeSchema.statics.getNodeWithGraph = async function(nodeId) {
  const node = await this.findById(nodeId)
    .populate('connectedEdgeIds')
    .exec();
    
  if (!node) return null;
  
  const connectedNodes = await node.getConnectedNodes();
  
  return {
    node,
    connectedNodes
  };
};

// Pre-save middleware to update lastActivity
chatNodeSchema.pre('save', function(next) {
  if (this.isModified() && !this.isModified('lastActivity')) {
    this.lastActivity = new Date();
  }
  // E2EE fence: any new or modified write that touches the legacy plaintext
  // `prompt`/`aiResponse` fields is forced to null. The encrypted variants
  // (`encryptedPrompt`, `encryptedAiResponse`) are the only persistent
  // surface for user content. Legacy docs that already carry plaintext stay
  // readable until they're next saved.
  if (this.isNew || this.isModified('prompt')) this.prompt = null;
  if (this.isNew || this.isModified('aiResponse')) this.aiResponse = null;
  next();
});

// Enable virtuals when converting to JSON
chatNodeSchema.set('toJSON', { virtuals: true });
chatNodeSchema.set('toObject', { virtuals: true });

const ChatNode = mongoose.model('ChatNode', chatNodeSchema);

module.exports = ChatNode;
