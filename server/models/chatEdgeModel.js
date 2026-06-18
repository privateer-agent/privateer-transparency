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

const chatEdgeSchema = new mongoose.Schema(
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
    sourceNodeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatNode',
      required: true,
      index: true
    },
    targetNodeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatNode',
      required: true,
      index: true
    },
    edgeType: {
      type: String,
      enum: ['bidirectional', 'directional'],
      default: 'bidirectional',
      required: true
    },
    label: {
      type: String,
      trim: true,
      maxlength: 100,
      default: ''
    },
    // Visual styling for the edge
    visualMetadata: {
      color: {
        type: String,
        default: '#4F46E5'
      },
      strokeWidth: {
        type: Number,
        default: 2,
        min: 1,
        max: 10
      },
      style: {
        type: String,
        enum: ['solid', 'dashed', 'dotted'],
        default: 'solid'
      },
      // Control points for bezier curves (optional)
      controlPoints: [{
        x: { type: Number },
        y: { type: Number }
      }]
    },
    isActive: {
      type: Boolean,
      default: true
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

// Compound indexes for efficient edge queries
chatEdgeSchema.index({ graphId: 1, sourceNodeId: 1 });
chatEdgeSchema.index({ graphId: 1, targetNodeId: 1 });
chatEdgeSchema.index({ sourceNodeId: 1, targetNodeId: 1 }, { unique: true });

// Virtual for getting both connected nodes
chatEdgeSchema.virtual('connectedNodes').get(function() {
  return [this.sourceNodeId, this.targetNodeId];
});

// Virtual for edge data (for API responses)
chatEdgeSchema.virtual('edgeData').get(function() {
  return {
    id: this._id,
    source: this.sourceNodeId,
    target: this.targetNodeId,
    type: this.edgeType,
    label: this.label,
    visual: this.visualMetadata
  };
});

// Static method to create an edge between two nodes
chatEdgeSchema.statics.createEdge = async function(graphId, userId, sourceNodeId, targetNodeId, options = {}) {
  const { edgeType = 'bidirectional', label = '', visualMetadata = {} } = options;
  
  // Check if edge already exists (in either direction for bidirectional)
  const existingEdge = await this.findOne({
    graphId,
    $or: [
      { sourceNodeId, targetNodeId },
      { sourceNodeId: targetNodeId, targetNodeId: sourceNodeId }
    ]
  });
  
  if (existingEdge) {
    throw new Error('Edge already exists between these nodes');
  }
  
  const edge = await this.create({
    graphId,
    userId,
    sourceNodeId,
    targetNodeId,
    edgeType,
    label,
    visualMetadata: {
      ...visualMetadata
    }
  });
  
  // Update the connected nodes to include this edge reference
  const ChatNode = mongoose.model('ChatNode');
  await Promise.all([
    ChatNode.findByIdAndUpdate(sourceNodeId, {
      $addToSet: { connectedEdgeIds: edge._id }
    }),
    ChatNode.findByIdAndUpdate(targetNodeId, {
      $addToSet: { connectedEdgeIds: edge._id }
    })
  ]);
  
  return edge;
};

// Static method to get all edges for a graph
chatEdgeSchema.statics.getEdgesForGraph = async function(graphId) {
  return this.find({ graphId, isActive: true })
    .populate('sourceNodeId', 'summary visualMetadata')
    .populate('targetNodeId', 'summary visualMetadata')
    .exec();
};

// Static method to get all edges connected to a specific node
chatEdgeSchema.statics.getEdgesForNode = async function(nodeId) {
  return this.find({
    isActive: true,
    $or: [
      { sourceNodeId: nodeId },
      { targetNodeId: nodeId }
    ]
  }).exec();
};

// Static method to delete an edge and update connected nodes
chatEdgeSchema.statics.deleteEdge = async function(edgeId) {
  const edge = await this.findById(edgeId);
  if (!edge) {
    throw new Error('Edge not found');
  }
  
  // Remove edge reference from connected nodes
  const ChatNode = mongoose.model('ChatNode');
  await Promise.all([
    ChatNode.findByIdAndUpdate(edge.sourceNodeId, {
      $pull: { connectedEdgeIds: edge._id }
    }),
    ChatNode.findByIdAndUpdate(edge.targetNodeId, {
      $pull: { connectedEdgeIds: edge._id }
    })
  ]);
  
  // Soft delete the edge
  edge.isActive = false;
  await edge.save();
  
  return edge;
};

// Pre-save validation to ensure nodes exist and belong to the same graph
chatEdgeSchema.pre('save', async function(next) {
  if (this.isNew) {
    const ChatNode = mongoose.model('ChatNode');
    const [sourceNode, targetNode] = await Promise.all([
      ChatNode.findById(this.sourceNodeId),
      ChatNode.findById(this.targetNodeId)
    ]);
    
    if (!sourceNode || !targetNode) {
      throw new Error('Source or target node not found');
    }
    
    if (sourceNode.graphId.toString() !== this.graphId.toString() ||
        targetNode.graphId.toString() !== this.graphId.toString()) {
      throw new Error('Nodes must belong to the same graph');
    }
    
    if (this.sourceNodeId.toString() === this.targetNodeId.toString()) {
      throw new Error('Cannot create edge to self');
    }
  }
  next();
});

// Ensure virtuals are included in JSON output
chatEdgeSchema.set('toJSON', { virtuals: true });
chatEdgeSchema.set('toObject', { virtuals: true });

const ChatEdge = mongoose.model('ChatEdge', chatEdgeSchema);

module.exports = ChatEdge;
