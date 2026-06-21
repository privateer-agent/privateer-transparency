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

// Encrypted canvas snapshot pointer. Defined as its own sub-schema so the
// path is simply ABSENT until a thumbnail is stored — avoids Mongoose
// auto-creating an empty `{ storageType: null }` that fails enum validation
// on every graph create.
const thumbnailSchema = new mongoose.Schema(
  {
    storageType: { type: String, enum: ['cloud', 'local'], required: true },
    s3Key:       { type: String, default: null },
    storageRef:  { type: String, default: null }, // local-backend fileId
    encIv:       { type: String, default: null },
    updatedAt:   { type: Date,   default: null }
  },
  { _id: false }
);

const chatGraphSchema = new mongoose.Schema(
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
      // Not required — encrypted graphs use encryptedTitle
    },
    // E2EE: encrypted graph title. JSON string: { "iv": "<base64>", "ct": "<base64>" }
    encryptedTitle: { type: String, default: null },
    description: {
      type: String,
      trim: true,
      maxlength: 500
    },
    // Entry nodes - multiple starting points for the graph
    entryNodeIds: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatNode'
    }],
    // Legacy support - link to original tree if migrated
    migratedFromTreeId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ChatTree',
      default: null
    },
    isActive: {
      type: Boolean,
      default: true
    },
    totalNodes: {
      type: Number,
      default: 0,
      min: 0
    },
    totalEdges: {
      type: Number,
      default: 0,
      min: 0
    },
    totalMessages: {
      type: Number,
      default: 0,
      min: 0
    },
    lastActivity: {
      type: Date,
      default: Date.now
    },
    tokensUsed: {
      type: Number,
      default: 0,
      min: 0
    },
    // Graph visualization settings
    viewSettings: {
      defaultZoom: {
        type: Number,
        default: 1,
        min: 0.1,
        max: 5
      },
      centerPosition: {
        x: { type: Number, default: 0 },
        y: { type: Number, default: 0 }
      },
      gridEnabled: {
        type: Boolean,
        default: false
      },
      snapToGrid: {
        type: Boolean,
        default: false
      },
      gridSize: {
        type: Number,
        default: 20
      }
    },
    projectId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      default: null,
      index: true
    },
    // Encrypted canvas snapshot used as the chart thumbnail. The binary is
    // E2EE-encrypted client-side; the server only stores the pointer + IV.
    // Absent until the first snapshot is captured.
    thumbnail: { type: thumbnailSchema, default: undefined },
    tags: [{
      type: String,
      trim: true,
      maxlength: 30
    }],
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
chatGraphSchema.index({ userId: 1, createdAt: -1 });
chatGraphSchema.index({ userId: 1, lastActivity: -1 });
chatGraphSchema.index({ isActive: 1, lastActivity: -1 });
chatGraphSchema.index({ tags: 1 });

// Virtual for graph statistics
chatGraphSchema.virtual('graphStats').get(function() {
  return {
    nodeCount: this.totalNodes,
    edgeCount: this.totalEdges,
    messageCount: this.totalMessages,
    entryPoints: this.entryNodeIds ? this.entryNodeIds.length : 0,
    tokensUsed: this.tokensUsed
  };
});

// Method to update graph statistics
chatGraphSchema.methods.updateStats = async function() {
  const ChatNode = mongoose.model('ChatNode');
  const ChatEdge = mongoose.model('ChatEdge');
  const Message = mongoose.model('Message');
  
  try {
    // Count total nodes in this graph
    const nodeCount = await ChatNode.countDocuments({ graphId: this._id, isActive: true });
    
    // Count total edges in this graph
    const edgeCount = await ChatEdge.countDocuments({ graphId: this._id, isActive: true });
    
    // Count total messages in this graph (via nodes)
    const nodes = await ChatNode.find({ graphId: this._id, isActive: true }).select('_id');
    const nodeIds = nodes.map(n => n._id);
    const messageCount = await Message.countDocuments({ nodeId: { $in: nodeIds } });
    
    // Update statistics
    this.totalNodes = nodeCount;
    this.totalEdges = edgeCount;
    this.totalMessages = messageCount;
    this.lastActivity = new Date();
    
    await this.save();
    return this;
  } catch (error) {
    logger.error('Error updating graph stats:', error);
    throw error;
  }
};

// Method to add an entry node
chatGraphSchema.methods.addEntryNode = async function(nodeId) {
  if (!this.entryNodeIds.includes(nodeId)) {
    this.entryNodeIds.push(nodeId);
    await this.save();
  }
  return this;
};

// Method to remove an entry node
chatGraphSchema.methods.removeEntryNode = async function(nodeId) {
  this.entryNodeIds = this.entryNodeIds.filter(id => !id.equals(nodeId));
  await this.save();
  return this;
};

// Method to get full graph structure (nodes + edges)
chatGraphSchema.methods.getFullStructure = async function() {
  const ChatNode = mongoose.model('ChatNode');
  const ChatEdge = mongoose.model('ChatEdge');
  
  const nodes = await ChatNode.find({ graphId: this._id, isActive: true })
    .select('messageCount nodeType visualMetadata connectedEdgeIds lastActivity prompt aiResponse encryptedPrompt encryptedAiResponse encryptedSources encryptedResearchTrail encryptedNoteBody imageUrl imageAttachments videoAttachments fileAttachments modelId')
    .exec();
    
  const edges = await ChatEdge.find({ graphId: this._id, isActive: true })
    .select('sourceNodeId targetNodeId edgeType label visualMetadata')
    .exec();
    
  return {
    graph: this,
    nodes,
    edges
  };
};

// Static method to create a new graph with an optional initial entry node.
// E2EE: the `title` arg is ignored as a persisted field — the encrypted title
// is the only stored surface. `title` is still consumed for the entry node's
// summary heading at creation time (caller has the plaintext in scope).
chatGraphSchema.statics.createNewGraph = async function(data) {
  const { userId, title, encryptedTitle, description, initialPosition = { x: 0, y: 0 }, skipEntryNode = false, projectId = null } = data;

  try {
    const ChatNode = mongoose.model('ChatNode');

    // Create the graph first (no nodes by default if skipEntryNode is true)
    const chatGraph = await this.create({
      userId,
      title: null,
      encryptedTitle: encryptedTitle || null,
      description: description || '',
      entryNodeIds: [],
      totalNodes: skipEntryNode ? 0 : 1,
      isActive: true,
      projectId: projectId || null,
    });

    logger.debug('[ChatGraph Model] Graph created with isActive:', chatGraph.isActive, 'skipEntryNode:', skipEntryNode);

    // Skip creating entry node if requested (for blank slate graphs)
    if (skipEntryNode) {
      return { graph: chatGraph, entryNode: null };
    }

    // Create the initial entry node
    const entryNode = await ChatNode.create({
      graphId: chatGraph._id,
      userId,
      nodeType: 'entry',
      summary: title || 'Start Here',
      detailedSummary: description || 'This is the entry point of your graph. Start a conversation here or create more nodes.',
      visualMetadata: {
        position: initialPosition,
        color: '#10B981', // Green for entry nodes
        nodeSize: 'medium'
      }
    });
    
    // Add entry node to graph
    chatGraph.entryNodeIds.push(entryNode._id);
    await chatGraph.save();
    
    return { graph: chatGraph, entryNode };
  } catch (error) {
    logger.error('Error in createNewGraph:', error);
    throw error;
  }
};

// Static method to migrate a tree to a graph
chatGraphSchema.statics.migrateFromTree = async function(treeId, userId) {
  const ChatTree = mongoose.model('ChatTree');
  const ChatNode = mongoose.model('ChatNode');
  const ChatEdge = mongoose.model('ChatEdge');

  try {
    // Get the original tree
    const tree = await ChatTree.findById(treeId);
    if (!tree) {
      throw new Error('Tree not found');
    }

    // Create new graph
    const graph = await this.create({
      userId,
      title: tree.title,
      description: tree.description,
      migratedFromTreeId: treeId,
      totalMessages: tree.totalMessages,
      tokensUsed: tree.tokensUsed,
      tags: tree.tags
    });
    
    // Get all nodes from the tree
    const treeNodes = await ChatNode.find({ treeId: treeId });
    
    // Map old node IDs to new graph IDs
    const nodeIdMap = new Map();
    
    // Update all nodes to reference the graph and calculate positions
    for (const node of treeNodes) {
      // Update node to reference graph
      node.graphId = graph._id;
      
      // Convert depth-based position to radial layout
      const angle = (node.depth - 1) * (Math.PI / 4); // Spread based on depth
      const radius = (node.depth - 1) * 200;
      
      // Add some randomness to avoid overlapping
      const childIndex = node.parentNodeId ? 
        treeNodes.filter(n => n.parentNodeId?.toString() === node.parentNodeId?.toString())
          .findIndex(n => n._id.toString() === node._id.toString()) : 0;
      
      const spreadAngle = angle + (childIndex * 0.5);
      
      node.visualMetadata.position = {
        x: Math.cos(spreadAngle) * radius,
        y: Math.sin(spreadAngle) * radius
      };
      
      // Update node type for root
      if (node.nodeType === 'root') {
        node.nodeType = 'entry';
        graph.entryNodeIds.push(node._id);
      }
      
      await node.save();
      nodeIdMap.set(node._id.toString(), node._id);
    }
    
    // Create edges from parent-child relationships
    let edgeCount = 0;
    for (const node of treeNodes) {
      if (node.parentNodeId) {
        try {
          const edge = await ChatEdge.create({
            graphId: graph._id,
            userId,
            sourceNodeId: node.parentNodeId,
            targetNodeId: node._id,
            edgeType: 'bidirectional'
          });
          
          // Add edge to both nodes
          await ChatNode.findByIdAndUpdate(node.parentNodeId, {
            $addToSet: { connectedEdgeIds: edge._id }
          });
          await ChatNode.findByIdAndUpdate(node._id, {
            $addToSet: { connectedEdgeIds: edge._id }
          });
          
          edgeCount++;
        } catch (edgeError) {
          logger.error('Error creating edge during migration:', edgeError);
        }
      }
    }
    
    // Update graph stats
    graph.totalNodes = treeNodes.length;
    graph.totalEdges = edgeCount;
    await graph.save();
    
    return graph;
  } catch (error) {
    logger.error('Error migrating tree to graph:', error);
    throw error;
  }
};

// Static method to get user's graphs with pagination
chatGraphSchema.statics.getUserGraphs = async function(userId, options = {}) {
  const {
    page = 1,
    limit = 10,
    sortBy = 'lastActivity',
    sortOrder = 'desc',
    isActive = true
  } = options;

  const skip = (page - 1) * limit;
  const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

  if (!userId) throw new Error('userId is required for getUserGraphs');
  const query = { userId };
  if (isActive !== undefined) {
    query.isActive = isActive;
  }
  
  const graphs = await this.find(query)
    .sort(sort)
    .skip(skip)
    .limit(limit)
    .populate('entryNodeIds', 'summary detailedSummary')
    .populate('projectId', 'encryptedName encryptedInstructions iconType iconValue iconColor')
    .exec();
    
  const totalCount = await this.countDocuments(query);
  
  return {
    graphs,
    pagination: {
      currentPage: page,
      totalPages: Math.ceil(totalCount / limit),
      totalCount,
      hasNext: page * limit < totalCount,
      hasPrev: page > 1
    }
  };
};

// Pre-save middleware to update lastActivity
chatGraphSchema.pre('save', function(next) {
  if (this.isModified() && !this.isModified('lastActivity')) {
    this.lastActivity = new Date();
  }
  // E2EE fence: legacy plaintext `title` is read-only — null it on any save.
  if (this.isNew || this.isModified('title')) this.title = null;
  next();
});

// Enable virtuals when converting to JSON
chatGraphSchema.set('toJSON', { virtuals: true });
chatGraphSchema.set('toObject', { virtuals: true });

const ChatGraph = mongoose.model('ChatGraph', chatGraphSchema);

module.exports = ChatGraph;
