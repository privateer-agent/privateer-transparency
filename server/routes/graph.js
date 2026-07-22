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
const router = express.Router();

const graphController = require('../controllers/graphController');
const nodeFileController = require('../controllers/nodeFileController');
const { authenticate } = require('../middleware/auth');
const { requireCreate, requireCloudBackend, requireStorage } = require('../middleware/entitlement');

router.use(authenticate);

// ==================== GRAPH ROUTES ====================

// Create a new graph
router.post('/create', requireCreate('graph'), graphController.createGraph);

// Get all graphs for the current user
router.get('/list', graphController.getUserGraphs);

// Paginated lists — chats and graphs are returned as separate streams
router.get('/chats', graphController.getChats);
router.get('/graphs', graphController.getGraphs);

// Get a specific graph with full structure
router.get('/:graphId', graphController.getGraph);

// Update graph metadata
router.patch('/:graphId', graphController.updateGraph);

// Delete a graph (soft delete)
router.delete('/:graphId', graphController.deleteGraph);

// ==================== NODE ROUTES ====================

// Create a node at a specific position
router.post('/:graphId/nodes', graphController.createNode);

// Get a specific node with connections
router.get('/:graphId/nodes/:nodeId', graphController.getNode);

// Update node position
router.patch('/:graphId/nodes/:nodeId/position', graphController.updateNodePosition);

// Update an embedded videoAttachment on a node (poller swaps pending → completed)
router.patch('/:graphId/nodes/:nodeId/video-attachment/:jobId', graphController.updateNodeVideoAttachment);

// Update node metadata
router.patch('/:graphId/nodes/:nodeId', graphController.updateNode);

// Delete a node
router.delete('/:graphId/nodes/:nodeId', graphController.deleteNode);

// ==================== NODE FILE ROUTES ====================

// Stage an encrypted file in S3 (returns s3Key for embedding in fileAttachments)
// requireStorage() bounds these against the tier cap from Content-Length, the
// same way chat's upload-image/upload-file are bounded. Without it the Boards
// media path incremented cloudStorageBytes but was never checked against it —
// so the cap wasn't a cap, and nodeFileController's STORAGE_FULL handling was
// unreachable.
router.post('/:graphId/files', requireCloudBackend(), requireStorage(), nodeFileController.uploadNodeFile);

// Stage an encrypted video in S3 (returns s3Key for embedding in videoAttachments)
router.post('/:graphId/videos', requireCloudBackend(), requireStorage(), nodeFileController.uploadNodeVideo);

// Download the encrypted blob for a file attached to a node
router.get('/:graphId/nodes/:nodeId/files/:fileId/content', nodeFileController.getNodeFileContent);

// Remove a single file from a node
router.delete('/:graphId/nodes/:nodeId/files/:fileId', nodeFileController.deleteNodeFile);

// ==================== GRAPH THUMBNAIL ROUTES ====================

// Stage an encrypted canvas snapshot in S3 (cloud backend)
//
// Deliberately NOT gated on requireStorage(), unlike the file/video routes
// above. This is a replace-in-place: the controller deletes the previous
// snapshot before uploading the new one, so net growth is ~zero and total
// growth is bounded at one small object per graph (and graphs are already
// capped by maxGraphs). Gating it would mean a user sitting exactly at their
// cap could never refresh a board thumbnail again — a permanently stale-looking
// board list — while freeing no space, since the check runs before the delete.
router.post('/:graphId/thumbnail', requireCloudBackend(), nodeFileController.uploadGraphThumbnail);

// Record an on-device thumbnail pointer (local backend)
router.patch('/:graphId/thumbnail-ref', nodeFileController.setGraphThumbnailRef);

// Stream the encrypted snapshot ciphertext (cloud backend)
router.get('/:graphId/thumbnail/content', nodeFileController.getGraphThumbnailContent);

// ==================== EDGE ROUTES ====================

// Create an edge between two nodes
router.post('/:graphId/edges', graphController.createEdge);

// Get all edges for a graph
router.get('/:graphId/edges', graphController.getEdges);

// Update an edge
router.patch('/:graphId/edges/:edgeId', graphController.updateEdge);

// Delete an edge
router.delete('/:graphId/edges/:edgeId', graphController.deleteEdge);

// ==================== NODE MESSAGE ROUTES ====================

// Get message history for a node
router.get('/:graphId/nodes/:nodeId/messages', graphController.getNodeMessages);

// Save a message to a node's history
router.post('/:graphId/nodes/:nodeId/messages', graphController.addNodeMessage);

// ==================== BATCH OPERATIONS ====================

// Batch update node positions
router.post('/:graphId/batch/positions', graphController.batchUpdatePositions);

// ==================== MIGRATION ====================

// Migrate a tree to a graph
router.post('/migrate/:treeId', graphController.migrateTreeToGraph);

// ==================== STANDALONE CHAT ROUTES ====================

// Create a new chat (on first message)
router.post('/chat/create', graphController.createChat);

// Get a specific chat
router.get('/chat/:chatId', graphController.getChat);

// Add message to existing chat
router.post('/chat/:chatId/message', graphController.addMessageToChat);

// Update an embedded videoAttachment by jobId (polling completion)
router.patch('/chat/:chatId/video-attachment/:jobId', graphController.updateChatVideoAttachment);

// Update chat metadata (pinned, projectId)
router.patch('/chat/:chatId', graphController.updateChat);

// Delete a chat (soft delete)
router.delete('/chat/:chatId', graphController.deleteChat);

module.exports = router;
