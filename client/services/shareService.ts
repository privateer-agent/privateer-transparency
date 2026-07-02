/**
 * Share service — turns an E2EE chat/graph/cargo artifact into a public,
 * read-only snapshot.
 *
 * At share time we (the owner, holding the master key) decrypt the conversation,
 * re-encrypt every text field and media binary under a fresh 32-byte *share
 * key*, and upload only that ciphertext. The share key is placed in the share
 * URL's #fragment and never sent to the server, so the server keeps storing
 * ciphertext only while anyone with the full link can decrypt locally.
 *
 * See server/models/shareSnapshotModel.js for the storage contract.
 */

import authService from './authService';
import { getServerUrl } from '../config/environment';
import { brand } from '../config/brand';
import * as graphService from './graphService';
import { getLocalChat } from './localChatService';
import { resolveChatBackend } from './chatService';
import { readLocal } from './localStorageService';
import { getCargoContent } from './cargoService';
import type { CargoKind } from '../utils/cargoKinds';
import {
  generateShareKey,
  getMasterKey,
  wrapMasterKey,
  unwrapMasterKey,
  encryptTextWithKey,
  decryptText,
  decryptBinaryRaw,
  encryptBinaryRawWithKey,
  shareKeyToFragment,
  isMasterKeyLoaded,
} from './cryptoService';

const req = (endpoint: string, options: RequestInit = {}): Promise<Response> =>
  authService.makeAuthenticatedRequest(endpoint, options);

export type ShareSourceType = 'chat' | 'graph' | 'cargo';
export type ShareSourceBackend = 'cloud' | 'local';

export interface ShareSource {
  type: ShareSourceType;
  id: string;
  // Where the source lives. The UI knows this at share time; if omitted we
  // resolve it. Only linear chats can be `local` (local graphs don't exist).
  backend?: ShareSourceBackend;
  // Cargo only: metadata the caller already holds (CargoScreen has the
  // decrypted row) — saves re-listing at share time. Ends up encrypted under
  // the share key; never sent plaintext.
  cargo?: { title: string; kind: CargoKind };
}

interface PresignSlot {
  s3Key: string;
  uploadUrl: string;
  contentType: string;
}

// A media attachment found on the source. Cloud sources carry the signed URL +
// IV needed to fetch and decrypt the current (master-key) ciphertext. Local
// sources instead carry an on-device `localFileId` whose bytes are read (already
// decrypted) via the local storage service — no signed URL / master-key IV.
interface PendingAsset {
  kind: 'image' | 'video';
  signedUrl?: string;
  encIv?: string;
  localFileId?: string;
  mimeType?: string | null;
  fileName?: string | null;
  width?: number | null;
  height?: number | null;
  durationMs?: number | null;
  // Filled after upload:
  s3Key?: string;
  newIv?: string;
}

interface AssetRef {
  kind: 'image' | 'video';
  s3Key: string;
  encIv: string;
  mimeType: string | null;
  fileName: string | null;
  width: number | null;
  height: number | null;
  durationMs: number | null;
}

// Document attachment (pdf/audio/docx/csv/code). Bytes are not durably stored,
// so a share carries metadata only — shown as a non-downloadable chip. The
// filename is encrypted under the share key.
interface FileRef {
  type: string;
  encryptedFileName: string | null;
  mimeType: string | null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** The base origin public share links point at (production web app). */
function shareBaseUrl(): string {
  if (typeof window !== 'undefined' && window.location?.origin) {
    // On web, link to the origin actually serving the app (works in dev too).
    return window.location.origin;
  }
  return `https://${brand.domain}`;
}

export function buildShareUrl(token: string, shareKey: Uint8Array): string {
  return `${shareBaseUrl()}/s/${token}#${shareKeyToFragment(shareKey)}`;
}

/**
 * Look up an existing (non-revoked) share for a source so the UI can offer
 * "copy existing link" vs "create". Returns the token, or null.
 */
export async function getExistingShare(source: ShareSource): Promise<string | null> {
  const response = await req(`/api/share/source/${source.id}`);
  if (!response.ok) return null;
  const data = await response.json().catch(() => ({}));
  return data?.token || null;
}

/**
 * Create or refresh a public snapshot for a chat/graph/cargo artifact and
 * return the full share URL (with the share key in the #fragment). Requires
 * the master key.
 */
export async function createOrUpdateShare(source: ShareSource): Promise<string> {
  if (!isMasterKeyLoaded()) {
    throw new Error('Unlock your account before sharing.');
  }
  const masterKey = getMasterKey();
  if (!masterKey) throw new Error('Master key not available.');

  const shareKey = await resolveShareKey(source, masterKey);

  // Resolve the backend (the caller usually knows it; fall back to a lookup).
  // Only linear chats can be local; graphs are always cloud. Cargo callers
  // pass the row's storageType (getCargoContent resolves its own backend).
  const backend: ShareSourceBackend =
    source.type === 'graph'
      ? 'cloud'
      : source.type === 'cargo'
        ? source.backend ?? 'cloud'
        : source.backend ?? ((await resolveChatBackend(source.id)) === 'local' ? 'local' : 'cloud');

  const built =
    source.type === 'graph'
      ? await buildGraphSnapshot(source.id, shareKey)
      : source.type === 'cargo'
        ? await buildCargoSnapshot(source, shareKey)
        : backend === 'local'
          ? await buildLocalChatSnapshot(source.id, shareKey)
          : await buildChatSnapshot(source.id, shareKey);

  // 1) Reserve a token + presigned upload slots for the media.
  const presign = await postJson('/api/share/assets/presign', {
    sourceType: source.type,
    sourceId: source.id,
    sourceBackend: backend,
    count: built.assets.length,
  });
  const token: string = presign.token;
  const slots: PresignSlot[] = presign.uploads || [];
  if (slots.length < built.assets.length) {
    throw new Error('Could not reserve upload slots for share media.');
  }

  // 2) Upload each re-encrypted binary directly to S3, recording its key + IV.
  for (let i = 0; i < built.assets.length; i++) {
    const asset = built.assets[i];
    const slot = slots[i];
    const ct = await reencryptBinary(asset, shareKey);
    const put = await fetch(slot.uploadUrl, {
      method: 'PUT',
      headers: { 'Content-Type': slot.contentType },
      body: ct.bytes as any,
    });
    if (!put.ok) throw new Error('Failed to upload share media.');
    asset.s3Key = slot.s3Key;
    asset.newIv = ct.iv;
  }

  // 3) Finalize: write the ciphertext snapshot with resolved asset refs.
  const wrappedShareKey = wrapMasterKey(shareKey, masterKey);
  await postJson('/api/share', {
    token,
    sourceType: source.type,
    sourceId: source.id,
    sourceBackend: backend,
    wrappedShareKey,
    encryptedTitle: built.encryptedTitle,
    messages: built.messages,
    nodes: built.nodes,
    edges: built.edges,
    entryNodeIds: built.entryNodeIds,
    cargo: built.cargo ?? null,
  });

  return buildShareUrl(token, shareKey);
}

/**
 * Re-sharing must be an in-place content update, not a key rotation: the key
 * lives in the already-distributed URL fragment, so minting a new one would
 * silently kill every copy of the old link (same token, key mismatch). Reuse
 * the existing share key by unwrapping the server-stored wrappedShareKey with
 * the master key; fall back to a fresh key for first shares or on any
 * lookup/unwrap failure (e.g. the share was created under a previous master
 * key after an account change — the old link is undecryptable then anyway).
 */
async function resolveShareKey(source: ShareSource, masterKey: Uint8Array): Promise<Uint8Array> {
  try {
    const response = await req(`/api/share/source/${encodeURIComponent(source.id)}`);
    if (response.ok) {
      const data = await response.json().catch(() => ({}));
      if (data?.token && typeof data?.wrappedShareKey === 'string' && data.wrappedShareKey) {
        const key = unwrapMasterKey(data.wrappedShareKey, masterKey);
        if (key.length === 32) return key;
      }
    }
  } catch { /* fall through to a fresh key */ }
  return generateShareKey();
}

export async function revokeShare(token: string): Promise<void> {
  const response = await req(`/api/share/${encodeURIComponent(token)}`, { method: 'DELETE' });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err?.message || 'Failed to revoke share.');
  }
}

// ---------------------------------------------------------------------------
// Public viewer fetch (unauthenticated)
// ---------------------------------------------------------------------------

export interface PublicAsset {
  kind: 'image' | 'video';
  encIv: string;
  mimeType: string | null;
  fileName: string | null;
  width: number | null;
  height: number | null;
  durationMs: number | null;
  url: string | null;
}

export interface PublicFile {
  type: string;
  encryptedFileName: string | null;
  mimeType: string | null;
}

export interface PublicSnapshot {
  sourceType: ShareSourceType;
  encryptedTitle: string | null;
  createdAt: string;
  messages?: Array<{
    role: 'user' | 'assistant' | 'system';
    encryptedContent: string | null;
    encryptedSources: string | null;
    attachments: PublicAsset[];
    files?: PublicFile[];
  }>;
  nodes?: Array<{
    clientNodeId: string;
    type: string;
    encryptedPrompt: string | null;
    encryptedAiResponse: string | null;
    encryptedNoteBody: string | null;
    position: { x: number; y: number };
    attachments: PublicAsset[];
    files?: PublicFile[];
  }>;
  edges?: Array<{ sourceNodeId: string; targetNodeId: string; edgeType: string }>;
  entryNodeIds?: string[];
  // Cargo artifact: {iv,ct} blobs under the share key. encryptedMeta decrypts
  // to JSON {title, kind}.
  cargo?: { encryptedMeta: string; encryptedContent: string } | null;
}

/** Fetch a public snapshot by token. No auth — used by PublicShareScreen. */
export async function getPublicSnapshot(token: string): Promise<PublicSnapshot | null> {
  const response = await fetch(`${getServerUrl()}/api/share/${encodeURIComponent(token)}`);
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('Failed to load shared chat.');
  const data = await response.json();
  return data.snapshot as PublicSnapshot;
}

// ---------------------------------------------------------------------------
// Snapshot builders (owner side — decrypt → re-encrypt under share key)
// ---------------------------------------------------------------------------

interface BuiltSnapshot {
  encryptedTitle: string | null;
  messages: any[];
  nodes: any[];
  edges: any[];
  entryNodeIds: string[];
  cargo?: { encryptedMeta: string; encryptedContent: string } | null;
  // Flat list of media to upload; the message/node attachment entries hold
  // references into this list (filled with s3Key/newIv after upload).
  assets: PendingAsset[];
}

function encTitle(plain: string | null | undefined, shareKey: Uint8Array): string | null {
  const t = (plain || '').trim();
  return t ? encryptTextWithKey(t, shareKey) : null;
}

// Collect uploadable media from a source attachment array (image + video).
function collectAssets(
  imageAttachments: any[] | undefined,
  videoAttachments: any[] | undefined,
  bucket: PendingAsset[],
): AssetRef[] {
  const refs: AssetRef[] = [];
  for (const img of imageAttachments || []) {
    const signedUrl = img.signedUrl || img.s3Url;
    if (!signedUrl || !img.encIv) continue; // unencrypted/legacy → skip
    const asset: PendingAsset = {
      kind: 'image',
      signedUrl,
      encIv: img.encIv,
      mimeType: img.mimeType || null,
      fileName: img.fileName || null,
      width: img.dimensions?.width ?? null,
      height: img.dimensions?.height ?? null,
      durationMs: null,
    };
    bucket.push(asset);
    refs.push(refFor(asset));
  }
  for (const vid of videoAttachments || []) {
    const signedUrl = vid.s3Url;
    if (vid.status !== 'completed' || !signedUrl || !vid.encIv) continue;
    const asset: PendingAsset = {
      kind: 'video',
      signedUrl,
      encIv: vid.encIv,
      mimeType: vid.mimeType || null,
      fileName: vid.fileName || null,
      width: null,
      height: null,
      durationMs: vid.duration != null ? Math.round(vid.duration * 1000) : null,
    };
    bucket.push(asset);
    refs.push(refFor(asset));
  }
  return refs;
}

// A lazy AssetRef whose s3Key/encIv resolve from the PendingAsset post-upload.
function refFor(asset: PendingAsset): AssetRef {
  return {
    kind: asset.kind,
    get s3Key() { return asset.s3Key!; },
    get encIv() { return asset.newIv!; },
    mimeType: asset.mimeType ?? null,
    fileName: asset.fileName ?? null,
    width: asset.width ?? null,
    height: asset.height ?? null,
    durationMs: asset.durationMs ?? null,
  } as AssetRef;
}

// Collect document attachments (metadata only) from a source attachment array.
// Linear-chat files are flat `{type, filename, mimeType}`; graph-node files keep
// the name inside decrypted `metadata` — read defensively across both shapes.
function collectFiles(fileAttachments: any[] | undefined, shareKey: Uint8Array): FileRef[] {
  const out: FileRef[] = [];
  for (const f of fileAttachments || []) {
    const name = f.filename || f.fileName || f.metadata?.filename || '';
    const type = f.type || f.fileType || 'file';
    const mimeType = f.mimeType || f.metadata?.mimeType || null;
    if (!name && !mimeType) continue; // nothing meaningful to render
    out.push({
      type,
      encryptedFileName: name ? encryptTextWithKey(name, shareKey) : null,
      mimeType,
    });
  }
  return out;
}

async function buildChatSnapshot(chatId: string, shareKey: Uint8Array): Promise<BuiltSnapshot> {
  const res = await graphService.getChat(chatId);
  if (!res.success || !res.chat) throw new Error(res.message || 'Could not load chat.');
  const chat: any = res.chat;
  const assets: PendingAsset[] = [];

  const title = chat.encryptedTitle ? await decryptText(chat.encryptedTitle) : '';

  const messages = [];
  for (const msg of chat.messages || []) {
    if (!msg.encryptedContent) continue;
    const content = await decryptText(msg.encryptedContent);
    const out: any = {
      role: msg.role,
      encryptedContent: encryptTextWithKey(content, shareKey),
      encryptedSources: null,
      attachments: collectAssets(msg.imageAttachments, msg.videoAttachments, assets),
      files: collectFiles(msg.fileAttachments, shareKey),
    };
    if (msg.encryptedSources) {
      const sources = await decryptText(msg.encryptedSources);
      out.encryptedSources = encryptTextWithKey(sources, shareKey);
    }
    messages.push(out);
  }

  return {
    encryptedTitle: encTitle(title, shareKey),
    messages,
    nodes: [],
    edges: [],
    entryNodeIds: [],
    assets,
  };
}

// Collect on-device image attachments from a local chat message. The bytes live
// in local storage under `s3Key` (the local file id); they're read + re-encrypted
// later in reencryptBinary(). Local videos aren't generated on-device, so skip.
function collectLocalAssets(imageAttachments: any[] | undefined, bucket: PendingAsset[]): AssetRef[] {
  const refs: AssetRef[] = [];
  for (const img of imageAttachments || []) {
    const fileId = img.s3Key || img.storageRef;
    if (img.storageType !== 'local' || !fileId) continue; // only on-device bytes
    const asset: PendingAsset = {
      kind: 'image',
      localFileId: fileId,
      mimeType: img.mimeType || null,
      fileName: img.fileName || null,
      width: img.dimensions?.width ?? null,
      height: img.dimensions?.height ?? null,
      durationMs: null,
    };
    bucket.push(asset);
    refs.push(refFor(asset));
  }
  return refs;
}

// Build a snapshot from a LOCAL (on-device) chat. Unlike cloud chats, the local
// file holds plaintext content, so we encrypt directly under the share key
// (no master-key decrypt) and read image bytes from local storage.
async function buildLocalChatSnapshot(chatId: string, shareKey: Uint8Array): Promise<BuiltSnapshot> {
  const res = await getLocalChat(chatId);
  if (!res.success || !res.chat) throw new Error(res.message || 'Could not load chat.');
  const chat = res.chat;
  const assets: PendingAsset[] = [];

  const messages = [];
  for (const msg of chat.messages || []) {
    const content = (msg.content || '').trim();
    if (!content && !(msg.imageAttachments?.length)) continue;
    const out: any = {
      role: msg.role,
      encryptedContent: content ? encryptTextWithKey(content, shareKey) : null,
      encryptedSources:
        msg.sources && msg.sources.length
          ? encryptTextWithKey(JSON.stringify(msg.sources), shareKey)
          : null,
      attachments: collectLocalAssets(msg.imageAttachments, assets),
      files: collectFiles(msg.fileAttachments, shareKey),
    };
    messages.push(out);
  }

  return {
    encryptedTitle: encTitle(chat.title, shareKey),
    messages,
    nodes: [],
    edges: [],
    entryNodeIds: [],
    assets,
  };
}

async function buildGraphSnapshot(graphId: string, shareKey: Uint8Array): Promise<BuiltSnapshot> {
  const res = await graphService.getGraph(graphId);
  if (!res.success || !res.graph) throw new Error(res.message || 'Could not load graph.');
  const assets: PendingAsset[] = [];

  const title = res.graph.encryptedTitle ? await decryptText(res.graph.encryptedTitle) : '';

  const nodes = [];
  for (const node of res.nodes || []) {
    const images = [...(node.imageAttachments || []), ...(node.messageAttachments || [])];
    const out: any = {
      clientNodeId: String(node._id),
      type: node.nodeType || 'standard',
      encryptedPrompt: node.encryptedPrompt ? encryptTextWithKey(await decryptText(node.encryptedPrompt), shareKey) : null,
      encryptedAiResponse: node.encryptedAiResponse ? encryptTextWithKey(await decryptText(node.encryptedAiResponse), shareKey) : null,
      encryptedNoteBody: node.encryptedNoteBody ? encryptTextWithKey(await decryptText(node.encryptedNoteBody), shareKey) : null,
      position: node.position || { x: 0, y: 0 },
      attachments: collectAssets(images, node.videoAttachments, assets),
      files: collectFiles(node.fileAttachments, shareKey),
    };
    nodes.push(out);
  }

  const edges = (res.edges || []).map((e: any) => ({
    sourceNodeId: String(e.sourceNodeId),
    targetNodeId: String(e.targetNodeId),
    edgeType: e.edgeType || 'directional',
  }));

  const entryNodeIds = (res.graph.entryNodeIds || []).map((id: any) => String(id));

  return {
    encryptedTitle: encTitle(title, shareKey),
    messages: [],
    nodes,
    edges,
    entryNodeIds,
    assets,
  };
}

// Build a snapshot for a Cargo artifact — the simplest share type: one inline
// content blob + a {title, kind} meta blob, both under the share key. Content
// is decrypted via getCargoContent (handles both storage backends); metadata
// rides in from the caller's already-decrypted row. No media assets.
async function buildCargoSnapshot(source: ShareSource, shareKey: Uint8Array): Promise<BuiltSnapshot> {
  const content = await getCargoContent(source.id);
  const title = source.cargo?.title || '';
  const kind: CargoKind = source.cargo?.kind || 'webpage';
  return {
    encryptedTitle: encTitle(title, shareKey),
    cargo: {
      encryptedMeta: encryptTextWithKey(JSON.stringify({ title, kind }), shareKey),
      encryptedContent: encryptTextWithKey(content, shareKey),
    },
    messages: [],
    nodes: [],
    edges: [],
    entryNodeIds: [],
    assets: [],
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function reencryptBinary(asset: PendingAsset, shareKey: Uint8Array): Promise<{ iv: string; bytes: Uint8Array }> {
  let plain: Uint8Array;
  if (asset.localFileId) {
    // On-device source: readLocal returns already-decrypted bytes.
    const { buffer } = await readLocal(asset.localFileId);
    plain = new Uint8Array(buffer);
  } else {
    const response = await fetch(asset.signedUrl!);
    if (!response.ok) throw new Error('Failed to fetch media for re-encryption.');
    const arrBuf = await response.arrayBuffer();
    plain = await decryptBinaryRaw(asset.encIv!, new Uint8Array(arrBuf));
  }
  const { iv, ct } = encryptBinaryRawWithKey(plain, shareKey);
  return { iv, bytes: ct };
}

async function postJson(endpoint: string, body: any): Promise<any> {
  const response = await req(endpoint, { method: 'POST', body: JSON.stringify(body) });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err?.message || `Share request failed (${response.status}).`);
  }
  return response.json();
}
