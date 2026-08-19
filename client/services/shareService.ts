/**
 * Share service — turns an E2EE chat/graph/cargo/audio artifact into a public,
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
import { isDesktop } from './desktopTransport';
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

/**
 * Why a share failed, in terms the sheet can localize.
 *
 * The messages here are English fallbacks for a caller that has no catalog —
 * the UI branches on `code`, never on the text (CLAUDE.md §7). Anything that
 * escapes uncaught used to reach the user verbatim, which is how QA saw the
 * raw `fetch` TypeError "Failed to fetch" as the whole explanation.
 */
export type ShareErrorCode = 'locked' | 'stale' | 'network' | 'upload' | 'server' | 'unknown';

export class ShareError extends Error {
  code: ShareErrorCode;
  constructor(code: ShareErrorCode, message: string) {
    super(message);
    this.name = 'ShareError';
    this.code = code;
  }
}

/**
 * A failed `fetch` rejects with a bare TypeError ("Failed to fetch" / "Network
 * request failed") that names neither the request nor anything the user can act
 * on. Every leg of a share that leaves the device runs through here so the
 * failure arrives as one of our codes instead.
 */
async function netStep<T>(code: Extract<ShareErrorCode, 'network' | 'upload'>, fallback: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e: any) {
    if (e instanceof ShareError) throw e;
    throw new ShareError(code, e?.message ? `${fallback} (${e.message})` : fallback);
  }
}

export type ShareSourceType = 'chat' | 'graph' | 'cargo' | 'audio';
export type ShareSourceBackend = 'cloud' | 'local';

/** What produced a shared clip — the viewer labels the three modes apart. */
export type ShareAudioKind = 'speech' | 'music' | 'sfx';

/**
 * Audio only: everything a clip share needs, all of it already in the caller's
 * hands (the Audio studio and the Library both hold a decrypted row when the
 * share button is pressed).
 *
 * The handles fetch the *current* ciphertext: `signedUrl` + `encIv` for a cloud
 * clip, or `storageRef` as an on-device file id when `backend` is `local`.
 * Everything else is rendered by the viewer and is sealed under the share key —
 * none of it is ever sent plaintext.
 */
export interface ShareAudio {
  storageRef: string;
  encIv?: string | null;
  signedUrl?: string | null;
  filename: string;
  mimeType: string;
  durationMs?: number | null;
  /** The text that was spoken, or the description that made the track. */
  prompt?: string | null;
  kind?: ShareAudioKind;
}

export interface ShareSource {
  type: ShareSourceType;
  /**
   * Identifies the source to the server. Chat/graph/cargo pass the row id; an
   * `audio` source passes the clip's **storageRef** instead — a Library audio
   * row's id is positional for chat-attached clips (`<chatId>_<msg>_<file>`),
   * so it is neither stable across an edit nor something ownership can be
   * checked against. See shareSnapshotModel's `sourceId`.
   */
  id: string;
  // Where the source lives. The UI knows this at share time; if omitted we
  // resolve it. Only linear chats and audio clips can be `local`.
  backend?: ShareSourceBackend;
  // Cargo only: metadata the caller already holds (CargoScreen has the
  // decrypted row) — saves re-listing at share time. Ends up encrypted under
  // the share key; never sent plaintext.
  cargo?: { title: string; kind: CargoKind };
  // Audio only — see ShareAudio.
  audio?: ShareAudio;
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
  kind: 'image' | 'video' | 'audio';
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
  kind: 'image' | 'video' | 'audio';
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

/**
 * The base origin public share links point at (production web app).
 *
 * On web this is the origin actually serving the app, so a dev/preview build
 * links to itself. The desktop shell is the exception it must NOT follow: its
 * renderer is served from a loopback static server on an ephemeral port, so
 * `window.location.origin` is `http://127.0.0.1:58206` — a link only that one
 * machine could open, and only until the app restarts. QA shipped exactly that
 * link to a recipient (#17). The test is the preload bridge rather than the
 * loopback shape of the URL, so a browser on `localhost:8081` keeps linking to
 * itself the way a dev expects.
 */
function shareBaseUrl(): string {
  if (typeof window !== 'undefined' && window.location?.origin && !isDesktop()) {
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
  const response = await req(sourceLookupPath(source.id));
  if (!response.ok) return null;
  const data = await response.json().catch(() => ({}));
  return data?.token || null;
}

/**
 * Owner-scoped lookup by source id. Always the query form: an audio share's id
 * is an S3 key, and a path segment can't carry its slashes — `%2F` is decoded
 * (or rejected) inconsistently across Express and the proxies in front of it.
 */
function sourceLookupPath(sourceId: string): string {
  return `/api/share/source?sourceId=${encodeURIComponent(sourceId)}`;
}

/**
 * Create or refresh a public snapshot for a chat/graph/cargo/audio source and
 * return the full share URL (with the share key in the #fragment). Requires
 * the master key.
 */
export async function createOrUpdateShare(source: ShareSource): Promise<string> {
  if (!isMasterKeyLoaded()) {
    throw new ShareError('locked', 'Unlock your account before sharing.');
  }
  const masterKey = getMasterKey();
  if (!masterKey) throw new ShareError('locked', 'Master key not available.');

  const shareKey = await resolveShareKey(source, masterKey);

  // Resolve the backend (the caller usually knows it; fall back to a lookup).
  // Only linear chats can be local; graphs are always cloud. Cargo callers
  // pass the row's storageType (getCargoContent resolves its own backend).
  const backend: ShareSourceBackend =
    source.type === 'graph'
      ? 'cloud'
      : source.type === 'cargo' || source.type === 'audio'
        ? source.backend ?? 'cloud'
        : source.backend ?? ((await resolveChatBackend(source.id)) === 'local' ? 'local' : 'cloud');

  const built =
    source.type === 'graph'
      ? await buildGraphSnapshot(source.id, shareKey)
      : source.type === 'cargo'
        ? await buildCargoSnapshot(source, shareKey)
        : source.type === 'audio'
          ? buildAudioSnapshot(source, shareKey, backend)
          : backend === 'local'
            ? await buildLocalChatSnapshot(source.id, shareKey)
            : await buildChatSnapshot(source.id, shareKey);

  // 1) Reserve a token + presigned upload slots for the media.
  const presign = await netStep('network', 'Could not reach the server to start the share.', () =>
    postJson('/api/share/assets/presign', {
      sourceType: source.type,
      sourceId: source.id,
      sourceBackend: backend,
      count: built.assets.length,
    }));
  const token: string = presign.token;
  const slots: PresignSlot[] = presign.uploads || [];
  if (slots.length < built.assets.length) {
    throw new ShareError('upload', 'Could not reserve upload slots for share media.');
  }

  // 2) Upload each re-encrypted binary directly to S3, recording its key + IV.
  for (let i = 0; i < built.assets.length; i++) {
    const asset = built.assets[i];
    const slot = slots[i];
    const ct = await reencryptBinary(asset, shareKey);
    const put = await netStep('upload', 'Could not upload the media for this link.', () =>
      fetch(slot.uploadUrl, {
        method: 'PUT',
        headers: { 'Content-Type': slot.contentType },
        body: ct.bytes as any,
      }));
    if (!put.ok) throw new ShareError('upload', `Could not upload the media for this link (${put.status}).`);
    asset.s3Key = slot.s3Key;
    asset.newIv = ct.iv;
  }

  // 3) Finalize: write the ciphertext snapshot with resolved asset refs.
  const wrappedShareKey = wrapMasterKey(shareKey, masterKey);
  await netStep('network', 'Could not reach the server to finish the share.', () => postJson('/api/share', {
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
    // The clip's bytes are one of the uploaded assets; its ref only resolves
    // (s3Key + IV) after the upload loop above, which is why it's read here.
    audio: built.audio
      ? { encryptedMeta: built.audio.encryptedMeta, asset: { s3Key: built.audio.asset.s3Key, encIv: built.audio.asset.encIv } }
      : null,
  }));

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
    const response = await req(sourceLookupPath(source.id));
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
  kind: 'image' | 'video' | 'audio';
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
  // Audio clip: the re-encrypted bytes (asset) plus {iv,ct} of JSON
  // {filename, mimeType, durationMs, kind, prompt}.
  audio?: { encryptedMeta: string; asset: PublicAsset | null } | null;
}

/** The decrypted shape of a shared clip's `encryptedMeta`. */
export interface PublicAudioMeta {
  filename: string;
  mimeType: string;
  durationMs: number | null;
  kind: ShareAudioKind;
  prompt: string | null;
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
  audio?: { encryptedMeta: string; asset: AssetRef } | null;
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

/**
 * Build a snapshot for one audio clip — the bytes plus a small metadata blob.
 *
 * Nothing is read here: the caller already holds the row, so this only stages
 * the fetch handles as a PendingAsset (the same shape images and videos use, so
 * the upload loop and reencryptBinary work unchanged) and seals the metadata.
 * The name, the prompt, the mime and the length all live inside encryptedMeta —
 * the server sees an opaque object key and an IV, exactly as it does for a
 * shared image.
 *
 * A local clip's `storageRef` is an on-device file id whose bytes come back
 * already decrypted; a cloud clip is fetched from its signed URL and opened with
 * the master key first.
 */
function buildAudioSnapshot(
  source: ShareSource,
  shareKey: Uint8Array,
  backend: ShareSourceBackend,
): BuiltSnapshot {
  const clip = source.audio;
  if (!clip) throw new Error('Nothing to share — this clip has no audio.');
  if (backend === 'cloud' && (!clip.signedUrl || !clip.encIv)) {
    // Signed URLs expire, so a stale row can reach here with nothing to fetch.
    // A cloud clip with no IV is a legacy unencrypted object — the other
    // builders skip those; a one-clip share has nothing left to make.
    throw new ShareError('stale', 'Reopen this clip and try sharing again.');
  }

  const asset: PendingAsset = backend === 'local'
    ? { kind: 'audio', localFileId: clip.storageRef, mimeType: clip.mimeType, fileName: null }
    : { kind: 'audio', signedUrl: clip.signedUrl!, encIv: clip.encIv || undefined, mimeType: clip.mimeType, fileName: null };

  const meta = {
    filename: clip.filename || '',
    mimeType: clip.mimeType || 'audio/mpeg',
    durationMs: clip.durationMs ?? null,
    kind: clip.kind || 'speech',
    prompt: clip.prompt || null,
  };

  return {
    encryptedTitle: encTitle(clip.filename, shareKey),
    audio: {
      encryptedMeta: encryptTextWithKey(JSON.stringify(meta), shareKey),
      asset: refFor(asset),
    },
    messages: [],
    nodes: [],
    edges: [],
    entryNodeIds: [],
    assets: [asset],
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
    const response = await netStep('upload', 'Could not read this media to re-encrypt it.', () => fetch(asset.signedUrl!));
    if (!response.ok) throw new ShareError('upload', `Could not read this media to re-encrypt it (${response.status}).`);
    const arrBuf = await response.arrayBuffer();
    plain = await decryptBinaryRaw(asset.encIv!, new Uint8Array(arrBuf));
  }
  const { iv, ct } = encryptBinaryRawWithKey(plain, shareKey);
  return { iv, bytes: ct };
}

/**
 * The server ANSWERED and refused — a different thing from not reaching it, and
 * the reason it carries its own code. `netStep` passes a ShareError through
 * untouched, so wrapping a call in it can't relabel "Chat not found" as a
 * network failure; and the server's message is already localized (CLAUDE.md
 * §7), so the sheet shows it rather than a generic replacement.
 */
async function postJson(endpoint: string, body: any): Promise<any> {
  const response = await req(endpoint, { method: 'POST', body: JSON.stringify(body) });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new ShareError('server', err?.message || `Share request failed (${response.status}).`);
  }
  return response.json();
}
