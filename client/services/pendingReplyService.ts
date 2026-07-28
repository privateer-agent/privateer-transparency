/**
 * Pending Reply Service (client) — the on-device half of "Finish replies in the
 * cloud" (opt-in; see server/services/pendingReplyStore.js and modelService
 * getHoldReplyInCloud).
 *
 * When the user has the feature on, every send drops a small **marker** in
 * EncryptedStorage BEFORE inference: {pendingMessageId, chatId, backend}. If the
 * app streams the reply through normally, the send path clears the marker. If
 * the app is backgrounded-then-killed mid-stream, the marker survives the cold
 * start — and on relaunch `recoverPendingReplies()` asks the server for any
 * reply it held (short-TTL Redis), encrypts it client-side, and appends it to
 * the right chat, then tells the server to drop the plaintext copy.
 *
 * Nothing here holds plaintext: the marker records only ids + which local store
 * owns the chat. The reply text lives (briefly, by consent) on the server until
 * pickup; the durable copy is always the client-encrypted assistant turn.
 *
 * Guests are never involved (they can't opt in, and have no server prefs), so
 * only 'cloud' and 'local' backends are recoverable.
 */

import { secureKv } from './internal/secureKv';
import { brand } from '../config/brand';
import authService from './authService';
import { isMasterKeyLoaded } from './cryptoService';
import { addMessageToChat } from './graphService';
import { addLocalMessage } from './localChatService';

const MARKERS_KEY = `${brand.storagePrefix}/pending_replies`;
// Hard cap on stored markers so a run of failed recoveries can't grow the blob
// unbounded. Oldest are dropped first.
const MAX_MARKERS = 50;
// Belt-and-suspenders: a marker older than the server hold TTL (1h) can only
// 404, so we prune locally past a generous multiple rather than re-hitting the
// server forever.
const MARKER_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export type PendingReplyBackend = 'cloud' | 'local';

export interface PendingReplyMarker {
  pendingMessageId: string;
  chatId: string;
  backend: PendingReplyBackend;
  createdAt: number;
  // Whether the USER turn for this send was already persisted before the app
  // died. New chats persist it eagerly (true → recovery appends only the reply).
  // Existing chats persist it only after the reply (false → recovery must write
  // the user turn from `userMessage` first, so the recovered reply isn't orphaned).
  userTurnPersisted?: boolean;
  // The user turn to restore when userTurnPersisted is false. Content only +
  // light metadata; attachment linkage is best-effort (the blob itself already
  // lives in S3/on-device — see the note at the ChatScreen marker site).
  userMessage?: {
    content: string;
    generationOptions?: any;
    contextRefs?: any[];
  };
}

async function readMarkers(): Promise<PendingReplyMarker[]> {
  try {
    const raw = await secureKv.getItem(MARKERS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

async function writeMarkers(list: PendingReplyMarker[]): Promise<void> {
  try {
    await secureKv.setItem(MARKERS_KEY, JSON.stringify(list.slice(-MAX_MARKERS)));
  } catch (_) {
    /* non-fatal — losing a marker just means a held reply isn't auto-recovered */
  }
}

/**
 * Record that a turn is in flight with cloud reply-hold enabled. Call this
 * BEFORE the stream starts. Replaces any existing marker with the same id.
 */
export async function addPendingMarker(marker: PendingReplyMarker): Promise<void> {
  if (!marker?.pendingMessageId || !marker?.chatId) return;
  const list = (await readMarkers()).filter(m => m.pendingMessageId !== marker.pendingMessageId);
  list.push(marker);
  await writeMarkers(list);
}

/**
 * Clear a marker once its reply has been delivered normally (or recovered).
 */
export async function clearPendingMarker(pendingMessageId: string): Promise<void> {
  if (!pendingMessageId) return;
  const list = await readMarkers();
  const next = list.filter(m => m.pendingMessageId !== pendingMessageId);
  if (next.length !== list.length) await writeMarkers(next);
}

/** A newly-generated per-turn id. Kept trivial to avoid a uuid dep here. */
export function newPendingMessageId(): string {
  // Time + randomness is plenty for a per-turn, per-user key (it's namespaced by
  // userId server-side). Not a security token.
  return `pm_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

async function persistRecoveredReply(marker: PendingReplyMarker, reply: any): Promise<void> {
  const append = marker.backend === 'local' ? addLocalMessage : addMessageToChat;

  // Restore the user turn first when the app died before it was persisted
  // (existing-chat path). New chats already have it (userTurnPersisted).
  if (marker.userTurnPersisted === false && marker.userMessage?.content) {
    await append(marker.chatId, {
      role: 'user' as const,
      content: marker.userMessage.content,
      ...(marker.userMessage.generationOptions ? { generationOptions: marker.userMessage.generationOptions } : {}),
      ...(marker.userMessage.contextRefs?.length ? { contextRefs: marker.userMessage.contextRefs } : {}),
    });
  }

  await append(marker.chatId, {
    role: 'assistant' as const,
    content: String(reply.response || ''),
    tokensUsed: typeof reply.tokensUsed === 'number' ? reply.tokensUsed : 0,
    ...(reply.modelUsed ? { modelUsed: reply.modelUsed } : {}),
    ...(Array.isArray(reply.sources) && reply.sources.length ? { sources: reply.sources } : {}),
  });
}

/**
 * On relaunch / resume: for each outstanding marker, fetch any server-held reply,
 * encrypt + persist it locally, and drop the server copy. Safe to call more than
 * once (each marker is processed at most once per run and cleared on success).
 * No-ops without a loaded master key (can't encrypt yet) — the caller should
 * retry after auth restores the key.
 *
 * Returns the number of replies recovered.
 */
let recovering = false;

export async function recoverPendingReplies(): Promise<number> {
  if (!isMasterKeyLoaded()) return 0;
  // Guard against overlapping runs (mount effect + AppState 'active' can fire
  // close together) so a marker isn't fetched + persisted twice.
  if (recovering) return 0;
  recovering = true;
  try {
    return await runRecovery();
  } finally {
    recovering = false;
  }
}

async function runRecovery(): Promise<number> {
  const markers = await readMarkers();
  if (markers.length === 0) return 0;

  let recovered = 0;
  const now = Date.now();

  for (const marker of markers) {
    // Prune obviously-dead markers without bothering the server.
    if (marker.createdAt && now - marker.createdAt > MARKER_MAX_AGE_MS) {
      await clearPendingMarker(marker.pendingMessageId);
      continue;
    }

    try {
      const res = await authService.makeAuthenticatedRequest(
        `/api/chat/pending/${encodeURIComponent(marker.pendingMessageId)}`
      );

      if (res.status === 404) {
        // Expired or never held — the reply is gone; stop tracking it.
        await clearPendingMarker(marker.pendingMessageId);
        continue;
      }
      if (!res.ok) {
        // Transient (network/5xx) — leave the marker for the next attempt.
        continue;
      }

      const data = await res.json().catch(() => null);
      const reply = data?.reply;
      if (!reply || !reply.response) {
        await clearPendingMarker(marker.pendingMessageId);
        continue;
      }

      await persistRecoveredReply(marker, reply);
      recovered += 1;

      // Ack + delete the server-side plaintext copy, then stop tracking it.
      try {
        await authService.makeAuthenticatedRequest(
          `/api/chat/pending/${encodeURIComponent(marker.pendingMessageId)}`,
          { method: 'DELETE' }
        );
      } catch (_) { /* TTL is the backstop */ }
      await clearPendingMarker(marker.pendingMessageId);
    } catch (_) {
      // Leave the marker in place; a later recovery pass will retry.
    }
  }

  return recovered;
}
