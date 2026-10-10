import { Platform } from 'react-native';
import authService from './authService';
import { getActionModel, resolveTtsVoice, getRequireZdr, getAllowNonZdrMedia } from './modelService';

/**
 * Progressive playback of a spoken sentence, web only.
 *
 * The buffered path (`synthesizeSpeechToUri`) can't make a sound until the last
 * byte of the clip has arrived: the server base64s the whole thing into a JSON
 * field and the client turns that into a `data:` URI. On a provider that
 * streams, that wastes most of the wait — Deepgram Aura-2 emits its first byte
 * in ~0.5s and then trickles the rest in real time, so buffering a 2s clip
 * means ~2s of silence to save nothing.
 *
 * MediaSource lets us hand the decoder bytes as they land, so playback starts on
 * the first frame. That is worth roughly a second on the *first* sentence of a
 * reply — the only sentence whose latency anyone hears, since later ones are
 * synthesized behind audio that's already playing.
 *
 * Everything here degrades to `null`, never to an error. Native has no
 * MediaSource; Safari doesn't support `audio/mpeg` in MSE; and some models
 * (Gemini's pcm-only TTS, or the enclave models that synthesize the whole clip
 * before responding) can't stream at all — the server answers 409 for those.
 * In every one of those cases the caller falls back to the buffered path and
 * the user hears the same words a beat later.
 *
 * E2EE (CLAUDE.md §5): identical to the buffered route — the reply text transits
 * the authenticated proxy for synthesis and is never persisted server-side.
 */

const MIME = 'audio/mpeg';

/**
 * The MediaSource constructor to stream through, or null.
 *
 * Every speech model we can route to answers mp3 on the streaming path (the
 * server 409s anything else — Gemini is PCM-only, fal renders whole clips), so
 * the only question is whether this browser's MSE takes `audio/mpeg`.
 *
 * iPhone Safari has no `MediaSource` at all; since iOS 17.1 it has
 * `ManagedMediaSource` instead, and checking only the first sent every iPhone
 * down the buffered path — the whole sentence synthesized and downloaded before
 * a sound, on the device where that wait is longest. Feature-detected per type,
 * never assumed: where it doesn't take mp3 this still returns null and the
 * buffered path runs exactly as before.
 */
function streamingSource(): { MS: any; managed: boolean } | null {
  if (Platform.OS !== 'web') return null;
  const g = globalThis as any;
  for (const [MS, managed] of [[g.MediaSource, false], [g.ManagedMediaSource, true]] as const) {
    try {
      if (typeof MS === 'function' && typeof MS.isTypeSupported === 'function' && MS.isTypeSupported(MIME)) {
        return { MS, managed };
      }
    } catch { /* keep looking */ }
  }
  return null;
}

/** Can this platform/browser decode a streamed mp3 through MediaSource? */
export function canStreamSpeech(): boolean {
  return streamingSource() !== null;
}

export interface StreamingSpeech {
  /** Ready to `play()` — the first bytes are already in the buffer. */
  el: HTMLAudioElement;
  /** Release the object URL and abort the download. Safe to call twice. */
  dispose: () => void;
}

/**
 * Start synthesizing `text` and return an audio element that is already playable.
 * Resolves as soon as the first chunk has been appended, while the rest is still
 * downloading. Returns null when streaming isn't possible — callers must handle
 * that by falling back rather than treating it as a failure.
 */
export async function streamSpeech(
  text: string,
  opts: { modelId?: string; voice?: string; requireZdr?: boolean; allowNonZdrMedia?: boolean } = {},
): Promise<StreamingSpeech | null> {
  const trimmed = (text || '').trim();
  const source = streamingSource();
  if (!trimmed || !source) return null;

  const modelId = opts.modelId || (await getActionModel('tts')).modelId;
  const voice = opts.voice || (await resolveTtsVoice(modelId));
  // Sent for the same reason the buffered path sends them: on the local backend
  // these prefs exist only on this device, and a non-ZDR voice is gated on them.
  // A blocked voice 403s here, which this function reports as `null` like any
  // other non-OK — the buffered path then produces the one user-facing error.
  // Callers synthesizing several sentences in a row resolve these once and pass
  // them in, rather than re-reading two secure-store keys per sentence.
  const [requireZdr, allowNonZdrMedia] = await Promise.all([
    opts.requireZdr ?? getRequireZdr(),
    opts.allowNonZdrMedia ?? getAllowNonZdrMedia(),
  ]);

  const controller = new AbortController();
  let res: Response;
  try {
    res = await authService.makeAuthenticatedRequest(
      '/api/audio/speech/stream',
      { method: 'POST', body: JSON.stringify({ text: trimmed, ttsModelId: modelId, voice, requireZdr, allowNonZdrMedia }) },
      controller.signal,
    );
  } catch {
    return null; // offline / aborted — the buffered path will report properly
  }
  // 409 is the server saying "this model can't stream", which is a routing fact,
  // not an error. Anything else non-OK is also left to the buffered path so
  // there's exactly one place that turns TTS failures into user-facing copy.
  if (!res.ok || !res.body) return null;

  const mediaSource = new source.MS();
  const el = new (globalThis as any).Audio() as HTMLAudioElement;
  // ManagedMediaSource only opens on an element that has opted out of AirPlay
  // (remote playback can't follow a MediaSource) — without this the source
  // never fires `sourceopen` and every sentence waits out the timeout below.
  if (source.managed) (el as any).disableRemotePlayback = true;
  const objectUrl = URL.createObjectURL(mediaSource);
  el.src = objectUrl;

  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    try { controller.abort(); } catch { /* */ }
    try { URL.revokeObjectURL(objectUrl); } catch { /* */ }
  };

  try {
    await new Promise<void>((resolve, reject) => {
      const onOpen = () => {
        mediaSource.removeEventListener('sourceopen', onOpen);
        let sourceBuffer: any;
        try {
          sourceBuffer = mediaSource.addSourceBuffer(MIME);
        } catch (e) {
          reject(e);
          return;
        }

        // appendBuffer is asynchronous and throws if called while the previous
        // append is still in flight, so writes are serialized behind updateend.
        const queue: Uint8Array[] = [];
        let ended = false;
        let firstAppended = false;

        const pumpQueue = () => {
          if (sourceBuffer.updating) return;
          const next = queue.shift();
          if (next) {
            try {
              sourceBuffer.appendBuffer(next);
            } catch (e) {
              reject(e);
            }
            return;
          }
          if (ended && mediaSource.readyState === 'open') {
            try { mediaSource.endOfStream(); } catch { /* already ended */ }
          }
        };

        sourceBuffer.addEventListener('updateend', () => {
          if (!firstAppended) {
            firstAppended = true;
            // Enough decoded audio exists to start; the rest keeps arriving
            // behind playback.
            resolve();
          }
          pumpQueue();
        });

        const reader = res.body!.getReader();
        const read = (): Promise<void> =>
          reader.read().then(({ done, value }) => {
            if (disposed) { try { reader.cancel(); } catch { /* */ } return; }
            if (done) { ended = true; pumpQueue(); return; }
            if (value) { queue.push(value); pumpQueue(); }
            return read();
          });
        read().catch(reject);
      };
      mediaSource.addEventListener('sourceopen', onOpen);
      // A source that never opens would hang the whole voice loop. Fail over to
      // the buffered path instead of leaving the conversation stuck.
      setTimeout(() => reject(new Error('MediaSource did not open')), 5000);
    });
  } catch {
    dispose();
    return null;
  }

  return { el, dispose };
}
