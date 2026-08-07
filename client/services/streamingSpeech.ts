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

/** Can this platform/browser decode a streamed mp3 through MediaSource? */
export function canStreamSpeech(): boolean {
  if (Platform.OS !== 'web') return false;
  const MS = (globalThis as any).MediaSource;
  return typeof MS === 'function' && typeof MS.isTypeSupported === 'function' && MS.isTypeSupported(MIME);
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
  opts: { modelId?: string; voice?: string } = {},
): Promise<StreamingSpeech | null> {
  const trimmed = (text || '').trim();
  if (!trimmed || !canStreamSpeech()) return null;

  const modelId = opts.modelId || (await getActionModel('tts')).modelId;
  const voice = opts.voice || (await resolveTtsVoice(modelId));
  // Sent for the same reason the buffered path sends them: on the local backend
  // these prefs exist only on this device, and a non-ZDR voice is gated on them.
  // A blocked voice 403s here, which this function reports as `null` like any
  // other non-OK — the buffered path then produces the one user-facing error.
  const [requireZdr, allowNonZdrMedia] = await Promise.all([
    getRequireZdr(),
    getAllowNonZdrMedia(),
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

  const MS = (globalThis as any).MediaSource;
  const mediaSource = new MS();
  const el = new (globalThis as any).Audio() as HTMLAudioElement;
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
