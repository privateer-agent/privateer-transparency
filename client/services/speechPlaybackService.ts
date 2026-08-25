/**
 * Read-aloud playback for chat messages.
 *
 * Two engines behind one call:
 *  - Signed-in users get the TTS model + voice they picked (Settings →
 *    Intelligence Models, or the Audio studio) synthesized server-side, so the
 *    voice they chose is the voice they hear everywhere in the app.
 *  - Guests get the device/browser engine (expo-speech). /api/audio/speech
 *    requires auth, so there is no server path for them.
 *
 * The device engine is also the fallback for *any* synthesis failure — out of
 * credits, offline, provider down. A read-aloud button that silently does
 * nothing is worse than one that reads in the stock system voice. It never
 * happens quietly: `onFallback` names the reason, once per app run.
 *
 * Long text is spoken as a QUEUE of chunks, one request each, synthesized one
 * ahead of the audio (`speakQueue`). Not an optimization — the default model
 * stops reading at ~2,200 characters with no error, so a routine result sent as
 * one request was cut off about a quarter of the way in, after a minute of
 * silence waiting for it. The sizes and the measurements behind them live in
 * `speechChunker.READ_ALOUD_CHUNKING`.
 *
 * Playback is a module-level singleton: only one message can be speaking at a
 * time, and tapping a second one has to interrupt the first from a different
 * component instance. Native uses expo-av `Audio.Sound`; web uses
 * `HTMLAudioElement` (expo-av's Sound isn't implemented there) — the same split
 * useVoiceChat and AudioPlayer already document.
 *
 * Read-aloud is also the one audio source with no control of its own once you
 * scroll past it, so this module publishes whether it is engaged — see
 * `useIsSpeaking` / `useSpeakingId` below. Every surface that can start speech
 * therefore has a reachable stop, including the nav rail's global one.
 *
 * E2EE (CLAUDE.md §5): the message text transits the authenticated proxy for
 * inference exactly like the chat request that produced it, and is never
 * persisted server-side.
 */
import { useCallback, useSyncExternalStore } from 'react';
import { Platform } from 'react-native';
import { Audio } from 'expo-av';
import * as Speech from 'expo-speech';
import { isGuestSession } from './sessionMode';
import { synthesizeSpeechBytes, fetchVoicePreview, audioBytesToUri } from './voiceChatService';
import { chunkForReadAloud } from './speechChunker';
import { setVoiceActive } from './audioFocus';
import { SHARED_PLAYBACK_MODE } from './audioSessionMode';
import { Sentry } from './sentryService';
import i18n from '../i18n';

interface SpeakOptions {
  /** Playback finished on its own. Not called when interrupted by stop(). */
  onDone?: () => void;
  /** Both engines failed — nothing is playing. */
  onError?: () => void;
  /**
   * Opaque caller id for whatever is being read (a message id). Published as
   * `useSpeakingId()` so the button that started it renders its speaking state
   * from the engine rather than from local state a global stop can't reach.
   */
  id?: string;
  /**
   * Synthesis failed and this utterance is being read by the device engine
   * instead, with `reason` already localized.
   *
   * The fallback itself is right — a read-aloud button that goes quiet is worse
   * than one that reads in the stock system voice — but doing it *silently* was
   * not: the chosen voice and the device voice are audibly different, so a
   * failed synthesis is indistinguishable from the app ignoring the voice you
   * picked. Callers use this to say which of the two happened.
   *
   * Called at most ONCE per app run, whichever surface gets there first — see
   * `deviceFallbackAnnounced`. Wire it everywhere; the engine does the rationing.
   */
  onFallback?: (reason: string) => void;
}

/**
 * Whether this app run has already explained a fall back to the device voice.
 *
 * The rationing lives in the engine rather than in each surface because the
 * cause is an account or network fact — out of credits, offline, a provider
 * down — not a property of the utterance: every read-aloud button in the app
 * would otherwise report the same standing failure the first time it was
 * pressed. Owning it here also means a surface can wire `onFallback` without
 * having to know that the one next to it already did.
 */
let deviceFallbackAnnounced = false;

/**
 * Hand the caller the reason the voice changed, once per run, and record the
 * underlying failure.
 *
 * The Sentry line is the half the user can't give us: `reason` is a localized
 * sentence, while the swap can equally be a 402, a ZDR gate, or a synthesis
 * that ran past a proxy's request ceiling — which of those it was decides
 * whether anything here is even broken.
 */
function reportDeviceFallback(options: SpeakOptions, reason: string, err: unknown, chars: number): void {
  Sentry.captureException(err, {
    level: 'warning',
    tags: { op: 'tts_device_fallback', code: (err as any)?.code || 'unknown' },
    extra: { chars },
  } as any);
  if (deviceFallbackAnnounced) return;
  deviceFallbackAnnounced = true;
  options.onFallback?.(reason);
}

let activeSound: Audio.Sound | null = null;
let activeWebAudio: HTMLAudioElement | null = null;
// Bumped by every stop() and every new speakText(). An in-flight synthesis
// compares the token it captured against this before playing, so a request the
// user has already moved on from can never start talking over the new one.
let generation = 0;

// ── Activity store ───────────────────────────────────────────────────────────
// "Engaged" spans synthesis *and* playback, not just audible sound: a user who
// taps read-aloud and then wants out shouldn't have to wait for the clip to
// arrive before a stop control appears.
let engaged = false;
let activeId: string | null = null;
const listeners = new Set<() => void>();

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => { listeners.delete(l); };
}
function setActivity(nextEngaged: boolean, nextId: string | null): void {
  if (engaged === nextEngaged && activeId === nextId) return;
  engaged = nextEngaged;
  activeId = nextId;
  // The music ducks under a voice rather than stopping for one, and this is the
  // one place that knows when the voice starts and stops — every seam below
  // (finished, stopped, errored, superseded, fell back to the device engine)
  // already lands here, so the track comes back up even on the paths that
  // never reach an `onDone`. See audioFocus.ts.
  setVoiceActive('readAloud', nextEngaged);
  listeners.forEach(l => l());
}

const getEngaged = () => engaged;
const getActiveId = () => activeId;

/** True from the moment read-aloud is asked for until it stops or finishes. */
export function useIsSpeaking(): boolean {
  return useSyncExternalStore(subscribe, getEngaged, getEngaged);
}
/** The `id` passed to the live `speakText`, or null. */
export function useSpeakingId(): string | null {
  return useSyncExternalStore(subscribe, getActiveId, getActiveId);
}
/**
 * Whether read-aloud is engaged on THIS id.
 *
 * The same fact as `useSpeakingId() === id`, but derived inside the store so a
 * surface that mounts one subscriber per item only re-renders the two items
 * whose answer actually changed. The graph canvas is why: every card on the
 * board carries its own read-aloud button, and the id-valued hook would re-render
 * all of them — markdown bodies and all — each time one of them started talking.
 */
export function useIsSpeakingId(id: string | null | undefined): boolean {
  const get = useCallback(() => !!id && activeId === id, [id]);
  return useSyncExternalStore(subscribe, get, get);
}

function teardownPlayers(): void {
  const sound = activeSound;
  activeSound = null;
  if (sound) {
    sound.setOnPlaybackStatusUpdate(null);
    sound.unloadAsync().catch(() => {});
  }
  const el = activeWebAudio;
  activeWebAudio = null;
  if (el) {
    el.onended = null;
    el.onerror = null;
    el.pause();
  }
}

/** Stop whatever is currently speaking, on either engine. Safe to call twice. */
export async function stopSpeech(): Promise<void> {
  generation += 1;
  setActivity(false, null);
  teardownPlayers();
  await Speech.stop().catch(() => {});
}

/** Device/browser engine. Used for guests and as the synthesis fallback. */
function speakOnDevice(text: string, handlers: SpeakOptions): void {
  Speech.speak(text, {
    onDone: () => handlers.onDone?.(),
    onStopped: () => handlers.onDone?.(),
    onError: () => handlers.onError?.(),
  });
}

/**
 * How one clip ended. `superseded` means a newer utterance took the players
 * over mid-clip, and the loser must touch no shared state on its way out.
 */
type ClipResult = 'ended' | 'error' | 'superseded';

/**
 * Start one clip, resolving when playback has STARTED; `onFinish` fires when it
 * ends, fails, or is superseded.
 *
 * The two are separate events because the queue needs both: the caller returns
 * to the user on the first (their spinner is about latency, not length) and
 * queues the next chunk on the second.
 */
async function startClip(uri: string, mine: number, onFinish: (r: ClipResult) => void): Promise<void> {
  const finish = (result: 'ended' | 'error') => {
    if (generation !== mine) { onFinish('superseded'); return; } // the newer speak owns state now
    teardownPlayers();
    onFinish(result);
  };

  if (Platform.OS === 'web') {
    const el = new (globalThis as any).Audio(uri) as HTMLAudioElement;
    activeWebAudio = el;
    el.onended = () => finish('ended');
    el.onerror = () => finish('error');
    await el.play();
    return;
  }

  // Honour the silent switch: a user who tapped "read aloud" meant to hear it.
  await Audio.setAudioModeAsync(SHARED_PLAYBACK_MODE).catch(() => {});
  const { sound } = await Audio.Sound.createAsync({ uri }, { shouldPlay: true });
  if (generation !== mine) {
    // Interrupted while the file was loading — drop it rather than start talking.
    sound.unloadAsync().catch(() => {});
    onFinish('superseded');
    return;
  }
  activeSound = sound;
  sound.setOnPlaybackStatusUpdate((status) => {
    if (!status.isLoaded || !status.didJustFinish) return;
    finish('ended');
  });
}

async function playUri(uri: string, mine: number, handlers: SpeakOptions): Promise<void> {
  await startClip(uri, mine, (result) => {
    if (result === 'ended') handlers.onDone?.();
    else if (result === 'error') handlers.onError?.();
  });
}

/** A clip's end, awaitable. */
function deferredFinish(): { promise: Promise<ClipResult>; resolve: (r: ClipResult) => void } {
  let resolve!: (r: ClipResult) => void;
  const promise = new Promise<ClipResult>((res) => { resolve = res; });
  return { promise, resolve };
}

/** Synthesize one chunk in the user's chosen voice → a playable URI. */
async function synthesizeToUri(text: string): Promise<string> {
  const { audioBase64, mimeType } = await synthesizeSpeechBytes(text);
  return audioBytesToUri(audioBase64, mimeType);
}

/**
 * Wrap a caller's handlers so the activity flag is released when this utterance
 * ends — unless a newer speak has already taken it over, in which case that one
 * owns the flag and this one must not clear it.
 */
function withActivity(mine: number, handlers: SpeakOptions): SpeakOptions {
  const release = () => { if (generation === mine) setActivity(false, null); };
  return {
    onDone: () => { release(); handlers.onDone?.(); },
    onError: () => { release(); handlers.onError?.(); },
  };
}

// ── Preview clip memo ────────────────────────────────────────────────────────
// Playable URIs for voices auditioned this session, keyed by model|voice|locale.
// The server already serves these from a cache shared across accounts, so this
// only saves the round trip and (on native) a second identical file write — but
// tapping back and forth between two voices is exactly how people choose one,
// and that comparison should be instant rather than a network wait each way.
//
// Bounded because each native entry owns a file in the cache directory. FIFO
// eviction: with ~90 voices in the largest catalog, the cap is "the handful you
// are actually comparing", not "everything you clicked".
const PREVIEW_MEMO_MAX = 24;
const previewMemo = new Map<string, string>();

const previewMemoKey = (o: { modelId: string; voice: string; locale?: string }) =>
  `${o.modelId}|${o.voice}|${o.locale || ''}`;

/** Clear the session's preview URIs (the sheet does this on close). */
export function clearVoicePreviewCache(): void {
  previewMemo.clear();
}

/**
 * Audition one specific model + voice, ignoring the saved preference.
 *
 * Separate from `speakText` because the intent is inverted: read-aloud speaks
 * with whatever the user has chosen, while this exists to let them hear a voice
 * they have *not* chosen yet. It deliberately does not fall back to the device
 * engine — a preview that silently plays the system voice would be telling the
 * user this is what the voice they're auditioning sounds like, which is a lie.
 *
 * The clip comes from /api/audio/voice-preview rather than /api/audio/speech:
 * same synthesis, but the sentence is the server's own and the result is cached
 * globally, so a given voice is paid for once across all accounts instead of
 * once per tap. That is also why there is no `text` parameter — see
 * `fetchVoicePreview`.
 *
 * Resolves when playback has started; rejects if synthesis failed, so the
 * caller can drop its spinner either way.
 */
export async function previewVoice(
  opts: { modelId: string; voice: string; locale?: string },
): Promise<void> {
  if (!opts?.modelId || !opts?.voice) return;

  await stopSpeech();
  const mine = generation;
  setActivity(true, null);

  try {
    const key = previewMemoKey(opts);
    let uri = previewMemo.get(key);
    if (!uri) {
      const { audioBase64, mimeType } = await fetchVoicePreview(opts);
      if (generation !== mine) return; // user moved on mid-fetch
      uri = await audioBytesToUri(audioBase64, mimeType);
      if (previewMemo.size >= PREVIEW_MEMO_MAX) {
        const oldest = previewMemo.keys().next().value;
        if (oldest !== undefined) previewMemo.delete(oldest);
      }
      previewMemo.set(key, uri);
    }
    if (generation !== mine) return;
    await playUri(uri, mine, withActivity(mine, {}));
  } catch (err) {
    if (generation === mine) setActivity(false, null);
    throw err;
  }
}

/**
 * Read the remaining chunks in order, synthesizing the next while the current
 * one plays.
 *
 * Detached from `speakText` on purpose: the caller is told the reading started
 * and drops its spinner, while this runs for as long as the text lasts. Every
 * hop re-checks `generation`, so a stop — from this surface, another one, or
 * the nav rail — ends the reading rather than leaving a queue talking over the
 * next thing the user asks for.
 *
 * `handlers` is only settled once, at the true end: the activity flag has to
 * stay engaged across the seams or the global stop would disappear between
 * chunks.
 */
async function speakQueue(
  chunks: string[],
  firstFinished: Promise<ClipResult>,
  mine: number,
  handlers: SpeakOptions,
  options: SpeakOptions,
): Promise<void> {
  let finished = firstFinished;

  for (let i = 1; i < chunks.length; i++) {
    // Started before awaiting the clip below, which is the whole trick: the
    // next chunk is synthesized during playback rather than after it.
    const pending = synthesizeToUri(chunks[i]);
    pending.catch(() => {}); // settled at the await below; this only disarms the unhandled-rejection warning

    const result = await finished;
    if (result === 'superseded' || generation !== mine) return;
    if (result === 'error') { handlers.onError?.(); return; }

    let uri: string;
    try {
      uri = await pending;
    } catch (err: any) {
      // The rest can't be synthesized — read what's left in the device voice
      // rather than stopping mid-result, and say why the voice changed.
      const rest = chunks.slice(i).join(' ');
      if (generation !== mine) return;
      reportDeviceFallback(
        options,
        typeof err?.message === 'string' && err?.code ? err.message : i18n.t('voice.errors.ttsFailed'),
        err,
        rest.length,
      );
      speakOnDevice(rest, handlers);
      return;
    }
    if (generation !== mine) return;

    const next = deferredFinish();
    try {
      await startClip(uri, mine, next.resolve);
    } catch {
      handlers.onError?.();
      return;
    }
    finished = next.promise;
  }

  const last = await finished;
  if (last === 'ended') handlers.onDone?.();
  else if (last === 'error') handlers.onError?.();
}

/**
 * Speak `text`, interrupting anything already playing.
 *
 * Long text is read as a queue of chunks rather than one clip — see
 * `speakQueue` and `READ_ALOUD_CHUNKING`. That is invisible to callers: the
 * promise still resolves when the first sound starts, `onDone` still fires once
 * at the true end, and `id`/`useSpeakingId` stay claimed throughout.
 *
 * Resolves once playback has *started* (or the fallback has been handed off),
 * not when it ends — callers track completion through `onDone`. Returns the
 * engine used so the caller can distinguish "synthesizing" latency from the
 * device engine's instant start.
 */
export async function speakText(text: string, options: SpeakOptions = {}): Promise<'server' | 'device'> {
  const trimmed = (text || '').trim();
  if (!trimmed) { options.onDone?.(); return 'device'; }

  await stopSpeech();
  const mine = generation;
  // Engage before synthesis, not after: the seconds spent waiting for the clip
  // are seconds the user may want to back out of.
  setActivity(true, options.id ?? null);
  const handlers = withActivity(mine, options);

  if (isGuestSession()) {
    speakOnDevice(trimmed, handlers);
    return 'device';
  }

  // One request per chunk, not per utterance — see READ_ALOUD_CHUNKING for the
  // two measurements that decide the sizes. Short text is a single chunk and
  // takes the same path it always did.
  const chunks = chunkForReadAloud(trimmed);
  // Nothing speakable survived the strip (a bare rule, an image-only line). Not
  // a failure, and not worth a synthesis request or a fallback notice.
  if (chunks.length === 0) { handlers.onDone?.(); return 'device'; }

  try {
    const uri = await synthesizeToUri(chunks[0]);
    if (generation !== mine) return 'server'; // user moved on mid-synthesis
    if (chunks.length === 1) {
      await playUri(uri, mine, handlers);
      return 'server';
    }
    // Hand back as soon as the first chunk is audible; the rest of the reading
    // is driven behind it, one chunk ahead of the audio.
    const first = deferredFinish();
    await startClip(uri, mine, first.resolve);
    void speakQueue(chunks, first.promise, mine, handlers, options);
    return 'server';
  } catch (err: any) {
    // Out of credits / offline / provider down / undecodable audio — fall back
    // so the button always does something audible, and report *why* the voice
    // changed. VoiceChatError messages are already localized; anything else is
    // reported as the generic synthesis failure.
    if (generation !== mine) return 'server';
    reportDeviceFallback(
      options,
      typeof err?.message === 'string' && err?.code ? err.message : i18n.t('voice.errors.ttsFailed'),
      err,
      trimmed.length,
    );
    speakOnDevice(trimmed, handlers);
    return 'device';
  }
}
