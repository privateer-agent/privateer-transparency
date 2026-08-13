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
 * nothing is worse than one that reads in the stock system voice.
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
import { useSyncExternalStore } from 'react';
import { Platform } from 'react-native';
import { Audio } from 'expo-av';
import * as Speech from 'expo-speech';
import { isGuestSession } from './sessionMode';
import { synthesizeSpeechBytes, fetchVoicePreview, audioBytesToUri } from './voiceChatService';
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
   */
  onFallback?: (reason: string) => void;
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
/** Non-reactive read, for callers outside React. */
export function isSpeechEngaged(): boolean {
  return engaged;
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

async function playUri(uri: string, mine: number, handlers: SpeakOptions): Promise<void> {
  const finish = () => {
    if (generation !== mine) return; // superseded — the newer speak owns state now
    teardownPlayers();
    handlers.onDone?.();
  };

  if (Platform.OS === 'web') {
    const el = new (globalThis as any).Audio(uri) as HTMLAudioElement;
    activeWebAudio = el;
    el.onended = finish;
    el.onerror = () => { if (generation === mine) { teardownPlayers(); handlers.onError?.(); } };
    await el.play();
    return;
  }

  // Honour the silent switch: a user who tapped "read aloud" meant to hear it.
  await Audio.setAudioModeAsync({ allowsRecordingIOS: false, playsInSilentModeIOS: true }).catch(() => {});
  const { sound } = await Audio.Sound.createAsync({ uri }, { shouldPlay: true });
  if (generation !== mine) {
    // Interrupted while the file was loading — drop it rather than start talking.
    sound.unloadAsync().catch(() => {});
    return;
  }
  activeSound = sound;
  sound.setOnPlaybackStatusUpdate((status) => {
    if (!status.isLoaded || !status.didJustFinish) return;
    finish();
  });
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
 * Speak `text`, interrupting anything already playing.
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

  try {
    const { audioBase64, mimeType } = await synthesizeSpeechBytes(trimmed);
    if (generation !== mine) return 'server'; // user moved on mid-synthesis
    const uri = await audioBytesToUri(audioBase64, mimeType);
    if (generation !== mine) return 'server';
    await playUri(uri, mine, handlers);
    return 'server';
  } catch (err: any) {
    // Out of credits / offline / provider down / undecodable audio — fall back
    // so the button always does something audible, and report *why* the voice
    // changed. VoiceChatError messages are already localized; anything else is
    // reported as the generic synthesis failure.
    if (generation !== mine) return 'server';
    options.onFallback?.(
      typeof err?.message === 'string' && err?.code ? err.message : i18n.t('voice.errors.ttsFailed'),
    );
    speakOnDevice(trimmed, handlers);
    return 'device';
  }
}
