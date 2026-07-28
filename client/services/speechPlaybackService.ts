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
 * E2EE (CLAUDE.md §5): the message text transits the authenticated proxy for
 * inference exactly like the chat request that produced it, and is never
 * persisted server-side.
 */
import { Platform } from 'react-native';
import { Audio } from 'expo-av';
import * as Speech from 'expo-speech';
import { isGuestSession } from './sessionMode';
import { synthesizeSpeechBytes, audioBytesToUri } from './voiceChatService';

interface SpeakHandlers {
  /** Playback finished on its own. Not called when interrupted by stop(). */
  onDone?: () => void;
  /** Both engines failed — nothing is playing. */
  onError?: () => void;
}

let activeSound: Audio.Sound | null = null;
let activeWebAudio: HTMLAudioElement | null = null;
// Bumped by every stop() and every new speakText(). An in-flight synthesis
// compares the token it captured against this before playing, so a request the
// user has already moved on from can never start talking over the new one.
let generation = 0;

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
  teardownPlayers();
  await Speech.stop().catch(() => {});
}

/** Device/browser engine. Used for guests and as the synthesis fallback. */
function speakOnDevice(text: string, handlers: SpeakHandlers): void {
  Speech.speak(text, {
    onDone: () => handlers.onDone?.(),
    onStopped: () => handlers.onDone?.(),
    onError: () => handlers.onError?.(),
  });
}

async function playUri(uri: string, mine: number, handlers: SpeakHandlers): Promise<void> {
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
 * Audition one specific model + voice, ignoring the saved preference.
 *
 * Separate from `speakText` because the intent is inverted: read-aloud speaks
 * with whatever the user has chosen, while this exists to let them hear a voice
 * they have *not* chosen yet. It deliberately does not fall back to the device
 * engine — a preview that silently plays the system voice would be telling the
 * user this is what the voice they're auditioning sounds like, which is a lie.
 *
 * Resolves when playback has started; rejects if synthesis failed, so the
 * caller can drop its spinner either way.
 */
export async function previewVoice(
  text: string,
  opts: { modelId: string; voice: string },
): Promise<void> {
  const trimmed = (text || '').trim();
  if (!trimmed) return;

  await stopSpeech();
  const mine = generation;

  const { audioBase64, mimeType } = await synthesizeSpeechBytes(trimmed, opts);
  if (generation !== mine) return; // user moved on mid-synthesis
  const uri = await audioBytesToUri(audioBase64, mimeType);
  if (generation !== mine) return;
  await playUri(uri, mine, {});
}

/**
 * Speak `text`, interrupting anything already playing.
 *
 * Resolves once playback has *started* (or the fallback has been handed off),
 * not when it ends — callers track completion through `onDone`. Returns the
 * engine used so the caller can distinguish "synthesizing" latency from the
 * device engine's instant start.
 */
export async function speakText(text: string, handlers: SpeakHandlers = {}): Promise<'server' | 'device'> {
  const trimmed = (text || '').trim();
  if (!trimmed) { handlers.onDone?.(); return 'device'; }

  await stopSpeech();
  const mine = generation;

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
  } catch {
    // Out of credits / offline / provider down / undecodable audio — fall back
    // so the button always does something audible.
    if (generation !== mine) return 'server';
    speakOnDevice(trimmed, handlers);
    return 'device';
  }
}
