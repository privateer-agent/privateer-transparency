import { Platform } from 'react-native';
import * as FileSystem from 'expo-file-system/legacy';
import authService from './authService';
import { getActionModel, resolveTtsVoice, getRequireZdr, getAllowNonZdrMedia } from './modelService';
import i18n from '../i18n';

/**
 * Network + audio-codec glue for voice chat mode. The state machine and the
 * recording/playback lifecycle live in `useVoiceChat`; this module only does
 * the OpenRouter-proxied STT/TTS round-trips and the base64 ⇄ file plumbing.
 *
 * E2EE (CLAUDE.md §5): the recorded audio (STT) and the AI reply text (TTS)
 * transit the authenticated server proxy exactly like chat inference — never
 * persisted. The transcript/AI text are encrypted client-side before any save
 * by the existing chat send path; nothing here writes user content to the DB.
 */

export class VoiceChatError extends Error {
  code: string;
  constructor(message: string, code: string) {
    super(message);
    this.code = code;
  }
}

/** Pick the OpenRouter audio `format` token from a recording URI / platform. */
export function formatForRecordingUri(uri: string): string {
  const ext = (uri.split('?')[0].split('.').pop() || '').toLowerCase();
  if (ext === 'caf' || ext === 'aac') return 'aac';
  if (ext === 'wav') return 'wav';
  if (ext === 'webm') return 'webm';
  if (ext === 'ogg') return 'ogg';
  if (ext === 'mp3') return 'mp3';
  if (ext === 'm4a' || ext === 'mp4') return 'm4a';
  // Web MediaRecorder generally yields webm; native presets yield m4a.
  return Platform.OS === 'web' ? 'webm' : 'm4a';
}

/** Read a recording (file:// on native, blob: on web) into raw base64. */
async function recordingUriToBase64(uri: string): Promise<string> {
  if (Platform.OS === 'web') {
    const blob = await (await fetch(uri)).blob();
    const dataUrl: string = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
    return dataUrl.split(',')[1] || '';
  }
  return FileSystem.readAsStringAsync(uri, { encoding: FileSystem.EncodingType.Base64 });
}

/**
 * Transcribe a recorded utterance via OpenRouter STT. Returns the trimmed
 * transcript (possibly empty when the clip was silence/noise). `format` is the
 * OpenRouter audio token from the recorder; falls back to inferring from the URI.
 */
export async function transcribeRecording(uri: string, format?: string): Promise<string> {
  const audioBase64 = await recordingUriToBase64(uri);
  if (!audioBase64) return '';
  const stt = await getActionModel('stt');

  const res = await authService.makeAuthenticatedRequest('/api/audio/transcribe', {
    method: 'POST',
    body: JSON.stringify({ audioBase64, format: format || formatForRecordingUri(uri), sttModelId: stt.modelId }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({} as any));
    if (data?.code === 'FEATURE_LOCKED') {
      throw new VoiceChatError(data?.message || i18n.t('voice.errors.featureLocked'), 'FEATURE_LOCKED');
    }
    if (res.status === 402 || data?.code === 'INSUFFICIENT_FUNDS') {
      throw new VoiceChatError(i18n.t('voice.errors.creditsStt'), 'INSUFFICIENT_FUNDS');
    }
    throw new VoiceChatError(i18n.t('voice.errors.sttFailed'), 'STT_FAILED');
  }
  const data = await res.json();
  return (typeof data?.text === 'string' ? data.text : '').trim();
}

/** Max input the server accepts in one TTS call — mirrors audioService.js. */
export const TTS_MAX_CHARS = 8000;

/**
 * Synthesize spoken audio via OpenRouter TTS and return the raw base64 + mime.
 *
 * Callers that only need to play the result want `synthesizeSpeechToUri`; this
 * lower-level form exists for the Audio studio, which has to encrypt the bytes
 * before persisting them and must not round-trip them through a plaintext
 * temp file to do so.
 *
 * The model and voice default to the user's saved TTS prefs. Overrides let a
 * caller synthesize with a selection the user hasn't committed yet.
 */
export async function synthesizeSpeechBytes(
  text: string,
  opts: { modelId?: string; voice?: string } = {},
): Promise<{ audioBase64: string; mimeType: string; modelId: string; voice: string }> {
  const trimmed = (text || '').trim();
  if (!trimmed) throw new VoiceChatError(i18n.t('voice.errors.nothingToSpeak'), 'TTS_EMPTY');

  // The voice pref is model-specific — validate it against the selected TTS
  // model's supported voices (carrying an old/foreign voice would error upstream).
  const modelId = opts.modelId || (await getActionModel('tts')).modelId;
  const voice = opts.voice || (await resolveTtsVoice(modelId));
  // The voice catalog now spans confidential-compute models and non-ZDR ones
  // (fal). Which of those an account may use is a *device* fact on the local
  // backend — the prefs never leave it (CLAUDE.md §2) — so they travel with the
  // request exactly as sfxService sends them, rather than being read server-side.
  const [requireZdr, allowNonZdrMedia] = await Promise.all([
    getRequireZdr(),
    getAllowNonZdrMedia(),
  ]);

  const res = await authService.makeAuthenticatedRequest('/api/audio/speech', {
    method: 'POST',
    body: JSON.stringify({ text: trimmed, ttsModelId: modelId, voice, requireZdr, allowNonZdrMedia }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({} as any));
    if (data?.code === 'FEATURE_LOCKED') {
      throw new VoiceChatError(data?.message || 'Voice chat requires a higher plan.', 'FEATURE_LOCKED');
    }
    // A non-ZDR voice with the opt-in off. A setting, not a failure — callers
    // branch on this code to offer the toggle, as they do for sound effects.
    if (res.status === 403 || data?.code === 'ZDR_MEDIA_BLOCKED') {
      throw new VoiceChatError(i18n.t('voice.errors.zdrBlocked'), 'ZDR_MEDIA_BLOCKED');
    }
    if (res.status === 402 || data?.code === 'INSUFFICIENT_FUNDS') {
      throw new VoiceChatError(i18n.t('voice.errors.creditsTts'), 'INSUFFICIENT_FUNDS');
    }
    throw new VoiceChatError(i18n.t('voice.errors.ttsFailed'), 'TTS_FAILED');
  }
  const data = await res.json();
  const audioBase64: string = data?.audioBase64 || '';
  const mimeType: string = data?.mimeType || 'audio/mpeg';
  if (!audioBase64) throw new VoiceChatError(i18n.t('voice.errors.ttsEmpty'), 'TTS_EMPTY');

  return { audioBase64, mimeType, modelId, voice };
}

/**
 * Fetch the audition clip for one model + voice → { audioBase64, mimeType }.
 *
 * Not `synthesizeSpeechBytes` with a sample string, deliberately. The clip this
 * returns is served from a cache shared by every account (server-side
 * voicePreviewStore), and the price of that sharing is that the caller doesn't
 * get to choose the words: we send a locale, the server reads the sample
 * sentence out of its own catalog, and the first account to audition a given
 * voice is the last one to pay for it. Passing text here would turn a cache of
 * app assets into a cross-account store of user content — hence no text param.
 *
 * `cached` comes back for diagnostics only; nothing branches on it today.
 */
export async function fetchVoicePreview(
  opts: { modelId: string; voice: string; locale?: string },
): Promise<{ audioBase64: string; mimeType: string; cached: boolean }> {
  // The same two prefs the synthesis routes are sent, and for the same reason:
  // /voice-preview runs the ZDR gate before the cache read, so a preview of a
  // non-ZDR (fal) voice is blocked unless this request carries the opt-in. On
  // the local backend those prefs exist ONLY on this device (CLAUDE.md §2), so
  // omitting them made the server fall back to a preference it cannot see and
  // 403 every fal voice — auditioning silently did nothing while *selecting*
  // the same voice worked, because /speech sends them.
  const [requireZdr, allowNonZdrMedia] = await Promise.all([
    getRequireZdr(),
    getAllowNonZdrMedia(),
  ]);

  const res = await authService.makeAuthenticatedRequest('/api/audio/voice-preview', {
    method: 'POST',
    body: JSON.stringify({
      ttsModelId: opts.modelId,
      voice: opts.voice,
      locale: opts.locale || i18n.language,
      requireZdr,
      allowNonZdrMedia,
    }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({} as any));
    if (data?.code === 'FEATURE_LOCKED') {
      throw new VoiceChatError(data?.message || i18n.t('voice.errors.featureLocked'), 'FEATURE_LOCKED');
    }
    // A non-ZDR voice with the opt-in off — a setting, not a failure. Mapped
    // like the synthesis path so the picker can name the toggle that fixes it
    // instead of reporting a generic provider error.
    if (res.status === 403 || data?.code === 'ZDR_MEDIA_BLOCKED') {
      throw new VoiceChatError(i18n.t('voice.errors.zdrBlocked'), 'ZDR_MEDIA_BLOCKED');
    }
    if (res.status === 402 || data?.code === 'INSUFFICIENT_FUNDS') {
      throw new VoiceChatError(i18n.t('voice.errors.creditsTts'), 'INSUFFICIENT_FUNDS');
    }
    throw new VoiceChatError(i18n.t('voice.errors.ttsFailed'), 'TTS_FAILED');
  }
  const data = await res.json();
  const audioBase64: string = data?.audioBase64 || '';
  const mimeType: string = data?.mimeType || 'audio/mpeg';
  if (!audioBase64) throw new VoiceChatError(i18n.t('voice.errors.ttsEmpty'), 'TTS_EMPTY');
  return { audioBase64, mimeType, cached: !!data?.cached };
}

/**
 * Synthesize spoken audio for the AI reply via OpenRouter TTS and return a
 * playable URI: a cached file:// on native, a data: URI on web.
 */
export async function synthesizeSpeechToUri(
  text: string,
  opts: { modelId?: string; voice?: string } = {},
): Promise<string> {
  const { audioBase64, mimeType } = await synthesizeSpeechBytes(text, opts);
  return audioBytesToUri(audioBase64, mimeType);
}

/**
 * Turn a base64 audio payload into something a player can open: a cache file on
 * native, a data: URI on web (and anywhere the cache directory is unavailable).
 */
export async function audioBytesToUri(b64: string, mime: string): Promise<string> {
  if (Platform.OS === 'web' || typeof FileSystem.cacheDirectory !== 'string' || !FileSystem.cacheDirectory) {
    return `data:${mime};base64,${b64}`;
  }
  const ext = extForAudioMime(mime);
  const path = `${FileSystem.cacheDirectory}voice_reply_${Date.now()}.${ext}`;
  await FileSystem.writeAsStringAsync(path, b64, { encoding: FileSystem.EncodingType.Base64 });
  return path;
}

/** Map a server audio mime to a container extension the player understands. */
function extForAudioMime(mime: string): string {
  const m = (mime || '').toLowerCase();
  if (m.includes('mpeg') || m.includes('mp3')) return 'mp3';
  if (m.includes('wav') || m.includes('wave')) return 'wav';
  if (m.includes('aac')) return 'aac';
  if (m.includes('mp4') || m.includes('m4a')) return 'm4a';
  if (m.includes('ogg') || m.includes('opus')) return 'ogg';
  // Raw PCM has no container expo-av can open on its own — keep the extension so
  // the failure is explicit rather than a silent mis-decode.
  if (m.includes('pcm') || m.includes('l16')) return 'pcm';
  return 'mp3';
}
