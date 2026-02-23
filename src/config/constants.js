const TEMPO_OPTIONS = ["Fast", "Medium", "Slow"];

const MUSICAL_KEY_OPTIONS = [
  "C Major",
  "G Major",
  "D Major",
  "A Major",
  "E Major",
  "B Major",
  "F# Major",
  "C# Major",
  "F Major",
  "Bb Major",
  "Eb Major",
  "Ab Major",
  "Db Major",
  "Gb Major",
  "Cb Major",
  "A Minor",
  "E Minor",
  "B Minor",
  "F# Minor",
  "C# Minor",
  "G# Minor",
  "D# Minor",
  "A# Minor",
  "D Minor",
  "G Minor",
  "C Minor",
  "F Minor",
  "Bb Minor",
  "Eb Minor",
  "Ab Minor"
];

const MAX_AUDIO_BYTES = 20 * 1024 * 1024;

const ALLOWED_AUDIO_MIME_TYPES = new Set([
  "audio/mpeg",
  "audio/mp3",
  "audio/wav",
  "audio/x-wav",
  "audio/wave",
  "audio/ogg",
  "audio/webm",
  "audio/flac",
  "audio/x-flac",
  "audio/aac",
  "audio/mp4",
  "audio/x-m4a"
]);

const ALLOWED_AUDIO_EXTENSIONS = new Set([
  ".mp3",
  ".wav",
  ".ogg",
  ".webm",
  ".flac",
  ".aac",
  ".m4a",
  ".mp4"
]);

module.exports = {
  TEMPO_OPTIONS,
  MUSICAL_KEY_OPTIONS,
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_MIME_TYPES,
  ALLOWED_AUDIO_EXTENSIONS
};
