const TEMPO_OPTIONS = ["Fast", "Medium", "Slow"];

const MODE_OPTIONS = ["Major", "Minor", "Ahavah Rabbah (Freygish)", "Magen Avot", "Adonai Malach"];
const METER_OPTIONS = ["4/4", "3/4", "6/8", "Other"];

const OCCASION_TAG_OPTIONS = [
  "Weekday",
  "Shabbat",
  "Festivals",
  "Rosh Chodesh",
  "High Holidays"
];

const PRAYER_TIME_TAG_OPTIONS = [
  "Shacharit",
  "Musaf",
  "Minchah",
  "Maariv"
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
  MODE_OPTIONS,
  METER_OPTIONS,
  OCCASION_TAG_OPTIONS,
  PRAYER_TIME_TAG_OPTIONS,
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_MIME_TYPES,
  ALLOWED_AUDIO_EXTENSIONS
};
