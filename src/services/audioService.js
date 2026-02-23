const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pipeline } = require("stream/promises");
const { Readable, Transform } = require("stream");

const {
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_MIME_TYPES,
  ALLOWED_AUDIO_EXTENSIONS
} = require("../config/constants");

const projectRoot = path.resolve(__dirname, "..", "..");
const audioDirectory = path.join(projectRoot, "uploads", "audio");

fs.mkdirSync(audioDirectory, { recursive: true });

function normalizeExtension(ext) {
  if (!ext) {
    return "";
  }
  return ext.toLowerCase();
}

function getMimeWithoutParameters(contentType) {
  if (!contentType) {
    return "";
  }
  return String(contentType).split(";")[0].trim().toLowerCase();
}

function extensionFromMime(mime) {
  const map = {
    "audio/mpeg": ".mp3",
    "audio/mp3": ".mp3",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
    "audio/wave": ".wav",
    "audio/ogg": ".ogg",
    "audio/webm": ".webm",
    "audio/flac": ".flac",
    "audio/x-flac": ".flac",
    "audio/aac": ".aac",
    "audio/mp4": ".m4a",
    "audio/x-m4a": ".m4a"
  };

  return map[mime] || "";
}

function generateFilename(extension) {
  const safeExtension = extension || ".bin";
  return `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${safeExtension}`;
}

function resolveAudioPath(filename) {
  return path.join(audioDirectory, filename);
}

function isAllowedAudioType({ mimeType, extension }) {
  if (mimeType && ALLOWED_AUDIO_MIME_TYPES.has(mimeType)) {
    return true;
  }

  if (extension && ALLOWED_AUDIO_EXTENSIONS.has(extension)) {
    return true;
  }

  return false;
}

function getFileMetadata(file) {
  const extension = normalizeExtension(path.extname(file.originalname || file.filename || ""));
  const mimeType = getMimeWithoutParameters(file.mimetype);

  return {
    extension,
    mimeType,
    originalFilename: file.originalname || ""
  };
}

function removeAudioFile(filename) {
  if (!filename) {
    return;
  }

  const targetPath = resolveAudioPath(path.basename(filename));
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
}

async function downloadAudioFromUrl(url) {
  const response = await fetch(url);

  if (!response.ok || !response.body) {
    throw new Error(`Unable to download audio from URL (status ${response.status}).`);
  }

  const mimeType = getMimeWithoutParameters(response.headers.get("content-type"));

  const sourcePathname = new URL(url).pathname;
  const extensionFromPath = normalizeExtension(path.extname(sourcePathname));
  const extensionFromHeader = extensionFromMime(mimeType);
  const safePathExtension = ALLOWED_AUDIO_EXTENSIONS.has(extensionFromPath)
    ? extensionFromPath
    : "";
  const chosenExtension = safePathExtension || extensionFromHeader;

  if (!isAllowedAudioType({ mimeType, extension: chosenExtension })) {
    throw new Error("URL does not point to a supported audio format.");
  }

  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_AUDIO_BYTES) {
    throw new Error("Audio file exceeds 20MB limit.");
  }

  const storedFilename = generateFilename(chosenExtension);
  const destinationPath = resolveAudioPath(storedFilename);

  let bytesWritten = 0;

  const sizeGuard = new Transform({
    transform(chunk, encoding, callback) {
      bytesWritten += chunk.length;
      if (bytesWritten > MAX_AUDIO_BYTES) {
        callback(new Error("Audio file exceeds 20MB limit."));
        return;
      }
      callback(null, chunk);
    }
  });

  try {
    await pipeline(
      Readable.fromWeb(response.body),
      sizeGuard,
      fs.createWriteStream(destinationPath, { flags: "wx" })
    );

    if (bytesWritten === 0) {
      throw new Error("Downloaded audio file was empty.");
    }

    return {
      storedFilename,
      mimeType,
      originalFilename: path.basename(sourcePathname) || storedFilename,
      size: bytesWritten
    };
  } catch (error) {
    if (fs.existsSync(destinationPath)) {
      fs.unlinkSync(destinationPath);
    }
    throw error;
  }
}

module.exports = {
  MAX_AUDIO_BYTES,
  audioDirectory,
  resolveAudioPath,
  getFileMetadata,
  extensionFromMime,
  isAllowedAudioType,
  generateFilename,
  removeAudioFile,
  downloadAudioFromUrl
};
