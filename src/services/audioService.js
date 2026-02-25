const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");
const dns = require("dns").promises;
const { pipeline } = require("stream/promises");
const { Readable, Transform } = require("stream");

const {
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_MIME_TYPES,
  ALLOWED_AUDIO_EXTENSIONS
} = require("../config/constants");

const projectRoot = path.resolve(__dirname, "..", "..");
const audioDirectory = path.join(projectRoot, "uploads", "audio");
const MAX_DOWNLOAD_REDIRECTS = 3;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata",
  "metadata.google.internal"
]);

const blockedAddressList = new net.BlockList();
const BLOCKED_IPV4_SUBNETS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
];
const BLOCKED_IPV6_SUBNETS = [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["2001:db8::", 32]
];

for (const [address, prefix] of BLOCKED_IPV4_SUBNETS) {
  blockedAddressList.addSubnet(address, prefix, "ipv4");
}

for (const [address, prefix] of BLOCKED_IPV6_SUBNETS) {
  blockedAddressList.addSubnet(address, prefix, "ipv6");
}

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

function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function unwrapIpv4MappedAddress(address) {
  const lowerAddress = String(address || "").toLowerCase();
  if (!lowerAddress.startsWith("::ffff:")) {
    return address;
  }

  const mappedIpv4 = lowerAddress.slice(7);
  return net.isIP(mappedIpv4) === 4 ? mappedIpv4 : address;
}

function isBlockedIpAddress(address) {
  const normalizedAddress = unwrapIpv4MappedAddress(address);
  const family = net.isIP(normalizedAddress);
  if (!family) {
    return true;
  }

  return blockedAddressList.check(normalizedAddress, family === 6 ? "ipv6" : "ipv4");
}

async function validateRemoteAudioUrl(candidateUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(candidateUrl);
  } catch (error) {
    throw new Error("Audio URL must be a valid http/https URL.");
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error("Audio URL must be a valid http/https URL.");
  }

  if (parsedUrl.username || parsedUrl.password) {
    throw new Error("Audio URL credentials are not allowed.");
  }

  const hostname = normalizeHostname(parsedUrl.hostname);
  if (!hostname) {
    throw new Error("Audio URL hostname is invalid.");
  }

  if (BLOCKED_HOSTNAMES.has(hostname) || hostname.endsWith(".localhost")) {
    throw new Error("Audio URL must not target local network resources.");
  }

  if (net.isIP(hostname)) {
    if (isBlockedIpAddress(hostname)) {
      throw new Error("Audio URL must resolve to a public internet address.");
    }

    return parsedUrl.toString();
  }

  let dnsRecords;
  try {
    dnsRecords = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw new Error("Unable to resolve audio URL hostname.");
  }

  if (!Array.isArray(dnsRecords) || dnsRecords.length === 0) {
    throw new Error("Unable to resolve audio URL hostname.");
  }

  for (const record of dnsRecords) {
    if (!record || !record.address || isBlockedIpAddress(record.address)) {
      throw new Error("Audio URL must resolve to a public internet address.");
    }
  }

  return parsedUrl.toString();
}

async function fetchAudioResponse(candidateUrl) {
  let currentUrl = candidateUrl;

  for (let redirectCount = 0; redirectCount <= MAX_DOWNLOAD_REDIRECTS; redirectCount += 1) {
    const safeUrl = await validateRemoteAudioUrl(currentUrl);
    const response = await fetch(safeUrl, { redirect: "manual" });

    if (REDIRECT_STATUS_CODES.has(response.status)) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error("Audio URL redirect is missing a location header.");
      }

      if (response.body) {
        try {
          await response.body.cancel();
        } catch (error) {
          // Best-effort cleanup for redirect response streams.
        }
      }

      currentUrl = new URL(location, safeUrl).toString();
      continue;
    }

    return {
      response,
      finalUrl: safeUrl
    };
  }

  throw new Error("Audio URL redirected too many times.");
}

async function downloadAudioFromUrl(url) {
  const { response, finalUrl } = await fetchAudioResponse(url);

  if (!response.ok || !response.body) {
    throw new Error(`Unable to download audio from URL (status ${response.status}).`);
  }

  const mimeType = getMimeWithoutParameters(response.headers.get("content-type"));

  const sourcePathname = new URL(finalUrl).pathname;
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
