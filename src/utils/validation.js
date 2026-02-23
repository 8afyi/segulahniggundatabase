function sanitizeText(value) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim();
}

function parseCsvInput(value) {
  if (typeof value !== "string") {
    return [];
  }

  const dedup = new Map();

  for (const raw of value.split(",")) {
    const cleaned = raw.trim();
    if (!cleaned) {
      continue;
    }

    const dedupKey = cleaned.toLowerCase();
    if (!dedup.has(dedupKey)) {
      dedup.set(dedupKey, cleaned);
    }
  }

  return Array.from(dedup.values());
}

function ensureHttpUrl(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }

  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch (error) {
    return null;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }

  return parsed.toString();
}

module.exports = {
  sanitizeText,
  parseCsvInput,
  ensureHttpUrl
};
