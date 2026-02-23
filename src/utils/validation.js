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

function parseMultiSelectInput(value, allowedValues = []) {
  const allowedSet = new Set(allowedValues);
  const rawList = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  const dedup = new Set();
  const result = [];

  for (const item of rawList) {
    if (typeof item !== "string") {
      continue;
    }

    const cleaned = item.trim();
    if (!cleaned || dedup.has(cleaned)) {
      continue;
    }

    if (allowedSet.size > 0 && !allowedSet.has(cleaned)) {
      continue;
    }

    dedup.add(cleaned);
    result.push(cleaned);
  }

  return result;
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
  parseMultiSelectInput,
  ensureHttpUrl
};
