const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const multer = require("multer");
const morgan = require("morgan");

const {
  initializeSchema,
  countUsers,
  createUser,
  getUserByUsername,
  getUserById,
  listUsers,
  deleteUser,
  updateUserPassword,
  upsertPublicGoogleUser,
  getPublicGoogleUserById,
  getLoginSecurityRecord,
  upsertLoginSecurityRecord,
  clearLoginSecurityRecord,
  createNiggun,
  updateNiggun,
  countNiggunim,
  listNiggunim,
  getNiggunById,
  listSingers,
  listAuthors,
  deleteNiggun
} = require("./src/db");
const { requireAuth } = require("./src/middleware/auth");
const {
  TEMPO_OPTIONS,
  MODE_OPTIONS,
  METER_OPTIONS,
  OCCASION_TAG_OPTIONS,
  PRAYER_TIME_TAG_OPTIONS,
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_EXTENSIONS
} = require("./src/config/constants");
const {
  sanitizeText,
  parseCsvInput,
  parseMultiSelectInput,
  ensureHttpUrl
} = require("./src/utils/validation");
const {
  audioDirectory,
  getFileMetadata,
  extensionFromMime,
  isAllowedAudioType,
  generateFilename,
  removeAudioFile,
  downloadAudioFromUrl
} = require("./src/services/audioService");

initializeSchema();

const app = express();
const projectRoot = __dirname;
const isProduction = process.env.NODE_ENV === "production";
const DEV_SESSION_SECRET = "dev-session-secret-change-me";

function parseTrustProxySetting(rawValue) {
  if (rawValue === undefined || rawValue === null || rawValue === "") {
    return null;
  }

  if (rawValue === "true") {
    return true;
  }

  if (rawValue === "false") {
    return false;
  }

  if (/^\d+$/.test(rawValue)) {
    return Number(rawValue);
  }

  return rawValue;
}

const explicitTrustProxy = parseTrustProxySetting(process.env.TRUST_PROXY);
if (explicitTrustProxy !== null) {
  app.set("trust proxy", explicitTrustProxy);
} else if (isProduction) {
  // Cloudflare -> Nginx -> Node
  app.set("trust proxy", 1);
}

function resolveSessionSecret() {
  const configuredSecret = sanitizeText(process.env.SESSION_SECRET || "");

  if (!configuredSecret) {
    if (isProduction) {
      throw new Error("SESSION_SECRET must be set in production.");
    }

    console.warn("SESSION_SECRET is not set. Using the development fallback secret.");
    return DEV_SESSION_SECRET;
  }

  if (isProduction && configuredSecret === DEV_SESSION_SECRET) {
    throw new Error("SESSION_SECRET cannot use the development fallback value in production.");
  }

  if (isProduction && configuredSecret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters in production.");
  }

  return configuredSecret;
}

function readGoogleClientSecretFile() {
  const configuredPath = sanitizeText(process.env.GOOGLE_CLIENT_SECRET_FILE || "");
  const candidatePaths = [];

  if (configuredPath) {
    candidatePaths.push(path.isAbsolute(configuredPath) ? configuredPath : path.join(projectRoot, configuredPath));
  } else {
    const localClientSecretFile = fs
      .readdirSync(projectRoot, { withFileTypes: true })
      .find((entry) => entry.isFile() && /^client_secret_.*\.json$/i.test(entry.name));
    if (localClientSecretFile) {
      candidatePaths.push(path.join(projectRoot, localClientSecretFile.name));
    }
  }

  for (const candidatePath of candidatePaths) {
    try {
      const raw = fs.readFileSync(candidatePath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && parsed.web && parsed.web.client_id && parsed.web.client_secret) {
        return {
          clientId: sanitizeText(parsed.web.client_id),
          clientSecret: sanitizeText(parsed.web.client_secret)
        };
      }
    } catch (error) {
      // Ignore and continue through candidate paths.
    }
  }

  return null;
}

function resolveGoogleAuthConfig() {
  const envClientId = sanitizeText(process.env.GOOGLE_CLIENT_ID || "");
  const envClientSecret = sanitizeText(process.env.GOOGLE_CLIENT_SECRET || "");
  const fileSecrets = readGoogleClientSecretFile();
  const clientId = envClientId || fileSecrets?.clientId || "";
  const clientSecret = envClientSecret || fileSecrets?.clientSecret || "";
  const callbackUrl = sanitizeText(process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback");

  return {
    clientId,
    clientSecret,
    callbackUrl
  };
}

const googleAuthConfig = resolveGoogleAuthConfig();
const googleAuthEnabled = Boolean(googleAuthConfig.clientId && googleAuthConfig.clientSecret);

if (googleAuthEnabled) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: googleAuthConfig.clientId,
        clientSecret: googleAuthConfig.clientSecret,
        callbackURL: googleAuthConfig.callbackUrl
      },
      (accessToken, refreshToken, profile, done) => {
        const primaryEmail = profile?.emails?.find((item) => item && item.value)?.value || "";
        const normalizedEmail = sanitizeText(primaryEmail).toLowerCase();
        if (!normalizedEmail) {
          return done(null, false);
        }

        return done(null, {
          googleSub: sanitizeText(profile?.id || ""),
          email: normalizedEmail,
          displayName: sanitizeText(profile?.displayName || ""),
          pictureUrl: sanitizeText(profile?.photos?.[0]?.value || "")
        });
      }
    )
  );
} else {
  const envClientIdSet = Boolean(sanitizeText(process.env.GOOGLE_CLIENT_ID || ""));
  const envClientSecretSet = Boolean(sanitizeText(process.env.GOOGLE_CLIENT_SECRET || ""));
  const envClientSecretFile = sanitizeText(process.env.GOOGLE_CLIENT_SECRET_FILE || "");
  console.warn(
    `Google public sign-in is disabled. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET (or add client_secret_*.json). ` +
      `Detected: GOOGLE_CLIENT_ID=${envClientIdSet ? "set" : "missing"}, ` +
      `GOOGLE_CLIENT_SECRET=${envClientSecretSet ? "set" : "missing"}, ` +
      `GOOGLE_CLIENT_SECRET_FILE=${envClientSecretFile || "unset"}.`
  );
}

app.set("view engine", "ejs");
app.set("views", path.join(projectRoot, "views"));

const cspDirectives = {
  defaultSrc: ["'self'"],
  baseUri: ["'self'"],
  connectSrc: ["'self'"],
  fontSrc: ["'self'", "https://fonts.gstatic.com"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
  imgSrc: ["'self'", "data:", "https:"],
  mediaSrc: ["'self'", "data:", "blob:"],
  objectSrc: ["'none'"],
  scriptSrc: ["'self'"],
  styleSrc: ["'self'", "https://fonts.googleapis.com"]
};

if (isProduction) {
  cspDirectives.upgradeInsecureRequests = [];
}

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: cspDirectives
    },
    hsts: isProduction
      ? {
          maxAge: 15552000,
          includeSubDomains: true,
          preload: false
        }
      : false,
    referrerPolicy: {
      policy: "no-referrer"
    }
  })
);
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(projectRoot, "public")));
app.use("/media", express.static(audioDirectory));

const configuredSessionStore = sanitizeText(process.env.SESSION_STORE || "").toLowerCase();
if (configuredSessionStore && configuredSessionStore !== "redis" && configuredSessionStore !== "memory") {
  console.warn(`Unknown SESSION_STORE=\"${configuredSessionStore}\". Falling back to environment default.`);
}

const useRedisSessions =
  configuredSessionStore === "redis"
    ? true
    : configuredSessionStore === "memory"
      ? false
      : isProduction;
const redisUrl = process.env.REDIS_URL || "redis://127.0.0.1:6379";
let redisClient = null;
let sessionStore = null;

if (useRedisSessions) {
  redisClient = createClient({ url: redisUrl });
  redisClient.on("error", (error) => {
    console.error("Redis session store error:", error);
  });

  sessionStore = new RedisStore({
    client: redisClient,
    prefix: `${process.env.SESSION_PREFIX || "segulah-niggun-database"}:sess:`
  });
} else if (isProduction) {
  console.warn("SESSION_STORE=memory is enabled in production. This is not recommended.");
} else {
  console.warn("Using in-memory session store for local development (SESSION_STORE=memory).");
}

const sessionOptions = {
  secret: resolveSessionSecret(),
  resave: false,
  saveUninitialized: false,
  proxy: isProduction,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 12
  }
};
if (sessionStore) {
  sessionOptions.store = sessionStore;
}
app.use(session(sessionOptions));
app.use(passport.initialize());

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  return req.session.csrfToken;
}

function tokensMatch(submittedToken, expectedToken) {
  if (typeof submittedToken !== "string" || typeof expectedToken !== "string") {
    return false;
  }

  const submittedBuffer = Buffer.from(submittedToken);
  const expectedBuffer = Buffer.from(expectedToken);

  if (submittedBuffer.length === 0 || submittedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(submittedBuffer, expectedBuffer);
}

function getCsrfFailureRedirect(req) {
  if (req.path.startsWith("/admin/login")) {
    return "/admin/login";
  }

  if (req.path.startsWith("/admin/setup")) {
    return "/admin/setup";
  }

  return "/admin";
}

function requireCsrfToken(req, res, next) {
  const submittedToken =
    (req.body && typeof req.body._csrf === "string" ? req.body._csrf : "") ||
    req.get("x-csrf-token") ||
    "";
  const expectedToken = req.session.csrfToken || "";

  if (!tokensMatch(submittedToken, expectedToken)) {
    if (req.file && req.file.filename) {
      removeAudioFile(req.file.filename);
    }

    setFlash(req, "error", "Security token is invalid or expired. Please retry.");
    return res.status(403).redirect(getCsrfFailureRedirect(req));
  }

  return next();
}

function attachAdminCsrfToken(req, res, next) {
  if (req.method === "GET" || req.method === "HEAD") {
    res.locals.csrfToken = ensureCsrfToken(req);
  }

  return next();
}

app.use((req, res, next) => {
  const flash = req.session.flash || null;
  res.locals.flash = flash;
  if (flash) {
    delete req.session.flash;
  }
  res.locals.csrfToken = null;

  if (req.session.userId) {
    const user = getUserById(req.session.userId);
    if (user) {
      res.locals.currentUser = user;
    } else {
      delete req.session.userId;
      res.locals.currentUser = null;
    }
  } else {
    res.locals.currentUser = null;
  }

  if (req.session.publicGoogleUserId) {
    const publicGoogleUser = getPublicGoogleUserById(req.session.publicGoogleUserId);
    if (publicGoogleUser) {
      res.locals.publicGoogleUser = publicGoogleUser;
    } else {
      delete req.session.publicGoogleUserId;
      res.locals.publicGoogleUser = null;
    }
  } else {
    res.locals.publicGoogleUser = null;
  }

  next();
});

app.use("/admin", attachAdminCsrfToken);

function toPositiveInt(rawValue, fallback) {
  const parsed = Number.parseInt(rawValue, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
}

const SORT_OPTIONS = [
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "title_asc", label: "Title (A-Z)" },
  { value: "title_desc", label: "Title (Z-A)" }
];
const ADMIN_NAV_ITEMS = [
  { key: "add", label: "Add Niggun", href: "/admin/niggunim/new" },
  { key: "existing", label: "Existing Niggunim", href: "/admin/niggunim" },
  { key: "users", label: "User Management", href: "/admin/users" }
];
const SORT_VALUES = new Set(SORT_OPTIONS.map((option) => option.value));
const SORT_LABELS = SORT_OPTIONS.reduce((accumulator, option) => {
  accumulator[option.value] = option.label;
  return accumulator;
}, {});
const DEFAULT_SORT_KEY = "newest";
const PUBLIC_PAGE_SIZE = Math.min(100, toPositiveInt(process.env.PUBLIC_PAGE_SIZE, 12));
const ADMIN_PAGE_SIZE = Math.min(200, toPositiveInt(process.env.ADMIN_PAGE_SIZE, 25));
const EASTERN_DATE_FORMATTER = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/New_York",
  year: "numeric",
  month: "long",
  day: "numeric"
});

const LOGIN_FAILURE_LIMIT = toPositiveInt(process.env.LOGIN_FAILURE_LIMIT, 5);
const LOGIN_FAILURE_WINDOW_MS = toPositiveInt(process.env.LOGIN_FAILURE_WINDOW_MINUTES, 15) * 60 * 1000;
const LOGIN_LOCKOUT_MS = toPositiveInt(process.env.LOGIN_LOCKOUT_MINUTES, 15) * 60 * 1000;
const LOGIN_RATE_LIMIT_MAX = toPositiveInt(process.env.LOGIN_RATE_LIMIT_MAX, 20);

function getClientIp(req) {
  return sanitizeText(String(req.ip || req.socket.remoteAddress || "")).toLowerCase();
}

function millisecondsUntil(isoDate) {
  if (!isoDate) {
    return 0;
  }

  const parsed = Date.parse(isoDate);
  if (!Number.isFinite(parsed)) {
    return 0;
  }

  return parsed - Date.now();
}

function formatLockWait(milliseconds) {
  const minutes = Math.max(1, Math.ceil(milliseconds / 60000));
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

function getActiveLockout(keyType, keyValue) {
  if (!keyValue) {
    return null;
  }

  const record = getLoginSecurityRecord(keyType, keyValue);
  if (!record || !record.lockedUntil) {
    return null;
  }

  const msRemaining = millisecondsUntil(record.lockedUntil);
  if (msRemaining <= 0) {
    clearLoginSecurityRecord(keyType, keyValue);
    return null;
  }

  return {
    msRemaining
  };
}

function recordLoginFailure(keyType, keyValue) {
  if (!keyValue) {
    return null;
  }

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const existing = getLoginSecurityRecord(keyType, keyValue);

  let failedCount = 1;
  let firstFailedAt = nowIso;
  let lockedUntil = null;

  if (existing) {
    const firstFailedMs = Date.parse(existing.firstFailedAt || nowIso);
    const withinWindow = Number.isFinite(firstFailedMs) && nowMs - firstFailedMs <= LOGIN_FAILURE_WINDOW_MS;

    if (withinWindow) {
      failedCount = existing.failedCount + 1;
      firstFailedAt = existing.firstFailedAt || nowIso;
    }
  }

  if (failedCount >= LOGIN_FAILURE_LIMIT) {
    lockedUntil = new Date(nowMs + LOGIN_LOCKOUT_MS).toISOString();
  }

  upsertLoginSecurityRecord({
    keyType,
    keyValue,
    failedCount,
    firstFailedAt,
    lockedUntil
  });

  return {
    failedCount,
    lockedUntil
  };
}

function clearLoginFailures(usernameKey, clientIpKey) {
  if (usernameKey) {
    clearLoginSecurityRecord("username", usernameKey);
  }

  if (clientIpKey) {
    clearLoginSecurityRecord("ip", clientIpKey);
  }
}

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: LOGIN_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    setFlash(req, "error", "Too many login attempts from this IP. Please try again later.");
    return res.status(429).redirect("/admin/login");
  }
});

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, audioDirectory);
    },
    filename: (req, file, cb) => {
      const metadata = getFileMetadata(file);
      const safeExtension = ALLOWED_AUDIO_EXTENSIONS.has(metadata.extension)
        ? metadata.extension
        : "";
      const extension = safeExtension || extensionFromMime(metadata.mimeType) || ".audio";
      cb(null, generateFilename(extension));
    }
  }),
  limits: {
    fileSize: MAX_AUDIO_BYTES
  },
  fileFilter: (req, file, cb) => {
    const metadata = getFileMetadata(file);
    if (!isAllowedAudioType(metadata)) {
      cb(new Error("Unsupported file type. Upload a browser-supported audio file."));
      return;
    }

    cb(null, true);
  }
});

function validateUsername(username) {
  return /^[A-Za-z0-9_\-]{3,32}$/.test(username);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function normalizeSortKey(rawSort) {
  const normalized = sanitizeText(rawSort || "");
  return SORT_VALUES.has(normalized) ? normalized : DEFAULT_SORT_KEY;
}

function normalizePage(rawPage) {
  return toPositiveInt(rawPage, 1);
}

function buildQueryString(query) {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        const cleaned = sanitizeText(item);
        if (cleaned) {
          params.append(key, cleaned);
        }
      }
      continue;
    }

    const cleaned = sanitizeText(value == null ? "" : String(value));
    if (cleaned) {
      params.set(key, cleaned);
    }
  }

  return params.toString();
}

function buildPagination(totalCount, requestedPage, pageSize) {
  const safeTotal = Number.isInteger(totalCount) && totalCount > 0 ? totalCount : 0;
  const totalPages = Math.max(1, Math.ceil(safeTotal / pageSize));
  const page = Math.min(Math.max(requestedPage, 1), totalPages);

  return {
    page,
    pageSize,
    totalCount: safeTotal,
    totalPages,
    offset: (page - 1) * pageSize,
    hasPrevious: page > 1,
    hasNext: page < totalPages,
    previousPage: page > 1 ? page - 1 : 1,
    nextPage: page < totalPages ? page + 1 : totalPages
  };
}

function toPathWithQuery(pathname, queryString) {
  return queryString ? `${pathname}?${queryString}` : pathname;
}

function normalizeAdminReturnTo(rawReturnTo, fallback = "/admin") {
  const cleaned = sanitizeText(rawReturnTo || "");
  if (!cleaned) {
    return fallback;
  }

  if (cleaned.startsWith("//")) {
    return fallback;
  }

  let parsed;
  try {
    parsed = new URL(cleaned, "http://localhost");
  } catch (error) {
    return fallback;
  }

  if (parsed.origin !== "http://localhost") {
    return fallback;
  }

  if (!parsed.pathname.startsWith("/admin")) {
    return fallback;
  }

  return `${parsed.pathname}${parsed.search}`;
}

function normalizePublicReturnTo(rawReturnTo, fallback = "/") {
  const cleaned = sanitizeText(rawReturnTo || "");
  if (!cleaned) {
    return fallback;
  }

  if (cleaned.startsWith("//")) {
    return fallback;
  }

  let parsed;
  try {
    parsed = new URL(cleaned, "http://localhost");
  } catch (error) {
    return fallback;
  }

  if (parsed.origin !== "http://localhost") {
    return fallback;
  }

  const pathname = parsed.pathname || "/";
  if (pathname.startsWith("/admin") || pathname.startsWith("/auth/google")) {
    return fallback;
  }

  return `${pathname}${parsed.search}`;
}

function canAccessPublicCatalog(req) {
  return Boolean(req.session.userId || req.session.publicGoogleUserId);
}

function requirePublicCatalogAccess(req, res, next) {
  if (canAccessPublicCatalog(req)) {
    return next();
  }

  const returnTo = normalizePublicReturnTo(req.originalUrl || req.url || "/", "/");
  return res.redirect(
    toPathWithQuery(
      "/public/login",
      buildQueryString({
        returnTo
      })
    )
  );
}

function buildPublicHeaderAction(req) {
  if (req.session.userId) {
    return { type: "link", href: "/admin", label: "Admin" };
  }

  if (req.session.publicGoogleUserId) {
    return { type: "link", href: "/public/logout", label: "Sign out" };
  }

  return { type: "link", href: "/public/login", label: "Sign in with Google" };
}

function toSefariaUrl(reference) {
  const cleanedReference = sanitizeText(reference || "").replace(/\s+/g, " ");
  if (!cleanedReference) {
    return "";
  }

  return `https://www.sefaria.org/${encodeURIComponent(cleanedReference)}`;
}

function parseScriptureReferences(rawInput) {
  if (typeof rawInput !== "string") {
    return [];
  }

  const dedup = new Map();
  const normalizedInput = rawInput.replace(/\\n/g, "\n");
  const rawItems = normalizedInput.split(/[\r\n,]+/);

  for (const rawItem of rawItems) {
    const cleanedReference = sanitizeText(rawItem);
    if (!cleanedReference) {
      continue;
    }

    const dedupKey = cleanedReference.toLowerCase();
    if (dedup.has(dedupKey)) {
      continue;
    }

    const sefariaUrl = toSefariaUrl(cleanedReference);
    if (!sefariaUrl) {
      continue;
    }

    dedup.set(dedupKey, {
      reference: cleanedReference,
      sefariaUrl
    });
  }

  return Array.from(dedup.values());
}

function buildAdminNavigation(activeKey) {
  return ADMIN_NAV_ITEMS.map((item) => ({
    ...item,
    active: item.key === activeKey
  }));
}

function normalizeFilters(
  query,
  availableModeOptions = MODE_OPTIONS,
  availableMeterOptions = METER_OPTIONS
) {
  const searchQuery = sanitizeText(query.q || "");
  const tempo = sanitizeText(query.tempo || "");
  const mode = sanitizeText(query.mode || query.key || "");
  const meter = sanitizeText(query.meter || "");
  const singer = sanitizeText(query.singer || "");
  const author = sanitizeText(query.author || "");
  const occasions = parseMultiSelectInput(query.occasions, OCCASION_TAG_OPTIONS);
  const prayerTimes = parseMultiSelectInput(query.prayerTimes, PRAYER_TIME_TAG_OPTIONS);

  return {
    searchQuery,
    tempo: TEMPO_OPTIONS.includes(tempo) ? tempo : "",
    mode: availableModeOptions.includes(mode) ? mode : "",
    meter: availableMeterOptions.includes(meter) ? meter : "",
    singer,
    author,
    occasions,
    prayerTimes
  };
}

function normalizeBasicFilters(query, availableModeOptions = MODE_OPTIONS) {
  const searchQuery = sanitizeText(query.q || "");
  const tempo = sanitizeText(query.tempo || "");
  const mode = sanitizeText(query.mode || query.key || "");

  return {
    searchQuery,
    tempo: TEMPO_OPTIONS.includes(tempo) ? tempo : "",
    mode: availableModeOptions.includes(mode) ? mode : "",
    meter: "",
    singer: "",
    author: "",
    occasions: [],
    prayerTimes: []
  };
}

function toEasternDateLabel(rawTimestamp) {
  const cleanedTimestamp = sanitizeText(rawTimestamp || "");
  if (!cleanedTimestamp) {
    return "";
  }

  const isoBase = cleanedTimestamp.includes("T") ? cleanedTimestamp : cleanedTimestamp.replace(" ", "T");
  const hasTimezone = /(?:[zZ]|[+-]\d{2}:\d{2})$/.test(isoBase);
  const isoWithTimezone = hasTimezone ? isoBase : `${isoBase}Z`;
  const parsedDate = new Date(isoWithTimezone);
  if (Number.isNaN(parsedDate.getTime())) {
    return cleanedTimestamp;
  }

  return EASTERN_DATE_FORMATTER.format(parsedDate);
}

function toFilterQueryState(filters, sortKey) {
  return {
    q: filters.searchQuery,
    tempo: filters.tempo,
    mode: filters.mode,
    meter: filters.meter,
    singer: filters.singer,
    author: filters.author,
    occasions: filters.occasions,
    prayerTimes: filters.prayerTimes,
    sort: sortKey
  };
}

function cloneFilterQueryState(queryState) {
  return {
    ...queryState,
    occasions: [...queryState.occasions],
    prayerTimes: [...queryState.prayerTimes]
  };
}

function buildActiveFilterChips(filters, sortKey, buildUrlForQueryState) {
  const queryState = toFilterQueryState(filters, sortKey);
  const chips = [];

  function addChip(label, updateQueryState) {
    const nextQueryState = cloneFilterQueryState(queryState);
    updateQueryState(nextQueryState);
    chips.push({
      label,
      url: buildUrlForQueryState(nextQueryState)
    });
  }

  if (queryState.q) {
    addChip(`Search: ${queryState.q}`, (nextQueryState) => {
      nextQueryState.q = "";
    });
  }

  if (queryState.tempo) {
    addChip(`Tempo: ${queryState.tempo}`, (nextQueryState) => {
      nextQueryState.tempo = "";
    });
  }

  if (queryState.mode) {
    addChip(`Mode: ${queryState.mode}`, (nextQueryState) => {
      nextQueryState.mode = "";
    });
  }

  if (queryState.meter) {
    addChip(`Meter: ${queryState.meter}`, (nextQueryState) => {
      nextQueryState.meter = "";
    });
  }

  if (queryState.singer) {
    addChip(`Singer: ${queryState.singer}`, (nextQueryState) => {
      nextQueryState.singer = "";
    });
  }

  if (queryState.author) {
    addChip(`Composer: ${queryState.author}`, (nextQueryState) => {
      nextQueryState.author = "";
    });
  }

  for (const occasion of queryState.occasions) {
    addChip(`Service Tag: ${occasion}`, (nextQueryState) => {
      nextQueryState.occasions = nextQueryState.occasions.filter((value) => value !== occasion);
    });
  }

  for (const prayerTime of queryState.prayerTimes) {
    addChip(`Prayer Tag: ${prayerTime}`, (nextQueryState) => {
      nextQueryState.prayerTimes = nextQueryState.prayerTimes.filter((value) => value !== prayerTime);
    });
  }

  if (sortKey && sortKey !== DEFAULT_SORT_KEY) {
    const sortLabel = SORT_LABELS[sortKey] || sortKey;
    addChip(`Sort: ${sortLabel}`, (nextQueryState) => {
      nextQueryState.sort = "";
    });
  }

  return chips;
}

function toNiggunTitleSlug(title) {
  const normalized = String(title || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/['\u2019]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || "niggun";
}

function buildNiggunPublicPath(niggun) {
  return `/niggunim/${niggun.id}-${toNiggunTitleSlug(niggun.title)}`;
}

function renderPublicSearchPage(req, res, { isAdvancedSearch = false } = {}) {
  const modeOptions = MODE_OPTIONS;
  const meterOptions = METER_OPTIONS;
  const filters = isAdvancedSearch
    ? normalizeFilters(req.query, modeOptions, meterOptions)
    : normalizeBasicFilters(req.query, modeOptions);
  const sortKey = isAdvancedSearch ? normalizeSortKey(req.query.sort) : DEFAULT_SORT_KEY;
  const querySortKey = isAdvancedSearch ? sortKey : "";
  const requestedPage = normalizePage(req.query.page);

  const listFilters = {
    searchQuery: filters.searchQuery,
    tempo: filters.tempo,
    mode: filters.mode,
    meter: filters.meter,
    singer: filters.singer,
    author: filters.author,
    occasions: filters.occasions,
    prayerTimes: filters.prayerTimes
  };
  const totalCount = countNiggunim(listFilters, { includeDrafts: false });
  const pagination = buildPagination(totalCount, requestedPage, PUBLIC_PAGE_SIZE);
  const searchPath = isAdvancedSearch ? "/advanced-search" : "/";

  const niggunim = listNiggunim(listFilters, {
    includeDrafts: false,
    sortKey,
    limit: PUBLIC_PAGE_SIZE,
    offset: pagination.offset
  });

  const singers = isAdvancedSearch ? listSingers() : [];
  const authors = isAdvancedSearch ? listAuthors() : [];
  const queryState = toFilterQueryState(filters, querySortKey);
  const buildSearchQuery = (pageNumber = pagination.page, nextQueryState = queryState) =>
    buildQueryString({
      ...nextQueryState,
      page: pageNumber > 1 ? String(pageNumber) : ""
    });
  const buildSearchUrl = (pageNumber = pagination.page, nextQueryState = queryState) =>
    toPathWithQuery(searchPath, buildSearchQuery(pageNumber, nextQueryState));
  const activeFilterChips = buildActiveFilterChips(filters, querySortKey, (nextQueryState) =>
    buildSearchUrl(1, nextQueryState)
  );
  const basicSearchUrl = toPathWithQuery(
    "/",
    buildQueryString({
      q: filters.searchQuery,
      tempo: filters.tempo,
      mode: filters.mode
    })
  );
  const advancedSearchUrl = toPathWithQuery(
    "/advanced-search",
    buildQueryString({
      q: filters.searchQuery,
      tempo: filters.tempo,
      mode: filters.mode
    })
  );

  res.render("public/index", {
    niggunim,
    isAdvancedSearch,
    searchPath,
    basicSearchUrl,
    advancedSearchUrl,
    filters,
    sortKey: querySortKey,
    sortOptions: SORT_OPTIONS,
    pagination,
    activeFilterChips,
    buildSearchQuery,
    buildSearchUrl,
    buildNiggunPublicPath,
    tempoOptions: TEMPO_OPTIONS,
    modeOptions,
    meterOptions,
    occasionOptions: OCCASION_TAG_OPTIONS,
    prayerTimeOptions: PRAYER_TIME_TAG_OPTIONS,
    singers,
    authors,
    publicHeaderAction: buildPublicHeaderAction(req),
    publicViewerEmail: res.locals.publicGoogleUser ? res.locals.publicGoogleUser.email : ""
  });
}

app.get("/public/login", (req, res) => {
  const returnTo = normalizePublicReturnTo(req.query.returnTo, "/");
  if (canAccessPublicCatalog(req)) {
    return res.redirect(returnTo);
  }

  return res.render("public/login", {
    returnTo,
    googleAuthEnabled
  });
});

app.get("/public/logout", (req, res) => {
  delete req.session.publicGoogleUserId;
  const returnTo = normalizePublicReturnTo(req.query.returnTo, "/public/login");
  return res.redirect(returnTo);
});

app.get("/auth/google", (req, res, next) => {
  const returnTo = normalizePublicReturnTo(req.query.returnTo, "/");
  req.session.publicAuthReturnTo = returnTo;

  if (!googleAuthEnabled) {
    setFlash(req, "error", "Google sign-in is not configured.");
    return res.redirect(toPathWithQuery("/public/login", buildQueryString({ returnTo })));
  }

  const handler = passport.authenticate("google", {
    session: false,
    scope: ["openid", "email", "profile"],
    prompt: "select_account"
  });

  return handler(req, res, next);
});

app.get("/auth/google/callback", (req, res, next) => {
  if (!googleAuthEnabled) {
    setFlash(req, "error", "Google sign-in is not configured.");
    return res.redirect("/public/login");
  }

  const handler = passport.authenticate("google", {
    session: false,
    failureRedirect: "/public/login"
  });

  return handler(req, res, next);
}, (req, res) => {
  if (!req.user || !req.user.googleSub || !req.user.email) {
    setFlash(req, "error", "Google sign-in did not return an email address.");
    return res.redirect("/public/login");
  }

  let publicGoogleUser = null;
  try {
    publicGoogleUser = upsertPublicGoogleUser(req.user);
  } catch (error) {
    console.error("Unable to persist Google public user:", error);
  }

  if (!publicGoogleUser) {
    setFlash(req, "error", "Unable to complete sign-in.");
    return res.redirect("/public/login");
  }

  req.session.publicGoogleUserId = publicGoogleUser.id;
  const returnTo = normalizePublicReturnTo(req.session.publicAuthReturnTo, "/");
  delete req.session.publicAuthReturnTo;
  return res.redirect(returnTo);
});

app.get("/", requirePublicCatalogAccess, (req, res) => {
  return renderPublicSearchPage(req, res, { isAdvancedSearch: false });
});

app.get("/advanced-search", requirePublicCatalogAccess, (req, res) => {
  return renderPublicSearchPage(req, res, { isAdvancedSearch: true });
});

app.get("/faq", requirePublicCatalogAccess, (req, res) => {
  return res.render("public/faq", {
    publicHeaderAction: buildPublicHeaderAction(req),
    publicViewerEmail: res.locals.publicGoogleUser ? res.locals.publicGoogleUser.email : ""
  });
});

app.get("/privacy-policy", (req, res) => {
  return res.render("public/privacy-policy");
});

app.get("/terms-of-service", (req, res) => {
  return res.render("public/terms-of-service");
});

app.get(/^\/niggunim\/(\d+)(?:-([^/]+))?$/, requirePublicCatalogAccess, (req, res) => {
  const niggunId = Number(req.params[0]);
  const requestedSlug = sanitizeText(req.params[1] || "").toLowerCase();
  const includeDrafts = Boolean(req.session.userId);
  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    return res.status(404).render("public/not-found");
  }

  const niggun = getNiggunById(niggunId, { includeDrafts });
  if (!niggun) {
    return res.status(404).render("public/not-found");
  }

  const canonicalSlug = toNiggunTitleSlug(niggun.title);
  if (requestedSlug !== canonicalSlug) {
    const queryString = buildQueryString(req.query || {});
    return res.redirect(toPathWithQuery(buildNiggunPublicPath(niggun), queryString));
  }

  const uploadedDateLabel = toEasternDateLabel(niggun.createdAt);

  return res.render("public/niggun", {
    niggun,
    uploadedDateLabel,
    publicHeaderAction: buildPublicHeaderAction(req),
    publicViewerEmail: res.locals.publicGoogleUser ? res.locals.publicGoogleUser.email : ""
  });
});

app.get("/admin/setup", (req, res) => {
  if (countUsers() > 0) {
    return res.redirect("/admin/login");
  }

  return res.render("admin/setup");
});

app.post("/admin/setup", requireCsrfToken, (req, res) => {
  if (countUsers() > 0) {
    return res.redirect("/admin/login");
  }

  const username = sanitizeText(req.body.username || "");
  const password = req.body.password || "";

  if (!validateUsername(username)) {
    setFlash(req, "error", "Username must be 3-32 chars and use only letters, numbers, _ or -.");
    return res.redirect("/admin/setup");
  }

  if (!validatePassword(password)) {
    setFlash(req, "error", "Password must be at least 8 characters.");
    return res.redirect("/admin/setup");
  }

  const passwordHash = bcrypt.hashSync(password, 12);

  try {
    const userId = createUser(username, passwordHash);

    return req.session.regenerate((error) => {
      if (error) {
        console.error(error);
        setFlash(req, "error", "Unable to complete setup session.");
        return res.redirect("/admin/login");
      }

      req.session.userId = Number(userId);
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      setFlash(req, "success", "Admin user created.");
      return res.redirect("/admin");
    });
  } catch (error) {
    setFlash(req, "error", "Unable to create admin user.");
    return res.redirect("/admin/setup");
  }
});

app.get("/admin/login", (req, res) => {
  if (countUsers() === 0) {
    return res.redirect("/admin/setup");
  }

  if (req.session.userId) {
    return res.redirect("/admin");
  }

  return res.render("admin/login");
});

app.post("/admin/login", loginRateLimiter, requireCsrfToken, (req, res) => {
  if (countUsers() === 0) {
    return res.redirect("/admin/setup");
  }

  const username = sanitizeText(req.body.username || "");
  const password = req.body.password || "";

  const usernameKey = username.toLowerCase();
  const clientIpKey = getClientIp(req);

  const usernameLock = getActiveLockout("username", usernameKey);
  const ipLock = getActiveLockout("ip", clientIpKey);
  const msRemaining = Math.max(usernameLock?.msRemaining || 0, ipLock?.msRemaining || 0);

  if (msRemaining > 0) {
    setFlash(req, "error", `Too many failed sign-in attempts. Try again in ${formatLockWait(msRemaining)}.`);
    return res.redirect("/admin/login");
  }

  const user = getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    const usernameFailure = recordLoginFailure("username", usernameKey);
    const ipFailure = recordLoginFailure("ip", clientIpKey);

    const lockMs = Math.max(
      millisecondsUntil(usernameFailure ? usernameFailure.lockedUntil : null),
      millisecondsUntil(ipFailure ? ipFailure.lockedUntil : null)
    );

    if (lockMs > 0) {
      setFlash(req, "error", `Too many failed sign-in attempts. Try again in ${formatLockWait(lockMs)}.`);
    } else {
      setFlash(req, "error", "Invalid username or password.");
    }

    return res.redirect("/admin/login");
  }

  clearLoginFailures(usernameKey, clientIpKey);

  return req.session.regenerate((error) => {
    if (error) {
      console.error(error);
      setFlash(req, "error", "Unable to establish authenticated session.");
      return res.redirect("/admin/login");
    }

    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    setFlash(req, "success", "Signed in.");
    return res.redirect("/admin");
  });
});

app.post("/admin/logout", requireCsrfToken, (req, res) => {
  req.session.destroy(() => {
    res.redirect("/admin/login");
  });
});

app.get("/admin", requireAuth, (req, res) => {
  return res.redirect("/admin/niggunim/new");
});

app.get("/admin/niggunim/new", requireAuth, (req, res) => {
  return res.render("admin/dashboard", {
    adminSection: "add",
    adminNavigation: buildAdminNavigation("add"),
    adminReturnTo: "/admin/niggunim/new",
    tempoOptions: TEMPO_OPTIONS,
    modeOptions: MODE_OPTIONS,
    meterOptions: METER_OPTIONS,
    occasionOptions: OCCASION_TAG_OPTIONS,
    prayerTimeOptions: PRAYER_TIME_TAG_OPTIONS
  });
});

app.get("/admin/niggunim", requireAuth, (req, res) => {
  const modeOptions = MODE_OPTIONS;
  const meterOptions = METER_OPTIONS;
  const filters = normalizeFilters(req.query, modeOptions, meterOptions);
  const sortKey = normalizeSortKey(req.query.sort);
  const requestedPage = normalizePage(req.query.page);
  const listFilters = {
    searchQuery: filters.searchQuery,
    tempo: filters.tempo,
    mode: filters.mode,
    meter: filters.meter,
    singer: filters.singer,
    author: filters.author,
    occasions: filters.occasions,
    prayerTimes: filters.prayerTimes
  };
  const totalCount = countNiggunim(listFilters, { includeDrafts: true });
  const pagination = buildPagination(totalCount, requestedPage, ADMIN_PAGE_SIZE);

  const singers = listSingers();
  const authors = listAuthors();
  const niggunim = listNiggunim(listFilters, {
    includeDrafts: true,
    sortKey,
    limit: ADMIN_PAGE_SIZE,
    offset: pagination.offset
  }).map((niggun) => ({
    ...niggun,
    createdAtLabel: toEasternDateLabel(niggun.createdAt)
  }));
  const queryState = toFilterQueryState(filters, sortKey);
  const buildAdminQuery = (pageNumber = pagination.page, nextQueryState = queryState) =>
    buildQueryString({
      ...nextQueryState,
      page: pageNumber > 1 ? String(pageNumber) : ""
    });
  const buildAdminUrl = (pageNumber = pagination.page, nextQueryState = queryState) =>
    toPathWithQuery("/admin/niggunim", buildAdminQuery(pageNumber, nextQueryState));
  const adminReturnTo = buildAdminUrl(pagination.page, queryState);
  const activeFilterChips = buildActiveFilterChips(filters, sortKey, (nextQueryState) =>
    buildAdminUrl(1, nextQueryState)
  );

  return res.render("admin/dashboard", {
    adminSection: "existing",
    adminNavigation: buildAdminNavigation("existing"),
    niggunim,
    filters,
    singers,
    authors,
    sortKey,
    sortOptions: SORT_OPTIONS,
    pagination,
    activeFilterChips,
    buildAdminQuery,
    buildAdminUrl,
    buildNiggunPublicPath,
    adminReturnTo,
    tempoOptions: TEMPO_OPTIONS,
    modeOptions,
    meterOptions,
    occasionOptions: OCCASION_TAG_OPTIONS,
    prayerTimeOptions: PRAYER_TIME_TAG_OPTIONS
  });
});

app.get("/admin/users", requireAuth, (req, res) => {
  const users = listUsers().map((user) => ({
    ...user,
    createdAtLabel: toEasternDateLabel(user.createdAt)
  }));

  return res.render("admin/dashboard", {
    adminSection: "users",
    adminNavigation: buildAdminNavigation("users"),
    users,
    adminReturnTo: "/admin/users",
    tempoOptions: TEMPO_OPTIONS,
    modeOptions: MODE_OPTIONS,
    meterOptions: METER_OPTIONS,
    occasionOptions: OCCASION_TAG_OPTIONS,
    prayerTimeOptions: PRAYER_TIME_TAG_OPTIONS
  });
});

app.post("/admin/users", requireAuth, requireCsrfToken, (req, res) => {
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/users");
  const username = sanitizeText(req.body.username || "");
  const password = req.body.password || "";

  if (!validateUsername(username)) {
    setFlash(req, "error", "Username must be 3-32 chars and use only letters, numbers, _ or -.");
    return res.redirect(returnTo);
  }

  if (!validatePassword(password)) {
    setFlash(req, "error", "Password must be at least 8 characters.");
    return res.redirect(returnTo);
  }

  const passwordHash = bcrypt.hashSync(password, 12);

  try {
    createUser(username, passwordHash);
    setFlash(req, "success", `User \"${username}\" added.`);
  } catch (error) {
    setFlash(req, "error", "Unable to add user. Username may already exist.");
  }

  return res.redirect(returnTo);
});

app.post("/admin/users/:id/password", requireAuth, requireCsrfToken, (req, res) => {
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/users");
  const userId = Number(req.params.id);
  const password = req.body.password || "";

  if (!Number.isInteger(userId) || userId <= 0) {
    setFlash(req, "error", "Invalid user id.");
    return res.redirect(returnTo);
  }

  if (!validatePassword(password)) {
    setFlash(req, "error", "Password must be at least 8 characters.");
    return res.redirect(returnTo);
  }

  const targetUser = getUserById(userId);
  if (!targetUser) {
    setFlash(req, "error", "User not found.");
    return res.redirect(returnTo);
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  const changes = updateUserPassword(userId, passwordHash);

  if (!changes) {
    setFlash(req, "error", "Unable to reset password.");
    return res.redirect(returnTo);
  }

  clearLoginSecurityRecord("username", targetUser.username.toLowerCase());
  setFlash(req, "success", `Password reset for \"${targetUser.username}\".`);
  return res.redirect(returnTo);
});

app.post("/admin/users/:id/delete", requireAuth, requireCsrfToken, (req, res) => {
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/users");
  const userId = Number(req.params.id);

  if (!Number.isInteger(userId) || userId <= 0) {
    setFlash(req, "error", "Invalid user id.");
    return res.redirect(returnTo);
  }

  if (req.session.userId === userId) {
    setFlash(req, "error", "You cannot delete your own logged-in account.");
    return res.redirect(returnTo);
  }

  if (countUsers() <= 1) {
    setFlash(req, "error", "Cannot delete the last remaining user.");
    return res.redirect(returnTo);
  }

  const changes = deleteUser(userId);

  if (!changes) {
    setFlash(req, "error", "User not found.");
  } else {
    setFlash(req, "success", "User deleted.");
  }

  return res.redirect(returnTo);
});

function createUploadMiddleware(defaultRedirect) {
  return (req, res, next) => {
    upload.single("audioFile")(req, res, (error) => {
      if (error) {
        if (req.file && req.file.filename) {
          removeAudioFile(req.file.filename);
        }

        if (error.code === "LIMIT_FILE_SIZE") {
          setFlash(req, "error", "Audio file exceeds 20MB limit.");
        } else {
          setFlash(req, "error", error.message || "Upload failed.");
        }

        const fallback = typeof defaultRedirect === "function" ? defaultRedirect(req) : defaultRedirect;
        const returnTo = normalizeAdminReturnTo(req.body?.returnTo, fallback);
        return res.redirect(returnTo);
      }

      return next();
    });
  };
}

const uploadForCreate = createUploadMiddleware("/admin/niggunim/new");
const uploadForEdit = createUploadMiddleware((req) => `/admin/niggunim/${req.params.id}/edit`);

app.post("/admin/niggunim", requireAuth, uploadForCreate, requireCsrfToken, async (req, res) => {
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/niggunim/new");
  const title = sanitizeText(req.body.title || "");
  const notes = sanitizeText(req.body.notes || "");
  const lyrics = sanitizeText(req.body.lyrics || "");
  const tempo = sanitizeText(req.body.tempo || "");
  const mode = sanitizeText(req.body.mode || req.body.musicalKey || "");
  const meter = sanitizeText(req.body.meter || "");
  const singers = parseCsvInput(req.body.singers || "");
  const authors = parseCsvInput(req.body.authors || "");
  const occasions = parseMultiSelectInput(req.body.occasions, OCCASION_TAG_OPTIONS);
  const prayerTimes = parseMultiSelectInput(req.body.prayerTimes, PRAYER_TIME_TAG_OPTIONS);
  const scriptureRefs = parseScriptureReferences(req.body.scriptureRefs || "");
  const audioUrlRaw = sanitizeText(req.body.audioUrl || "");
  const audioUrl = ensureHttpUrl(audioUrlRaw);

  const uploadedFile = req.file || null;

  if (!title) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Title is required.");
    return res.redirect(returnTo);
  }

  if (singers.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one singer is required.");
    return res.redirect(returnTo);
  }

  if (authors.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one composer is required.");
    return res.redirect(returnTo);
  }

  if (tempo && !TEMPO_OPTIONS.includes(tempo)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Tempo must be Fast, Medium, or Slow.");
    return res.redirect(returnTo);
  }

  if (mode && !MODE_OPTIONS.includes(mode)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Please choose a valid mode.");
    return res.redirect(returnTo);
  }

  if (meter && !METER_OPTIONS.includes(meter)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Please choose a valid meter.");
    return res.redirect(returnTo);
  }

  if (uploadedFile && audioUrl) {
    removeAudioFile(uploadedFile.filename);
    setFlash(req, "error", "Choose either file upload or audio URL, not both.");
    return res.redirect(returnTo);
  }

  if (!uploadedFile && audioUrlRaw && !audioUrl) {
    setFlash(req, "error", "Audio URL must be a valid http/https URL.");
    return res.redirect(returnTo);
  }

  let storedFilename = "";
  let mimeType = "";
  let originalFilename = "";
  let audioSourceUrl = "";
  let publicationStatus = "draft";

  try {
    if (uploadedFile) {
      const metadata = getFileMetadata(uploadedFile);
      if (!isAllowedAudioType(metadata)) {
        removeAudioFile(uploadedFile.filename);
        setFlash(req, "error", "Unsupported audio format.");
        return res.redirect(returnTo);
      }

      storedFilename = uploadedFile.filename;
      mimeType = metadata.mimeType;
      originalFilename = metadata.originalFilename;
      publicationStatus = "published";
    } else {
      if (audioUrl) {
        const downloaded = await downloadAudioFromUrl(audioUrl);
        storedFilename = downloaded.storedFilename;
        mimeType = downloaded.mimeType;
        originalFilename = downloaded.originalFilename;
        audioSourceUrl = audioUrl;
        publicationStatus = "published";
      }
    }

    createNiggun({
      title,
      notes,
      lyrics,
      tempo,
      mode,
      meter,
      singers,
      authors,
      occasions,
      prayerTimes,
      scriptureRefs,
      publicationStatus,
      audioPath: storedFilename,
      audioSourceUrl,
      originalFilename,
      mimeType
    });

    if (publicationStatus === "draft") {
      setFlash(req, "success", `Niggun \"${title}\" saved as draft (no audio uploaded yet).`);
    } else {
      setFlash(req, "success", `Niggun \"${title}\" added.`);
    }
    return res.redirect(returnTo);
  } catch (error) {
    if (storedFilename && (!uploadedFile || storedFilename !== uploadedFile.filename)) {
      removeAudioFile(storedFilename);
    }

    if (uploadedFile && uploadedFile.filename) {
      removeAudioFile(uploadedFile.filename);
    }

    setFlash(req, "error", error.message || "Unable to add niggun.");
    return res.redirect(returnTo);
  }
});

app.get("/admin/niggunim/:id/edit", requireAuth, (req, res) => {
  const niggunId = Number(req.params.id);
  const returnTo = normalizeAdminReturnTo(req.query.returnTo, "/admin/niggunim");

  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    setFlash(req, "error", "Invalid niggun id.");
    return res.redirect(returnTo);
  }

  const niggun = getNiggunById(niggunId, { includeDrafts: true });
  if (!niggun) {
    setFlash(req, "error", "Niggun not found.");
    return res.redirect(returnTo);
  }

  return res.render("admin/edit-niggun", {
    niggun,
    returnTo,
    tempoOptions: TEMPO_OPTIONS,
    modeOptions: MODE_OPTIONS,
    meterOptions: METER_OPTIONS,
    occasionOptions: OCCASION_TAG_OPTIONS,
    prayerTimeOptions: PRAYER_TIME_TAG_OPTIONS
  });
});

app.post("/admin/niggunim/:id", requireAuth, uploadForEdit, requireCsrfToken, async (req, res) => {
  const niggunId = Number(req.params.id);
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/niggunim");
  const title = sanitizeText(req.body.title || "");
  const notes = sanitizeText(req.body.notes || "");
  const lyrics = sanitizeText(req.body.lyrics || "");
  const tempo = sanitizeText(req.body.tempo || "");
  const mode = sanitizeText(req.body.mode || req.body.musicalKey || "");
  const meter = sanitizeText(req.body.meter || "");
  const singers = parseCsvInput(req.body.singers || "");
  const authors = parseCsvInput(req.body.authors || "");
  const occasions = parseMultiSelectInput(req.body.occasions, OCCASION_TAG_OPTIONS);
  const prayerTimes = parseMultiSelectInput(req.body.prayerTimes, PRAYER_TIME_TAG_OPTIONS);
  const scriptureRefs = parseScriptureReferences(req.body.scriptureRefs || "");
  const audioUrlRaw = sanitizeText(req.body.audioUrl || "");
  const audioUrl = ensureHttpUrl(audioUrlRaw);

  const uploadedFile = req.file || null;

  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Invalid niggun id.");
    return res.redirect(returnTo);
  }

  const existingNiggun = getNiggunById(niggunId, { includeDrafts: true });
  if (!existingNiggun) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Niggun not found.");
    return res.redirect(returnTo);
  }

  if (!title) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Title is required.");
    return res.redirect(returnTo);
  }

  if (singers.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one singer is required.");
    return res.redirect(returnTo);
  }

  if (authors.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one composer is required.");
    return res.redirect(returnTo);
  }

  if (tempo && !TEMPO_OPTIONS.includes(tempo)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Tempo must be Fast, Medium, or Slow.");
    return res.redirect(returnTo);
  }

  if (mode && !MODE_OPTIONS.includes(mode)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Please choose a valid mode.");
    return res.redirect(returnTo);
  }

  if (meter && !METER_OPTIONS.includes(meter)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Please choose a valid meter.");
    return res.redirect(returnTo);
  }

  if (uploadedFile && audioUrl) {
    removeAudioFile(uploadedFile.filename);
    setFlash(req, "error", "Choose either file upload or audio URL, not both.");
    return res.redirect(returnTo);
  }

  if (!uploadedFile && audioUrlRaw && !audioUrl) {
    setFlash(req, "error", "Audio URL must be a valid http/https URL.");
    return res.redirect(returnTo);
  }

  let storedFilename = existingNiggun.audioPath;
  let mimeType = existingNiggun.mimeType || "";
  let originalFilename = existingNiggun.originalFilename || "";
  let audioSourceUrl = existingNiggun.audioSourceUrl || "";
  let didReplaceAudio = false;
  let publicationStatus = existingNiggun.publicationStatus || (storedFilename ? "published" : "draft");

  try {
    if (uploadedFile) {
      const metadata = getFileMetadata(uploadedFile);
      if (!isAllowedAudioType(metadata)) {
        removeAudioFile(uploadedFile.filename);
        setFlash(req, "error", "Unsupported audio format.");
        return res.redirect(returnTo);
      }

      storedFilename = uploadedFile.filename;
      mimeType = metadata.mimeType;
      originalFilename = metadata.originalFilename;
      audioSourceUrl = "";
      didReplaceAudio = true;
      publicationStatus = "published";
    } else if (audioUrl) {
      const downloaded = await downloadAudioFromUrl(audioUrl);
      storedFilename = downloaded.storedFilename;
      mimeType = downloaded.mimeType;
      originalFilename = downloaded.originalFilename;
      audioSourceUrl = audioUrl;
      didReplaceAudio = true;
      publicationStatus = "published";
    }

    if (!storedFilename) {
      publicationStatus = "draft";
    }

    const updated = updateNiggun({
      id: niggunId,
      title,
      notes,
      lyrics,
      tempo,
      mode,
      meter,
      singers,
      authors,
      occasions,
      prayerTimes,
      scriptureRefs,
      publicationStatus,
      audioPath: storedFilename,
      audioSourceUrl,
      originalFilename,
      mimeType
    });

    if (!updated) {
      if (didReplaceAudio && storedFilename !== existingNiggun.audioPath) {
        removeAudioFile(storedFilename);
      }
      setFlash(req, "error", "Niggun not found.");
      return res.redirect(returnTo);
    }

    if (didReplaceAudio && updated.previousAudioPath && updated.previousAudioPath !== updated.newAudioPath) {
      removeAudioFile(updated.previousAudioPath);
    }

    setFlash(req, "success", `Niggun \"${title}\" updated.`);
    return res.redirect(returnTo);
  } catch (error) {
    if (didReplaceAudio && storedFilename && storedFilename !== existingNiggun.audioPath) {
      removeAudioFile(storedFilename);
    }

    if (
      uploadedFile &&
      uploadedFile.filename &&
      uploadedFile.filename !== existingNiggun.audioPath &&
      uploadedFile.filename !== storedFilename
    ) {
      removeAudioFile(uploadedFile.filename);
    }

    setFlash(req, "error", error.message || "Unable to update niggun.");
    return res.redirect(returnTo);
  }
});

app.post("/admin/niggunim/:id/delete", requireAuth, requireCsrfToken, (req, res) => {
  const returnTo = normalizeAdminReturnTo(req.body.returnTo, "/admin/niggunim");
  const niggunId = Number(req.params.id);

  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    setFlash(req, "error", "Invalid niggun id.");
    return res.redirect(returnTo);
  }

  const deleted = deleteNiggun(niggunId);

  if (!deleted) {
    setFlash(req, "error", "Niggun not found.");
    return res.redirect(returnTo);
  }

  if (deleted.audioPath) {
    removeAudioFile(deleted.audioPath);
  }
  setFlash(req, "success", "Niggun deleted.");
  return res.redirect(returnTo);
});

app.use((req, res) => {
  res.status(404).render("public/not-found");
});

app.use((error, req, res, next) => {
  console.error(error);
  if (req.path.startsWith("/admin")) {
    setFlash(req, "error", "Unexpected server error.");
    return res.redirect("/admin/niggunim/new");
  }

  return res.status(500).send("Internal server error");
});

async function startServer() {
  try {
    if (useRedisSessions && redisClient) {
      await redisClient.connect();
      console.log(`Redis session store connected (${redisUrl}).`);
    } else {
      console.log("Session store: in-memory.");
    }

    const port = Number(process.env.PORT || 3000);
    app.listen(port, () => {
      console.log(`Segulah Niggun database listening on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to Redis session store.", error);
    if (!isProduction) {
      console.error("For local dev, set SESSION_STORE=memory in .env to run without Redis.");
    }
    process.exit(1);
  }
}

startServer();
