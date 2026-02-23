const crypto = require("crypto");
const path = require("path");
const express = require("express");
const session = require("express-session");
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
  getLoginSecurityRecord,
  upsertLoginSecurityRecord,
  clearLoginSecurityRecord,
  createNiggun,
  listNiggunim,
  getNiggunById,
  listSingers,
  listAuthors,
  deleteNiggun
} = require("./src/db");
const { requireAuth } = require("./src/middleware/auth");
const {
  TEMPO_OPTIONS,
  MUSICAL_KEY_OPTIONS,
  MAX_AUDIO_BYTES,
  ALLOWED_AUDIO_EXTENSIONS
} = require("./src/config/constants");
const { sanitizeText, parseCsvInput, ensureHttpUrl } = require("./src/utils/validation");
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

const redisUrl = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const redisClient = createClient({ url: redisUrl });
redisClient.on("error", (error) => {
  console.error("Redis session store error:", error);
});

const sessionStore = new RedisStore({
  client: redisClient,
  prefix: `${process.env.SESSION_PREFIX || "segulah-niggun-database"}:sess:`
});

app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || "dev-session-secret-change-me",
    resave: false,
    saveUninitialized: false,
    proxy: isProduction,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProduction,
      maxAge: 1000 * 60 * 60 * 12
    }
  })
);

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

app.use((req, res, next) => {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;

  res.locals.csrfToken = ensureCsrfToken(req);

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

  next();
});

function toPositiveInt(rawValue, fallback) {
  const parsed = Number.parseInt(rawValue, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
}

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

function normalizeFilters(query) {
  const searchQuery = sanitizeText(query.q || "");
  const tempo = sanitizeText(query.tempo || "");
  const musicalKey = sanitizeText(query.key || "");
  const singer = sanitizeText(query.singer || "");
  const author = sanitizeText(query.author || "");

  return {
    searchQuery,
    tempo: TEMPO_OPTIONS.includes(tempo) ? tempo : "",
    musicalKey: MUSICAL_KEY_OPTIONS.includes(musicalKey) ? musicalKey : "",
    singer,
    author
  };
}

app.get("/", (req, res) => {
  const filters = normalizeFilters(req.query);

  const niggunim = listNiggunim({
    searchQuery: filters.searchQuery,
    tempo: filters.tempo,
    musicalKey: filters.musicalKey,
    singer: filters.singer,
    author: filters.author
  });

  const singers = listSingers();
  const authors = listAuthors();

  res.render("public/index", {
    niggunim,
    filters,
    tempoOptions: TEMPO_OPTIONS,
    keyOptions: MUSICAL_KEY_OPTIONS,
    singers,
    authors
  });
});

app.get("/niggunim/:id", (req, res) => {
  const niggunId = Number(req.params.id);
  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    return res.status(404).render("public/not-found");
  }

  const niggun = getNiggunById(niggunId);
  if (!niggun) {
    return res.status(404).render("public/not-found");
  }

  return res.render("public/niggun", { niggun });
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
  const users = listUsers();
  const niggunim = listNiggunim({});

  return res.render("admin/dashboard", {
    users,
    niggunim,
    tempoOptions: TEMPO_OPTIONS,
    keyOptions: MUSICAL_KEY_OPTIONS
  });
});

app.post("/admin/users", requireAuth, requireCsrfToken, (req, res) => {
  const username = sanitizeText(req.body.username || "");
  const password = req.body.password || "";

  if (!validateUsername(username)) {
    setFlash(req, "error", "Username must be 3-32 chars and use only letters, numbers, _ or -.");
    return res.redirect("/admin");
  }

  if (!validatePassword(password)) {
    setFlash(req, "error", "Password must be at least 8 characters.");
    return res.redirect("/admin");
  }

  const passwordHash = bcrypt.hashSync(password, 12);

  try {
    createUser(username, passwordHash);
    setFlash(req, "success", `User \"${username}\" added.`);
  } catch (error) {
    setFlash(req, "error", "Unable to add user. Username may already exist.");
  }

  return res.redirect("/admin");
});

app.post("/admin/users/:id/delete", requireAuth, requireCsrfToken, (req, res) => {
  const userId = Number(req.params.id);

  if (!Number.isInteger(userId) || userId <= 0) {
    setFlash(req, "error", "Invalid user id.");
    return res.redirect("/admin");
  }

  if (req.session.userId === userId) {
    setFlash(req, "error", "You cannot delete your own logged-in account.");
    return res.redirect("/admin");
  }

  if (countUsers() <= 1) {
    setFlash(req, "error", "Cannot delete the last remaining user.");
    return res.redirect("/admin");
  }

  const changes = deleteUser(userId);

  if (!changes) {
    setFlash(req, "error", "User not found.");
  } else {
    setFlash(req, "success", "User deleted.");
  }

  return res.redirect("/admin");
});

function uploadMiddleware(req, res, next) {
  upload.single("audioFile")(req, res, (error) => {
    if (error) {
      if (error.code === "LIMIT_FILE_SIZE") {
        setFlash(req, "error", "Audio file exceeds 20MB limit.");
      } else {
        setFlash(req, "error", error.message || "Upload failed.");
      }

      return res.redirect("/admin");
    }

    return next();
  });
}

app.post("/admin/niggunim", requireAuth, uploadMiddleware, requireCsrfToken, async (req, res) => {
  const title = sanitizeText(req.body.title || "");
  const notes = sanitizeText(req.body.notes || "");
  const tempo = sanitizeText(req.body.tempo || "");
  const musicalKey = sanitizeText(req.body.musicalKey || "");
  const singers = parseCsvInput(req.body.singers || "");
  const authors = parseCsvInput(req.body.authors || "");
  const audioUrlRaw = sanitizeText(req.body.audioUrl || "");
  const audioUrl = ensureHttpUrl(audioUrlRaw);

  const uploadedFile = req.file || null;

  if (!title) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Title is required.");
    return res.redirect("/admin");
  }

  if (singers.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one singer is required.");
    return res.redirect("/admin");
  }

  if (authors.length === 0) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "At least one author is required.");
    return res.redirect("/admin");
  }

  if (tempo && !TEMPO_OPTIONS.includes(tempo)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Tempo must be Fast, Medium, or Slow.");
    return res.redirect("/admin");
  }

  if (musicalKey && !MUSICAL_KEY_OPTIONS.includes(musicalKey)) {
    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }
    setFlash(req, "error", "Please choose a valid musical key.");
    return res.redirect("/admin");
  }

  if (uploadedFile && audioUrl) {
    removeAudioFile(uploadedFile.filename);
    setFlash(req, "error", "Choose either file upload or audio URL, not both.");
    return res.redirect("/admin");
  }

  if (!uploadedFile && audioUrlRaw && !audioUrl) {
    setFlash(req, "error", "Audio URL must be a valid http/https URL.");
    return res.redirect("/admin");
  }

  if (!uploadedFile && !audioUrl) {
    setFlash(req, "error", "Audio file is required (upload or URL).");
    return res.redirect("/admin");
  }

  let storedFilename = "";
  let mimeType = "";
  let originalFilename = "";
  let audioSourceUrl = "";

  try {
    if (uploadedFile) {
      const metadata = getFileMetadata(uploadedFile);
      if (!isAllowedAudioType(metadata)) {
        removeAudioFile(uploadedFile.filename);
        setFlash(req, "error", "Unsupported audio format.");
        return res.redirect("/admin");
      }

      storedFilename = uploadedFile.filename;
      mimeType = metadata.mimeType;
      originalFilename = metadata.originalFilename;
    } else {
      const downloaded = await downloadAudioFromUrl(audioUrl);
      storedFilename = downloaded.storedFilename;
      mimeType = downloaded.mimeType;
      originalFilename = downloaded.originalFilename;
      audioSourceUrl = audioUrl;
    }

    createNiggun({
      title,
      notes,
      tempo,
      musicalKey,
      singers,
      authors,
      audioPath: storedFilename,
      audioSourceUrl,
      originalFilename,
      mimeType
    });

    setFlash(req, "success", `Niggun \"${title}\" added.`);
    return res.redirect("/admin");
  } catch (error) {
    if (storedFilename) {
      removeAudioFile(storedFilename);
    }

    if (uploadedFile) {
      removeAudioFile(uploadedFile.filename);
    }

    setFlash(req, "error", error.message || "Unable to add niggun.");
    return res.redirect("/admin");
  }
});

app.post("/admin/niggunim/:id/delete", requireAuth, requireCsrfToken, (req, res) => {
  const niggunId = Number(req.params.id);

  if (!Number.isInteger(niggunId) || niggunId <= 0) {
    setFlash(req, "error", "Invalid niggun id.");
    return res.redirect("/admin");
  }

  const deleted = deleteNiggun(niggunId);

  if (!deleted) {
    setFlash(req, "error", "Niggun not found.");
    return res.redirect("/admin");
  }

  removeAudioFile(deleted.audioPath);
  setFlash(req, "success", "Niggun deleted.");
  return res.redirect("/admin");
});

app.use((req, res) => {
  res.status(404).render("public/not-found");
});

app.use((error, req, res, next) => {
  console.error(error);
  if (req.path.startsWith("/admin")) {
    setFlash(req, "error", "Unexpected server error.");
    return res.redirect("/admin");
  }

  return res.status(500).send("Internal server error");
});

async function startServer() {
  try {
    await redisClient.connect();

    const port = Number(process.env.PORT || 3000);
    app.listen(port, () => {
      console.log(`Segulah Niggun database listening on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to Redis session store.", error);
    process.exit(1);
  }
}

startServer();
