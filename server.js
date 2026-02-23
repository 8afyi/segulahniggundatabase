const path = require("path");
const express = require("express");
const session = require("express-session");
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

app.set("view engine", "ejs");
app.set("views", path.join(projectRoot, "views"));

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(projectRoot, "public")));
app.use("/media", express.static(audioDirectory));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-session-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 12
    }
  })
);

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

app.use((req, res, next) => {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;

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

app.post("/admin/setup", (req, res) => {
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
    req.session.userId = Number(userId);
    setFlash(req, "success", "Admin user created.");
    return res.redirect("/admin");
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

app.post("/admin/login", (req, res) => {
  if (countUsers() === 0) {
    return res.redirect("/admin/setup");
  }

  const username = sanitizeText(req.body.username || "");
  const password = req.body.password || "";

  const user = getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    setFlash(req, "error", "Invalid username or password.");
    return res.redirect("/admin/login");
  }

  req.session.userId = user.id;
  setFlash(req, "success", "Signed in.");
  return res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
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

app.post("/admin/users", requireAuth, (req, res) => {
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

app.post("/admin/users/:id/delete", requireAuth, (req, res) => {
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

app.post("/admin/niggunim", requireAuth, uploadMiddleware, async (req, res) => {
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

app.post("/admin/niggunim/:id/delete", requireAuth, (req, res) => {
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

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`Segulah Niggun database listening on port ${PORT}`);
});
