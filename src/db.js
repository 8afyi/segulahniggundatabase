const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const projectRoot = path.resolve(__dirname, "..");
const dataDirectory = path.join(projectRoot, "data");
const dbPath = process.env.DB_PATH || path.join(dataDirectory, "app.db");

if (!process.env.DB_PATH) {
  fs.mkdirSync(dataDirectory, { recursive: true });
} else {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

function initializeSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS niggunim (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      notes TEXT,
      tempo TEXT,
      musical_key TEXT,
      audio_path TEXT NOT NULL,
      audio_source_url TEXT,
      original_filename TEXT,
      mime_type TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS singers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE
    );

    CREATE TABLE IF NOT EXISTS authors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE
    );

    CREATE TABLE IF NOT EXISTS niggun_singers (
      niggun_id INTEGER NOT NULL,
      singer_id INTEGER NOT NULL,
      PRIMARY KEY (niggun_id, singer_id),
      FOREIGN KEY (niggun_id) REFERENCES niggunim(id) ON DELETE CASCADE,
      FOREIGN KEY (singer_id) REFERENCES singers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS niggun_authors (
      niggun_id INTEGER NOT NULL,
      author_id INTEGER NOT NULL,
      PRIMARY KEY (niggun_id, author_id),
      FOREIGN KEY (niggun_id) REFERENCES niggunim(id) ON DELETE CASCADE,
      FOREIGN KEY (author_id) REFERENCES authors(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_niggunim_tempo ON niggunim(tempo);
    CREATE INDEX IF NOT EXISTS idx_niggunim_key ON niggunim(musical_key);
    CREATE INDEX IF NOT EXISTS idx_niggun_singers_singer ON niggun_singers(singer_id);
    CREATE INDEX IF NOT EXISTS idx_niggun_authors_author ON niggun_authors(author_id);
  `);
}

function splitCsv(csv) {
  if (!csv) {
    return [];
  }

  return csv
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function toNiggunRecord(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    title: row.title,
    notes: row.notes || "",
    tempo: row.tempo || "",
    musicalKey: row.musicalKey || "",
    audioPath: row.audioPath,
    audioSourceUrl: row.audioSourceUrl || "",
    originalFilename: row.originalFilename || "",
    mimeType: row.mimeType || "",
    createdAt: row.createdAt,
    singers: splitCsv(row.singersCsv),
    authors: splitCsv(row.authorsCsv)
  };
}

function countUsers() {
  const row = db.prepare("SELECT COUNT(*) AS count FROM users").get();
  return row.count;
}

function createUser(username, passwordHash) {
  const result = db
    .prepare(
      `INSERT INTO users (username, password_hash)
       VALUES (?, ?)`
    )
    .run(username, passwordHash);

  return result.lastInsertRowid;
}

function getUserByUsername(username) {
  return (
    db
      .prepare(
        `SELECT id, username, password_hash AS passwordHash, created_at AS createdAt
         FROM users
         WHERE username = ? COLLATE NOCASE`
      )
      .get(username) || null
  );
}

function getUserById(userId) {
  return (
    db
      .prepare(
        `SELECT id, username, created_at AS createdAt
         FROM users
         WHERE id = ?`
      )
      .get(userId) || null
  );
}

function listUsers() {
  return db
    .prepare(
      `SELECT id, username, created_at AS createdAt
       FROM users
       ORDER BY username COLLATE NOCASE ASC`
    )
    .all();
}

function deleteUser(userId) {
  return db.prepare("DELETE FROM users WHERE id = ?").run(userId).changes;
}

function getOrCreateSingerId(name) {
  const existing = db.prepare("SELECT id FROM singers WHERE name = ? COLLATE NOCASE").get(name);
  if (existing) {
    return existing.id;
  }

  const inserted = db.prepare("INSERT INTO singers (name) VALUES (?)").run(name);
  return inserted.lastInsertRowid;
}

function getOrCreateAuthorId(name) {
  const existing = db.prepare("SELECT id FROM authors WHERE name = ? COLLATE NOCASE").get(name);
  if (existing) {
    return existing.id;
  }

  const inserted = db.prepare("INSERT INTO authors (name) VALUES (?)").run(name);
  return inserted.lastInsertRowid;
}

const createNiggunTxn = db.transaction((payload) => {
  const niggunResult = db
    .prepare(
      `INSERT INTO niggunim (
        title,
        notes,
        tempo,
        musical_key,
        audio_path,
        audio_source_url,
        original_filename,
        mime_type
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      payload.title,
      payload.notes || null,
      payload.tempo || null,
      payload.musicalKey || null,
      payload.audioPath,
      payload.audioSourceUrl || null,
      payload.originalFilename || null,
      payload.mimeType || null
    );

  const niggunId = niggunResult.lastInsertRowid;

  const insertSingerLink = db.prepare(
    "INSERT INTO niggun_singers (niggun_id, singer_id) VALUES (?, ?)"
  );
  const insertAuthorLink = db.prepare(
    "INSERT INTO niggun_authors (niggun_id, author_id) VALUES (?, ?)"
  );

  for (const singerName of payload.singers) {
    const singerId = getOrCreateSingerId(singerName);
    insertSingerLink.run(niggunId, singerId);
  }

  for (const authorName of payload.authors) {
    const authorId = getOrCreateAuthorId(authorName);
    insertAuthorLink.run(niggunId, authorId);
  }

  return niggunId;
});

function createNiggun(payload) {
  return createNiggunTxn(payload);
}

function listNiggunim(filters = {}) {
  const conditions = [];
  const params = [];

  if (filters.searchQuery) {
    const pattern = `%${filters.searchQuery.toLowerCase()}%`;
    conditions.push(`(
      LOWER(n.title) LIKE ?
      OR LOWER(COALESCE(n.notes, '')) LIKE ?
      OR EXISTS (
        SELECT 1
        FROM niggun_singers ns2
        JOIN singers s2 ON s2.id = ns2.singer_id
        WHERE ns2.niggun_id = n.id
          AND LOWER(s2.name) LIKE ?
      )
      OR EXISTS (
        SELECT 1
        FROM niggun_authors na2
        JOIN authors a2 ON a2.id = na2.author_id
        WHERE na2.niggun_id = n.id
          AND LOWER(a2.name) LIKE ?
      )
    )`);
    params.push(pattern, pattern, pattern, pattern);
  }

  if (filters.tempo) {
    conditions.push("n.tempo = ?");
    params.push(filters.tempo);
  }

  if (filters.musicalKey) {
    conditions.push("n.musical_key = ?");
    params.push(filters.musicalKey);
  }

  if (filters.singer) {
    conditions.push(`EXISTS (
      SELECT 1
      FROM niggun_singers ns3
      JOIN singers s3 ON s3.id = ns3.singer_id
      WHERE ns3.niggun_id = n.id
        AND s3.name = ? COLLATE NOCASE
    )`);
    params.push(filters.singer);
  }

  if (filters.author) {
    conditions.push(`EXISTS (
      SELECT 1
      FROM niggun_authors na3
      JOIN authors a3 ON a3.id = na3.author_id
      WHERE na3.niggun_id = n.id
        AND a3.name = ? COLLATE NOCASE
    )`);
    params.push(filters.author);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  const rows = db
    .prepare(
      `
      SELECT
        n.id,
        n.title,
        n.notes,
        n.tempo,
        n.musical_key AS musicalKey,
        n.audio_path AS audioPath,
        n.audio_source_url AS audioSourceUrl,
        n.original_filename AS originalFilename,
        n.mime_type AS mimeType,
        n.created_at AS createdAt,
        COALESCE(GROUP_CONCAT(DISTINCT s.name), '') AS singersCsv,
        COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv
      FROM niggunim n
      LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
      LEFT JOIN singers s ON s.id = ns.singer_id
      LEFT JOIN niggun_authors na ON na.niggun_id = n.id
      LEFT JOIN authors a ON a.id = na.author_id
      ${whereClause}
      GROUP BY n.id
      ORDER BY n.created_at DESC, n.id DESC
      `
    )
    .all(...params);

  return rows.map(toNiggunRecord);
}

function getNiggunById(niggunId) {
  const row = db
    .prepare(
      `
      SELECT
        n.id,
        n.title,
        n.notes,
        n.tempo,
        n.musical_key AS musicalKey,
        n.audio_path AS audioPath,
        n.audio_source_url AS audioSourceUrl,
        n.original_filename AS originalFilename,
        n.mime_type AS mimeType,
        n.created_at AS createdAt,
        COALESCE(GROUP_CONCAT(DISTINCT s.name), '') AS singersCsv,
        COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv
      FROM niggunim n
      LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
      LEFT JOIN singers s ON s.id = ns.singer_id
      LEFT JOIN niggun_authors na ON na.niggun_id = n.id
      LEFT JOIN authors a ON a.id = na.author_id
      WHERE n.id = ?
      GROUP BY n.id
      `
    )
    .get(niggunId);

  return toNiggunRecord(row);
}

function listSingers() {
  return db
    .prepare(
      `SELECT name
       FROM singers
       ORDER BY name COLLATE NOCASE ASC`
    )
    .all()
    .map((row) => row.name);
}

function listAuthors() {
  return db
    .prepare(
      `SELECT name
       FROM authors
       ORDER BY name COLLATE NOCASE ASC`
    )
    .all()
    .map((row) => row.name);
}

const deleteNiggunTxn = db.transaction((niggunId) => {
  const existing = db
    .prepare(
      `SELECT id, audio_path AS audioPath
       FROM niggunim
       WHERE id = ?`
    )
    .get(niggunId);

  if (!existing) {
    return null;
  }

  db.prepare("DELETE FROM niggunim WHERE id = ?").run(niggunId);
  db.prepare(
    `DELETE FROM singers
     WHERE id NOT IN (SELECT singer_id FROM niggun_singers)`
  ).run();
  db.prepare(
    `DELETE FROM authors
     WHERE id NOT IN (SELECT author_id FROM niggun_authors)`
  ).run();

  return existing;
});

function deleteNiggun(niggunId) {
  return deleteNiggunTxn(niggunId);
}

module.exports = {
  db,
  dbPath,
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
};
