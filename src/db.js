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
let niggunSearchFtsEnabled = false;

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

    CREATE TABLE IF NOT EXISTS occasions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE COLLATE NOCASE
    );

    CREATE TABLE IF NOT EXISTS prayer_times (
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

    CREATE TABLE IF NOT EXISTS niggun_occasions (
      niggun_id INTEGER NOT NULL,
      occasion_id INTEGER NOT NULL,
      PRIMARY KEY (niggun_id, occasion_id),
      FOREIGN KEY (niggun_id) REFERENCES niggunim(id) ON DELETE CASCADE,
      FOREIGN KEY (occasion_id) REFERENCES occasions(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS niggun_prayer_times (
      niggun_id INTEGER NOT NULL,
      prayer_time_id INTEGER NOT NULL,
      PRIMARY KEY (niggun_id, prayer_time_id),
      FOREIGN KEY (niggun_id) REFERENCES niggunim(id) ON DELETE CASCADE,
      FOREIGN KEY (prayer_time_id) REFERENCES prayer_times(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS login_security (
      key_type TEXT NOT NULL,
      key_value TEXT NOT NULL,
      failed_count INTEGER NOT NULL DEFAULT 0,
      first_failed_at TEXT,
      locked_until TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (key_type, key_value)
    );

    CREATE INDEX IF NOT EXISTS idx_niggunim_tempo ON niggunim(tempo);
    CREATE INDEX IF NOT EXISTS idx_niggunim_key ON niggunim(musical_key);
    CREATE INDEX IF NOT EXISTS idx_niggun_singers_singer ON niggun_singers(singer_id);
    CREATE INDEX IF NOT EXISTS idx_niggun_authors_author ON niggun_authors(author_id);
    CREATE INDEX IF NOT EXISTS idx_niggun_occasions_occasion ON niggun_occasions(occasion_id);
    CREATE INDEX IF NOT EXISTS idx_niggun_prayers_prayer_time ON niggun_prayer_times(prayer_time_id);
    CREATE INDEX IF NOT EXISTS idx_login_security_locked_until ON login_security(locked_until);
  `);

  try {
    db.exec(`
      CREATE VIRTUAL TABLE IF NOT EXISTS niggun_search
      USING fts5(
        niggun_id UNINDEXED,
        title,
        notes,
        singers,
        authors,
        occasions,
        prayer_times
      );
    `);
    niggunSearchFtsEnabled = true;
    rebuildNiggunSearchIndex();
  } catch (error) {
    niggunSearchFtsEnabled = false;
    console.warn("SQLite FTS5 unavailable; falling back to LIKE search.", error.message || error);
  }
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

function csvToSearchText(csv) {
  return splitCsv(csv).join(" ");
}

function toNiggunSearchRecord(row) {
  if (!row) {
    return null;
  }

  return {
    niggunId: row.niggunId,
    title: row.title || "",
    notes: row.notes || "",
    singers: csvToSearchText(row.singersCsv),
    authors: csvToSearchText(row.authorsCsv),
    occasions: csvToSearchText(row.occasionsCsv),
    prayerTimes: csvToSearchText(row.prayerTimesCsv)
  };
}

function fetchNiggunSearchRowById(niggunId) {
  return (
    db
      .prepare(
        `
        SELECT
          n.id AS niggunId,
          n.title AS title,
          COALESCE(n.notes, '') AS notes,
          COALESCE(GROUP_CONCAT(DISTINCT s.name), '') AS singersCsv,
          COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv,
          COALESCE(GROUP_CONCAT(DISTINCT o.name), '') AS occasionsCsv,
          COALESCE(GROUP_CONCAT(DISTINCT pt.name), '') AS prayerTimesCsv
        FROM niggunim n
        LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
        LEFT JOIN singers s ON s.id = ns.singer_id
        LEFT JOIN niggun_authors na ON na.niggun_id = n.id
        LEFT JOIN authors a ON a.id = na.author_id
        LEFT JOIN niggun_occasions no ON no.niggun_id = n.id
        LEFT JOIN occasions o ON o.id = no.occasion_id
        LEFT JOIN niggun_prayer_times npt ON npt.niggun_id = n.id
        LEFT JOIN prayer_times pt ON pt.id = npt.prayer_time_id
        WHERE n.id = ?
        GROUP BY n.id
        `
      )
      .get(niggunId) || null
  );
}

function listNiggunSearchRows() {
  return db
    .prepare(
      `
      SELECT
        n.id AS niggunId,
        n.title AS title,
        COALESCE(n.notes, '') AS notes,
        COALESCE(GROUP_CONCAT(DISTINCT s.name), '') AS singersCsv,
        COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv,
        COALESCE(GROUP_CONCAT(DISTINCT o.name), '') AS occasionsCsv,
        COALESCE(GROUP_CONCAT(DISTINCT pt.name), '') AS prayerTimesCsv
      FROM niggunim n
      LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
      LEFT JOIN singers s ON s.id = ns.singer_id
      LEFT JOIN niggun_authors na ON na.niggun_id = n.id
      LEFT JOIN authors a ON a.id = na.author_id
      LEFT JOIN niggun_occasions no ON no.niggun_id = n.id
      LEFT JOIN occasions o ON o.id = no.occasion_id
      LEFT JOIN niggun_prayer_times npt ON npt.niggun_id = n.id
      LEFT JOIN prayer_times pt ON pt.id = npt.prayer_time_id
      GROUP BY n.id
      `
    )
    .all();
}

function deleteNiggunSearchRecord(niggunId) {
  if (!niggunSearchFtsEnabled) {
    return;
  }

  db.prepare("DELETE FROM niggun_search WHERE niggun_id = ?").run(niggunId);
}

function upsertNiggunSearchRecord(niggunId) {
  if (!niggunSearchFtsEnabled) {
    return;
  }

  const row = fetchNiggunSearchRowById(niggunId);
  deleteNiggunSearchRecord(niggunId);

  if (!row) {
    return;
  }

  const record = toNiggunSearchRecord(row);
  db.prepare(
    `INSERT INTO niggun_search (
      niggun_id,
      title,
      notes,
      singers,
      authors,
      occasions,
      prayer_times
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    record.niggunId,
    record.title,
    record.notes,
    record.singers,
    record.authors,
    record.occasions,
    record.prayerTimes
  );
}

const rebuildNiggunSearchIndexTxn = db.transaction(() => {
  db.prepare("DELETE FROM niggun_search").run();

  const insert = db.prepare(
    `INSERT INTO niggun_search (
      niggun_id,
      title,
      notes,
      singers,
      authors,
      occasions,
      prayer_times
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)`
  );

  for (const row of listNiggunSearchRows()) {
    const record = toNiggunSearchRecord(row);
    insert.run(
      record.niggunId,
      record.title,
      record.notes,
      record.singers,
      record.authors,
      record.occasions,
      record.prayerTimes
    );
  }
});

function rebuildNiggunSearchIndex() {
  if (!niggunSearchFtsEnabled) {
    return;
  }

  rebuildNiggunSearchIndexTxn();
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
    authors: splitCsv(row.authorsCsv),
    occasions: splitCsv(row.occasionsCsv),
    prayerTimes: splitCsv(row.prayerTimesCsv)
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

function updateUserPassword(userId, passwordHash) {
  return db
    .prepare(
      `UPDATE users
       SET password_hash = ?
       WHERE id = ?`
    )
    .run(passwordHash, userId).changes;
}

function getLoginSecurityRecord(keyType, keyValue) {
  return (
    db
      .prepare(
        `SELECT
          key_type AS keyType,
          key_value AS keyValue,
          failed_count AS failedCount,
          first_failed_at AS firstFailedAt,
          locked_until AS lockedUntil
         FROM login_security
         WHERE key_type = ?
           AND key_value = ?`
      )
      .get(keyType, keyValue) || null
  );
}

function upsertLoginSecurityRecord(payload) {
  db.prepare(
    `INSERT INTO login_security (
      key_type,
      key_value,
      failed_count,
      first_failed_at,
      locked_until,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(key_type, key_value)
    DO UPDATE SET
      failed_count = excluded.failed_count,
      first_failed_at = excluded.first_failed_at,
      locked_until = excluded.locked_until,
      updated_at = datetime('now')`
  ).run(
    payload.keyType,
    payload.keyValue,
    payload.failedCount,
    payload.firstFailedAt || null,
    payload.lockedUntil || null
  );
}

function clearLoginSecurityRecord(keyType, keyValue) {
  db.prepare(
    `DELETE FROM login_security
     WHERE key_type = ?
       AND key_value = ?`
  ).run(keyType, keyValue);
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

function getOrCreateOccasionId(name) {
  const existing = db.prepare("SELECT id FROM occasions WHERE name = ? COLLATE NOCASE").get(name);
  if (existing) {
    return existing.id;
  }

  const inserted = db.prepare("INSERT INTO occasions (name) VALUES (?)").run(name);
  return inserted.lastInsertRowid;
}

function getOrCreatePrayerTimeId(name) {
  const existing = db.prepare("SELECT id FROM prayer_times WHERE name = ? COLLATE NOCASE").get(name);
  if (existing) {
    return existing.id;
  }

  const inserted = db.prepare("INSERT INTO prayer_times (name) VALUES (?)").run(name);
  return inserted.lastInsertRowid;
}

function cleanupUnusedLookupTables() {
  db.prepare(
    `DELETE FROM singers
     WHERE id NOT IN (SELECT singer_id FROM niggun_singers)`
  ).run();
  db.prepare(
    `DELETE FROM authors
     WHERE id NOT IN (SELECT author_id FROM niggun_authors)`
  ).run();
  db.prepare(
    `DELETE FROM occasions
     WHERE id NOT IN (SELECT occasion_id FROM niggun_occasions)`
  ).run();
  db.prepare(
    `DELETE FROM prayer_times
     WHERE id NOT IN (SELECT prayer_time_id FROM niggun_prayer_times)`
  ).run();
}

function insertNiggunLinks(niggunId, payload) {
  const insertSingerLink = db.prepare(
    "INSERT INTO niggun_singers (niggun_id, singer_id) VALUES (?, ?)"
  );
  const insertAuthorLink = db.prepare(
    "INSERT INTO niggun_authors (niggun_id, author_id) VALUES (?, ?)"
  );
  const insertOccasionLink = db.prepare(
    "INSERT INTO niggun_occasions (niggun_id, occasion_id) VALUES (?, ?)"
  );
  const insertPrayerTimeLink = db.prepare(
    "INSERT INTO niggun_prayer_times (niggun_id, prayer_time_id) VALUES (?, ?)"
  );

  for (const singerName of payload.singers) {
    const singerId = getOrCreateSingerId(singerName);
    insertSingerLink.run(niggunId, singerId);
  }

  for (const authorName of payload.authors) {
    const authorId = getOrCreateAuthorId(authorName);
    insertAuthorLink.run(niggunId, authorId);
  }

  for (const occasionName of payload.occasions || []) {
    const occasionId = getOrCreateOccasionId(occasionName);
    insertOccasionLink.run(niggunId, occasionId);
  }

  for (const prayerTimeName of payload.prayerTimes || []) {
    const prayerTimeId = getOrCreatePrayerTimeId(prayerTimeName);
    insertPrayerTimeLink.run(niggunId, prayerTimeId);
  }
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
  insertNiggunLinks(niggunId, payload);
  upsertNiggunSearchRecord(niggunId);

  return niggunId;
});

function createNiggun(payload) {
  return createNiggunTxn(payload);
}

const updateNiggunTxn = db.transaction((payload) => {
  const existing = db
    .prepare(
      `SELECT id, audio_path AS audioPath
       FROM niggunim
       WHERE id = ?`
    )
    .get(payload.id);

  if (!existing) {
    return null;
  }

  db.prepare(
    `UPDATE niggunim
     SET title = ?,
         notes = ?,
         tempo = ?,
         musical_key = ?,
         audio_path = ?,
         audio_source_url = ?,
         original_filename = ?,
         mime_type = ?
     WHERE id = ?`
  ).run(
    payload.title,
    payload.notes || null,
    payload.tempo || null,
    payload.musicalKey || null,
    payload.audioPath,
    payload.audioSourceUrl || null,
    payload.originalFilename || null,
    payload.mimeType || null,
    payload.id
  );

  db.prepare("DELETE FROM niggun_singers WHERE niggun_id = ?").run(payload.id);
  db.prepare("DELETE FROM niggun_authors WHERE niggun_id = ?").run(payload.id);
  db.prepare("DELETE FROM niggun_occasions WHERE niggun_id = ?").run(payload.id);
  db.prepare("DELETE FROM niggun_prayer_times WHERE niggun_id = ?").run(payload.id);

  insertNiggunLinks(payload.id, payload);
  upsertNiggunSearchRecord(payload.id);
  cleanupUnusedLookupTables();

  return {
    id: payload.id,
    previousAudioPath: existing.audioPath,
    newAudioPath: payload.audioPath
  };
});

function updateNiggun(payload) {
  return updateNiggunTxn(payload);
}

function toFtsMatchQuery(rawSearchQuery) {
  if (!rawSearchQuery) {
    return "";
  }

  const tokens = String(rawSearchQuery)
    .split(/\s+/)
    .map((token) => token.replace(/[^\p{L}\p{N}_'-]/gu, "").trim())
    .filter((token) => token && /[\p{L}\p{N}]/u.test(token))
    .slice(0, 10);

  if (tokens.length === 0) {
    return "";
  }

  return tokens
    .map((token) => `"${token.replace(/"/g, "\"\"")}"*`)
    .join(" AND ");
}

function buildNiggunWhereClause(filters = {}) {
  const conditions = [];
  const params = [];

  if (filters.searchQuery) {
    const ftsQuery = toFtsMatchQuery(filters.searchQuery);
    if (niggunSearchFtsEnabled && ftsQuery) {
      conditions.push(`n.id IN (
        SELECT niggun_id
        FROM niggun_search
        WHERE niggun_search MATCH ?
      )`);
      params.push(ftsQuery);
    } else {
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

  if (filters.occasions && filters.occasions.length > 0) {
    const placeholders = filters.occasions.map(() => "?").join(",");
    conditions.push(`EXISTS (
      SELECT 1
      FROM niggun_occasions no2
      JOIN occasions o2 ON o2.id = no2.occasion_id
      WHERE no2.niggun_id = n.id
        AND o2.name IN (${placeholders})
    )`);
    params.push(...filters.occasions);
  }

  if (filters.prayerTimes && filters.prayerTimes.length > 0) {
    const placeholders = filters.prayerTimes.map(() => "?").join(",");
    conditions.push(`EXISTS (
      SELECT 1
      FROM niggun_prayer_times npt2
      JOIN prayer_times pt2 ON pt2.id = npt2.prayer_time_id
      WHERE npt2.niggun_id = n.id
        AND pt2.name IN (${placeholders})
    )`);
    params.push(...filters.prayerTimes);
  }

  return {
    whereClause: conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "",
    params
  };
}

function countNiggunim(filters = {}) {
  const { whereClause, params } = buildNiggunWhereClause(filters);
  const row = db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM niggunim n
       ${whereClause}`
    )
    .get(...params);

  return row ? row.count : 0;
}

function resolveSortClause(sortKey) {
  switch (sortKey) {
    case "oldest":
      return "n.created_at ASC, n.id ASC";
    case "title_asc":
      return "LOWER(n.title) ASC, n.id ASC";
    case "title_desc":
      return "LOWER(n.title) DESC, n.id DESC";
    case "newest":
    default:
      return "n.created_at DESC, n.id DESC";
  }
}

function listNiggunim(filters = {}, options = {}) {
  const { whereClause, params } = buildNiggunWhereClause(filters);
  const sortClause = resolveSortClause(options.sortKey || "newest");

  const hasLimit = Number.isInteger(options.limit) && options.limit > 0;
  const offset = Number.isInteger(options.offset) && options.offset >= 0 ? options.offset : 0;

  let sql = `
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
      COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv,
      COALESCE(GROUP_CONCAT(DISTINCT o.name), '') AS occasionsCsv,
      COALESCE(GROUP_CONCAT(DISTINCT pt.name), '') AS prayerTimesCsv
    FROM niggunim n
    LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
    LEFT JOIN singers s ON s.id = ns.singer_id
    LEFT JOIN niggun_authors na ON na.niggun_id = n.id
    LEFT JOIN authors a ON a.id = na.author_id
    LEFT JOIN niggun_occasions no ON no.niggun_id = n.id
    LEFT JOIN occasions o ON o.id = no.occasion_id
    LEFT JOIN niggun_prayer_times npt ON npt.niggun_id = n.id
    LEFT JOIN prayer_times pt ON pt.id = npt.prayer_time_id
    ${whereClause}
    GROUP BY n.id
    ORDER BY ${sortClause}
  `;

  if (hasLimit) {
    sql += " LIMIT ? OFFSET ?";
    params.push(options.limit, offset);
  }

  const rows = db.prepare(sql).all(...params);
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
        COALESCE(GROUP_CONCAT(DISTINCT a.name), '') AS authorsCsv,
        COALESCE(GROUP_CONCAT(DISTINCT o.name), '') AS occasionsCsv,
        COALESCE(GROUP_CONCAT(DISTINCT pt.name), '') AS prayerTimesCsv
      FROM niggunim n
      LEFT JOIN niggun_singers ns ON ns.niggun_id = n.id
      LEFT JOIN singers s ON s.id = ns.singer_id
      LEFT JOIN niggun_authors na ON na.niggun_id = n.id
      LEFT JOIN authors a ON a.id = na.author_id
      LEFT JOIN niggun_occasions no ON no.niggun_id = n.id
      LEFT JOIN occasions o ON o.id = no.occasion_id
      LEFT JOIN niggun_prayer_times npt ON npt.niggun_id = n.id
      LEFT JOIN prayer_times pt ON pt.id = npt.prayer_time_id
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

  deleteNiggunSearchRecord(niggunId);
  db.prepare("DELETE FROM niggunim WHERE id = ?").run(niggunId);
  cleanupUnusedLookupTables();

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
  updateUserPassword,
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
};
