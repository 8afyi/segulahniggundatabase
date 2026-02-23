# Segulah Niggun Database (MVP)

MVP web application for a public niggun catalog with an admin panel.

## Stack choice
- Frontend: server-rendered EJS templates + vanilla CSS/JS
- Backend: Node.js + Express
- Database: SQLite (`better-sqlite3`)
- Auth: session cookie auth (`express-session`)

Why this stack for MVP:
- Fast to build and deploy on Ubuntu
- Low ops overhead (single service + local DB + filesystem audio storage)
- Easy path to scale later (swap DB/storage with minimal route changes)

## Features
- Public catalog open to everyone (no login)
- Search by title/notes and filter by tempo/key/singer/author
- Niggun detail card with built-in audio player
- Admin auth with first-run setup flow
- Admin user management (add/remove users)
- Niggun management (add/remove)
- Audio input via upload or URL (downloaded and stored server-side)
- Upload constraints:
  - max file size `20MB`
  - only browser-playable audio types

## Data model summary
- `users`
- `niggunim`
- `singers` + `niggun_singers` (many-to-many)
- `authors` + `niggun_authors` (many-to-many)

## Run locally
1. Install dependencies:
   ```bash
   npm install
   ```
2. Set environment:
   ```bash
   cp .env.example .env
   ```
3. Start server:
   ```bash
   npm start
   ```
4. Open:
   - Public site: `http://localhost:3000`
   - First-run admin setup: `http://localhost:3000/admin/setup`

## Production notes (Ubuntu)
- Set a strong `SESSION_SECRET`
- Run behind Nginx/Caddy with TLS
- Replace the default in-memory session store with Redis or a DB-backed store
- Back up:
  - `data/app.db`
  - `uploads/audio/`
- For larger scale, migrate DB to PostgreSQL and media to object storage.
