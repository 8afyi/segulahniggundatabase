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

## Deploy helper (fresh Ubuntu)
Use `scripts/deploy-production-ubuntu.sh` on the server as `root`.

Example (with TLS):
```bash
sudo ./scripts/deploy-production-ubuntu.sh \
  --repo-url git@github.com:YOUR_ORG/YOUR_REPO.git \
  --branch main \
  --domain niggun.example.com \
  --email admin@example.com \
  --port 3000
```

Example (no domain/TLS yet):
```bash
sudo ./scripts/deploy-production-ubuntu.sh \
  --repo-url git@github.com:YOUR_ORG/YOUR_REPO.git \
  --branch main \
  --port 3000 \
  --skip-certbot
```

What the script does:
- Installs system packages (`git`, `nginx`, `ufw`, Node.js 20, etc.)
- Creates an app user and deploys code to `/srv/segulah-niggun-database`
- Installs production Node dependencies
- Creates runtime dirs for DB and uploaded audio
- Writes `/etc/segulah-niggun-database.env` (preserves existing `SESSION_SECRET` on reruns)
- Configures and starts a `systemd` service
- Configures Nginx reverse proxy with `client_max_body_size 20M`
- Optionally provisions Let’s Encrypt certs when `--domain` and `--email` are provided

Update deploy:
- Re-run the same deploy command; it will pull latest code from the configured branch and restart the service.

## Production notes (Ubuntu)
- Set a strong `SESSION_SECRET`
- Run behind Nginx/Caddy with TLS
- Replace the default in-memory session store with Redis or a DB-backed store
- Back up:
  - `data/app.db`
  - `uploads/audio/`
- For larger scale, migrate DB to PostgreSQL and media to object storage.
