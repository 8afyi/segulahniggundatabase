# Segulah Niggun Database (MVP)

MVP web application for a public niggun catalog with an admin panel.

## Stack choice
- Frontend: server-rendered EJS templates + vanilla CSS/JS
- Backend: Node.js + Express
- Database: SQLite (`better-sqlite3`)
- Auth: session cookie auth (`express-session` + Redis store)

Why this stack for MVP:
- Fast to build and deploy on Ubuntu
- Low ops overhead (single service + local DB + filesystem audio storage)
- Easy path to scale later (swap DB/storage with minimal route changes)

## Features
- Public catalog open to everyone (no login)
- Search by title/notes and filter by tempo/key/singer/author
- SQLite FTS5-backed text search (with automatic fallback to LIKE if FTS5 is unavailable)
- Additional tag filters:
  - Service tags: Weekday, Shabbat, Festivals, Rosh Chodesh, High Holidays
  - Prayer tags: Shacharit, Musaf, Minchah, Maariv
- Public/admin list sorting and pagination
- Admin catalog search/filter parity with public filters (query state preserved across pagination/actions)
- Niggun detail card with built-in audio player
- Admin auth with first-run setup flow
- Admin user management (add/remove users, reset passwords)
- Niggun management (add/edit/remove)
- Audio input via upload or URL (downloaded and stored server-side)
- Redis-backed sessions (no in-memory session store)
- CSRF protection for admin POST actions
- Login hardening: IP rate limiting + temporary lockout after repeated failures
- Upload constraints:
  - max file size `20MB`
  - only browser-playable audio types

## Data model summary
- `users`
- `niggunim`
- `singers` + `niggun_singers` (many-to-many)
- `authors` + `niggun_authors` (many-to-many)
- `occasions` + `niggun_occasions` (many-to-many)
- `prayer_times` + `niggun_prayer_times` (many-to-many)

## Run locally
1. Install dependencies:
   ```bash
   npm install
   ```
2. Set environment:
   ```bash
   cp .env.example .env
   ```
3. Session store choice:
   - local default is `SESSION_STORE=memory` (no Redis required)
   - if you want Redis-backed sessions locally, set `SESSION_STORE=redis`
4. Optional: start Redis for local parity with production:
   ```bash
   sudo systemctl start redis-server
   ```
5. Start server:
   ```bash
   npm start
   ```
6. Open:
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
  --redis-url redis://127.0.0.1:6379 \
  --port 3000
```

Example (no domain/TLS yet):
```bash
sudo ./scripts/deploy-production-ubuntu.sh \
  --repo-url git@github.com:YOUR_ORG/YOUR_REPO.git \
  --branch main \
  --redis-url redis://127.0.0.1:6379 \
  --port 3000 \
  --skip-certbot
```

What the script does:
- Installs system packages (`git`, `nginx`, `ufw`, `sqlite3`, `rsync`, Node.js 20, etc.)
- Creates an app user and deploys code to `/srv/segulah-niggun-database`
- Installs production Node dependencies
- Installs and enables local `redis-server`
- Creates runtime dirs for DB and uploaded audio
- Writes `/etc/segulah-niggun-database.env` (preserves existing `SESSION_SECRET` on reruns)
- Configures and starts a `systemd` service
- Configures a daily backup timer (`systemd`) writing to `/var/backups/segulah-niggun-database/`
- Configures Nginx reverse proxy with `client_max_body_size 20M`
- Optionally provisions Let’s Encrypt certs when `--domain` and `--email` are provided

Update deploy:
- Re-run the same deploy command; it will pull latest code from the configured branch and restart the service.

## Backup and restore
Manual backup:
```bash
sudo ./scripts/backup-data.sh \
  --app-name segulah-niggun-database \
  --app-dir /srv/segulah-niggun-database \
  --env-file /etc/segulah-niggun-database.env
```

Manual restore:
```bash
sudo ./scripts/restore-data.sh \
  --archive /var/backups/segulah-niggun-database/segulah-niggun-database-YYYYMMDDTHHMMSSZ.tar.gz
```

Backup timer commands:
```bash
sudo systemctl status segulah-niggun-database-backup.timer
sudo systemctl list-timers | grep segulah-niggun-database-backup
```

## Production notes (Ubuntu)
- Set a strong `SESSION_SECRET`
- Keep Redis local-only (`127.0.0.1`) unless you intentionally externalize it
- Run behind Nginx/Caddy with TLS
- For Cloudflare, use Full (strict) TLS mode and keep `TRUST_PROXY=1`
- Back up:
  - `data/app.db`
  - `uploads/audio/`
- For larger scale, migrate DB to PostgreSQL and media to object storage.
