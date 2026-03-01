# Segulah Niggun Database 

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
4. Configure Google OAuth for public sign-in:
   - set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`
   - set `GOOGLE_CALLBACK_URL` (default: `/auth/google/callback`)
   - if needed, you can point `GOOGLE_CLIENT_SECRET_FILE` to a downloaded Google client secret JSON
5. Optional: start Redis for local parity with production:
   ```bash
   sudo systemctl start redis-server
   ```
6. Start server:
   ```bash
   npm start
   ```
7. Open:
   - Public site: `http://localhost:3000`
   - First-run admin setup: `http://localhost:3000/admin/setup`

## Deploy helper 
Use `scripts/deploy-production-ubuntu-debian.sh` on the server as `root`.

Example (with TLS):
```bash
sudo ./scripts/deploy-production-ubuntu-debian.sh \
  --repo-url https://github.com/8afyi/segulahniggundatabase.git \
  --domain niggun.example.com \
  --email admin@example.com \
  --port 3000
```

Example (no domain/TLS yet):
```bash
sudo ./scripts/deploy-production-ubuntu-debian.sh \
  --repo-url https://github.com/8afyi/segulahniggundatabase.git \
  --port 3000 \
  --skip-certbot
```

What the script does:
- Installs required system packages
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

## Production notes (Ubuntu/Debian)
- Deploy helper scripts:
  - Ubuntu + Debian (unified): `scripts/deploy-production-ubuntu-debian.sh`
  - Ubuntu: `scripts/deploy-production-ubuntu.sh`
  - Debian 13: `scripts/deploy-production-debian13.sh`
- Set a strong `SESSION_SECRET`
- In production, startup fails if `SESSION_SECRET` is missing, too short, or left at the development fallback value
- Keep Redis local-only (`127.0.0.1`) unless you intentionally externalize it
- Run behind Nginx/Caddy with TLS
- For Cloudflare, use Full (strict) TLS mode and keep `TRUST_PROXY=1`
- Back up:
  - `data/app.db`
  - `uploads/audio/`
- For larger scale, migrate DB to PostgreSQL and media to object storage.
