#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="segulah-niggun-database"
APP_USER="segulah"
APP_GROUP="segulah"
APP_DIR="/srv/segulah-niggun-database"
REPO_URL=""
BRANCH="main"
DOMAIN=""
LETSENCRYPT_EMAIL=""
PORT="3000"
REDIS_URL="redis://127.0.0.1:6379"
ENABLE_UFW="1"
SKIP_CERTBOT="0"

usage() {
  cat <<'USAGE'
Usage:
  sudo ./scripts/deploy-production-ubuntu.sh \
    --repo-url <git_repo_url> \
    [--branch main] \
    [--domain example.com] \
    [--email admin@example.com] \
    [--port 3000] \
    [--redis-url redis://127.0.0.1:6379] \
    [--app-name segulah-niggun-database] \
    [--app-user segulah] \
    [--app-dir /srv/segulah-niggun-database] \
    [--no-ufw] \
    [--skip-certbot]

Notes:
- Run as root on a fresh Ubuntu server.
- --repo-url is required.
- If both --domain and --email are provided, TLS is configured with certbot.
- Re-running the script updates code and keeps existing SESSION_SECRET.
USAGE
}

log() {
  printf '\n[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "This script must be run as root."
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-url)
        REPO_URL="${2:-}"
        shift 2
        ;;
      --branch)
        BRANCH="${2:-}"
        shift 2
        ;;
      --domain)
        DOMAIN="${2:-}"
        shift 2
        ;;
      --email)
        LETSENCRYPT_EMAIL="${2:-}"
        shift 2
        ;;
      --port)
        PORT="${2:-}"
        shift 2
        ;;
      --redis-url)
        REDIS_URL="${2:-}"
        shift 2
        ;;
      --app-name)
        APP_NAME="${2:-}"
        shift 2
        ;;
      --app-user)
        APP_USER="${2:-}"
        APP_GROUP="${2:-}"
        shift 2
        ;;
      --app-dir)
        APP_DIR="${2:-}"
        shift 2
        ;;
      --no-ufw)
        ENABLE_UFW="0"
        shift
        ;;
      --skip-certbot)
        SKIP_CERTBOT="1"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "Unknown argument: $1"
        ;;
    esac
  done

  [[ -n "$REPO_URL" ]] || fail "--repo-url is required"
  [[ -n "$BRANCH" ]] || fail "--branch cannot be empty"
  [[ "$PORT" =~ ^[0-9]+$ ]] || fail "--port must be numeric"
  [[ -n "$REDIS_URL" ]] || fail "--redis-url cannot be empty"

  if [[ -n "$LETSENCRYPT_EMAIL" && -z "$DOMAIN" ]]; then
    fail "--email requires --domain"
  fi
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

install_nodejs() {
  local major
  if command -v node >/dev/null 2>&1; then
    major="$(node -p "process.versions.node.split('.')[0]")"
    if [[ "$major" -ge 20 ]]; then
      log "Node.js $(node -v) already installed"
      return
    fi
  fi

  log "Installing Node.js 20.x"
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update
  apt_install nodejs
}

ensure_app_user() {
  if ! id -u "$APP_USER" >/dev/null 2>&1; then
    log "Creating system user: $APP_USER"
    useradd --system --create-home --shell /bin/bash "$APP_USER"
  fi
}

checkout_or_update_repo() {
  install -d -m 0755 "$APP_DIR"

  if [[ -d "$APP_DIR/.git" ]]; then
    log "Updating existing repository in $APP_DIR"
    chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
    runuser -u "$APP_USER" -- git -C "$APP_DIR" fetch origin "$BRANCH"
    runuser -u "$APP_USER" -- git -C "$APP_DIR" checkout "$BRANCH"
    runuser -u "$APP_USER" -- git -C "$APP_DIR" pull --ff-only origin "$BRANCH"
  else
    log "Cloning repository to $APP_DIR"
    chown "$APP_USER:$APP_GROUP" "$APP_DIR"
    runuser -u "$APP_USER" -- git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
  fi

  chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"
}

install_node_deps() {
  log "Installing Node dependencies"
  if [[ -f "$APP_DIR/package-lock.json" ]]; then
    runuser -u "$APP_USER" -- bash -lc "cd '$APP_DIR' && npm ci --omit=dev"
  else
    runuser -u "$APP_USER" -- bash -lc "cd '$APP_DIR' && npm install --omit=dev"
  fi
}

ensure_runtime_dirs() {
  install -d -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/data"
  install -d -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/uploads"
  install -d -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$APP_DIR/uploads/audio"
}

ensure_helper_scripts_executable() {
  chmod +x "$APP_DIR/scripts/backup-data.sh"
  chmod +x "$APP_DIR/scripts/restore-data.sh"
}

ensure_redis_service() {
  if [[ ! -d /run/systemd/system ]]; then
    fail "systemd is not running on this host. Cannot enable Redis service with systemctl."
  fi

  local candidate
  for candidate in redis-server redis redis-server.service redis.service; do
    systemctl unmask "$candidate" >/dev/null 2>&1 || true
    if systemctl enable --now "$candidate" >/dev/null 2>&1; then
      log "Enabled Redis service (${candidate})"
      return
    fi
  done

  local discovered_units
  discovered_units="$(ls /etc/systemd/system/redis*.service /lib/systemd/system/redis*.service /usr/lib/systemd/system/redis*.service 2>/dev/null || true)"

  if [[ -n "$discovered_units" ]]; then
    echo "Detected Redis-related systemd unit files:" >&2
    echo "$discovered_units" >&2
  else
    echo "No Redis-related unit files found under /etc/systemd/system, /lib/systemd/system, or /usr/lib/systemd/system." >&2
  fi

  fail "Could not enable Redis service. Try: systemctl daemon-reload && systemctl list-unit-files | grep -i redis"
}

write_env_file() {
  local env_file="/etc/${APP_NAME}.env"
  local session_secret=""

  if [[ -f "$env_file" ]]; then
    session_secret="$(grep -E '^SESSION_SECRET=' "$env_file" | head -n1 | cut -d= -f2- || true)"
  fi

  if [[ -z "$session_secret" ]]; then
    session_secret="$(openssl rand -hex 48)"
  fi

  cat > "$env_file" <<ENV
NODE_ENV=production
PORT=${PORT}
SESSION_SECRET=${session_secret}
DB_PATH=${APP_DIR}/data/app.db
SESSION_STORE=redis
REDIS_URL=${REDIS_URL}
TRUST_PROXY=1
LOGIN_FAILURE_LIMIT=5
LOGIN_FAILURE_WINDOW_MINUTES=15
LOGIN_LOCKOUT_MINUTES=15
LOGIN_RATE_LIMIT_MAX=20
ENV

  chmod 0600 "$env_file"
}

write_systemd_service() {
  local service_file="/etc/systemd/system/${APP_NAME}.service"

  cat > "$service_file" <<SERVICE
[Unit]
Description=Segulah Niggun Database
After=network-online.target redis-server.service
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=/etc/${APP_NAME}.env
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${APP_DIR}/data ${APP_DIR}/uploads/audio
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICE

  systemctl daemon-reload
  systemctl enable "$APP_NAME"
  systemctl restart "$APP_NAME"
}

write_backup_timer() {
  local backup_service_file="/etc/systemd/system/${APP_NAME}-backup.service"
  local backup_timer_file="/etc/systemd/system/${APP_NAME}-backup.timer"

  cat > "$backup_service_file" <<SERVICE
[Unit]
Description=Backup ${APP_NAME} data

[Service]
Type=oneshot
User=root
Group=root
ExecStart=${APP_DIR}/scripts/backup-data.sh --app-name ${APP_NAME} --app-dir ${APP_DIR} --env-file /etc/${APP_NAME}.env --backup-dir /var/backups/${APP_NAME} --retention-days 14
SERVICE

  cat > "$backup_timer_file" <<TIMER
[Unit]
Description=Daily backup timer for ${APP_NAME}

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}-backup.timer"
}

write_nginx_config() {
  local server_name="_"
  local nginx_site="/etc/nginx/sites-available/${APP_NAME}"

  if [[ -n "$DOMAIN" ]]; then
    server_name="$DOMAIN"
  fi

  cat > "$nginx_site" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${server_name};

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINX

  ln -sfn "$nginx_site" "/etc/nginx/sites-enabled/${APP_NAME}"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl restart nginx
  systemctl enable nginx
}

setup_firewall() {
  if [[ "$ENABLE_UFW" != "1" ]]; then
    log "Skipping UFW configuration (--no-ufw)"
    return
  fi

  log "Configuring UFW"
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
  ufw --force enable
}

setup_tls_if_requested() {
  if [[ "$SKIP_CERTBOT" == "1" ]]; then
    log "Skipping certbot setup (--skip-certbot)"
    return
  fi

  if [[ -z "$DOMAIN" || -z "$LETSENCRYPT_EMAIL" ]]; then
    log "TLS skipped (provide both --domain and --email to enable certbot)"
    return
  fi

  log "Installing certbot and requesting certificate for ${DOMAIN}"
  apt_install certbot python3-certbot-nginx
  certbot --nginx \
    --non-interactive \
    --agree-tos \
    --email "$LETSENCRYPT_EMAIL" \
    --redirect \
    --keep-until-expiring \
    -d "$DOMAIN"
}

main() {
  parse_args "$@"
  require_root

  log "Installing base packages"
  apt-get update
  apt_install ca-certificates curl gnupg git nginx openssl redis-server rsync sqlite3 ufw

  install_nodejs
  ensure_app_user
  checkout_or_update_repo
  install_node_deps
  ensure_runtime_dirs
  ensure_helper_scripts_executable
  ensure_redis_service
  write_env_file
  write_systemd_service
  write_backup_timer
  write_nginx_config
  setup_firewall
  setup_tls_if_requested

  log "Deployment complete"
  echo ""
  echo "Service status:"
  systemctl --no-pager --full status "$APP_NAME" || true
  echo ""
  echo "Useful commands:"
  echo "  journalctl -u ${APP_NAME} -f"
  echo "  systemctl restart ${APP_NAME}"
  echo "  systemctl status ${APP_NAME}-backup.timer"
  echo "  /var/backups/${APP_NAME}/"
  echo "  nginx -t && systemctl reload nginx"
}

main "$@"
