#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="segulah-niggun-database"
APP_DIR="/srv/segulah-niggun-database"
ENV_FILE=""
BACKUP_DIR=""
RETENTION_DAYS="14"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/backup-data.sh \
    [--app-name segulah-niggun-database] \
    [--app-dir /srv/segulah-niggun-database] \
    [--env-file /etc/segulah-niggun-database.env] \
    [--backup-dir /var/backups/segulah-niggun-database] \
    [--retention-days 14]

Notes:
- Backs up SQLite DB and uploads/audio into a timestamped tar.gz archive.
- Removes archives older than --retention-days.
- If sqlite3 is installed, it uses SQLite's .backup command for a consistent snapshot.
USAGE
}

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --app-name)
        APP_NAME="${2:-}"
        shift 2
        ;;
      --app-dir)
        APP_DIR="${2:-}"
        shift 2
        ;;
      --env-file)
        ENV_FILE="${2:-}"
        shift 2
        ;;
      --backup-dir)
        BACKUP_DIR="${2:-}"
        shift 2
        ;;
      --retention-days)
        RETENTION_DAYS="${2:-}"
        shift 2
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

  [[ -n "$APP_NAME" ]] || fail "--app-name cannot be empty"
  [[ -n "$APP_DIR" ]] || fail "--app-dir cannot be empty"
  [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || fail "--retention-days must be a non-negative integer"

  if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="/etc/${APP_NAME}.env"
  fi

  if [[ -z "$BACKUP_DIR" ]]; then
    BACKUP_DIR="/var/backups/${APP_NAME}"
  fi
}

load_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  else
    log "Env file not found at $ENV_FILE, using defaults/flags"
  fi
}

main() {
  parse_args "$@"
  load_env_file

  local db_path="${DB_PATH:-${APP_DIR}/data/app.db}"
  local audio_dir="${AUDIO_DIR:-${APP_DIR}/uploads/audio}"
  local timestamp
  timestamp="$(date -u +'%Y%m%dT%H%M%SZ')"
  local archive_path="${BACKUP_DIR}/${APP_NAME}-${timestamp}.tar.gz"

  [[ -f "$db_path" ]] || fail "Database file not found: $db_path"

  mkdir -p "$BACKUP_DIR"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  mkdir -p "$tmp_dir/data"
  mkdir -p "$tmp_dir/uploads/audio"

  if command -v sqlite3 >/dev/null 2>&1; then
    log "Creating SQLite snapshot via sqlite3 .backup"
    sqlite3 "$db_path" ".backup '$tmp_dir/data/app.db'"
  else
    log "sqlite3 command not found; copying DB files directly"
    cp -a "$db_path" "$tmp_dir/data/app.db"
    if [[ -f "${db_path}-wal" ]]; then
      cp -a "${db_path}-wal" "$tmp_dir/data/app.db-wal"
    fi
    if [[ -f "${db_path}-shm" ]]; then
      cp -a "${db_path}-shm" "$tmp_dir/data/app.db-shm"
    fi
  fi

  if [[ -d "$audio_dir" ]]; then
    log "Copying audio files"
    rsync -a --delete "${audio_dir}/" "$tmp_dir/uploads/audio/"
  else
    log "Audio directory not found at $audio_dir, writing empty audio backup"
  fi

  cat > "$tmp_dir/backup-metadata.txt" <<EOF
created_at_utc=${timestamp}
app_name=${APP_NAME}
db_path=${db_path}
audio_dir=${audio_dir}
source_host=$(hostname -f 2>/dev/null || hostname)
EOF

  log "Writing archive: $archive_path"
  tar -C "$tmp_dir" -czf "$archive_path" data uploads backup-metadata.txt
  chmod 0600 "$archive_path" || true

  if [[ "$RETENTION_DAYS" -gt 0 ]]; then
    find "$BACKUP_DIR" -maxdepth 1 -type f -name "${APP_NAME}-*.tar.gz" -mtime +"$RETENTION_DAYS" -delete
  fi

  log "Backup completed"
  echo "$archive_path"
}

main "$@"
