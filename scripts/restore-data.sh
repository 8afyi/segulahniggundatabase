#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="segulah-niggun-database"
APP_DIR="/srv/segulah-niggun-database"
ENV_FILE=""
ARCHIVE_PATH=""
AUTO_APPROVE="0"

TMP_DIR=""
SERVICE_WAS_ACTIVE="0"
SERVICE_STOPPED="0"

usage() {
  cat <<'USAGE'
Usage:
  sudo ./scripts/restore-data.sh \
    --archive /var/backups/segulah-niggun-database/segulah-niggun-database-YYYYMMDDTHHMMSSZ.tar.gz \
    [--app-name segulah-niggun-database] \
    [--app-dir /srv/segulah-niggun-database] \
    [--env-file /etc/segulah-niggun-database.env] \
    [--yes]

Notes:
- Restores SQLite DB and uploads/audio from a backup archive created by backup-data.sh.
- Stops the app service during restore and restarts it when done.
USAGE
}

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$1"
}

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Restore must run as root."
  fi
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi

  if [[ "$SERVICE_STOPPED" == "1" && "$SERVICE_WAS_ACTIVE" == "1" ]]; then
    log "Attempting to restart ${APP_NAME} after interrupted restore"
    systemctl start "$APP_NAME" || true
  fi
}
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --archive)
        ARCHIVE_PATH="${2:-}"
        shift 2
        ;;
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
      --yes)
        AUTO_APPROVE="1"
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

  [[ -n "$ARCHIVE_PATH" ]] || fail "--archive is required"
  [[ -f "$ARCHIVE_PATH" ]] || fail "Archive not found: $ARCHIVE_PATH"

  if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="/etc/${APP_NAME}.env"
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

confirm_restore() {
  if [[ "$AUTO_APPROVE" == "1" ]]; then
    return
  fi

  echo "Archive: $ARCHIVE_PATH"
  echo "App name: $APP_NAME"
  echo "This will overwrite the current database and audio files."
  read -r -p "Continue restore? [y/N] " answer
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    fail "Restore cancelled."
  fi
}

stop_service_if_needed() {
  if ! systemctl cat "${APP_NAME}.service" >/dev/null 2>&1; then
    log "Service ${APP_NAME}.service not found; skipping stop/start"
    return
  fi

  if systemctl is-active --quiet "$APP_NAME"; then
    SERVICE_WAS_ACTIVE="1"
    log "Stopping service ${APP_NAME}"
    systemctl stop "$APP_NAME"
    SERVICE_STOPPED="1"
  fi
}

start_service_if_needed() {
  if [[ "$SERVICE_WAS_ACTIVE" == "1" ]]; then
    log "Starting service ${APP_NAME}"
    systemctl start "$APP_NAME"
    SERVICE_STOPPED="0"
  fi
}

main() {
  require_root
  parse_args "$@"
  load_env_file
  confirm_restore
  stop_service_if_needed

  local db_path="${DB_PATH:-${APP_DIR}/data/app.db}"
  local audio_dir="${AUDIO_DIR:-${APP_DIR}/uploads/audio}"
  local db_dir
  db_dir="$(dirname "$db_path")"

  TMP_DIR="$(mktemp -d)"
  tar -C "$TMP_DIR" -xzf "$ARCHIVE_PATH"

  [[ -f "$TMP_DIR/data/app.db" ]] || fail "Invalid archive: data/app.db not found"
  [[ -d "$TMP_DIR/uploads/audio" ]] || fail "Invalid archive: uploads/audio not found"

  mkdir -p "$db_dir"
  mkdir -p "$audio_dir"

  log "Restoring database to $db_path"
  install -m 0640 "$TMP_DIR/data/app.db" "$db_path"

  if [[ -f "$TMP_DIR/data/app.db-wal" ]]; then
    install -m 0640 "$TMP_DIR/data/app.db-wal" "${db_path}-wal"
  else
    rm -f "${db_path}-wal"
  fi

  if [[ -f "$TMP_DIR/data/app.db-shm" ]]; then
    install -m 0640 "$TMP_DIR/data/app.db-shm" "${db_path}-shm"
  else
    rm -f "${db_path}-shm"
  fi

  log "Restoring audio files to $audio_dir"
  rsync -a --delete "$TMP_DIR/uploads/audio/" "$audio_dir/"

  if [[ -d "$APP_DIR" ]]; then
    chown --reference="$APP_DIR" "$db_path" || true
    if [[ -f "${db_path}-wal" ]]; then
      chown --reference="$APP_DIR" "${db_path}-wal" || true
    fi
    if [[ -f "${db_path}-shm" ]]; then
      chown --reference="$APP_DIR" "${db_path}-shm" || true
    fi
    chown -R --reference="$APP_DIR" "$audio_dir" || true
  fi

  start_service_if_needed
  log "Restore completed"
}

main "$@"
