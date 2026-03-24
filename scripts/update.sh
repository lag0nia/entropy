#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${ENTROPY_INSTALL_ROOT:-/opt/entropy}"
SOURCE_DIR="${ENTROPY_SOURCE_DIR:-$INSTALL_ROOT/src}"
BIN_PATH="${ENTROPY_BIN_PATH:-/usr/local/bin/entropy}"
BUILD_OPTIMIZE="${ENTROPY_BUILD_OPTIMIZE:-ReleaseFast}"

log() {
  printf '[entropy-update] %s\n' "$*"
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      log "sudo not found. run as root or install sudo"
      exit 1
    fi
    sudo "$@"
  fi
}

main() {
  if [ ! -d "$SOURCE_DIR/.git" ]; then
    log "source not found at $SOURCE_DIR"
    log "run install first"
    exit 1
  fi

  if ! command -v zig >/dev/null 2>&1; then
    log "zig is not installed. run install first"
    exit 1
  fi

  log "pulling latest changes"
  git -C "$SOURCE_DIR" fetch --tags
  git -C "$SOURCE_DIR" pull --ff-only

  log "building entropy ($BUILD_OPTIMIZE)"
  (cd "$SOURCE_DIR" && zig build -Doptimize="$BUILD_OPTIMIZE")

  if [ ! -f "$SOURCE_DIR/zig-out/bin/enthropy" ]; then
    log "binary not found after build at zig-out/bin/enthropy"
    exit 1
  fi

  log "installing global binary at $BIN_PATH"
  as_root install -m 755 "$SOURCE_DIR/zig-out/bin/enthropy" "$BIN_PATH"

  log "update finished"
}

main "$@"
