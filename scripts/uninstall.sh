#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${ENTROPY_INSTALL_ROOT:-/opt/entropy}"
CONFIG_DIR="${ENTROPY_CONFIG_DIR:-$HOME/.config/enthropy}"
BIN_PATH="${ENTROPY_BIN_PATH:-/usr/local/bin/entropy}"
LEGACY_BIN_PATH="${ENTROPY_LEGACY_BIN_PATH:-/usr/local/bin/enthropy}"
REMOVE_ZIG=false
PURGE_VAULT=false

log() {
  printf '[entropy-uninstall] %s\n' "$*"
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

usage() {
  cat <<USAGE
Usage: uninstall.sh [--purge-vault] [--remove-zig]

Options:
  --purge-vault  Remove ~/.config/enthropy/vault.enc too.
  --remove-zig   Remove /opt/zig and /usr/local/bin/zig.
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --purge-vault)
        PURGE_VAULT=true
        ;;
      --remove-zig)
        REMOVE_ZIG=true
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log "unknown option: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done
}

remove_binaries() {
  log "removing global binaries"
  as_root rm -f "$BIN_PATH" "$LEGACY_BIN_PATH"
}

remove_install_root() {
  log "removing install root: $INSTALL_ROOT"
  as_root rm -rf "$INSTALL_ROOT"
}

cleanup_config() {
  if [ ! -d "$CONFIG_DIR" ]; then
    return
  fi

  if [ "$PURGE_VAULT" = true ]; then
    log "removing full config directory: $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
    return
  fi

  log "preserving vault.enc and cleaning remaining config files"
  mkdir -p "$CONFIG_DIR"
  find "$CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name 'vault.enc' -exec rm -rf {} +
}

remove_zig() {
  if [ "$REMOVE_ZIG" = false ]; then
    return
  fi

  log "removing zig installation"
  as_root rm -f /usr/local/bin/zig
  as_root rm -rf /opt/zig
}

main() {
  parse_args "$@"
  remove_binaries
  remove_install_root
  cleanup_config
  remove_zig
  log "uninstall finished"
}

main "$@"
