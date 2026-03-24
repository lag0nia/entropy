#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${ENTROPY_REPO_URL:-https://github.com/lag0nia/entropy.git}"
INSTALL_ROOT="${ENTROPY_INSTALL_ROOT:-/opt/entropy}"
SOURCE_DIR="${ENTROPY_SOURCE_DIR:-$INSTALL_ROOT/src}"
BIN_PATH="${ENTROPY_BIN_PATH:-/usr/local/bin/entropy}"
BUILD_OPTIMIZE="${ENTROPY_BUILD_OPTIMIZE:-ReleaseFast}"
ZIG_VERSION="${ENTROPY_ZIG_VERSION:-0.15.2}"

log() {
  printf '[entropy-install] %s\n' "$*"
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

ensure_apt_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    log "apt-get not found. install dependencies manually: git curl xz-utils build-essential libsodium-dev"
    exit 1
  fi

  log "installing system dependencies"
  as_root apt-get update
  as_root apt-get install -y git curl xz-utils build-essential libsodium-dev ca-certificates
}

install_zig() {
  local arch zarch zig_url tmp_archive current
  arch="$(uname -m)"

  case "$arch" in
    x86_64) zarch="x86_64-linux" ;;
    aarch64|arm64) zarch="aarch64-linux" ;;
    *)
      log "unsupported architecture: $arch"
      exit 1
      ;;
  esac

  if command -v zig >/dev/null 2>&1; then
    current="$(zig version || true)"
    if [ "$current" = "$ZIG_VERSION" ]; then
      log "zig $ZIG_VERSION already installed"
      return
    fi
    log "zig version mismatch (current=$current expected=$ZIG_VERSION). reinstalling"
  else
    log "zig not found. installing $ZIG_VERSION"
  fi

  zig_url="https://ziglang.org/download/${ZIG_VERSION}/zig-${zarch}-${ZIG_VERSION}.tar.xz"
  tmp_archive="/tmp/zig-${ZIG_VERSION}-${zarch}.tar.xz"

  curl -fsSL "$zig_url" -o "$tmp_archive"
  as_root rm -rf /opt/zig
  as_root mkdir -p /opt/zig
  as_root tar -xJf "$tmp_archive" -C /opt/zig --strip-components=1
  as_root ln -sf /opt/zig/zig /usr/local/bin/zig

  log "zig installed: $(zig version)"
}

sync_source() {
  if ! command -v git >/dev/null 2>&1; then
    log "git not found after dependency install"
    exit 1
  fi

  as_root mkdir -p "$INSTALL_ROOT"

  if [ -d "$SOURCE_DIR/.git" ]; then
    log "updating source at $SOURCE_DIR"
    git -C "$SOURCE_DIR" fetch --tags
    git -C "$SOURCE_DIR" pull --ff-only
  else
    log "cloning source into $SOURCE_DIR"
    as_root rm -rf "$SOURCE_DIR"
    as_root git clone "$REPO_URL" "$SOURCE_DIR"
    as_root chown -R "$(id -u):$(id -g)" "$SOURCE_DIR"
  fi
}

build_and_install() {
  log "building entropy ($BUILD_OPTIMIZE)"
  (cd "$SOURCE_DIR" && zig build -Doptimize="$BUILD_OPTIMIZE")

  if [ ! -f "$SOURCE_DIR/zig-out/bin/enthropy" ]; then
    log "build completed but binary not found at zig-out/bin/enthropy"
    exit 1
  fi

  log "installing global binary at $BIN_PATH"
  as_root install -m 755 "$SOURCE_DIR/zig-out/bin/enthropy" "$BIN_PATH"
}

main() {
  if ! command -v curl >/dev/null 2>&1; then
    log "curl not found. install curl and retry"
    exit 1
  fi

  ensure_apt_deps
  install_zig
  sync_source
  build_and_install

  log "done. run: entropy"
}

main "$@"
