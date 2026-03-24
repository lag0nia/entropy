# Entropy

Encrypted terminal password manager built with Zig.

## Install

Install globally with one command:

```bash
curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/install.sh | bash
```

What it does:

1. Installs system dependencies (`git`, `curl`, `xz-utils`, `build-essential`, `libsodium-dev`).
2. Installs Zig `0.15.2` in `/opt/zig`.
3. Clones the source in `/opt/entropy/src`.
4. Builds the app in release mode.
5. Installs global command `entropy` in `/usr/local/bin/entropy`.

## Update

Update globally from anywhere:

```bash
curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/update.sh | bash
```

This pulls latest code, rebuilds, and replaces the global binary.

## Uninstall

Uninstall global binary and install files while preserving your vault by default:

```bash
curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/uninstall.sh | bash
```

Optional flags:

- `--purge-vault`: remove `~/.config/enthropy/vault.enc` too.
- `--remove-zig`: remove `/opt/zig` and `/usr/local/bin/zig`.

Examples:

```bash
curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/uninstall.sh | bash -s -- --remove-zig
curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/uninstall.sh | bash -s -- --purge-vault --remove-zig
```

## Local development

```bash
zig build
zig build run
zig build test
```

## Bitwarden import

```bash
entropy import bitwarden --file /path/to/bitwarden.json --mode strict --replace
entropy import bitwarden --file /path/to/bitwarden.json --mode best_effort --dry-run --merge
```

## Notes

- Vault path: `~/.config/enthropy/vault.enc`
- `english.txt` is the BIP-39 English wordlist used for password generation.
