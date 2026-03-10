# enthropy

Terminal password manager written in Zig.

## Current status

This repository contains the active encrypted vault + TUI application in `src/`.

The only active entrypoint for the application is:

- `src/main.zig`

## Architecture

The active app is split into these modules:

- `src/main.zig`: bootstrap, vault creation/unlock flow, launches TUI.
- `src/tui.zig`: terminal UI state machine and CRUD interactions.
- `src/vault_service.zig`: business logic for item/category CRUD and invariants.
- `src/schema_v2.zig`: v2 migration schema for 1:1 Bitwarden JSON compatibility.
- `src/relations_v2.zig`: normalized v2 container relations (`item-folder`, `item-collection`) and integrity checks.
- `src/storage.zig`: encrypted vault persistence (JSON wrapper on disk).
- `src/crypto.zig`: libsodium wrappers (Argon2id + XChaCha20-Poly1305).
- `src/model.zig`: core entities (`Vault`, `Item`, `Category`) and helpers.
- `src/bip39.zig`: BIP-39 mnemonic generation for passwords.
- `src/utils.zig`: terminal helpers (colors, raw input, hidden password input).

## Vault flow

1. Resolve vault path: `~/.config/enthropy/vault.enc`
2. If exists: prompt for master password and decrypt.
3. If not exists: create a new vault and encrypt it.
4. Run TUI loop and persist after CRUD changes.

## Build and run

Requires Zig `0.15.2` and `libsodium` available in the system.

```bash
zig build
zig build run
zig build test
```

## Bitwarden import

```bash
enthropy import bitwarden --file /path/to/bitwarden.json --mode strict --replace
enthropy import bitwarden --file /path/to/bitwarden.json --mode best_effort --dry-run --merge
```

## Notes

- `english.txt` is the BIP-39 English wordlist used for password generation.
