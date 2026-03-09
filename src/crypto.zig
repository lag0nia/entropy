const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

pub const SALT_LEN = c.crypto_pwhash_SALTBYTES; // 16
pub const KEY_LEN = c.crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
pub const NONCE_LEN = c.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
pub const TAG_LEN = c.crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16

pub const OPS_LIMIT: u64 = c.crypto_pwhash_OPSLIMIT_MODERATE;
pub const MEM_LIMIT: usize = c.crypto_pwhash_MEMLIMIT_MODERATE;
pub const OPS_LIMIT_MIN: u64 = c.crypto_pwhash_OPSLIMIT_MIN;
pub const OPS_LIMIT_MAX: u64 = c.crypto_pwhash_OPSLIMIT_MAX;
pub const MEM_LIMIT_MIN: usize = c.crypto_pwhash_MEMLIMIT_MIN;
pub const MEM_LIMIT_MAX: usize = c.crypto_pwhash_MEMLIMIT_MAX;

pub const CryptoError = error{
    SodiumInitFailed,
    InvalidKdfParams,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
};

/// Must be called once before any crypto operations
pub fn init() CryptoError!void {
    if (c.sodium_init() < 0) {
        return CryptoError.SodiumInitFailed;
    }
}

/// Generate a random salt for KDF
pub fn generateSalt() [SALT_LEN]u8 {
    var salt: [SALT_LEN]u8 = undefined;
    c.randombytes_buf(&salt, SALT_LEN);
    return salt;
}

/// Derive encryption key from master password using Argon2id
pub fn deriveKey(password: []const u8, salt: *const [SALT_LEN]u8) CryptoError![KEY_LEN]u8 {
    return deriveKeyWithParams(password, salt, OPS_LIMIT, MEM_LIMIT);
}

/// Derive encryption key from master password using explicit Argon2id params
pub fn deriveKeyWithParams(
    password: []const u8,
    salt: *const [SALT_LEN]u8,
    ops_limit: u64,
    mem_limit: usize,
) CryptoError![KEY_LEN]u8 {
    if (ops_limit < OPS_LIMIT_MIN or ops_limit > OPS_LIMIT_MAX) {
        return CryptoError.InvalidKdfParams;
    }
    if (mem_limit < MEM_LIMIT_MIN or mem_limit > MEM_LIMIT_MAX) {
        return CryptoError.InvalidKdfParams;
    }

    var key: [KEY_LEN]u8 = undefined;

    const result = c.crypto_pwhash(
        &key,
        KEY_LEN,
        password.ptr,
        password.len,
        salt,
        @intCast(ops_limit),
        @intCast(mem_limit),
        c.crypto_pwhash_ALG_ARGON2ID13,
    );

    if (result != 0) {
        return CryptoError.KeyDerivationFailed;
    }

    return key;
}

/// Encrypt plaintext using XChaCha20-Poly1305
/// Returns: ciphertext (plaintext.len + TAG_LEN bytes)
pub fn encrypt(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: *const [KEY_LEN]u8,
) CryptoError!struct { ciphertext: []u8, nonce: [NONCE_LEN]u8 } {
    var nonce: [NONCE_LEN]u8 = undefined;
    c.randombytes_buf(&nonce, NONCE_LEN);

    const ciphertext = allocator.alloc(u8, plaintext.len + TAG_LEN) catch
        return CryptoError.EncryptionFailed;

    var ciphertext_len: c_ulonglong = undefined;

    const result = c.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.ptr,
        &ciphertext_len,
        plaintext.ptr,
        plaintext.len,
        null, // no additional data
        0,
        null, // nsec (unused in this API)
        &nonce,
        key,
    );

    if (result != 0) {
        allocator.free(ciphertext);
        return CryptoError.EncryptionFailed;
    }

    return .{ .ciphertext = ciphertext[0..@intCast(ciphertext_len)], .nonce = nonce };
}

/// Decrypt ciphertext using XChaCha20-Poly1305
/// Returns plaintext or error if authentication fails
pub fn decrypt(
    allocator: std.mem.Allocator,
    ciphertext: []const u8,
    nonce: *const [NONCE_LEN]u8,
    key: *const [KEY_LEN]u8,
) CryptoError![]u8 {
    if (ciphertext.len < TAG_LEN) {
        return CryptoError.DecryptionFailed;
    }

    const plaintext = allocator.alloc(u8, ciphertext.len - TAG_LEN) catch
        return CryptoError.DecryptionFailed;

    var plaintext_len: c_ulonglong = undefined;

    const result = c.crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.ptr,
        &plaintext_len,
        null, // nsec (unused)
        ciphertext.ptr,
        ciphertext.len,
        null, // no additional data
        0,
        nonce,
        key,
    );

    if (result != 0) {
        allocator.free(plaintext);
        return CryptoError.DecryptionFailed;
    }

    return plaintext[0..@intCast(plaintext_len)];
}

/// Securely zero memory
pub fn zeroize(buf: []u8) void {
    c.sodium_memzero(buf.ptr, buf.len);
}

test "encrypt and decrypt roundtrip" {
    try init();

    const allocator = std.testing.allocator;
    const password = "test-master-password";
    const salt = generateSalt();
    const key = try deriveKey(password, &salt);

    const plaintext = "hello, enthropy vault!";
    const encrypted = try encrypt(allocator, plaintext, &key);
    defer allocator.free(encrypted.ciphertext);

    const decrypted = try decrypt(allocator, encrypted.ciphertext, &encrypted.nonce, &key);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "decrypt with wrong key fails" {
    try init();

    const allocator = std.testing.allocator;
    const password = "correct-password";
    const salt = generateSalt();
    const key = try deriveKey(password, &salt);

    const plaintext = "secret data";
    const encrypted = try encrypt(allocator, plaintext, &key);
    defer allocator.free(encrypted.ciphertext);

    // Derive a different key
    const wrong_key = try deriveKey("wrong-password", &salt);
    const result = decrypt(allocator, encrypted.ciphertext, &encrypted.nonce, &wrong_key);
    try std.testing.expectError(CryptoError.DecryptionFailed, result);
}
