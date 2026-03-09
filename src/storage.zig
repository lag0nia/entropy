const std = @import("std");
const model = @import("model.zig");
const crypto = @import("crypto.zig");

pub const StorageError = error{
    VaultNotFound,
    CorruptedVault,
    InvalidFormat,
    WriteError,
};

const base64_encoder = std.base64.standard.Encoder;
const base64_decoder = std.base64.standard.Decoder;

/// Get the default vault file path: ~/.config/enthropy/vault.enc
pub fn getVaultPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch
        return StorageError.VaultNotFound;
    defer allocator.free(home);

    return std.fmt.allocPrint(allocator, "{s}/.config/enthropy/vault.enc", .{home});
}

/// Get the wordlist path: same directory as executable or cwd
pub fn getWordlistPath() []const u8 {
    return "english.txt";
}

/// Serialize a value to JSON using an allocating writer
fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, &aw.writer);
    try aw.writer.flush();
    return aw.toOwnedSlice();
}

/// Save vault to disk encrypted with master key
pub fn saveVault(
    allocator: std.mem.Allocator,
    vault: model.Vault,
    key: *const [crypto.KEY_LEN]u8,
    salt: *const [crypto.SALT_LEN]u8,
    vault_path: []const u8,
) !void {
    // Serialize vault to JSON
    const plaintext = jsonStringifyAlloc(allocator, vault) catch
        return StorageError.WriteError;
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    // Encrypt
    const encrypted = crypto.encrypt(allocator, plaintext, key) catch
        return StorageError.WriteError;
    defer allocator.free(encrypted.ciphertext);

    // Base64 encode fields
    const salt_b64 = try base64Encode(allocator, salt);
    defer allocator.free(salt_b64);

    const nonce_b64 = try base64Encode(allocator, &encrypted.nonce);
    defer allocator.free(nonce_b64);

    const ct_b64 = try base64Encode(allocator, encrypted.ciphertext);
    defer allocator.free(ct_b64);

    // Build encrypted vault wrapper
    const wrapper = model.EncryptedVault{
        .version = 1,
        .kdf = .{
            .alg = "argon2id",
            .salt = salt_b64,
            .ops_limit = crypto.OPS_LIMIT,
            .mem_limit = crypto.MEM_LIMIT,
        },
        .cipher = .{
            .alg = "xchacha20poly1305",
            .nonce = nonce_b64,
            .ciphertext = ct_b64,
        },
    };

    // Serialize wrapper to JSON
    const wrapper_json = jsonStringifyAlloc(allocator, wrapper) catch
        return StorageError.WriteError;
    defer allocator.free(wrapper_json);

    // Ensure directory exists
    const dir_end = std.mem.lastIndexOfScalar(u8, vault_path, '/') orelse
        return StorageError.WriteError;
    const dir_path = vault_path[0..dir_end];

    std.fs.cwd().makePath(dir_path) catch {};

    // Write to file
    const file = std.fs.cwd().createFile(vault_path, .{}) catch
        return StorageError.WriteError;
    defer file.close();
    std.posix.fchmod(file.handle, 0o600) catch return StorageError.WriteError;

    file.writeAll(wrapper_json) catch return StorageError.WriteError;
}

/// Load and decrypt vault from disk
pub fn loadVault(
    allocator: std.mem.Allocator,
    password: []const u8,
    vault_path: []const u8,
) !struct { vault: model.Vault, key: [crypto.KEY_LEN]u8, salt: [crypto.SALT_LEN]u8 } {
    // Read encrypted wrapper
    const file = std.fs.cwd().openFile(vault_path, .{ .mode = .read_only }) catch
        return StorageError.VaultNotFound;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    defer allocator.free(data);

    // Parse wrapper JSON
    const parsed = std.json.parseFromSlice(model.EncryptedVault, allocator, data, .{}) catch
        return StorageError.CorruptedVault;
    defer parsed.deinit();

    const wrapper = parsed.value;
    try validateWrapperMetadata(wrapper);

    // Decode base64 fields
    var salt: [crypto.SALT_LEN]u8 = undefined;
    const salt_len = base64_decoder.calcSizeForSlice(wrapper.kdf.salt) catch
        return StorageError.CorruptedVault;
    if (salt_len != crypto.SALT_LEN) return StorageError.InvalidFormat;
    base64_decoder.decode(&salt, wrapper.kdf.salt) catch return StorageError.CorruptedVault;

    var nonce: [crypto.NONCE_LEN]u8 = undefined;
    const nonce_len = base64_decoder.calcSizeForSlice(wrapper.cipher.nonce) catch
        return StorageError.CorruptedVault;
    if (nonce_len != crypto.NONCE_LEN) return StorageError.InvalidFormat;
    base64_decoder.decode(&nonce, wrapper.cipher.nonce) catch return StorageError.CorruptedVault;

    const ct_len = base64_decoder.calcSizeForSlice(wrapper.cipher.ciphertext) catch
        return StorageError.CorruptedVault;
    if (ct_len < crypto.TAG_LEN) return StorageError.InvalidFormat;
    const ciphertext = allocator.alloc(u8, ct_len) catch return StorageError.CorruptedVault;
    defer allocator.free(ciphertext);
    base64_decoder.decode(ciphertext, wrapper.cipher.ciphertext) catch return StorageError.CorruptedVault;

    // Derive key
    const mem_limit = std.math.cast(usize, wrapper.kdf.mem_limit) orelse
        return StorageError.InvalidFormat;
    const key = crypto.deriveKeyWithParams(
        password,
        &salt,
        wrapper.kdf.ops_limit,
        mem_limit,
    ) catch |err| switch (err) {
        crypto.CryptoError.InvalidKdfParams => return StorageError.InvalidFormat,
        else => return StorageError.CorruptedVault,
    };

    // Decrypt
    const plaintext = crypto.decrypt(allocator, ciphertext, &nonce, &key) catch
        return StorageError.CorruptedVault;
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    // Parse vault JSON
    const vault_parsed = std.json.parseFromSlice(model.Vault, allocator, plaintext, .{}) catch
        return StorageError.CorruptedVault;
    defer vault_parsed.deinit();
    const vault = model.cloneVault(allocator, vault_parsed.value) catch
        return StorageError.CorruptedVault;

    return .{
        .vault = vault,
        .key = key,
        .salt = salt,
    };
}

fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const len = base64_encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, len);
    _ = base64_encoder.encode(buf, data);
    return buf;
}

fn validateWrapperMetadata(wrapper: model.EncryptedVault) !void {
    if (wrapper.version != 1) return StorageError.InvalidFormat;
    if (!std.mem.eql(u8, wrapper.kdf.alg, "argon2id")) return StorageError.InvalidFormat;
    if (!std.mem.eql(u8, wrapper.cipher.alg, "xchacha20poly1305")) return StorageError.InvalidFormat;
    if (wrapper.kdf.salt.len == 0) return StorageError.InvalidFormat;
    if (wrapper.cipher.nonce.len == 0) return StorageError.InvalidFormat;
    if (wrapper.cipher.ciphertext.len == 0) return StorageError.InvalidFormat;
}

fn makeSampleVault(allocator: std.mem.Allocator) !model.Vault {
    const now = "2026-03-09T12:00:00";

    var items = try allocator.alloc(model.Item, 1);
    errdefer allocator.free(items);
    items[0] = .{
        .id = try allocator.dupe(u8, "item-1"),
        .name = try allocator.dupe(u8, "github"),
        .mail = try allocator.dupe(u8, "dev@example.com"),
        .password = try allocator.dupe(u8, "super-secret"),
        .notes = try allocator.dupe(u8, "personal account"),
        .category_id = try allocator.dupe(u8, "cat-1"),
        .created_at = try allocator.dupe(u8, now),
        .updated_at = try allocator.dupe(u8, now),
    };
    errdefer model.freeItem(allocator, &items[0]);

    var categories = try allocator.alloc(model.Category, 1);
    errdefer allocator.free(categories);
    categories[0] = .{
        .id = try allocator.dupe(u8, "cat-1"),
        .name = try allocator.dupe(u8, "work"),
    };
    errdefer model.freeCategory(allocator, &categories[0]);

    return .{
        .version = 1,
        .items = items,
        .categories = categories,
    };
}

fn makeTempVaultPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    const abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs);
    return try std.fmt.allocPrint(allocator, "{s}/vault.enc", .{abs});
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    return try file.readToEndAlloc(allocator, 8 * 1024 * 1024);
}

fn writeFile(path: []const u8, data: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
}

test "saveVault and loadVault roundtrip" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "test-master-password";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);

    try saveVault(allocator, vault, &key, &salt, vault_path);
    const loaded = try loadVault(allocator, password, vault_path);
    defer {
        model.freeVault(allocator, @constCast(&loaded.vault));
        crypto.zeroize(@constCast(&loaded.key));
    }

    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.categories.len);
    try std.testing.expectEqualStrings("github", loaded.vault.items[0].name.?);
    try std.testing.expectEqualStrings("dev@example.com", loaded.vault.items[0].mail.?);
    try std.testing.expectEqualStrings("super-secret", loaded.vault.items[0].password);
    try std.testing.expectEqualStrings("work", loaded.vault.categories[0].name);
}

test "loadVault with wrong password fails" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey("correct-password", &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    const result = loadVault(allocator, "wrong-password", vault_path);
    try std.testing.expectError(StorageError.CorruptedVault, result);
}

test "loadVault rejects unsupported wrapper version" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "version-check";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    const raw = try readFileAlloc(allocator, vault_path);
    defer allocator.free(raw);
    var parsed = try std.json.parseFromSlice(model.EncryptedVault, allocator, raw, .{});
    defer parsed.deinit();

    var wrapper = parsed.value;
    wrapper.version = 2;
    const mutated = try jsonStringifyAlloc(allocator, wrapper);
    defer allocator.free(mutated);
    try writeFile(vault_path, mutated);

    const result = loadVault(allocator, password, vault_path);
    try std.testing.expectError(StorageError.InvalidFormat, result);
}

test "loadVault rejects unknown KDF algorithm" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "kdf-check";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    const raw = try readFileAlloc(allocator, vault_path);
    defer allocator.free(raw);
    var parsed = try std.json.parseFromSlice(model.EncryptedVault, allocator, raw, .{});
    defer parsed.deinit();

    var wrapper = parsed.value;
    wrapper.kdf.alg = "bad-kdf";
    const mutated = try jsonStringifyAlloc(allocator, wrapper);
    defer allocator.free(mutated);
    try writeFile(vault_path, mutated);

    const result = loadVault(allocator, password, vault_path);
    try std.testing.expectError(StorageError.InvalidFormat, result);
}

test "loadVault rejects invalid KDF params from metadata" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "kdf-params";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    const raw = try readFileAlloc(allocator, vault_path);
    defer allocator.free(raw);
    var parsed = try std.json.parseFromSlice(model.EncryptedVault, allocator, raw, .{});
    defer parsed.deinit();

    var wrapper = parsed.value;
    wrapper.kdf.mem_limit = 1;
    const mutated = try jsonStringifyAlloc(allocator, wrapper);
    defer allocator.free(mutated);
    try writeFile(vault_path, mutated);

    const result = loadVault(allocator, password, vault_path);
    try std.testing.expectError(StorageError.InvalidFormat, result);
}
