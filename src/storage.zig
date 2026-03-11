const std = @import("std");
const model = @import("model.zig");
const crypto = @import("crypto.zig");
const schema = @import("schema_v2.zig");

pub const StorageError = error{
    VaultNotFound,
    CorruptedVault,
    InvalidFormat,
    WriteError,
};

const base64_encoder = std.base64.standard.Encoder;
const base64_decoder = std.base64.standard.Decoder;

pub const LoadedVaultV2 = struct {
    arena: std.heap.ArenaAllocator,
    vault: schema.VaultV2,
    key: [crypto.KEY_LEN]u8,
    salt: [crypto.SALT_LEN]u8,

    pub fn deinit(self: *LoadedVaultV2) void {
        crypto.zeroize(self.key[0..]);
        self.arena.deinit();
        self.* = undefined;
    }
};

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
    // Persist runtime vault as v2 schema payload while preserving existing typed metadata.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const projected = try projectRuntimeVaultToV2(a, vault);

    var loaded_existing: ?LoadedVaultV2 = loadVaultV2WithKey(allocator, key, vault_path) catch |err| switch (err) {
        StorageError.VaultNotFound => null,
        else => return err,
    };
    defer if (loaded_existing) |*existing| existing.deinit();

    const final_payload = if (loaded_existing) |*existing|
        try mergeProjectedWithExistingForSave(a, &existing.vault, &projected)
    else
        projected;

    return saveVaultV2(allocator, final_payload, key, salt, vault_path);
}

pub fn saveVaultV2(
    allocator: std.mem.Allocator,
    vault: schema.VaultV2,
    key: *const [crypto.KEY_LEN]u8,
    salt: *const [crypto.SALT_LEN]u8,
    vault_path: []const u8,
) !void {
    const plaintext = jsonStringifyAlloc(allocator, vault) catch
        return StorageError.WriteError;
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    return saveEncryptedPayload(allocator, plaintext, key, salt, vault_path);
}

fn saveEncryptedPayload(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    key: *const [crypto.KEY_LEN]u8,
    salt: *const [crypto.SALT_LEN]u8,
    vault_path: []const u8,
) !void {
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

pub fn loadVaultV2(
    allocator: std.mem.Allocator,
    password: []const u8,
    vault_path: []const u8,
) !LoadedVaultV2 {
    const file = std.fs.cwd().openFile(vault_path, .{ .mode = .read_only }) catch
        return StorageError.VaultNotFound;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    defer allocator.free(data);

    const parsed = std.json.parseFromSlice(model.EncryptedVault, allocator, data, .{}) catch
        return StorageError.CorruptedVault;
    defer parsed.deinit();

    const wrapper = parsed.value;
    try validateWrapperMetadata(wrapper);

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

    const mem_limit = std.math.cast(usize, wrapper.kdf.mem_limit) orelse
        return StorageError.InvalidFormat;
    var key = crypto.deriveKeyWithParams(
        password,
        &salt,
        wrapper.kdf.ops_limit,
        mem_limit,
    ) catch |err| switch (err) {
        crypto.CryptoError.InvalidKdfParams => return StorageError.InvalidFormat,
        else => return StorageError.CorruptedVault,
    };
    errdefer crypto.zeroize(key[0..]);

    const plaintext = crypto.decrypt(allocator, ciphertext, &nonce, &key) catch
        return StorageError.CorruptedVault;
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const v2: schema.VaultV2 = if (std.json.parseFromSlice(schema.VaultV2, a, plaintext, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    })) |v2_parsed| blk: {
        break :blk v2_parsed.value;
    } else |_| blk: {
        const v1_parsed = std.json.parseFromSlice(model.Vault, a, plaintext, .{
            .allocate = .alloc_always,
        }) catch
            return StorageError.CorruptedVault;
        break :blk try projectRuntimeVaultToV2(a, v1_parsed.value);
    };

    return .{
        .arena = arena,
        .vault = v2,
        .key = key,
        .salt = salt,
    };
}

pub fn loadVaultV2WithKey(
    allocator: std.mem.Allocator,
    key: *const [crypto.KEY_LEN]u8,
    vault_path: []const u8,
) !LoadedVaultV2 {
    const file = std.fs.cwd().openFile(vault_path, .{ .mode = .read_only }) catch
        return StorageError.VaultNotFound;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 64 * 1024 * 1024);
    defer allocator.free(data);

    const parsed = std.json.parseFromSlice(model.EncryptedVault, allocator, data, .{}) catch
        return StorageError.CorruptedVault;
    defer parsed.deinit();

    const wrapper = parsed.value;
    try validateWrapperMetadata(wrapper);

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

    const plaintext = crypto.decrypt(allocator, ciphertext, &nonce, key) catch
        return StorageError.CorruptedVault;
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const v2: schema.VaultV2 = if (std.json.parseFromSlice(schema.VaultV2, a, plaintext, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    })) |v2_parsed| blk: {
        break :blk v2_parsed.value;
    } else |_| blk: {
        const v1_parsed = std.json.parseFromSlice(model.Vault, a, plaintext, .{
            .allocate = .alloc_always,
        }) catch
            return StorageError.CorruptedVault;
        break :blk try projectRuntimeVaultToV2(a, v1_parsed.value);
    };

    return .{
        .arena = arena,
        .vault = v2,
        .key = key.*,
        .salt = salt,
    };
}

/// Load and decrypt vault from disk
pub fn loadVault(
    allocator: std.mem.Allocator,
    password: []const u8,
    vault_path: []const u8,
) !struct { vault: model.Vault, key: [crypto.KEY_LEN]u8, salt: [crypto.SALT_LEN]u8 } {
    var loaded_v2 = try loadVaultV2(allocator, password, vault_path);
    defer loaded_v2.deinit();

    const vault = projectVaultV2ToRuntime(allocator, loaded_v2.vault) catch
        return StorageError.CorruptedVault;

    return .{
        .vault = vault,
        .key = loaded_v2.key,
        .salt = loaded_v2.salt,
    };
}

pub fn projectRuntimeVaultToV2(
    allocator: std.mem.Allocator,
    runtime: model.Vault,
) !schema.VaultV2 {
    return runtimeVaultToV2View(allocator, runtime);
}

pub fn projectVaultV2ToRuntime(
    allocator: std.mem.Allocator,
    v2: schema.VaultV2,
) !model.Vault {
    return v2ToRuntimeVault(allocator, v2);
}

fn parseRuntimeVaultPayload(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
) !model.Vault {
    if (std.json.parseFromSlice(schema.VaultV2, allocator, plaintext, .{
        .ignore_unknown_fields = true,
    })) |v2_parsed| {
        defer v2_parsed.deinit();
        return try v2ToRuntimeVault(allocator, v2_parsed.value);
    } else |_| {
        const v1_parsed = std.json.parseFromSlice(model.Vault, allocator, plaintext, .{}) catch
            return StorageError.CorruptedVault;
        defer v1_parsed.deinit();
        return model.cloneVault(allocator, v1_parsed.value) catch
            return StorageError.CorruptedVault;
    }
}

fn runtimeVaultToV2View(
    allocator: std.mem.Allocator,
    runtime: model.Vault,
) !schema.VaultV2 {
    var folders = std.ArrayList(schema.Folder){};
    var collections = std.ArrayList(schema.Collection){};
    var collection_ids = std.StringHashMap([]const u8).init(allocator);
    defer collection_ids.deinit();

    for (runtime.categories) |cat| {
        if (std.mem.startsWith(u8, cat.id, "collection:")) {
            const collection_id = cat.id["collection:".len..];
            const collection_name = if (std.mem.startsWith(u8, cat.name, "Collection: "))
                cat.name["Collection: ".len..]
            else
                cat.name;
            try collections.append(allocator, .{
                .id = collection_id,
                .organizationId = null,
                .name = collection_name,
                .externalId = null,
            });
            try collection_ids.put(cat.id, collection_id);
        } else {
            try folders.append(allocator, .{
                .id = cat.id,
                .name = cat.name,
            });
        }
    }

    var items = std.ArrayList(schema.Item){};
    for (runtime.items) |item| {
        const display_name = if (item.name) |name|
            if (name.len > 0) name else (item.mail orelse item.id)
        else
            (item.mail orelse item.id);

        var mapped: schema.Item = .{
            .id = item.id,
            .organizationId = null,
            .folderId = item.category_id,
            .collectionIds = null,
            .type = if (item.item_type >= 1 and item.item_type <= 4) item.item_type else 1,
            .name = display_name,
            .notes = item.notes,
            .favorite = null,
            .reprompt = null,
            .fields = null,
            .passwordHistory = null,
            .login = null,
            .secureNote = null,
            .card = null,
            .identity = null,
            .attachments = null,
            .revisionDate = item.updated_at,
            .creationDate = item.created_at,
            .deletedDate = null,
            .original_json = null,
        };

        if (item.category_id) |cat_id| {
            if (collection_ids.get(cat_id)) |collection_id| {
                mapped.folderId = null;
                const ids = try allocator.alloc(?[]const u8, 1);
                ids[0] = collection_id;
                mapped.collectionIds = ids;
            }
        }

        switch (mapped.type) {
            1 => {
                mapped.login = .{
                    .uris = null,
                    .username = item.mail,
                    .password = item.password,
                    .totp = null,
                    .passwordRevisionDate = null,
                    .fido2Credentials = null,
                };
            },
            2 => {
                mapped.secureNote = .{
                    .type = 0,
                };
            },
            3 => {
                mapped.card = .{
                    .cardholderName = null,
                    .brand = null,
                    .number = item.password,
                    .expMonth = null,
                    .expYear = null,
                    .code = null,
                };
            },
            4 => {
                mapped.identity = .{
                    .title = null,
                    .firstName = null,
                    .middleName = null,
                    .lastName = null,
                    .address1 = null,
                    .address2 = null,
                    .address3 = null,
                    .city = null,
                    .state = null,
                    .postalCode = null,
                    .country = null,
                    .company = null,
                    .email = item.mail,
                    .phone = null,
                    .ssn = null,
                    .username = null,
                    .passportNumber = null,
                    .licenseNumber = null,
                };
            },
            else => {},
        }
        try items.append(allocator, mapped);
    }

    return .{
        .version = 2,
        .encrypted = false,
        .source = if (runtime.items.len == 0 and runtime.categories.len == 0) .unknown else .individual,
        .folders = try folders.toOwnedSlice(allocator),
        .collections = try collections.toOwnedSlice(allocator),
        .items = try items.toOwnedSlice(allocator),
    };
}

fn mergeProjectedWithExistingForSave(
    allocator: std.mem.Allocator,
    existing: *const schema.VaultV2,
    projected: *const schema.VaultV2,
) !schema.VaultV2 {
    var existing_collection_by_id = std.StringHashMap(schema.Collection).init(allocator);
    defer existing_collection_by_id.deinit();
    for (existing.collections) |collection| {
        try existing_collection_by_id.put(collection.id, collection);
    }

    var collections = std.ArrayList(schema.Collection){};
    for (projected.collections) |collection| {
        var out = collection;
        if (existing_collection_by_id.get(collection.id)) |old| {
            if (out.organizationId == null) out.organizationId = old.organizationId;
            if (out.externalId == null) out.externalId = old.externalId;
        }
        try collections.append(allocator, out);
    }

    var existing_item_by_id = std.StringHashMap(schema.Item).init(allocator);
    defer existing_item_by_id.deinit();
    for (existing.items) |item| {
        try existing_item_by_id.put(item.id, item);
    }

    var items = std.ArrayList(schema.Item){};
    for (projected.items) |item| {
        var out = item;
        if (existing_item_by_id.get(item.id)) |old| {
            out = mergeProjectedItem(old, item);
        }
        try items.append(allocator, out);
    }

    return .{
        .version = 2,
        .encrypted = false,
        .source = if (projected.source != .unknown) projected.source else existing.source,
        .folders = try allocator.dupe(schema.Folder, projected.folders),
        .collections = try collections.toOwnedSlice(allocator),
        .items = try items.toOwnedSlice(allocator),
    };
}

fn mergeProjectedItem(existing: schema.Item, projected: schema.Item) schema.Item {
    var out = projected;
    if (out.organizationId == null) out.organizationId = existing.organizationId;
    if (out.collectionIds == null) out.collectionIds = existing.collectionIds;

    switch (out.type) {
        1 => {
            var merged_login = existing.login orelse schema.Login{};
            if (out.login) |new_login| {
                if (new_login.username != null) merged_login.username = new_login.username;
                if (new_login.password != null) merged_login.password = new_login.password;
            }
            out.login = merged_login;
        },
        2 => {
            if (out.secureNote == null) out.secureNote = existing.secureNote;
        },
        3 => {
            var merged_card = existing.card orelse schema.Card{};
            if (out.card) |new_card| {
                if (new_card.number != null) merged_card.number = new_card.number;
                if (new_card.brand != null) merged_card.brand = new_card.brand;
                if (new_card.code != null) merged_card.code = new_card.code;
            }
            out.card = merged_card;
        },
        4 => {
            var merged_identity = existing.identity orelse schema.Identity{};
            if (out.identity) |new_identity| {
                if (new_identity.email != null) merged_identity.email = new_identity.email;
                if (new_identity.firstName != null) merged_identity.firstName = new_identity.firstName;
            }
            out.identity = merged_identity;
        },
        else => {},
    }

    return out;
}

fn v2ToRuntimeVault(
    allocator: std.mem.Allocator,
    v2: schema.VaultV2,
) !model.Vault {
    var categories = std.ArrayList(model.Category){};
    errdefer {
        for (categories.items) |*category| {
            model.freeCategory(allocator, category);
        }
        categories.deinit(allocator);
    }

    var folder_category_ids = std.StringHashMap([]const u8).init(allocator);
    defer folder_category_ids.deinit();
    var collection_category_ids = std.StringHashMap([]const u8).init(allocator);
    defer collection_category_ids.deinit();

    for (v2.folders) |folder| {
        var cat = model.Category{
            .id = try allocator.dupe(u8, folder.id),
            .name = try allocator.dupe(u8, folder.name),
            .color = null,
        };
        errdefer model.freeCategory(allocator, &cat);
        try categories.append(allocator, cat);
        try folder_category_ids.put(folder.id, categories.items[categories.items.len - 1].id);
    }

    for (v2.collections) |collection| {
        const id = try std.fmt.allocPrint(allocator, "collection:{s}", .{collection.id});
        errdefer allocator.free(id);
        const name = try std.fmt.allocPrint(allocator, "Collection: {s}", .{collection.name});
        errdefer allocator.free(name);

        var cat = model.Category{
            .id = id,
            .name = name,
            .color = null,
        };
        errdefer model.freeCategory(allocator, &cat);
        try categories.append(allocator, cat);
        try collection_category_ids.put(collection.id, categories.items[categories.items.len - 1].id);
    }

    var items = std.ArrayList(model.Item){};
    errdefer {
        for (items.items) |*item| {
            model.freeItem(allocator, item);
        }
        items.deinit(allocator);
    }

    for (v2.items) |src| {
        const password = if (src.login) |login|
            (login.password orelse "")
        else if (src.card) |card|
            (card.number orelse "")
        else
            "";

        const mail: ?[]const u8 = blk: {
            if (src.login) |login| {
                if (login.username) |username| break :blk if (username.len > 0) try allocator.dupe(u8, username) else null;
            }
            if (src.identity) |identity| {
                if (identity.email) |email| break :blk if (email.len > 0) try allocator.dupe(u8, email) else null;
            }
            break :blk null;
        };
        errdefer if (mail) |v| allocator.free(v);

        const name: ?[]const u8 = if (src.name.len > 0)
            try allocator.dupe(u8, src.name)
        else
            null;
        errdefer if (name) |v| allocator.free(v);

        const notes = try dupOptionalNonEmpty(allocator, src.notes);
        errdefer if (notes) |v| allocator.free(v);

        const category_id = try resolveRuntimeCategoryId(
            allocator,
            src,
            &folder_category_ids,
            &collection_category_ids,
        );
        errdefer if (category_id) |v| allocator.free(v);

        var now_buf: [20]u8 = undefined;
        const created = normalizeTimestamp(src.creationDate, model.nowTimestamp(&now_buf));
        const updated = normalizeTimestamp(src.revisionDate, created);

        var out = model.Item{
            .id = try allocator.dupe(u8, src.id),
            .item_type = src.type,
            .name = name,
            .mail = mail,
            .password = try allocator.dupe(u8, password),
            .notes = notes,
            .category_id = category_id,
            .created_at = try allocator.dupe(u8, created),
            .updated_at = try allocator.dupe(u8, updated),
        };
        errdefer model.freeItem(allocator, &out);
        try items.append(allocator, out);
    }

    return .{
        .version = 1,
        .items = try items.toOwnedSlice(allocator),
        .categories = try categories.toOwnedSlice(allocator),
    };
}

fn resolveRuntimeCategoryId(
    allocator: std.mem.Allocator,
    src: schema.Item,
    folder_category_ids: *const std.StringHashMap([]const u8),
    collection_category_ids: *const std.StringHashMap([]const u8),
) !?[]const u8 {
    if (src.folderId) |folder_id| {
        if (folder_category_ids.get(folder_id)) |runtime_cat_id| {
            return try allocator.dupe(u8, runtime_cat_id);
        }
    }
    if (src.collectionIds) |collection_ids| {
        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            if (collection_category_ids.get(collection_id)) |runtime_cat_id| {
                return try allocator.dupe(u8, runtime_cat_id);
            }
        }
    }
    return null;
}

fn dupOptionalNonEmpty(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    const v = value orelse return null;
    if (v.len == 0) return null;
    return try allocator.dupe(u8, v);
}

fn normalizeTimestamp(input: ?[]const u8, fallback: []const u8) []const u8 {
    const raw = input orelse return fallback;
    if (raw.len >= 19) return raw[0..19];
    return fallback;
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

fn decryptVaultPayload(
    allocator: std.mem.Allocator,
    password: []const u8,
    vault_path: []const u8,
) ![]u8 {
    const raw = try readFileAlloc(allocator, vault_path);
    defer allocator.free(raw);

    var parsed = try std.json.parseFromSlice(model.EncryptedVault, allocator, raw, .{});
    defer parsed.deinit();
    const wrapper = parsed.value;
    try validateWrapperMetadata(wrapper);

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
    const ciphertext = try allocator.alloc(u8, ct_len);
    defer allocator.free(ciphertext);
    base64_decoder.decode(ciphertext, wrapper.cipher.ciphertext) catch return StorageError.CorruptedVault;

    const mem_limit = std.math.cast(usize, wrapper.kdf.mem_limit) orelse
        return StorageError.InvalidFormat;
    const key = crypto.deriveKeyWithParams(password, &salt, wrapper.kdf.ops_limit, mem_limit) catch
        return StorageError.CorruptedVault;

    return crypto.decrypt(allocator, ciphertext, &nonce, &key) catch
        return StorageError.CorruptedVault;
}

fn writeEncryptedPayload(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    password: []const u8,
    vault_path: []const u8,
) !void {
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    const encrypted = try crypto.encrypt(allocator, plaintext, &key);
    defer allocator.free(encrypted.ciphertext);

    const salt_b64 = try base64Encode(allocator, &salt);
    defer allocator.free(salt_b64);
    const nonce_b64 = try base64Encode(allocator, &encrypted.nonce);
    defer allocator.free(nonce_b64);
    const ct_b64 = try base64Encode(allocator, encrypted.ciphertext);
    defer allocator.free(ct_b64);

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

    const wrapper_json = try jsonStringifyAlloc(allocator, wrapper);
    defer allocator.free(wrapper_json);
    try writeFile(vault_path, wrapper_json);
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

test "saveVaultV2 and loadVaultV2 preserve typed Bitwarden fields" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    const input_json =
        \\{
        \\  "version": 2,
        \\  "encrypted": false,
        \\  "folders": [{"id":"f1","name":"Personal"}],
        \\  "collections": [{"id":"c1","organizationId":"org-1","name":"Shared","externalId":"ext-1"}],
        \\  "items": [
        \\    {
        \\      "id":"item-login",
        \\      "type":1,
        \\      "name":"GitHub",
        \\      "folderId":"f1",
        \\      "login":{
        \\        "username":"dev@example.com",
        \\        "password":"pw-login",
        \\        "totp":"ABCDEF",
        \\        "uris":[{"uri":"https://github.com","match":0}]
        \\      },
        \\      "creationDate":"2026-03-10T10:00:00.000Z",
        \\      "revisionDate":"2026-03-10T11:00:00.000Z"
        \\    },
        \\    {
        \\      "id":"item-card",
        \\      "type":3,
        \\      "name":"Visa",
        \\      "collectionIds":["c1"],
        \\      "card":{"brand":"visa","number":"4111111111111111","code":"123"},
        \\      "fields":[{"name":"pin","value":"9999","type":0}],
        \\      "attachments":[{"id":"a1","fileName":"statement.pdf","size":"123"}]
        \\    }
        \\  ]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, input_json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const password = "typed-v2";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);

    try saveVaultV2(allocator, parsed.value, &key, &salt, vault_path);
    var loaded = try loadVaultV2(allocator, password, vault_path);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 1), loaded.vault.folders.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.collections.len);
    try std.testing.expectEqual(@as(usize, 2), loaded.vault.items.len);
    try std.testing.expect(loaded.vault.items[0].login != null);
    try std.testing.expectEqualStrings("ABCDEF", loaded.vault.items[0].login.?.totp.?);
    try std.testing.expect(loaded.vault.items[1].card != null);
    try std.testing.expectEqualStrings("4111111111111111", loaded.vault.items[1].card.?.number.?);
    try std.testing.expect(loaded.vault.items[1].attachments != null);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items[1].attachments.?.len);
    try std.testing.expect(loaded.vault.items[1].fields != null);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items[1].fields.?.len);
}

test "loadVaultV2 upgrades legacy runtime payloads to v2 shape" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var legacy = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &legacy);
    const legacy_json = try jsonStringifyAlloc(allocator, legacy);
    defer allocator.free(legacy_json);

    try writeEncryptedPayload(allocator, legacy_json, "legacy-v2", vault_path);
    var loaded = try loadVaultV2(allocator, "legacy-v2", vault_path);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 1), loaded.vault.folders.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items.len);
    try std.testing.expectEqual(@as(u8, 1), loaded.vault.items[0].type);
    try std.testing.expect(loaded.vault.items[0].login != null);
    try std.testing.expectEqualStrings("dev@example.com", loaded.vault.items[0].login.?.username.?);
}

test "loadVaultV2WithKey decrypts and parses without master password" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "with-key";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    var loaded = try loadVaultV2WithKey(allocator, &key, vault_path);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.folders.len);
    try std.testing.expect(loaded.vault.items[0].login != null);
    try std.testing.expectEqualStrings("dev@example.com", loaded.vault.items[0].login.?.username.?);
}

test "projectRuntimeVaultToV2 maps runtime items to login entries" {
    const allocator = std.testing.allocator;

    var runtime = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &runtime);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const v2 = try projectRuntimeVaultToV2(arena.allocator(), runtime);

    try std.testing.expectEqual(@as(usize, 1), v2.folders.len);
    try std.testing.expectEqual(@as(usize, 1), v2.items.len);
    try std.testing.expectEqual(@as(u8, 1), v2.items[0].type);
    try std.testing.expect(v2.items[0].login != null);
    try std.testing.expectEqualStrings("dev@example.com", v2.items[0].login.?.username.?);
}

test "projectVaultV2ToRuntime preserves collection-linked item references" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "version":2,
        \\  "folders":[{"id":"f1","name":"Personal"}],
        \\  "collections":[{"id":"c1","organizationId":"org-1","name":"Team"}],
        \\  "items":[
        \\    {"id":"i1","type":1,"name":"n","login":{"username":"u","password":"p"},"folderId":"f1"},
        \\    {"id":"i2","type":2,"name":"note","secureNote":{"type":0},"organizationId":"org-1","collectionIds":["c1"]}
        \\  ]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var runtime = try projectVaultV2ToRuntime(allocator, parsed.value);
    defer model.freeVault(allocator, &runtime);

    try std.testing.expectEqual(@as(usize, 2), runtime.items.len);
    try std.testing.expectEqual(@as(usize, 2), runtime.categories.len);
    try std.testing.expectEqual(@as(u8, 1), runtime.items[0].item_type);
    try std.testing.expectEqual(@as(u8, 2), runtime.items[1].item_type);
    try std.testing.expect(runtime.items[0].category_id != null);
    try std.testing.expect(runtime.items[1].category_id != null);
}

test "saveVault preserves existing typed card metadata for unchanged runtime item" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator,
        \\{
        \\  "version":2,
        \\  "items":[
        \\    {
        \\      "id":"card-1",
        \\      "type":3,
        \\      "name":"visa",
        \\      "card":{"brand":"visa","number":"4111111111111111","code":"123"}
        \\    }
        \\  ]
        \\}
    , .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const password = "keep-card";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVaultV2(allocator, parsed.value, &key, &salt, vault_path);

    const loaded_runtime = try loadVault(allocator, password, vault_path);
    defer {
        model.freeVault(allocator, @constCast(&loaded_runtime.vault));
        crypto.zeroize(@constCast(&loaded_runtime.key));
    }
    try std.testing.expectEqual(@as(u8, 3), loaded_runtime.vault.items[0].item_type);

    try saveVault(allocator, loaded_runtime.vault, &key, &salt, vault_path);

    var loaded_v2 = try loadVaultV2(allocator, password, vault_path);
    defer loaded_v2.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded_v2.vault.items.len);
    try std.testing.expectEqual(@as(u8, 3), loaded_v2.vault.items[0].type);
    try std.testing.expect(loaded_v2.vault.items[0].card != null);
    try std.testing.expectEqualStrings("123", loaded_v2.vault.items[0].card.?.code.?);
}

test "saveVault stores v2 payload format" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var vault = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &vault);

    const password = "payload-v2";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);
    try saveVault(allocator, vault, &key, &salt, vault_path);

    const plaintext = try decryptVaultPayload(allocator, password, vault_path);
    defer {
        crypto.zeroize(plaintext);
        allocator.free(plaintext);
    }

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, plaintext, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const root = parsed.value;

    try std.testing.expectEqual(@as(u32, 2), root.version);
    try std.testing.expectEqual(@as(usize, 1), root.folders.len);
    try std.testing.expectEqual(@as(usize, 0), root.collections.len);
    try std.testing.expectEqual(@as(usize, 1), root.items.len);
    try std.testing.expectEqual(@as(u8, 1), root.items[0].type);
    try std.testing.expectEqualStrings("cat-1", root.folders[0].id);
    try std.testing.expectEqualStrings("work", root.folders[0].name);
}

test "loadVault supports legacy v1 payload format" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vault_path = try makeTempVaultPath(allocator, &tmp);
    defer allocator.free(vault_path);

    var legacy = try makeSampleVault(allocator);
    defer model.freeVault(allocator, &legacy);

    const plaintext = try jsonStringifyAlloc(allocator, legacy);
    defer allocator.free(plaintext);
    try writeEncryptedPayload(allocator, plaintext, "legacy-password", vault_path);

    const loaded = try loadVault(allocator, "legacy-password", vault_path);
    defer {
        model.freeVault(allocator, @constCast(&loaded.vault));
        crypto.zeroize(@constCast(&loaded.key));
    }

    try std.testing.expectEqual(@as(usize, 1), loaded.vault.items.len);
    try std.testing.expectEqual(@as(usize, 1), loaded.vault.categories.len);
    try std.testing.expectEqualStrings("github", loaded.vault.items[0].name.?);
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
