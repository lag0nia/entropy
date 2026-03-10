const std = @import("std");
const model = @import("model.zig");
const schema = @import("schema_v2.zig");
const relations = @import("relations_v2.zig");
const storage = @import("storage.zig");
const crypto = @import("crypto.zig");

pub const ImportMode = enum {
    strict,
    best_effort,
};

pub const ImportAction = enum {
    replace,
    merge,
};

pub const ImportOptions = struct {
    mode: ImportMode = .strict,
    dry_run: bool = false,
    action: ImportAction = .replace,
};

pub const CliOptions = struct {
    file_path: []const u8,
    options: ImportOptions = .{},
};

pub const CliError = error{
    MissingFilePath,
    MissingModeValue,
    InvalidModeValue,
    UnexpectedArgument,
};

pub const ImportSummary = struct {
    source: schema.Source = .unknown,
    folders: usize = 0,
    collections: usize = 0,
    items_total: usize = 0,
    items_login: usize = 0,
    items_secure_note: usize = 0,
    items_card: usize = 0,
    items_identity: usize = 0,
    imported_categories: usize = 0,
    imported_items: usize = 0,
    replaced_items: usize = 0,
    merged_items: usize = 0,
    skipped_items: usize = 0,
    warning_count: usize = 0,
};

pub const ImportError = std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || error{
    InvalidBitwardenJson,
    MissingRuntimePassword,
} || relations.RelationError || storage.StorageError;

pub const ImportTarget = struct {
    vault: *model.Vault,
    key: *const [crypto.KEY_LEN]u8,
    salt: *const [crypto.SALT_LEN]u8,
    vault_path: []const u8,
};

pub fn parseImportCommand(args: []const []const u8) CliError!?CliOptions {
    if (args.len < 3) return null;
    if (!std.mem.eql(u8, args[1], "import")) return null;
    if (!std.mem.eql(u8, args[2], "bitwarden")) return null;

    var file_path: ?[]const u8 = null;
    var options: ImportOptions = .{};

    var i: usize = 3;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--file")) {
            i += 1;
            if (i >= args.len) return CliError.MissingFilePath;
            file_path = args[i];
        } else if (std.mem.eql(u8, arg, "--mode")) {
            i += 1;
            if (i >= args.len) return CliError.MissingModeValue;
            if (std.mem.eql(u8, args[i], "strict")) {
                options.mode = .strict;
            } else if (std.mem.eql(u8, args[i], "best_effort")) {
                options.mode = .best_effort;
            } else {
                return CliError.InvalidModeValue;
            }
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            options.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--merge")) {
            options.action = .merge;
        } else if (std.mem.eql(u8, arg, "--replace")) {
            options.action = .replace;
        } else {
            return CliError.UnexpectedArgument;
        }
    }

    return .{
        .file_path = file_path orelse return CliError.MissingFilePath,
        .options = options,
    };
}

pub fn importFromBitwardenJsonFile(
    allocator: std.mem.Allocator,
    target: *ImportTarget,
    json_path: []const u8,
    options: ImportOptions,
) ImportError!ImportSummary {
    const raw = try readFileAlloc(allocator, json_path);
    defer allocator.free(raw);

    var parsed = std.json.parseFromSlice(schema.VaultV2, allocator, raw, .{
        .ignore_unknown_fields = true,
    }) catch return ImportError.InvalidBitwardenJson;
    defer parsed.deinit();

    var bitwarden = parsed.value;
    bitwarden.source = schema.detectSource(&bitwarden);

    var summary: ImportSummary = .{
        .source = bitwarden.source,
        .folders = bitwarden.folders.len,
        .collections = bitwarden.collections.len,
        .items_total = bitwarden.items.len,
    };
    countByType(&summary, bitwarden.items);

    if (options.mode == .strict) {
        var rel = try relations.build(allocator, &bitwarden);
        defer rel.deinit(allocator);
    } else {
        var rel_result = relations.build(allocator, &bitwarden);
        if (rel_result) |*rel| {
            rel.deinit(allocator);
        } else |_| {
            summary.warning_count += 1;
        }
    }

    var loaded_current: ?storage.LoadedVaultV2 = storage.loadVaultV2WithKey(
        allocator,
        target.key,
        target.vault_path,
    ) catch |err| switch (err) {
        storage.StorageError.VaultNotFound => null,
        else => return err,
    };
    defer if (loaded_current) |*loaded| loaded.deinit();

    var empty_current: schema.VaultV2 = .{
        .version = 2,
        .encrypted = false,
        .source = .unknown,
        .folders = &.{},
        .collections = &.{},
        .items = &.{},
    };
    const current_v2: *const schema.VaultV2 = if (loaded_current) |*loaded| &loaded.vault else &empty_current;

    if (options.dry_run) {
        try estimateDryRunSummaryV2(allocator, current_v2, &bitwarden, options.action, &summary);
        return summary;
    }

    var merged_v2: ?schema.VaultV2 = null;
    defer if (merged_v2) |*vault| freeShallowVaultSlices(allocator, vault);

    const final_v2: *const schema.VaultV2 = switch (options.action) {
        .replace => blk: {
            summary.imported_categories = bitwarden.folders.len + bitwarden.collections.len;
            summary.imported_items = bitwarden.items.len;
            break :blk &bitwarden;
        },
        .merge => blk: {
            var merged = try mergeVaultV2(allocator, current_v2, &bitwarden, &summary);
            merged.source = schema.detectSource(&merged);
            merged_v2 = merged;
            break :blk &merged_v2.?;
        },
    };

    try storage.saveVaultV2(
        allocator,
        final_v2.*,
        target.key,
        target.salt,
        target.vault_path,
    );

    var projection_summary: ImportSummary = .{};
    var runtime = try toRuntimeVault(allocator, final_v2, .best_effort, &projection_summary);
    replaceVault(allocator, target.vault, &runtime);

    return summary;
}

fn estimateDryRunSummaryV2(
    allocator: std.mem.Allocator,
    current: *const schema.VaultV2,
    imported: *const schema.VaultV2,
    action: ImportAction,
    summary: *ImportSummary,
) !void {
    switch (action) {
        .replace => {
            summary.imported_categories = imported.folders.len + imported.collections.len;
            summary.imported_items = imported.items.len;
        },
        .merge => {
            var folder_ids = std.StringHashMap(void).init(allocator);
            defer folder_ids.deinit();
            for (current.folders) |folder| {
                try folder_ids.put(folder.id, {});
            }
            for (imported.folders) |folder| {
                const gop = try folder_ids.getOrPut(folder.id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = {};
                    summary.imported_categories += 1;
                }
            }
            var collection_ids = std.StringHashMap(void).init(allocator);
            defer collection_ids.deinit();
            for (current.collections) |collection| {
                try collection_ids.put(collection.id, {});
            }
            for (imported.collections) |collection| {
                const gop = try collection_ids.getOrPut(collection.id);
                if (!gop.found_existing) {
                    gop.value_ptr.* = {};
                    summary.imported_categories += 1;
                }
            }

            var item_ids = std.StringHashMap(void).init(allocator);
            defer item_ids.deinit();
            for (current.items) |item| {
                try item_ids.put(item.id, {});
            }
            var final_count = current.items.len;
            for (imported.items) |item| {
                const gop = try item_ids.getOrPut(item.id);
                if (gop.found_existing) {
                    summary.replaced_items += 1;
                } else {
                    gop.value_ptr.* = {};
                    summary.merged_items += 1;
                    final_count += 1;
                }
            }
            summary.imported_items = final_count;
        },
    }
}

fn countByType(summary: *ImportSummary, items: []const schema.Item) void {
    for (items) |item| {
        switch (item.type) {
            1 => summary.items_login += 1,
            2 => summary.items_secure_note += 1,
            3 => summary.items_card += 1,
            4 => summary.items_identity += 1,
            else => summary.skipped_items += 1,
        }
    }
}

fn mergeVaultV2(
    allocator: std.mem.Allocator,
    current: *const schema.VaultV2,
    imported: *const schema.VaultV2,
    summary: *ImportSummary,
) !schema.VaultV2 {
    var folders = std.ArrayList(schema.Folder){};
    errdefer folders.deinit(allocator);
    try folders.appendSlice(allocator, current.folders);

    var folder_ids = std.StringHashMap(void).init(allocator);
    defer folder_ids.deinit();
    for (current.folders) |folder| {
        try folder_ids.put(folder.id, {});
    }
    for (imported.folders) |folder| {
        const gop = try folder_ids.getOrPut(folder.id);
        if (!gop.found_existing) {
            gop.value_ptr.* = {};
            try folders.append(allocator, folder);
            summary.imported_categories += 1;
        }
    }

    var collections = std.ArrayList(schema.Collection){};
    errdefer collections.deinit(allocator);
    try collections.appendSlice(allocator, current.collections);

    var collection_ids = std.StringHashMap(void).init(allocator);
    defer collection_ids.deinit();
    for (current.collections) |collection| {
        try collection_ids.put(collection.id, {});
    }
    for (imported.collections) |collection| {
        const gop = try collection_ids.getOrPut(collection.id);
        if (!gop.found_existing) {
            gop.value_ptr.* = {};
            try collections.append(allocator, collection);
            summary.imported_categories += 1;
        }
    }

    var items = std.ArrayList(schema.Item){};
    errdefer items.deinit(allocator);
    try items.appendSlice(allocator, current.items);

    var item_ids = std.StringHashMap(usize).init(allocator);
    defer item_ids.deinit();
    for (current.items, 0..) |item, idx| {
        try item_ids.put(item.id, idx);
    }
    for (imported.items) |item| {
        if (item_ids.get(item.id)) |existing_idx| {
            items.items[existing_idx] = item;
            summary.replaced_items += 1;
        } else {
            try items.append(allocator, item);
            try item_ids.put(item.id, items.items.len - 1);
            summary.merged_items += 1;
        }
    }

    summary.imported_items = items.items.len;

    return .{
        .version = 2,
        .encrypted = false,
        .source = if (imported.source != .unknown) imported.source else current.source,
        .folders = try folders.toOwnedSlice(allocator),
        .collections = try collections.toOwnedSlice(allocator),
        .items = try items.toOwnedSlice(allocator),
    };
}

fn freeShallowVaultSlices(allocator: std.mem.Allocator, vault: *schema.VaultV2) void {
    allocator.free(vault.folders);
    allocator.free(vault.collections);
    allocator.free(vault.items);
    vault.* = .{
        .version = 2,
        .encrypted = false,
        .source = .unknown,
        .folders = &.{},
        .collections = &.{},
        .items = &.{},
    };
}

fn toRuntimeVault(
    allocator: std.mem.Allocator,
    bitwarden: *const schema.VaultV2,
    mode: ImportMode,
    summary: *ImportSummary,
) ImportError!model.Vault {
    var categories = std.ArrayList(model.Category){};
    errdefer {
        for (categories.items) |*c| model.freeCategory(allocator, c);
        categories.deinit(allocator);
    }

    var folder_category = std.StringHashMap([]const u8).init(allocator);
    defer folder_category.deinit();
    var collection_category = std.StringHashMap([]const u8).init(allocator);
    defer collection_category.deinit();

    for (bitwarden.folders) |folder| {
        const cat = try makeCategory(allocator, "Folder", folder.name);
        try categories.append(allocator, cat);
        try folder_category.put(folder.id, cat.id);
    }
    for (bitwarden.collections) |collection| {
        const cat = try makeCategory(allocator, "Collection", collection.name);
        try categories.append(allocator, cat);
        try collection_category.put(collection.id, cat.id);
    }

    var items = std.ArrayList(model.Item){};
    errdefer {
        for (items.items) |*it| model.freeItem(allocator, it);
        items.deinit(allocator);
    }

    for (bitwarden.items) |src_item| {
        const out_item = try mapItemToRuntime(
            allocator,
            src_item,
            &folder_category,
            &collection_category,
            mode,
            summary,
        );
        if (out_item == null) {
            summary.skipped_items += 1;
            continue;
        }
        try items.append(allocator, out_item.?);
    }

    return .{
        .version = 1,
        .items = try items.toOwnedSlice(allocator),
        .categories = try categories.toOwnedSlice(allocator),
    };
}

fn makeCategory(
    allocator: std.mem.Allocator,
    kind: []const u8,
    name: []const u8,
) !model.Category {
    const uuid = model.generateUuid();
    const label = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ kind, name });
    errdefer allocator.free(label);
    return .{
        .id = try allocator.dupe(u8, &uuid),
        .name = label,
    };
}

fn mapItemToRuntime(
    allocator: std.mem.Allocator,
    src: schema.Item,
    folder_category: *const std.StringHashMap([]const u8),
    collection_category: *const std.StringHashMap([]const u8),
    mode: ImportMode,
    summary: *ImportSummary,
) ImportError!?model.Item {
    if (src.type < 1 or src.type > 4) {
        summary.warning_count += 1;
        if (mode == .strict) return null;
        return null;
    }

    const runtime_password = if (src.login) |login|
        (login.password orelse "")
    else if (src.card) |card|
        (card.number orelse "")
    else
        "";

    var notes_builder = std.ArrayList(u8){};
    defer notes_builder.deinit(allocator);
    if (src.notes) |n| try notes_builder.appendSlice(allocator, n);

    if (src.type != 1) {
        summary.warning_count += 1;
        if (notes_builder.items.len > 0) try notes_builder.appendSlice(allocator, "\n\n");
        try notes_builder.appendSlice(allocator, "[bitwarden] non-login item flattened to runtime fields");
    } else if (src.login) |login| {
        if (login.totp != null or (login.uris != null and login.uris.?.len > 0)) {
            summary.warning_count += 1;
        }
    }

    if (src.fields != null or src.attachments != null or src.passwordHistory != null) {
        summary.warning_count += 1;
    }

    var now_buf: [20]u8 = undefined;
    const created = normalizeTimestamp(src.creationDate, model.nowTimestamp(&now_buf));
    const updated = normalizeTimestamp(src.revisionDate, created);

    const cat_id = resolveCategoryId(src, folder_category, collection_category, mode, summary);

    const resolved_name: ?[]const u8 = if (src.name.len > 0)
        try allocator.dupe(u8, src.name)
    else
        null;
    errdefer if (resolved_name) |v| allocator.free(v);

    const resolved_mail: ?[]const u8 = blk: {
        if (src.login) |login| {
            if (login.username) |username| break :blk try allocator.dupe(u8, username);
        }
        if (src.identity) |identity| {
            if (identity.email) |email| break :blk try allocator.dupe(u8, email);
        }
        break :blk null;
    };
    errdefer if (resolved_mail) |v| allocator.free(v);

    const resolved_notes: ?[]const u8 = if (notes_builder.items.len > 0)
        try allocator.dupe(u8, notes_builder.items)
    else
        null;
    errdefer if (resolved_notes) |v| allocator.free(v);

    var out = model.Item{
        .id = try allocator.dupe(u8, src.id),
        .name = resolved_name,
        .mail = resolved_mail,
        .password = try allocator.dupe(u8, runtime_password),
        .notes = resolved_notes,
        .category_id = if (cat_id) |id| try allocator.dupe(u8, id) else null,
        .created_at = try allocator.dupe(u8, created),
        .updated_at = try allocator.dupe(u8, updated),
    };
    errdefer model.freeItem(allocator, &out);
    return out;
}

fn resolveCategoryId(
    src: schema.Item,
    folder_category: *const std.StringHashMap([]const u8),
    collection_category: *const std.StringHashMap([]const u8),
    mode: ImportMode,
    summary: *ImportSummary,
) ?[]const u8 {
    if (src.folderId) |folder_id| {
        if (folder_category.get(folder_id)) |cat_id| {
            return cat_id;
        }
        if (mode == .best_effort) summary.warning_count += 1;
    }
    if (src.collectionIds) |collection_ids| {
        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            if (collection_category.get(collection_id)) |cat_id| {
                return cat_id;
            }
            if (mode == .best_effort) summary.warning_count += 1;
        }
    }
    return null;
}

fn normalizeTimestamp(input: ?[]const u8, fallback: []const u8) []const u8 {
    const raw = input orelse return fallback;
    if (raw.len >= 19) return raw[0..19];
    return fallback;
}

fn replaceVault(
    allocator: std.mem.Allocator,
    target_vault: *model.Vault,
    imported: *model.Vault,
) void {
    model.freeVault(allocator, target_vault);
    target_vault.* = imported.*;
    imported.* = .{
        .version = 1,
        .items = &.{},
        .categories = &.{},
    };
}

fn mergeVault(
    allocator: std.mem.Allocator,
    target_vault: *model.Vault,
    imported: *const model.Vault,
    summary: *ImportSummary,
) ImportError!void {
    var category_name_to_id = std.StringHashMap([]const u8).init(allocator);
    defer category_name_to_id.deinit();
    for (target_vault.categories) |category| {
        try category_name_to_id.put(category.name, category.id);
    }

    var imported_cat_to_final_id = std.StringHashMap([]const u8).init(allocator);
    defer imported_cat_to_final_id.deinit();

    for (imported.categories) |category| {
        if (category_name_to_id.get(category.name)) |existing_id| {
            try imported_cat_to_final_id.put(category.id, existing_id);
            continue;
        }

        var cloned = try model.cloneCategory(allocator, category);
        errdefer model.freeCategory(allocator, &cloned);
        try appendCategory(allocator, target_vault, cloned);
        try category_name_to_id.put(target_vault.categories[target_vault.categories.len - 1].name, target_vault.categories[target_vault.categories.len - 1].id);
        try imported_cat_to_final_id.put(category.id, target_vault.categories[target_vault.categories.len - 1].id);
        summary.imported_categories += 1;
    }

    var item_id_to_index = std.StringHashMap(usize).init(allocator);
    defer item_id_to_index.deinit();
    for (target_vault.items, 0..) |item, idx| {
        try item_id_to_index.put(item.id, idx);
    }

    for (imported.items) |item| {
        var cloned = try model.cloneItem(allocator, item);
        errdefer model.freeItem(allocator, &cloned);

        if (cloned.category_id) |imported_cat_id| {
            if (imported_cat_to_final_id.get(imported_cat_id)) |final_cat_id| {
                allocator.free(imported_cat_id);
                cloned.category_id = try allocator.dupe(u8, final_cat_id);
            } else {
                allocator.free(imported_cat_id);
                cloned.category_id = null;
                summary.warning_count += 1;
            }
        }

        if (item_id_to_index.get(cloned.id)) |existing_idx| {
            model.freeItem(allocator, &target_vault.items[existing_idx]);
            target_vault.items[existing_idx] = cloned;
            summary.replaced_items += 1;
        } else {
            try appendItem(allocator, target_vault, cloned);
            try item_id_to_index.put(target_vault.items[target_vault.items.len - 1].id, target_vault.items.len - 1);
            summary.merged_items += 1;
        }
    }

    summary.imported_items = target_vault.items.len;
}

fn appendItem(allocator: std.mem.Allocator, vault: *model.Vault, item: model.Item) !void {
    const old = vault.items;
    var items = std.ArrayList(model.Item){};
    try items.appendSlice(allocator, old);
    try items.append(allocator, item);
    vault.items = try items.toOwnedSlice(allocator);
    allocator.free(old);
}

fn appendCategory(allocator: std.mem.Allocator, vault: *model.Vault, category: model.Category) !void {
    const old = vault.categories;
    var categories = std.ArrayList(model.Category){};
    try categories.appendSlice(allocator, old);
    try categories.append(allocator, category);
    vault.categories = try categories.toOwnedSlice(allocator);
    allocator.free(old);
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();
    return try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
}

fn writeFile(path: []const u8, data: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(data);
}

fn makeTempPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    const abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs);
    return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ abs, name });
}

fn makeEmptyVault(allocator: std.mem.Allocator) !model.Vault {
    return .{
        .version = 1,
        .items = try allocator.alloc(model.Item, 0),
        .categories = try allocator.alloc(model.Category, 0),
    };
}

fn appendRuntimeItem(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    id: []const u8,
    password: []const u8,
) !void {
    const now = "2026-03-10T12:00:00";
    var item = model.Item{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .mail = null,
        .password = try allocator.dupe(u8, password),
        .notes = null,
        .category_id = null,
        .created_at = try allocator.dupe(u8, now),
        .updated_at = try allocator.dupe(u8, now),
    };
    errdefer model.freeItem(allocator, &item);
    try appendItem(allocator, vault, item);
}

test "parseImportCommand parses import flags" {
    const args = [_][]const u8{
        "enthropy",
        "import",
        "bitwarden",
        "--file",
        "/tmp/bw.json",
        "--mode",
        "best_effort",
        "--dry-run",
        "--merge",
    };

    const parsed = (try parseImportCommand(&args)).?;
    try std.testing.expectEqualStrings("/tmp/bw.json", parsed.file_path);
    try std.testing.expect(parsed.options.dry_run);
    try std.testing.expectEqual(ImportMode.best_effort, parsed.options.mode);
    try std.testing.expectEqual(ImportAction.merge, parsed.options.action);
}

test "import strict fails on unknown collection reference" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const import_path = try makeTempPath(allocator, &tmp, "bw.json");
    defer allocator.free(import_path);
    try writeFile(import_path,
        \\{
        \\  "collections": [],
        \\  "items": [{
        \\    "id":"i1",
        \\    "organizationId":"org-1",
        \\    "collectionIds":["missing"],
        \\    "type":2,
        \\    "name":"broken",
        \\    "secureNote":{"type":0}
        \\  }]
        \\}
    );

    var vault = try makeEmptyVault(allocator);
    defer model.freeVault(allocator, &vault);

    const vault_path = try makeTempPath(allocator, &tmp, "vault.enc");
    defer allocator.free(vault_path);
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey("master", &salt);

    var target: ImportTarget = .{
        .vault = &vault,
        .key = &key,
        .salt = &salt,
        .vault_path = vault_path,
    };

    const result = importFromBitwardenJsonFile(allocator, &target, import_path, .{
        .mode = .strict,
        .dry_run = true,
        .action = .replace,
    });
    try std.testing.expectError(relations.RelationError.UnknownCollectionId, result);
}

test "import best_effort continues with warnings and dry-run does not mutate vault" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const import_path = try makeTempPath(allocator, &tmp, "bw.json");
    defer allocator.free(import_path);
    try writeFile(import_path,
        \\{
        \\  "collections": [],
        \\  "items": [{
        \\    "id":"i1",
        \\    "organizationId":"org-1",
        \\    "collectionIds":["missing"],
        \\    "type":1,
        \\    "name":"ok-login",
        \\    "login":{"username":"u","password":"p"}
        \\  }]
        \\}
    );

    var vault = try makeEmptyVault(allocator);
    defer model.freeVault(allocator, &vault);

    const vault_path = try makeTempPath(allocator, &tmp, "vault.enc");
    defer allocator.free(vault_path);
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey("master", &salt);

    var target: ImportTarget = .{
        .vault = &vault,
        .key = &key,
        .salt = &salt,
        .vault_path = vault_path,
    };

    const summary = try importFromBitwardenJsonFile(allocator, &target, import_path, .{
        .mode = .best_effort,
        .dry_run = true,
        .action = .replace,
    });

    try std.testing.expect(summary.warning_count > 0);
    try std.testing.expectEqual(@as(usize, 1), summary.imported_items);
    try std.testing.expectEqual(@as(usize, 0), vault.items.len);
}

test "import replace persists full v2 fields" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const import_path = try makeTempPath(allocator, &tmp, "bw.json");
    defer allocator.free(import_path);
    try writeFile(import_path,
        \\{
        \\  "folders": [{"id":"f1","name":"Personal"}],
        \\  "items": [
        \\    {
        \\      "id":"new-id",
        \\      "folderId":"f1",
        \\      "type":1,
        \\      "name":"github",
        \\      "login":{"username":"dev@example.com","password":"newpw"}
        \\    },
        \\    {
        \\      "id":"card-id",
        \\      "type":3,
        \\      "name":"visa",
        \\      "card":{"number":"4111111111111111","code":"123"},
        \\      "fields":[{"name":"pin","value":"9999","type":0}],
        \\      "attachments":[{"id":"a1","fileName":"card.png","size":"128"}]
        \\    }
        \\  ]
        \\}
    );

    var vault = try makeEmptyVault(allocator);
    defer model.freeVault(allocator, &vault);
    try appendRuntimeItem(allocator, &vault, "old-id", "oldpw");

    const vault_path = try makeTempPath(allocator, &tmp, "vault.enc");
    defer allocator.free(vault_path);
    const password = "master";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);

    var target: ImportTarget = .{
        .vault = &vault,
        .key = &key,
        .salt = &salt,
        .vault_path = vault_path,
    };

    const summary = try importFromBitwardenJsonFile(allocator, &target, import_path, .{
        .mode = .strict,
        .dry_run = false,
        .action = .replace,
    });

    try std.testing.expectEqual(@as(usize, 2), summary.imported_items);
    try std.testing.expectEqual(@as(usize, 2), vault.items.len);

    const loaded = try storage.loadVault(allocator, password, vault_path);
    defer {
        model.freeVault(allocator, @constCast(&loaded.vault));
        crypto.zeroize(@constCast(&loaded.key));
    }
    try std.testing.expectEqual(@as(usize, 2), loaded.vault.items.len);

    var loaded_v2 = try storage.loadVaultV2(allocator, password, vault_path);
    defer loaded_v2.deinit();
    try std.testing.expectEqual(@as(usize, 2), loaded_v2.vault.items.len);
    try std.testing.expect(loaded_v2.vault.items[1].card != null);
    try std.testing.expectEqualStrings("4111111111111111", loaded_v2.vault.items[1].card.?.number.?);
    try std.testing.expect(loaded_v2.vault.items[1].fields != null);
    try std.testing.expectEqual(@as(usize, 1), loaded_v2.vault.items[1].fields.?.len);
    try std.testing.expect(loaded_v2.vault.items[1].attachments != null);
    try std.testing.expectEqual(@as(usize, 1), loaded_v2.vault.items[1].attachments.?.len);
}

test "import merge keeps existing v2 fields and appends new typed items" {
    try crypto.init();
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var vault = try makeEmptyVault(allocator);
    defer model.freeVault(allocator, &vault);

    const vault_path = try makeTempPath(allocator, &tmp, "vault.enc");
    defer allocator.free(vault_path);
    const password = "master";
    const salt = crypto.generateSalt();
    const key = try crypto.deriveKey(password, &salt);

    var seed_v2_parsed = try std.json.parseFromSlice(schema.VaultV2, allocator,
        \\{
        \\  "version":2,
        \\  "items":[
        \\    {
        \\      "id":"same-id",
        \\      "type":3,
        \\      "name":"same-card",
        \\      "card":{"number":"4000000000000002","code":"000"}
        \\    }
        \\  ]
        \\}
    , .{ .ignore_unknown_fields = true });
    defer seed_v2_parsed.deinit();
    try storage.saveVaultV2(allocator, seed_v2_parsed.value, &key, &salt, vault_path);
    const seeded_runtime = try storage.loadVault(allocator, password, vault_path);
    defer {
        model.freeVault(allocator, @constCast(&seeded_runtime.vault));
        crypto.zeroize(@constCast(&seeded_runtime.key));
    }
    model.freeVault(allocator, &vault);
    vault = try model.cloneVault(allocator, seeded_runtime.vault);

    const import_path = try makeTempPath(allocator, &tmp, "bw.json");
    defer allocator.free(import_path);
    try writeFile(import_path,
        \\{
        \\  "items": [
        \\    {
        \\      "id":"same-id",
        \\      "type":1,
        \\      "name":"same",
        \\      "login":{"username":"u","password":"newpw"}
        \\    },
        \\    {
        \\      "id":"new-id",
        \\      "type":4,
        \\      "name":"new-identity",
        \\      "identity":{"email":"u2@example.com","firstName":"U2"}
        \\    }
        \\  ]
        \\}
    );

    var target: ImportTarget = .{
        .vault = &vault,
        .key = &key,
        .salt = &salt,
        .vault_path = vault_path,
    };

    const summary = try importFromBitwardenJsonFile(allocator, &target, import_path, .{
        .mode = .strict,
        .dry_run = false,
        .action = .merge,
    });

    try std.testing.expectEqual(@as(usize, 2), vault.items.len);
    try std.testing.expectEqual(@as(usize, 1), summary.replaced_items);
    try std.testing.expectEqual(@as(usize, 1), summary.merged_items);

    var loaded_v2 = try storage.loadVaultV2(allocator, password, vault_path);
    defer loaded_v2.deinit();
    try std.testing.expectEqual(@as(usize, 2), loaded_v2.vault.items.len);

    var found_same = false;
    var found_new = false;
    for (loaded_v2.vault.items) |item| {
        if (std.mem.eql(u8, item.id, "same-id")) {
            found_same = true;
            try std.testing.expect(item.login != null);
            try std.testing.expectEqualStrings("newpw", item.login.?.password.?);
            try std.testing.expect(item.card == null);
        }
        if (std.mem.eql(u8, item.id, "new-id")) {
            found_new = true;
            try std.testing.expect(item.identity != null);
            try std.testing.expectEqualStrings("u2@example.com", item.identity.?.email.?);
        }
    }
    try std.testing.expect(found_same);
    try std.testing.expect(found_new);
}
