const std = @import("std");

/// Unique identifier for items and categories (v4 UUID string)
pub const Uuid = [36]u8;

pub const Item = struct {
    id: []const u8,
    name: ?[]const u8 = null,
    mail: ?[]const u8 = null,
    password: []const u8,
    notes: ?[]const u8 = null,
    category_id: ?[]const u8 = null,
    created_at: []const u8,
    updated_at: []const u8,
};

pub const Category = struct {
    id: []const u8,
    name: []const u8,
    color: ?[]const u8 = null,
};

pub const Vault = struct {
    version: u32 = 1,
    items: []Item,
    categories: []Category,
};

/// Ownership contract:
/// - Every string field inside Item/Category is owned by the Vault.
/// - Vault owns items/categories slices and every element's string fields.
/// - Call freeVault() exactly once to release all owned memory.

/// Encrypted file wrapper (what's actually written to disk)
pub const EncryptedVault = struct {
    version: u32 = 1,
    kdf: KdfParams,
    cipher: CipherParams,
};

pub const KdfParams = struct {
    alg: []const u8,
    salt: []const u8, // base64-encoded
    ops_limit: u64,
    mem_limit: u64,
};

pub const CipherParams = struct {
    alg: []const u8,
    nonce: []const u8, // base64-encoded
    ciphertext: []const u8, // base64-encoded
};

/// Generate a v4 UUID (random)
pub fn generateUuid() Uuid {
    var uuid: Uuid = undefined;
    var random_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    // Set version 4
    random_bytes[6] = (random_bytes[6] & 0x0f) | 0x40;
    // Set variant 1
    random_bytes[8] = (random_bytes[8] & 0x3f) | 0x80;

    const hex = "0123456789abcdef";
    var pos: usize = 0;
    for (random_bytes, 0..) |byte, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            uuid[pos] = '-';
            pos += 1;
        }
        uuid[pos] = hex[byte >> 4];
        uuid[pos + 1] = hex[byte & 0x0f];
        pos += 2;
    }

    return uuid;
}

/// Get current ISO 8601 timestamp
pub fn nowTimestamp(buf: *[20]u8) []const u8 {
    const epoch = std.time.timestamp();
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(epoch) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();

    const month_day = year_day.calculateMonthDay();
    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    _ = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        year, month, day, hour, minute, second,
    }) catch unreachable;

    return buf[0..19];
}

pub fn cloneItem(allocator: std.mem.Allocator, item: Item) !Item {
    return .{
        .id = try allocator.dupe(u8, item.id),
        .name = try dupOptional(allocator, item.name),
        .mail = try dupOptional(allocator, item.mail),
        .password = try allocator.dupe(u8, item.password),
        .notes = try dupOptional(allocator, item.notes),
        .category_id = try dupOptional(allocator, item.category_id),
        .created_at = try allocator.dupe(u8, item.created_at),
        .updated_at = try allocator.dupe(u8, item.updated_at),
    };
}

pub fn cloneCategory(allocator: std.mem.Allocator, category: Category) !Category {
    return .{
        .id = try allocator.dupe(u8, category.id),
        .name = try allocator.dupe(u8, category.name),
        .color = try dupOptional(allocator, category.color),
    };
}

pub fn cloneVault(allocator: std.mem.Allocator, vault: Vault) !Vault {
    var items = try allocator.alloc(Item, vault.items.len);
    var item_count: usize = 0;
    errdefer {
        for (0..item_count) |i| {
            freeItem(allocator, &items[i]);
        }
        allocator.free(items);
    }
    for (vault.items, 0..) |item, i| {
        items[i] = try cloneItem(allocator, item);
        item_count += 1;
    }

    var categories = try allocator.alloc(Category, vault.categories.len);
    var category_count: usize = 0;
    errdefer {
        for (0..category_count) |i| {
            freeCategory(allocator, &categories[i]);
        }
        allocator.free(categories);
        for (items) |*item| {
            freeItem(allocator, item);
        }
        allocator.free(items);
    }
    for (vault.categories, 0..) |category, i| {
        categories[i] = try cloneCategory(allocator, category);
        category_count += 1;
    }

    return .{
        .version = vault.version,
        .items = items,
        .categories = categories,
    };
}

pub fn freeItem(allocator: std.mem.Allocator, item: *Item) void {
    allocator.free(item.id);
    if (item.name) |name| allocator.free(name);
    if (item.mail) |mail| allocator.free(mail);
    allocator.free(item.password);
    if (item.notes) |notes| allocator.free(notes);
    if (item.category_id) |category_id| allocator.free(category_id);
    allocator.free(item.created_at);
    allocator.free(item.updated_at);

    item.* = .{
        .id = "",
        .name = null,
        .mail = null,
        .password = "",
        .notes = null,
        .category_id = null,
        .created_at = "",
        .updated_at = "",
    };
}

pub fn freeCategory(allocator: std.mem.Allocator, category: *Category) void {
    allocator.free(category.id);
    allocator.free(category.name);
    if (category.color) |color| allocator.free(color);

    category.* = .{
        .id = "",
        .name = "",
        .color = null,
    };
}

pub fn freeVault(allocator: std.mem.Allocator, vault: *Vault) void {
    for (vault.items) |*item| {
        freeItem(allocator, item);
    }
    allocator.free(vault.items);

    for (vault.categories) |*category| {
        freeCategory(allocator, category);
    }
    allocator.free(vault.categories);

    vault.* = .{
        .version = vault.version,
        .items = &.{},
        .categories = &.{},
    };
}

fn dupOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    if (value) |v| return try allocator.dupe(u8, v);
    return null;
}

test "generateUuid produces valid format" {
    const uuid = generateUuid();
    // Check dashes at correct positions
    try std.testing.expectEqual(uuid[8], '-');
    try std.testing.expectEqual(uuid[13], '-');
    try std.testing.expectEqual(uuid[18], '-');
    try std.testing.expectEqual(uuid[23], '-');
    try std.testing.expectEqual(uuid.len, 36);
}

test "nowTimestamp produces valid ISO format" {
    var buf: [20]u8 = undefined;
    const ts = nowTimestamp(&buf);
    try std.testing.expectEqual(ts.len, 19);
    try std.testing.expectEqual(ts[4], '-');
    try std.testing.expectEqual(ts[10], 'T');
}

test "cloneVault performs deep copy and freeVault releases memory" {
    const allocator = std.testing.allocator;

    const item = Item{
        .id = try allocator.dupe(u8, "item-1"),
        .name = try allocator.dupe(u8, "example"),
        .mail = try allocator.dupe(u8, "a@b.com"),
        .password = try allocator.dupe(u8, "secret"),
        .notes = try allocator.dupe(u8, "note"),
        .category_id = try allocator.dupe(u8, "cat-1"),
        .created_at = try allocator.dupe(u8, "2026-03-09T12:00:00"),
        .updated_at = try allocator.dupe(u8, "2026-03-09T12:00:00"),
    };
    const category = Category{
        .id = try allocator.dupe(u8, "cat-1"),
        .name = try allocator.dupe(u8, "personal"),
        .color = try allocator.dupe(u8, "blue"),
    };

    var items = try allocator.alloc(Item, 1);
    items[0] = item;
    var categories = try allocator.alloc(Category, 1);
    categories[0] = category;

    var original = Vault{
        .version = 1,
        .items = items,
        .categories = categories,
    };

    var cloned = try cloneVault(allocator, original);

    try std.testing.expect(cloned.items[0].id.ptr != original.items[0].id.ptr);
    try std.testing.expect(cloned.items[0].password.ptr != original.items[0].password.ptr);
    try std.testing.expect(cloned.categories[0].name.ptr != original.categories[0].name.ptr);

    freeVault(allocator, &original);
    freeVault(allocator, &cloned);
}
