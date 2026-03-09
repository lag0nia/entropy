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
