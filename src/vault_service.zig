const std = @import("std");
const model = @import("model.zig");
const bip39 = @import("bip39.zig");

pub const ServiceError = std.mem.Allocator.Error || error{
    NameOrMailRequired,
    CategoryNameRequired,
    CategoryNameAlreadyExists,
    CategoryNotFound,
    ItemIndexOutOfRange,
    CategoryIndexOutOfRange,
    NoWordlistLoaded,
};

pub const ItemFormInput = struct {
    name: []const u8,
    mail: []const u8,
    password: []const u8,
    notes: []const u8,
    category_name: []const u8,
};

pub fn createItem(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    input: ItemFormInput,
    wordlist: ?[][]const u8,
) ServiceError!void {
    if (input.name.len == 0 and input.mail.len == 0) return ServiceError.NameOrMailRequired;

    const category_id = try resolveCategoryId(allocator, vault.categories, input.category_name);
    errdefer if (category_id) |v| allocator.free(v);

    const password = if (input.password.len > 0)
        try allocator.dupe(u8, input.password)
    else blk: {
        const wl = wordlist orelse return ServiceError.NoWordlistLoaded;
        break :blk try bip39.generateMnemonic(allocator, wl, "-");
    };

    var ts_buf: [20]u8 = undefined;
    const now = model.nowTimestamp(&ts_buf);
    const uuid = model.generateUuid();

    var new_item = model.Item{
        .id = try allocator.dupe(u8, &uuid),
        .name = try dupOptionalNonEmpty(allocator, input.name),
        .mail = try dupOptionalNonEmpty(allocator, input.mail),
        .password = password,
        .notes = try dupOptionalNonEmpty(allocator, input.notes),
        .category_id = category_id,
        .created_at = try allocator.dupe(u8, now),
        .updated_at = try allocator.dupe(u8, now),
    };
    errdefer model.freeItem(allocator, &new_item);

    const old_items = vault.items;
    var new_items: std.ArrayList(model.Item) = .{};
    try new_items.appendSlice(allocator, old_items);
    try new_items.append(allocator, new_item);
    vault.items = try new_items.toOwnedSlice(allocator);
    allocator.free(old_items);
}

pub fn updateItem(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    item_index: usize,
    input: ItemFormInput,
) ServiceError!void {
    if (item_index >= vault.items.len) return ServiceError.ItemIndexOutOfRange;
    if (input.name.len == 0 and input.mail.len == 0) return ServiceError.NameOrMailRequired;

    const new_name = try dupOptionalNonEmpty(allocator, input.name);
    errdefer if (new_name) |v| allocator.free(v);

    const new_mail = try dupOptionalNonEmpty(allocator, input.mail);
    errdefer if (new_mail) |v| allocator.free(v);

    const new_password = if (input.password.len > 0) try allocator.dupe(u8, input.password) else null;
    errdefer if (new_password) |v| allocator.free(v);

    const new_notes = try dupOptionalNonEmpty(allocator, input.notes);
    errdefer if (new_notes) |v| allocator.free(v);

    const new_category_id = try resolveCategoryId(allocator, vault.categories, input.category_name);
    errdefer if (new_category_id) |v| allocator.free(v);

    var ts_buf: [20]u8 = undefined;
    const new_updated_at = try allocator.dupe(u8, model.nowTimestamp(&ts_buf));
    errdefer allocator.free(new_updated_at);

    var item = &vault.items[item_index];
    if (item.name) |v| allocator.free(v);
    item.name = new_name;

    if (item.mail) |v| allocator.free(v);
    item.mail = new_mail;

    if (new_password) |pw| {
        allocator.free(item.password);
        item.password = pw;
    }

    if (item.notes) |v| allocator.free(v);
    item.notes = new_notes;

    if (item.category_id) |v| allocator.free(v);
    item.category_id = new_category_id;

    allocator.free(item.updated_at);
    item.updated_at = new_updated_at;
}

pub fn deleteItem(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    item_index: usize,
) ServiceError!void {
    const old_items = vault.items;
    if (item_index >= old_items.len) return ServiceError.ItemIndexOutOfRange;

    var removed = old_items[item_index];

    var new_items: std.ArrayList(model.Item) = .{};
    for (old_items, 0..) |item, i| {
        if (i != item_index) {
            try new_items.append(allocator, item);
        }
    }

    vault.items = try new_items.toOwnedSlice(allocator);
    model.freeItem(allocator, &removed);
    allocator.free(old_items);
}

pub fn createCategory(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    category_name: []const u8,
) ServiceError!void {
    if (category_name.len == 0) return ServiceError.CategoryNameRequired;
    if (categoryNameExists(vault.categories, category_name, null)) {
        return ServiceError.CategoryNameAlreadyExists;
    }

    const uuid = model.generateUuid();
    var new_category = model.Category{
        .id = try allocator.dupe(u8, &uuid),
        .name = try allocator.dupe(u8, category_name),
    };
    errdefer model.freeCategory(allocator, &new_category);

    const old_categories = vault.categories;
    var new_categories: std.ArrayList(model.Category) = .{};
    try new_categories.appendSlice(allocator, old_categories);
    try new_categories.append(allocator, new_category);
    vault.categories = try new_categories.toOwnedSlice(allocator);
    allocator.free(old_categories);
}

pub fn updateCategory(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    category_index: usize,
    category_name: []const u8,
) ServiceError!void {
    if (category_index >= vault.categories.len) return ServiceError.CategoryIndexOutOfRange;
    if (category_name.len == 0) return ServiceError.CategoryNameRequired;
    if (categoryNameExists(vault.categories, category_name, category_index)) {
        return ServiceError.CategoryNameAlreadyExists;
    }

    const new_name = try allocator.dupe(u8, category_name);
    var category = &vault.categories[category_index];
    allocator.free(category.name);
    category.name = new_name;
}

pub fn deleteCategory(
    allocator: std.mem.Allocator,
    vault: *model.Vault,
    category_index: usize,
) ServiceError!void {
    const old_categories = vault.categories;
    if (category_index >= old_categories.len) return ServiceError.CategoryIndexOutOfRange;

    var removed = old_categories[category_index];
    const removed_cat_id = removed.id;

    for (vault.items) |*item| {
        if (item.category_id) |cid| {
            if (std.mem.eql(u8, cid, removed_cat_id)) {
                allocator.free(cid);
                item.category_id = null;
            }
        }
    }

    var new_categories: std.ArrayList(model.Category) = .{};
    for (old_categories, 0..) |category, i| {
        if (i != category_index) {
            try new_categories.append(allocator, category);
        }
    }

    vault.categories = try new_categories.toOwnedSlice(allocator);
    model.freeCategory(allocator, &removed);
    allocator.free(old_categories);
}

fn dupOptionalNonEmpty(allocator: std.mem.Allocator, value: []const u8) !?[]const u8 {
    if (value.len == 0) return null;
    return try allocator.dupe(u8, value);
}

fn resolveCategoryId(
    allocator: std.mem.Allocator,
    categories: []const model.Category,
    category_name: []const u8,
) ServiceError!?[]const u8 {
    if (category_name.len == 0) return null;

    for (categories) |category| {
        if (std.mem.eql(u8, category.name, category_name)) {
            return try allocator.dupe(u8, category.id);
        }
    }
    return ServiceError.CategoryNotFound;
}

fn categoryNameExists(
    categories: []const model.Category,
    category_name: []const u8,
    ignore_index: ?usize,
) bool {
    for (categories, 0..) |category, i| {
        if (ignore_index != null and i == ignore_index.?) continue;
        if (std.mem.eql(u8, category.name, category_name)) return true;
    }
    return false;
}

