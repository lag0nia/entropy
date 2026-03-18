const std = @import("std");
const model = @import("model.zig");
const schema = @import("schema_v2.zig");

pub const ServiceError = std.mem.Allocator.Error || error{
    FolderNameRequired,
    CollectionNameRequired,
    ItemNameRequired,
    ItemNotFound,
    NotLoginItem,
};

pub const CreateItemInput = struct {
    type: schema.ItemType,
    name: []const u8,
    notes: []const u8 = "",
    organization_id: ?[]const u8 = null,
    folder_id: ?[]const u8 = null,
    collection_ids: []const []const u8 = &.{},
    login_username: ?[]const u8 = null,
    login_password: ?[]const u8 = null,
    login_totp: ?[]const u8 = null,
    login_uri: ?[]const u8 = null,
    secure_note_type: u8 = 0,
    card_brand: ?[]const u8 = null,
    card_number: ?[]const u8 = null,
    card_code: ?[]const u8 = null,
    card_holder: ?[]const u8 = null,
    card_exp_month: ?[]const u8 = null,
    card_exp_year: ?[]const u8 = null,
    identity_email: ?[]const u8 = null,
    identity_first_name: ?[]const u8 = null,
    identity_last_name: ?[]const u8 = null,
    identity_phone: ?[]const u8 = null,
};

pub fn initEmptyVault(allocator: std.mem.Allocator) !schema.VaultV2 {
    return .{
        .version = 2,
        .encrypted = false,
        .source = .unknown,
        .folders = try allocator.alloc(schema.Folder, 0),
        .collections = try allocator.alloc(schema.Collection, 0),
        .items = try allocator.alloc(schema.Item, 0),
    };
}

pub fn freeVault(allocator: std.mem.Allocator, vault: *schema.VaultV2) void {
    for (vault.folders) |*folder| freeFolder(allocator, folder);
    allocator.free(vault.folders);

    for (vault.collections) |*collection| freeCollection(allocator, collection);
    allocator.free(vault.collections);

    for (vault.items) |*item| freeItem(allocator, item);
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

pub fn createFolder(
    allocator: std.mem.Allocator,
    vault: *schema.VaultV2,
    name: []const u8,
) ServiceError![]const u8 {
    if (name.len == 0) return ServiceError.FolderNameRequired;
    const uuid = model.generateUuid();
    const folder = schema.Folder{
        .id = try allocator.dupe(u8, &uuid),
        .name = try allocator.dupe(u8, name),
    };
    errdefer {
        allocator.free(folder.id);
        allocator.free(folder.name);
    }
    try appendFolder(allocator, vault, folder);
    vault.source = schema.detectSource(vault);
    return vault.folders[vault.folders.len - 1].id;
}

pub fn createCollection(
    allocator: std.mem.Allocator,
    vault: *schema.VaultV2,
    organization_id: []const u8,
    name: []const u8,
) ServiceError![]const u8 {
    if (name.len == 0) return ServiceError.CollectionNameRequired;
    const uuid = model.generateUuid();
    const collection = schema.Collection{
        .id = try allocator.dupe(u8, &uuid),
        .organizationId = try allocator.dupe(u8, organization_id),
        .name = try allocator.dupe(u8, name),
        .externalId = null,
    };
    errdefer {
        allocator.free(collection.id);
        allocator.free(collection.organizationId.?);
        allocator.free(collection.name);
    }
    try appendCollection(allocator, vault, collection);
    vault.source = schema.detectSource(vault);
    return vault.collections[vault.collections.len - 1].id;
}

pub fn createItem(
    allocator: std.mem.Allocator,
    vault: *schema.VaultV2,
    input: CreateItemInput,
) ServiceError![]const u8 {
    if (input.name.len == 0) return ServiceError.ItemNameRequired;

    const uuid = model.generateUuid();
    var now_buf: [20]u8 = undefined;
    const now = model.nowTimestamp(&now_buf);

    var item = schema.Item{
        .id = try allocator.dupe(u8, &uuid),
        .organizationId = if (input.organization_id) |v| try allocator.dupe(u8, v) else null,
        .folderId = if (input.folder_id) |v| try allocator.dupe(u8, v) else null,
        .collectionIds = null,
        .type = @intFromEnum(input.type),
        .name = try allocator.dupe(u8, input.name),
        .notes = if (input.notes.len > 0) try allocator.dupe(u8, input.notes) else null,
        .favorite = null,
        .reprompt = null,
        .fields = null,
        .passwordHistory = null,
        .login = null,
        .secureNote = null,
        .card = null,
        .identity = null,
        .attachments = null,
        .revisionDate = try allocator.dupe(u8, now),
        .creationDate = try allocator.dupe(u8, now),
        .deletedDate = null,
        .original_json = null,
    };
    errdefer freeItem(allocator, &item);

    if (input.collection_ids.len > 0) {
        const ids = try allocator.alloc(?[]const u8, input.collection_ids.len);
        errdefer allocator.free(ids);
        var i: usize = 0;
        errdefer {
            for (0..i) |j| allocator.free(ids[j].?);
        }
        for (input.collection_ids, 0..) |collection_id, idx| {
            ids[idx] = try allocator.dupe(u8, collection_id);
            i += 1;
        }
        item.collectionIds = ids;
    }

    switch (input.type) {
        .login => {
            var uris: ?[]schema.LoginUri = null;
            if (input.login_uri) |uri| {
                if (uri.len > 0) {
                    var out = try allocator.alloc(schema.LoginUri, 1);
                    out[0] = .{
                        .uri = try allocator.dupe(u8, uri),
                        .match = null,
                    };
                    uris = out;
                }
            }
            item.login = .{
                .uris = uris,
                .username = if (input.login_username) |v| try allocator.dupe(u8, v) else null,
                .password = if (input.login_password) |v| try allocator.dupe(u8, v) else null,
                .totp = if (input.login_totp) |v| try allocator.dupe(u8, v) else null,
                .passwordRevisionDate = null,
                .fido2Credentials = null,
            };
        },
        .secure_note => {
            item.secureNote = .{
                .type = input.secure_note_type,
            };
        },
        .card => {
            item.card = .{
                .cardholderName = if (input.card_holder) |v| try allocator.dupe(u8, v) else null,
                .brand = if (input.card_brand) |v| try allocator.dupe(u8, v) else null,
                .number = if (input.card_number) |v| try allocator.dupe(u8, v) else null,
                .expMonth = if (input.card_exp_month) |v| try allocator.dupe(u8, v) else null,
                .expYear = if (input.card_exp_year) |v| try allocator.dupe(u8, v) else null,
                .code = if (input.card_code) |v| try allocator.dupe(u8, v) else null,
            };
        },
        .identity => {
            item.identity = .{
                .title = null,
                .firstName = if (input.identity_first_name) |v| try allocator.dupe(u8, v) else null,
                .middleName = null,
                .lastName = if (input.identity_last_name) |v| try allocator.dupe(u8, v) else null,
                .address1 = null,
                .address2 = null,
                .address3 = null,
                .city = null,
                .state = null,
                .postalCode = null,
                .country = null,
                .company = null,
                .email = if (input.identity_email) |v| try allocator.dupe(u8, v) else null,
                .phone = if (input.identity_phone) |v| try allocator.dupe(u8, v) else null,
                .ssn = null,
                .username = null,
                .passportNumber = null,
                .licenseNumber = null,
            };
        },
    }

    try appendItem(allocator, vault, item);
    vault.source = schema.detectSource(vault);
    return vault.items[vault.items.len - 1].id;
}

pub fn updateLoginCredentials(
    allocator: std.mem.Allocator,
    vault: *schema.VaultV2,
    item_id: []const u8,
    username: []const u8,
    password: []const u8,
) ServiceError!void {
    const idx = findItemIndexById(vault.items, item_id) orelse return ServiceError.ItemNotFound;
    var item = &vault.items[idx];
    if (item.type != @intFromEnum(schema.ItemType.login)) return ServiceError.NotLoginItem;
    if (item.login == null) item.login = .{};

    if (item.login.?.username) |v| allocator.free(v);
    item.login.?.username = if (username.len > 0) try allocator.dupe(u8, username) else null;

    if (item.login.?.password) |v| allocator.free(v);
    item.login.?.password = if (password.len > 0) try allocator.dupe(u8, password) else null;

    var now_buf: [20]u8 = undefined;
    if (item.revisionDate) |v| allocator.free(v);
    item.revisionDate = try allocator.dupe(u8, model.nowTimestamp(&now_buf));
}

pub fn deleteItem(
    allocator: std.mem.Allocator,
    vault: *schema.VaultV2,
    item_id: []const u8,
) ServiceError!void {
    const idx = findItemIndexById(vault.items, item_id) orelse return ServiceError.ItemNotFound;

    var removed = vault.items[idx];
    const old = vault.items;
    var items = std.ArrayList(schema.Item){};
    for (old, 0..) |item, i| {
        if (i != idx) try items.append(allocator, item);
    }

    vault.items = try items.toOwnedSlice(allocator);
    freeItem(allocator, &removed);
    allocator.free(old);
}

fn findItemIndexById(items: []const schema.Item, item_id: []const u8) ?usize {
    for (items, 0..) |item, idx| {
        if (std.mem.eql(u8, item.id, item_id)) return idx;
    }
    return null;
}

fn appendFolder(allocator: std.mem.Allocator, vault: *schema.VaultV2, folder: schema.Folder) !void {
    const old = vault.folders;
    var folders = std.ArrayList(schema.Folder){};
    try folders.appendSlice(allocator, old);
    try folders.append(allocator, folder);
    vault.folders = try folders.toOwnedSlice(allocator);
    allocator.free(old);
}

fn appendCollection(allocator: std.mem.Allocator, vault: *schema.VaultV2, collection: schema.Collection) !void {
    const old = vault.collections;
    var collections = std.ArrayList(schema.Collection){};
    try collections.appendSlice(allocator, old);
    try collections.append(allocator, collection);
    vault.collections = try collections.toOwnedSlice(allocator);
    allocator.free(old);
}

fn appendItem(allocator: std.mem.Allocator, vault: *schema.VaultV2, item: schema.Item) !void {
    const old = vault.items;
    var items = std.ArrayList(schema.Item){};
    try items.appendSlice(allocator, old);
    try items.append(allocator, item);
    vault.items = try items.toOwnedSlice(allocator);
    allocator.free(old);
}

fn freeFolder(allocator: std.mem.Allocator, folder: *schema.Folder) void {
    allocator.free(folder.id);
    allocator.free(folder.name);
    folder.* = .{ .id = "", .name = "" };
}

fn freeCollection(allocator: std.mem.Allocator, collection: *schema.Collection) void {
    allocator.free(collection.id);
    if (collection.organizationId) |v| allocator.free(v);
    allocator.free(collection.name);
    if (collection.externalId) |v| allocator.free(v);
    collection.* = .{
        .id = "",
        .organizationId = null,
        .name = "",
        .externalId = null,
    };
}

fn freeItem(allocator: std.mem.Allocator, item: *schema.Item) void {
    allocator.free(item.id);
    if (item.organizationId) |v| allocator.free(v);
    if (item.folderId) |v| allocator.free(v);
    if (item.collectionIds) |ids| {
        for (ids) |maybe_id| {
            if (maybe_id) |id| allocator.free(id);
        }
        allocator.free(ids);
    }
    allocator.free(item.name);
    if (item.notes) |v| allocator.free(v);
    if (item.login) |*login| {
        if (login.uris) |uris| {
            for (uris) |uri| {
                if (uri.uri) |v| allocator.free(v);
            }
            allocator.free(uris);
        }
        if (login.username) |v| allocator.free(v);
        if (login.password) |v| allocator.free(v);
        if (login.totp) |v| allocator.free(v);
        if (login.passwordRevisionDate) |v| allocator.free(v);
        if (login.fido2Credentials) |credentials| {
            for (credentials) |credential| {
                if (credential.credentialId) |v| allocator.free(v);
                if (credential.keyType) |v| allocator.free(v);
                if (credential.keyAlgorithm) |v| allocator.free(v);
                if (credential.keyCurve) |v| allocator.free(v);
                if (credential.keyValue) |v| allocator.free(v);
                if (credential.rpId) |v| allocator.free(v);
                if (credential.rpName) |v| allocator.free(v);
                if (credential.userHandle) |v| allocator.free(v);
                if (credential.userName) |v| allocator.free(v);
                if (credential.userDisplayName) |v| allocator.free(v);
                if (credential.discoverable) |v| allocator.free(v);
                if (credential.creationDate) |v| allocator.free(v);
            }
            allocator.free(credentials);
        }
    }
    if (item.card) |*card| {
        if (card.brand) |v| allocator.free(v);
        if (card.number) |v| allocator.free(v);
        if (card.code) |v| allocator.free(v);
        if (card.cardholderName) |v| allocator.free(v);
        if (card.expMonth) |v| allocator.free(v);
        if (card.expYear) |v| allocator.free(v);
    }
    if (item.identity) |*identity| {
        if (identity.firstName) |v| allocator.free(v);
        if (identity.email) |v| allocator.free(v);
        if (identity.title) |v| allocator.free(v);
        if (identity.middleName) |v| allocator.free(v);
        if (identity.lastName) |v| allocator.free(v);
        if (identity.address1) |v| allocator.free(v);
        if (identity.address2) |v| allocator.free(v);
        if (identity.address3) |v| allocator.free(v);
        if (identity.city) |v| allocator.free(v);
        if (identity.state) |v| allocator.free(v);
        if (identity.postalCode) |v| allocator.free(v);
        if (identity.country) |v| allocator.free(v);
        if (identity.company) |v| allocator.free(v);
        if (identity.phone) |v| allocator.free(v);
        if (identity.ssn) |v| allocator.free(v);
        if (identity.username) |v| allocator.free(v);
        if (identity.passportNumber) |v| allocator.free(v);
        if (identity.licenseNumber) |v| allocator.free(v);
    }
    if (item.revisionDate) |v| allocator.free(v);
    if (item.creationDate) |v| allocator.free(v);
    if (item.deletedDate) |v| allocator.free(v);
    if (item.original_json) |v| allocator.free(v);

    item.* = .{
        .id = "",
        .organizationId = null,
        .folderId = null,
        .collectionIds = null,
        .type = 1,
        .name = "",
    };
}

test "folder and login CRUD on v2 vault" {
    const allocator = std.testing.allocator;

    var vault = try initEmptyVault(allocator);
    defer freeVault(allocator, &vault);

    const folder_id = try createFolder(allocator, &vault, "Personal");
    _ = folder_id;
    const item_id = try createItem(allocator, &vault, .{
        .type = .login,
        .name = "GitHub",
        .folder_id = vault.folders[0].id,
        .login_username = "dev@example.com",
        .login_password = "pw",
        .login_totp = "ABC123",
        .login_uri = "https://github.com",
    });

    try std.testing.expectEqual(@as(usize, 1), vault.folders.len);
    try std.testing.expectEqual(@as(usize, 1), vault.items.len);
    try std.testing.expect(vault.items[0].login != null);
    try std.testing.expectEqualStrings("dev@example.com", vault.items[0].login.?.username.?);
    try std.testing.expectEqualStrings("ABC123", vault.items[0].login.?.totp.?);
    try std.testing.expect(vault.items[0].login.?.uris != null);
    try std.testing.expectEqual(@as(usize, 1), vault.items[0].login.?.uris.?.len);
    try std.testing.expectEqualStrings("https://github.com", vault.items[0].login.?.uris.?[0].uri.?);

    try updateLoginCredentials(allocator, &vault, item_id, "new@example.com", "newpw");
    try std.testing.expectEqualStrings("newpw", vault.items[0].login.?.password.?);

    try deleteItem(allocator, &vault, item_id);
    try std.testing.expectEqual(@as(usize, 0), vault.items.len);
}

test "collection and typed item creation on v2 vault" {
    const allocator = std.testing.allocator;

    var vault = try initEmptyVault(allocator);
    defer freeVault(allocator, &vault);

    _ = try createCollection(allocator, &vault, "org-1", "Engineering");
    _ = try createItem(allocator, &vault, .{
        .type = .secure_note,
        .name = "Shared Note",
        .organization_id = "org-1",
        .collection_ids = &.{vault.collections[0].id},
        .notes = "hello",
    });
    _ = try createItem(allocator, &vault, .{
        .type = .card,
        .name = "Visa",
        .card_brand = "visa",
        .card_number = "4111111111111111",
        .card_code = "123",
        .card_holder = "John Dev",
        .card_exp_month = "10",
        .card_exp_year = "2030",
    });

    try std.testing.expectEqual(@as(usize, 1), vault.collections.len);
    try std.testing.expectEqual(@as(usize, 2), vault.items.len);
    try std.testing.expect(vault.items[0].secureNote != null);
    try std.testing.expect(vault.items[1].card != null);
    try std.testing.expectEqualStrings("4111111111111111", vault.items[1].card.?.number.?);
    try std.testing.expectEqualStrings("John Dev", vault.items[1].card.?.cardholderName.?);
    try std.testing.expectEqualStrings("10", vault.items[1].card.?.expMonth.?);
}

test "updateLoginCredentials rejects non-login item" {
    const allocator = std.testing.allocator;

    var vault = try initEmptyVault(allocator);
    defer freeVault(allocator, &vault);

    const id = try createItem(allocator, &vault, .{
        .type = .identity,
        .name = "John",
        .identity_first_name = "John",
        .identity_email = "john@example.com",
    });

    const result = updateLoginCredentials(allocator, &vault, id, "u", "p");
    try std.testing.expectError(ServiceError.NotLoginItem, result);
}
