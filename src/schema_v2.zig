const std = @import("std");

/// Vault schema v2 targets a 1:1 mapping with Bitwarden JSON exports.
/// It supports both individual and organization roots.
pub const VaultV2 = struct {
    version: u32 = 2,
    encrypted: ?bool = null,
    source: Source = .unknown,
    folders: []Folder = &.{},
    collections: []Collection = &.{},
    items: []Item = &.{},
};

pub const Source = enum {
    individual,
    organization,
    unknown,
};

pub const Folder = struct {
    id: []const u8,
    name: []const u8,
};

pub const Collection = struct {
    id: []const u8,
    organizationId: ?[]const u8 = null,
    name: []const u8,
    externalId: ?[]const u8 = null,
};

pub const ItemType = enum(u8) {
    login = 1,
    secure_note = 2,
    card = 3,
    identity = 4,
};

pub const Item = struct {
    id: []const u8,
    organizationId: ?[]const u8 = null,
    folderId: ?[]const u8 = null,
    collectionIds: ?[]const ?[]const u8 = null,
    type: u8,
    name: []const u8,
    notes: ?[]const u8 = null,
    favorite: ?bool = null,
    reprompt: ?u8 = null,
    fields: ?[]Field = null,
    passwordHistory: ?[]PasswordHistory = null,
    login: ?Login = null,
    secureNote: ?SecureNote = null,
    card: ?Card = null,
    identity: ?Identity = null,
    attachments: ?[]Attachment = null,
    revisionDate: ?[]const u8 = null,
    creationDate: ?[]const u8 = null,
    deletedDate: ?[]const u8 = null,

    // Lossless safety net for unknown/forward-compatible payloads.
    original_json: ?[]const u8 = null,
};

pub const Field = struct {
    name: ?[]const u8 = null,
    value: ?[]const u8 = null,
    type: ?u8 = null,
    linkedId: ?u8 = null,
};

pub const PasswordHistory = struct {
    lastUsedDate: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

pub const Login = struct {
    uris: ?[]LoginUri = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    totp: ?[]const u8 = null,
    passwordRevisionDate: ?[]const u8 = null,
    fido2Credentials: ?[]Passkey = null,
};

pub const LoginUri = struct {
    uri: ?[]const u8 = null,
    match: ?u8 = null,
};

pub const SecureNote = struct {
    type: ?u8 = null,
};

pub const Card = struct {
    cardholderName: ?[]const u8 = null,
    brand: ?[]const u8 = null,
    number: ?[]const u8 = null,
    expMonth: ?[]const u8 = null,
    expYear: ?[]const u8 = null,
    code: ?[]const u8 = null,
};

pub const Identity = struct {
    title: ?[]const u8 = null,
    firstName: ?[]const u8 = null,
    middleName: ?[]const u8 = null,
    lastName: ?[]const u8 = null,
    address1: ?[]const u8 = null,
    address2: ?[]const u8 = null,
    address3: ?[]const u8 = null,
    city: ?[]const u8 = null,
    state: ?[]const u8 = null,
    postalCode: ?[]const u8 = null,
    country: ?[]const u8 = null,
    company: ?[]const u8 = null,
    email: ?[]const u8 = null,
    phone: ?[]const u8 = null,
    ssn: ?[]const u8 = null,
    username: ?[]const u8 = null,
    passportNumber: ?[]const u8 = null,
    licenseNumber: ?[]const u8 = null,
};

pub const Passkey = struct {
    credentialId: ?[]const u8 = null,
    keyType: ?[]const u8 = null,
    keyAlgorithm: ?[]const u8 = null,
    keyCurve: ?[]const u8 = null,
    keyValue: ?[]const u8 = null,
    rpId: ?[]const u8 = null,
    rpName: ?[]const u8 = null,
    userHandle: ?[]const u8 = null,
    userName: ?[]const u8 = null,
    userDisplayName: ?[]const u8 = null,
    discoverable: ?[]const u8 = null,
    creationDate: ?[]const u8 = null,
};

pub const Attachment = struct {
    id: ?[]const u8 = null,
    url: ?[]const u8 = null,
    fileName: ?[]const u8 = null,
    key: ?[]const u8 = null,
    size: ?[]const u8 = null,
    sizeName: ?[]const u8 = null,
};

pub fn detectSource(vault: *const VaultV2) Source {
    if (vault.collections.len > 0) return .organization;
    if (vault.folders.len > 0) return .individual;
    if (vault.items.len == 0) return .unknown;
    // Items without collections are typically from individual exports.
    return .individual;
}

test "VaultV2 parses minimal individual export shape" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "encrypted": false,
        \\  "folders": [{"id":"f1","name":"Personal"}],
        \\  "items": [{
        \\    "id":"i1",
        \\    "organizationId": null,
        \\    "folderId": "f1",
        \\    "type": 1,
        \\    "name": "GitHub",
        \\    "notes": "main account",
        \\    "favorite": false,
        \\    "reprompt": 0,
        \\    "login": {
        \\      "username": "dev@example.com",
        \\      "password": "secret",
        \\      "totp": null,
        \\      "uris": [{"uri":"https://github.com","match":0}]
        \\    }
        \\  }]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const root = parsed.value;
    try std.testing.expectEqual(@as(usize, 1), root.folders.len);
    try std.testing.expectEqual(@as(usize, 1), root.items.len);
    try std.testing.expectEqual(@as(u8, 1), root.items[0].type);
    try std.testing.expectEqualStrings("GitHub", root.items[0].name);
    try std.testing.expectEqualStrings("dev@example.com", root.items[0].login.?.username.?);
}

test "VaultV2 parses organization collections and nullable collectionIds entries" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "encrypted": false,
        \\  "collections": [{
        \\    "id": "c1",
        \\    "organizationId": "org1",
        \\    "name": "Engineering",
        \\    "externalId": null
        \\  }],
        \\  "items": [{
        \\    "id": "i-org-1",
        \\    "organizationId": "org1",
        \\    "folderId": null,
        \\    "collectionIds": [null, "c1"],
        \\    "type": 2,
        \\    "name": "Shared note",
        \\    "secureNote": { "type": 0 }
        \\  }]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const root = parsed.value;
    try std.testing.expectEqual(@as(usize, 1), root.collections.len);
    try std.testing.expectEqual(@as(usize, 1), root.items.len);
    try std.testing.expect(root.items[0].collectionIds != null);
    try std.testing.expectEqual(@as(usize, 2), root.items[0].collectionIds.?.len);
    try std.testing.expect(root.items[0].collectionIds.?[0] == null);
    try std.testing.expectEqualStrings("c1", root.items[0].collectionIds.?[1].?);
}
