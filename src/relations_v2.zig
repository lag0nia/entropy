const std = @import("std");
const schema = @import("schema_v2.zig");

pub const RelationError = std.mem.Allocator.Error || error{
    DuplicateItemId,
    DuplicateFolderId,
    DuplicateCollectionId,
    UnknownFolderId,
    UnknownCollectionId,
    OrganizationMismatch,
};

pub const ItemFolderLink = struct {
    item_index: usize,
    folder_index: usize,
};

pub const ItemCollectionLink = struct {
    item_index: usize,
    collection_index: usize,
};

/// Normalized relationship model for v2:
/// - folder assignment is represented as a separate link list (0..1 per item).
/// - collection assignment is represented as many-to-many links.
pub const NormalizedRelations = struct {
    item_folder_links: []ItemFolderLink,
    item_collection_links: []ItemCollectionLink,

    pub fn deinit(self: *NormalizedRelations, allocator: std.mem.Allocator) void {
        allocator.free(self.item_folder_links);
        allocator.free(self.item_collection_links);
        self.* = .{
            .item_folder_links = &.{},
            .item_collection_links = &.{},
        };
    }
};

pub fn build(allocator: std.mem.Allocator, vault: *const schema.VaultV2) RelationError!NormalizedRelations {
    var item_id_index = std.StringHashMap(usize).init(allocator);
    defer item_id_index.deinit();
    var folder_id_index = std.StringHashMap(usize).init(allocator);
    defer folder_id_index.deinit();
    var collection_id_index = std.StringHashMap(usize).init(allocator);
    defer collection_id_index.deinit();

    for (vault.items, 0..) |item, index| {
        const gop = try item_id_index.getOrPut(item.id);
        if (gop.found_existing) return RelationError.DuplicateItemId;
        gop.value_ptr.* = index;
    }
    for (vault.folders, 0..) |folder, index| {
        const gop = try folder_id_index.getOrPut(folder.id);
        if (gop.found_existing) return RelationError.DuplicateFolderId;
        gop.value_ptr.* = index;
    }
    for (vault.collections, 0..) |collection, index| {
        const gop = try collection_id_index.getOrPut(collection.id);
        if (gop.found_existing) return RelationError.DuplicateCollectionId;
        gop.value_ptr.* = index;
    }

    var folder_links = std.ArrayList(ItemFolderLink){};
    errdefer folder_links.deinit(allocator);

    var collection_links = std.ArrayList(ItemCollectionLink){};
    errdefer collection_links.deinit(allocator);

    // Deduplicate (item, collection) pairs when export includes repeated collectionIds.
    var seen_pairs = std.AutoHashMap(u128, void).init(allocator);
    defer seen_pairs.deinit();

    for (vault.items, 0..) |item, item_index| {
        if (item.folderId) |folder_id| {
            const folder_index = folder_id_index.get(folder_id) orelse
                return RelationError.UnknownFolderId;
            try folder_links.append(allocator, .{
                .item_index = item_index,
                .folder_index = folder_index,
            });
        }

        if (item.collectionIds) |collection_ids| {
            for (collection_ids) |maybe_collection_id| {
                const collection_id = maybe_collection_id orelse continue;

                const collection_index = collection_id_index.get(collection_id) orelse
                    return RelationError.UnknownCollectionId;
                const collection = vault.collections[collection_index];

                if (item.organizationId) |item_org| {
                    if (collection.organizationId) |collection_org| {
                        if (!std.mem.eql(u8, item_org, collection_org)) {
                            return RelationError.OrganizationMismatch;
                        }
                    } else {
                        return RelationError.OrganizationMismatch;
                    }
                } else if (collection.organizationId != null) {
                    return RelationError.OrganizationMismatch;
                }

                const key = (@as(u128, item_index) << 64) | @as(u128, collection_index);
                const pair_gop = try seen_pairs.getOrPut(key);
                if (pair_gop.found_existing) continue;
                pair_gop.value_ptr.* = {};

                try collection_links.append(allocator, .{
                    .item_index = item_index,
                    .collection_index = collection_index,
                });
            }
        }
    }

    return .{
        .item_folder_links = try folder_links.toOwnedSlice(allocator),
        .item_collection_links = try collection_links.toOwnedSlice(allocator),
    };
}

test "build normalized relations for mixed folder/collection assignments" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "folders": [{"id":"f1","name":"Personal"}],
        \\  "collections": [{"id":"c1","organizationId":"org-1","name":"Engineering"}],
        \\  "items": [
        \\    {
        \\      "id":"i1",
        \\      "folderId":"f1",
        \\      "organizationId": null,
        \\      "type":1,
        \\      "name":"local-login",
        \\      "login": {}
        \\    },
        \\    {
        \\      "id":"i2",
        \\      "folderId":null,
        \\      "organizationId":"org-1",
        \\      "collectionIds":["c1","c1",null],
        \\      "type":2,
        \\      "name":"org-note",
        \\      "secureNote":{"type":0}
        \\    }
        \\  ]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var relations = try build(allocator, &parsed.value);
    defer relations.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), relations.item_folder_links.len);
    try std.testing.expectEqual(@as(usize, 1), relations.item_collection_links.len);
    try std.testing.expectEqual(@as(usize, 0), relations.item_folder_links[0].item_index);
    try std.testing.expectEqual(@as(usize, 0), relations.item_folder_links[0].folder_index);
    try std.testing.expectEqual(@as(usize, 1), relations.item_collection_links[0].item_index);
    try std.testing.expectEqual(@as(usize, 0), relations.item_collection_links[0].collection_index);
}

test "build fails when item references unknown collection" {
    const allocator = std.testing.allocator;

    const json =
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
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const result = build(allocator, &parsed.value);
    try std.testing.expectError(RelationError.UnknownCollectionId, result);
}

test "build fails on organization mismatch between item and collection" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "collections": [{"id":"c1","organizationId":"org-A","name":"A"}],
        \\  "items": [{
        \\    "id":"i1",
        \\    "organizationId":"org-B",
        \\    "collectionIds":["c1"],
        \\    "type":2,
        \\    "name":"broken",
        \\    "secureNote":{"type":0}
        \\  }]
        \\}
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const result = build(allocator, &parsed.value);
    try std.testing.expectError(RelationError.OrganizationMismatch, result);
}

test "build fails on duplicate collection ids" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "collections": [
        \\    {"id":"c1","organizationId":"org-1","name":"A"},
        \\    {"id":"c1","organizationId":"org-1","name":"B"}
        \\  ],
        \\  "items": []
        \\}
    ;

    var parsed = try std.json.parseFromSlice(schema.VaultV2, allocator, json, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const result = build(allocator, &parsed.value);
    try std.testing.expectError(RelationError.DuplicateCollectionId, result);
}
