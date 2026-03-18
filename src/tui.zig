const std = @import("std");
const utils = @import("utils.zig");
const model = @import("model.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const bip39 = @import("bip39.zig");
const vault_service_v2 = @import("vault_service_v2.zig");
const schema = @import("schema_v2.zig");
const relations_v2 = @import("relations_v2.zig");

pub const Color = utils.Color;
pub const Box = utils.Box;
pub const Icon = utils.Icon;
pub const Term = utils.Term;

const Writer = std.Io.Writer;

// ─── Key codes ──────────────────────────────────────────────────────────────

const Key = enum {
    up,
    down,
    left,
    right,
    enter,
    escape,
    backspace,
    tab,
    char,
    unknown,
};

const KeyEvent = struct {
    key: Key,
    char: u8 = 0,
};

// ─── Screen types ───────────────────────────────────────────────────────────

const Screen = enum {
    item_list,
    item_detail,
    item_form,
    category_list,
    category_form,
    confirm_delete,
    help,
};

const ContainerKind = enum {
    folder,
    collection,
};

const ContainerSelection = struct {
    kind: ContainerKind,
    index: usize,
};

// ─── Input buffer for forms ─────────────────────────────────────────────────

const InputField = struct {
    label: []const u8,
    buf: [256]u8 = [_]u8{0} ** 256,
    len: usize = 0,

    fn slice(self: *const InputField) []const u8 {
        return self.buf[0..self.len];
    }

    fn appendChar(self: *InputField, c: u8) void {
        if (self.len < 255) {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    fn deleteChar(self: *InputField) void {
        if (self.len > 0) {
            self.len -= 1;
            self.buf[self.len] = 0;
        }
    }

    fn clear(self: *InputField) void {
        self.len = 0;
        @memset(&self.buf, 0);
    }

    fn setFromSlice(self: *InputField, data: []const u8) void {
        const copy_len = @min(data.len, 255);
        @memcpy(self.buf[0..copy_len], data[0..copy_len]);
        self.len = copy_len;
    }
};

// ─── TUI State ──────────────────────────────────────────────────────────────

pub const VaultSession = struct {
    vault: model.Vault,
    vault_v2: schema.VaultV2,
    vault_v2_arena: std.heap.ArenaAllocator,
    vault_v2_allocator: std.mem.Allocator,
    key: [crypto.KEY_LEN]u8,
    salt: [crypto.SALT_LEN]u8,
    vault_path: []const u8,
    dirty: bool = false,

    pub fn deinit(self: *VaultSession, allocator: std.mem.Allocator) void {
        model.freeVault(allocator, &self.vault);
        self.vault_v2_arena.deinit();
        crypto.zeroize(&self.key);
    }
};

const TuiState = struct {
    allocator: std.mem.Allocator,
    session: *VaultSession,
    screen: Screen = .item_list,
    prev_screen: Screen = .item_list,
    selected: usize = 0,
    scroll: usize = 0,
    rows: u16 = 24,
    cols: u16 = 80,
    running: bool = true,
    message: ?[]const u8 = null,
    message_is_error: bool = false,

    // Form state
    form_fields: [12]InputField = undefined,
    form_field_count: usize = 0,
    form_active_field: usize = 0,
    form_editing_index: ?usize = null, // null = creating new
    form_is_category: bool = false,
    item_form_type: schema.ItemType = .login,
    form_container_kind: ContainerKind = .folder,
    form_folder_pick_index: ?usize = null,

    // Delete confirm
    delete_target_name: []const u8 = "",
    delete_is_category: bool = false,

    // Wordlist
    wordlist: ?[][]const u8 = null,

    fn init(allocator: std.mem.Allocator, session: *VaultSession) TuiState {
        const size = Term.getSize();
        return .{
            .allocator = allocator,
            .session = session,
            .rows = size.rows,
            .cols = size.cols,
        };
    }

    fn refreshSize(self: *TuiState) void {
        const size = Term.getSize();
        self.rows = size.rows;
        self.cols = size.cols;
    }

    fn setMessage(self: *TuiState, msg: []const u8, is_error: bool) void {
        self.message = msg;
        self.message_is_error = is_error;
    }

    fn clearMessage(self: *TuiState) void {
        self.message = null;
    }

    fn visibleItems(self: *const TuiState) usize {
        return if (self.rows > 8) self.rows - 8 else 4;
    }

    fn itemCount(self: *const TuiState) usize {
        if (self.screen == .category_list) {
            return self.session.vault_v2.folders.len + self.session.vault_v2.collections.len;
        }
        return self.session.vault_v2.items.len;
    }
};

// ─── Raw mode ───────────────────────────────────────────────────────────────

const RawMode = struct {
    original: std.posix.termios,
    fd: std.posix.fd_t,

    fn enable() !RawMode {
        const fd = std.fs.File.stdin().handle;
        var raw = try std.posix.tcgetattr(fd);
        const original = raw;

        // Disable canonical mode & echo
        raw.lflag.ECHO = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;

        // Disable input processing
        raw.iflag.IXON = false;
        raw.iflag.ICRNL = false;
        raw.iflag.BRKINT = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;

        // Set read timeout: min 0 bytes, timeout 1 (100ms)
        raw.cc[@intFromEnum(std.posix.V.MIN)] = 0;
        raw.cc[@intFromEnum(std.posix.V.TIME)] = 1;

        try std.posix.tcsetattr(fd, .FLUSH, raw);
        return .{ .original = original, .fd = fd };
    }

    fn disable(self: *const RawMode) void {
        std.posix.tcsetattr(self.fd, .FLUSH, self.original) catch {};
    }
};

fn readKey(fd: std.posix.fd_t) ?KeyEvent {
    var buf: [8]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return null;
    if (n == 0) return null;

    if (n == 1) {
        return switch (buf[0]) {
            27 => .{ .key = .escape },
            13, 10 => .{ .key = .enter },
            127, 8 => .{ .key = .backspace },
            9 => .{ .key = .tab },
            7 => .{ .key = .char, .char = 7 }, // Ctrl+G
            else => |c| if (c >= 32 and c < 127)
                .{ .key = .char, .char = c }
            else
                .{ .key = .unknown },
        };
    }

    // Escape sequences
    if (n >= 3 and buf[0] == 27 and buf[1] == '[') {
        return switch (buf[2]) {
            'A' => .{ .key = .up },
            'B' => .{ .key = .down },
            'C' => .{ .key = .right },
            'D' => .{ .key = .left },
            else => .{ .key = .unknown },
        };
    }

    return .{ .key = .unknown };
}

// ─── Drawing ────────────────────────────────────────────────────────────────

fn drawHeader(w: *Writer, state: *const TuiState) !void {
    try w.print("{s}{s}", .{ Color.bold, Color.bright_cyan });
    try w.print(" {s} enthropy", .{Icon.shield});
    try w.print("{s}{s}  v0.1.0{s}", .{ Color.reset, Color.dim, Color.reset });

    // Right-aligned vault info
    const vault_short = "vault.enc";
    const padding = if (state.cols > 40) state.cols - 40 else 2;
    var i: usize = 0;
    while (i < padding) : (i += 1) {
        try w.writeAll(" ");
    }
    try w.print("{s}{s}{s}\n", .{ Color.dim, vault_short, Color.reset });

    // Separator
    try w.print("{s}", .{Color.bright_black});
    i = 0;
    while (i < state.cols) : (i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n", .{Color.reset});
}

fn drawItemList(w: *Writer, state: *TuiState) !void {
    const items = state.session.vault_v2.items;

    if (items.len == 0) {
        try w.writeAll("\n");
        try w.print("  {s}{s}No items yet.{s}\n", .{ Color.dim, Color.italic, Color.reset });
        try w.print("  {s}Press {s}n{s}{s} to create your first item.{s}\n\n", .{
            Color.dim, Color.bold, Color.reset, Color.dim, Color.reset,
        });
        return;
    }

    const visible = state.visibleItems();
    const total = items.len;

    // Adjust scroll
    if (state.selected >= state.scroll + visible) {
        state.scroll = state.selected - visible + 1;
    }
    if (state.selected < state.scroll) {
        state.scroll = state.selected;
    }

    try w.writeAll("\n");

    const end = @min(state.scroll + visible, total);
    for (state.scroll..end) |i| {
        const item = items[i];
        const is_selected = (i == state.selected);

        if (is_selected) {
            try w.print("  {s}{s}{s}{s} ", .{ Color.cyan, Color.bold, Icon.arrow_right, Color.reset });
        } else {
            try w.writeAll("    ");
        }

        try w.print("{s}[{s}]{s} ", .{ Color.dim, itemTypeLabel(item.type), Color.reset });

        // Name
        const name = if (item.name.len > 0) item.name else "(unnamed)";
        if (is_selected) {
            try w.print("{s}{s}{s}{s}", .{ Color.bold, Color.bright_white, name, Color.reset });
        } else {
            try w.print("{s}", .{name});
        }

        // Container badge
        if (resolveContainerLabel(state, item)) |label| {
            if (is_selected) {
                try w.print("  {s}[{s}]{s}", .{ Color.dim, label, Color.reset });
            } else {
                try w.print("  {s}[{s}]{s}", .{ Color.yellow, label, Color.reset });
            }
        }

        // Username/email (dimmed)
        if (itemPrimaryIdentifier(item)) |id_text| {
            try w.print("  {s}{s}{s}", .{ Color.dim, id_text, Color.reset });
        }
        try w.writeAll("\n");
    }

    // Scroll indicator
    if (total > visible) {
        try w.print("\n  {s}({d}/{d}){s}\n", .{ Color.dim, state.selected + 1, total, Color.reset });
    }
    try w.writeAll("\n");
}

fn drawItemDetail(w: *Writer, state: *const TuiState) !void {
    const items = state.session.vault_v2.items;
    if (state.selected >= items.len) return;
    const item = items[state.selected];

    try w.writeAll("\n");
    try w.print("  {s}{s}Item Detail{s}\n", .{ Color.bold, Color.bright_white, Color.reset });
    try w.print("  {s}", .{Color.bright_black});
    var i: usize = 0;
    while (i < @min(state.cols -| 4, 50)) : (i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    // Name
    try w.print("  {s}Name:{s}     {s}\n", .{
        Color.cyan, Color.reset, if (item.name.len > 0) item.name else "(none)",
    });

    // Type
    try w.print("  {s}Type:{s}     {s}\n", .{
        Color.cyan, Color.reset, itemTypeLabel(item.type),
    });

    // Username/email
    try w.print("  {s}User:{s}     {s}\n", .{
        Color.cyan, Color.reset, itemPrimaryIdentifier(item) orelse "(none)",
    });

    // Password (masked)
    try w.print("  {s}Password:{s} {s}", .{ Color.cyan, Color.reset, Color.dim });
    const secret = itemPrimarySecret(item);
    for (secret) |_| {
        try w.writeAll(Icon.dot);
    }
    try w.print("{s}\n", .{Color.reset});

    // Notes
    try w.print("  {s}Notes:{s}    {s}\n", .{
        Color.cyan, Color.reset, item.notes orelse "(none)",
    });

    // Container
    try w.print("  {s}Container:{s} {s}\n", .{
        Color.cyan, Color.reset, resolveContainerLabel(state, item) orelse "(none)",
    });

    try w.writeAll("\n");
    try w.print("  {s}p{s}{s} reveal password  {s}y{s}{s} copy password{s}\n", .{
        Color.bold, Color.reset, Color.dim, Color.bold, Color.reset, Color.dim, Color.reset,
    });
}

fn itemTypeLabel(item_type: u8) []const u8 {
    return switch (item_type) {
        1 => "login",
        2 => "secure-note",
        3 => "card",
        4 => "identity",
        else => "unknown",
    };
}

fn itemPrimaryIdentifier(item: schema.Item) ?[]const u8 {
    if (item.login) |login| {
        if (login.username) |username| {
            if (username.len > 0) return username;
        }
    }
    if (item.identity) |identity| {
        if (identity.email) |email| {
            if (email.len > 0) return email;
        }
    }
    return null;
}

fn itemPrimarySecret(item: schema.Item) []const u8 {
    if (item.login) |login| {
        if (login.password) |password| return password;
    }
    if (item.card) |card| {
        if (card.number) |number| return number;
    }
    return "";
}

fn resolveContainerLabel(state: *const TuiState, item: schema.Item) ?[]const u8 {
    if (item.folderId) |folder_id| {
        for (state.session.vault_v2.folders) |folder| {
            if (std.mem.eql(u8, folder.id, folder_id)) return folder.name;
        }
    }
    if (item.collectionIds) |collection_ids| {
        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            for (state.session.vault_v2.collections) |collection| {
                if (std.mem.eql(u8, collection.id, collection_id)) return collection.name;
            }
        }
    }
    return null;
}

fn drawCategoryList(w: *Writer, state: *TuiState) !void {
    const folders = state.session.vault_v2.folders;
    const collections = state.session.vault_v2.collections;
    const total = folders.len + collections.len;

    try w.writeAll("\n");
    try w.print("  {s}{s}Containers{s}\n", .{ Color.bold, Color.bright_white, Color.reset });
    try w.print("  {s}", .{Color.bright_black});
    var sep_i: usize = 0;
    while (sep_i < @min(state.cols -| 4, 50)) : (sep_i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    if (total == 0) {
        try w.print("  {s}No containers yet. Press {s}n{s}{s} for folder or {s}o{s}{s} for collection.{s}\n\n", .{
            Color.dim, Color.bold, Color.reset, Color.dim,
            Color.bold, Color.reset, Color.dim, Color.reset,
        });
        return;
    }

    for (folders, 0..) |folder, i| {
        const is_selected = (i == state.selected);
        if (is_selected) {
            try w.print("  {s}{s}{s}{s} ", .{ Color.cyan, Color.bold, Icon.arrow_right, Color.reset });
        } else {
            try w.writeAll("    ");
        }

        if (is_selected) {
            try w.print("{s}{s}[folder]{s} {s}{s}{s}", .{
                Color.dim, Color.yellow, Color.reset,
                Color.bold, folder.name, Color.reset,
            });
        } else {
            try w.print("{s}[folder]{s} {s}", .{
                Color.dim, Color.reset, folder.name,
            });
        }

        var count: usize = 0;
        for (state.session.vault_v2.items) |item| {
            if (item.folderId) |folder_id| {
                if (std.mem.eql(u8, folder.id, folder_id)) count += 1;
            }
        }
        try w.print("  {s}({d} items){s}\n", .{ Color.dim, count, Color.reset });
    }

    for (collections, 0..) |collection, idx| {
        const row_index = folders.len + idx;
        const is_selected = (row_index == state.selected);
        if (is_selected) {
            try w.print("  {s}{s}{s}{s} ", .{ Color.cyan, Color.bold, Icon.arrow_right, Color.reset });
        } else {
            try w.writeAll("    ");
        }

        if (is_selected) {
            try w.print("{s}{s}[collection]{s} {s}{s}{s}", .{
                Color.dim, Color.yellow, Color.reset,
                Color.bold, collection.name, Color.reset,
            });
        } else {
            try w.print("{s}[collection]{s} {s}", .{
                Color.dim, Color.reset, collection.name,
            });
        }

        var count: usize = 0;
        for (state.session.vault_v2.items) |item| {
            if (item.collectionIds) |collection_ids| {
                var matched = false;
                for (collection_ids) |maybe_id| {
                    const id = maybe_id orelse continue;
                    if (std.mem.eql(u8, collection.id, id)) {
                        matched = true;
                        break;
                    }
                }
                if (matched) count += 1;
            }
        }
        try w.print("  {s}({d} items){s}\n", .{ Color.dim, count, Color.reset });
    }

    try w.writeAll("\n");
}

fn selectedContainer(state: *const TuiState) ?ContainerSelection {
    const folders_len = state.session.vault_v2.folders.len;
    if (state.selected < folders_len) {
        return .{ .kind = .folder, .index = state.selected };
    }
    const collection_index = state.selected - folders_len;
    if (collection_index < state.session.vault_v2.collections.len) {
        return .{ .kind = .collection, .index = collection_index };
    }
    return null;
}

fn containerDisplayName(state: *const TuiState, sel: ContainerSelection) []const u8 {
    return switch (sel.kind) {
        .folder => state.session.vault_v2.folders[sel.index].name,
        .collection => state.session.vault_v2.collections[sel.index].name,
    };
}

fn initContainerForm(state: *TuiState, kind: ContainerKind) void {
    state.form_is_category = true;
    state.form_container_kind = kind;
    state.form_active_field = 0;

    switch (kind) {
        .folder => {
            state.form_field_count = 1;
            state.form_fields[0] = .{ .label = "Name:" };
        },
        .collection => {
            state.form_field_count = 2;
            state.form_fields[0] = .{ .label = "Name:" };
            state.form_fields[1] = .{ .label = "Org ID:" };
        },
    }
}

fn deleteCollectionLinksById(
    allocator: std.mem.Allocator,
    item: *schema.Item,
    collection_id: []const u8,
) !void {
    const old = item.collectionIds orelse return;
    var kept = std.ArrayList(?[]const u8){};
    defer kept.deinit(allocator);

    for (old) |maybe_id| {
        const id = maybe_id orelse continue;
        if (std.mem.eql(u8, id, collection_id)) {
            allocator.free(id);
        } else {
            try kept.append(allocator, maybe_id);
        }
    }
    allocator.free(old);
    if (kept.items.len == 0) {
        item.collectionIds = null;
    } else {
        item.collectionIds = try kept.toOwnedSlice(allocator);
    }
}

fn removeContainerAtSelection(state: *TuiState, sel: ContainerSelection) !void {
    const allocator = state.session.vault_v2_allocator;
    switch (sel.kind) {
        .folder => {
            const old = state.session.vault_v2.folders;
            const removed = old[sel.index];
            var folders = std.ArrayList(schema.Folder){};
            defer folders.deinit(allocator);
            for (old, 0..) |folder, i| {
                if (i != sel.index) try folders.append(allocator, folder);
            }
            state.session.vault_v2.folders = try folders.toOwnedSlice(allocator);
            allocator.free(old);
            for (state.session.vault_v2.items) |*item| {
                if (item.folderId) |folder_id| {
                    if (std.mem.eql(u8, folder_id, removed.id)) {
                        allocator.free(folder_id);
                        item.folderId = null;
                    }
                }
            }
            allocator.free(removed.id);
            allocator.free(removed.name);
        },
        .collection => {
            const old = state.session.vault_v2.collections;
            const removed = old[sel.index];
            var collections = std.ArrayList(schema.Collection){};
            defer collections.deinit(allocator);
            for (old, 0..) |collection, i| {
                if (i != sel.index) try collections.append(allocator, collection);
            }
            state.session.vault_v2.collections = try collections.toOwnedSlice(allocator);
            allocator.free(old);
            for (state.session.vault_v2.items) |*item| {
                try deleteCollectionLinksById(allocator, item, removed.id);
            }
            allocator.free(removed.id);
            if (removed.organizationId) |org_id| allocator.free(org_id);
            allocator.free(removed.name);
            if (removed.externalId) |external_id| allocator.free(external_id);
        },
    }
}

fn drawForm(w: *Writer, state: *const TuiState) !void {
    const title = if (state.form_editing_index != null)
        (if (state.form_is_category)
            (if (state.form_container_kind == .folder) "Edit Folder" else "Edit Collection")
        else
            "Edit Item")
    else
        (if (state.form_is_category)
            (if (state.form_container_kind == .folder) "New Folder" else "New Collection")
        else
            "New Item");
    const item_type_hint: []const u8 = if (state.form_is_category) "" else itemTypeLabel(@intFromEnum(state.item_form_type));

    try w.writeAll("\n");
    if (state.form_is_category) {
        try w.print("  {s}{s}{s}{s}\n", .{ Color.bold, Color.bright_white, title, Color.reset });
    } else {
        try w.print("  {s}{s}{s}{s} {s}[{s}]{s}\n", .{
            Color.bold, Color.bright_white, title, Color.reset,
            Color.dim, item_type_hint, Color.reset,
        });
    }
    try w.print("  {s}", .{Color.bright_black});
    var sep_i: usize = 0;
    while (sep_i < @min(state.cols -| 4, 50)) : (sep_i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    for (0..state.form_field_count) |i| {
        const field = &state.form_fields[i];
        const is_active = (i == state.form_active_field);

        if (is_active) {
            try w.print("  {s}{s}{s:<10}{s} ", .{ Color.bold, Color.cyan, field.label, Color.reset });
            try w.print("{s}{s}", .{ Color.underline, field.slice() });
            try w.print("{s}{s}_{s}\n", .{ Color.reset, Color.bright_black, Color.reset });
        } else {
            try w.print("  {s}{s:<10}{s} {s}\n", .{ Color.dim, field.label, Color.reset, field.slice() });
        }
    }

    if (folderFieldIsActive(state)) {
        const folders = state.session.vault_v2.folders;
        if (folders.len > 0) {
            const folder_field_idx = folderFieldIndexForType(state.item_form_type);
            const current_name = state.form_fields[folder_field_idx].slice();
            try w.writeAll("\n");
            try w.print("  {s}Available folders (Up/Down to select):{s}\n", .{
                Color.dim, Color.reset,
            });
            for (folders, 0..) |folder, idx| {
                const is_marked = if (state.form_folder_pick_index) |picked|
                    picked == idx
                else
                    std.mem.eql(u8, current_name, folder.name);
                if (is_marked) {
                    try w.print("    {s}> {s}{s}{s}\n", .{
                        Color.cyan, Color.bold, folder.name, Color.reset,
                    });
                } else {
                    try w.print("      {s}\n", .{folder.name});
                }
            }
        }
    }

    try w.writeAll("\n");
    if (!state.form_is_category) {
        if (state.item_form_type == .login) {
            try w.print("  {s}Tab{s}{s} next field  {s}Up/Down{s}{s} folder  {s}Ctrl+G{s}{s} generate password  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.reset,
            });
        } else {
            try w.print("  {s}Tab{s}{s} next field  {s}Up/Down{s}{s} folder  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.reset,
            });
        }
    } else {
        try w.print("  {s}Tab{s}{s} next field  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
            Color.reset,
        });
    }
}

fn drawConfirmDelete(w: *Writer, state: *const TuiState) !void {
    try w.writeAll("\n\n");
    try w.print("  {s}{s}Are you sure you want to delete:{s}\n\n", .{
        Color.bold, Color.red, Color.reset,
    });
    try w.print("    {s}{s}{s}\n\n", .{ Color.bright_white, state.delete_target_name, Color.reset });
    try w.print("  {s}y{s}{s} yes  {s}n{s}{s}/Esc cancel{s}\n", .{
        Color.bold,  Color.reset, Color.dim,
        Color.bold,  Color.reset, Color.dim,
        Color.reset,
    });
}

fn drawHelp(w: *Writer, state: *const TuiState) !void {
    _ = state;

    try w.writeAll("\n");
    try w.print("  {s}{s}Help{s}\n", .{ Color.bold, Color.bright_white, Color.reset });
    try w.print("  {s}", .{Color.bright_black});
    var sep_i: usize = 0;
    while (sep_i < 50) : (sep_i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    try w.print("  {s}Item list{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    Up/Down navigate, Enter detail, n/1 login, 2 note, 3 card, 4 identity, e edit, d delete, c categories, q quit\n");

    try w.print("\n  {s}Item detail{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    p reveal password in message area, y copy password to clipboard\n");

    try w.print("\n  {s}Item/category forms{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    Tab next field, Enter save, Esc cancel\n");
    try w.writeAll("    In Folder field: Up/Down lists and selects existing folders\n");
    try w.writeAll("    Ctrl+G generate password (login form)\n");
    try w.writeAll("    In containers: n folder, o collection\n");

    try w.print("\n  {s}Global{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    ? open help, Esc or q close help\n\n");
}

fn drawMessage(w: *Writer, state: *const TuiState) !void {
    if (state.message) |msg| {
        if (state.message_is_error) {
            try w.print(" {s}{s} {s}{s}\n", .{ Color.red, Icon.cross_mark, msg, Color.reset });
        } else {
            try w.print(" {s}{s} {s}{s}\n", .{ Color.green, Icon.check, msg, Color.reset });
        }
    }
}

fn drawFooter(w: *Writer, state: *const TuiState) !void {
    try w.print("{s}", .{Color.bright_black});
    var i: usize = 0;
    while (i < state.cols) : (i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n", .{Color.reset});

    try w.writeAll(" ");
    switch (state.screen) {
        .item_list => {
            try drawKeyHint(w, "n", "new");
            try drawKeyHint(w, "1..4", "new type");
            try drawKeyHint(w, "e", "edit");
            try drawKeyHint(w, "d", "delete");
            try drawKeyHint(w, "Enter", "detail");
            try drawKeyHint(w, "c", "categories");
            try drawKeyHint(w, "?", "help");
            try drawKeyHint(w, "q", "quit");
        },
        .item_detail => {
            try drawKeyHint(w, "e", "edit");
            try drawKeyHint(w, "d", "delete");
            try drawKeyHint(w, "p", "reveal");
            try drawKeyHint(w, "?", "help");
            try drawKeyHint(w, "Esc", "back");
        },
        .category_list => {
            try drawKeyHint(w, "n", "new folder");
            try drawKeyHint(w, "o", "new collection");
            try drawKeyHint(w, "e", "edit");
            try drawKeyHint(w, "d", "delete");
            try drawKeyHint(w, "?", "help");
            try drawKeyHint(w, "Esc", "back");
        },
        else => {},
    }
    try w.writeAll("\n");
}

fn drawKeyHint(w: *Writer, key: []const u8, desc: []const u8) !void {
    try w.print(" {s}{s}{s}{s} {s}{s} ", .{
        Color.bg_bright_black, Color.bright_white, key, Color.reset,
        Color.dim,             desc,
    });
}

// ─── Screen rendering ───────────────────────────────────────────────────────

fn render(w: *Writer, state: *TuiState) !void {
    // Clear screen and go home
    try w.writeAll(Term.clear_screen);
    try w.writeAll(Term.cursor_home);

    try drawHeader(w, state);

    switch (state.screen) {
        .item_list => try drawItemList(w, state),
        .item_detail => try drawItemDetail(w, state),
        .item_form, .category_form => try drawForm(w, state),
        .category_list => try drawCategoryList(w, state),
        .confirm_delete => try drawConfirmDelete(w, state),
        .help => try drawHelp(w, state),
    }

    try drawMessage(w, state);
    try drawFooter(w, state);
    try w.flush();
}

// ─── Item CRUD ──────────────────────────────────────────────────────────────

fn initItemFormForType(state: *TuiState, item_type: schema.ItemType) void {
    state.form_is_category = false;
    state.form_active_field = 0;
    state.item_form_type = item_type;
    state.form_folder_pick_index = null;

    switch (item_type) {
        .login => {
            state.form_field_count = 9;
            state.form_fields[0] = .{ .label = "Name:" };
            state.form_fields[1] = .{ .label = "User:" };
            state.form_fields[2] = .{ .label = "Password:" };
            state.form_fields[3] = .{ .label = "TOTP:" };
            state.form_fields[4] = .{ .label = "URL:" };
            state.form_fields[5] = .{ .label = "Notes:" };
            state.form_fields[6] = .{ .label = "Folder:" };
            state.form_fields[7] = .{ .label = "Collections:" };
            state.form_fields[8] = .{ .label = "Org ID:" };
        },
        .secure_note => {
            state.form_field_count = 6;
            state.form_fields[0] = .{ .label = "Name:" };
            state.form_fields[1] = .{ .label = "NoteType:" };
            state.form_fields[2] = .{ .label = "Notes:" };
            state.form_fields[3] = .{ .label = "Folder:" };
            state.form_fields[4] = .{ .label = "Collections:" };
            state.form_fields[5] = .{ .label = "Org ID:" };
        },
        .card => {
            state.form_field_count = 11;
            state.form_fields[0] = .{ .label = "Name:" };
            state.form_fields[1] = .{ .label = "Number:" };
            state.form_fields[2] = .{ .label = "Brand:" };
            state.form_fields[3] = .{ .label = "Code:" };
            state.form_fields[4] = .{ .label = "Holder:" };
            state.form_fields[5] = .{ .label = "ExpMonth:" };
            state.form_fields[6] = .{ .label = "ExpYear:" };
            state.form_fields[7] = .{ .label = "Notes:" };
            state.form_fields[8] = .{ .label = "Folder:" };
            state.form_fields[9] = .{ .label = "Collections:" };
            state.form_fields[10] = .{ .label = "Org ID:" };
        },
        .identity => {
            state.form_field_count = 9;
            state.form_fields[0] = .{ .label = "Name:" };
            state.form_fields[1] = .{ .label = "FirstName:" };
            state.form_fields[2] = .{ .label = "LastName:" };
            state.form_fields[3] = .{ .label = "Email:" };
            state.form_fields[4] = .{ .label = "Phone:" };
            state.form_fields[5] = .{ .label = "Notes:" };
            state.form_fields[6] = .{ .label = "Folder:" };
            state.form_fields[7] = .{ .label = "Collections:" };
            state.form_fields[8] = .{ .label = "Org ID:" };
        },
    }
    syncFolderPickerFromCurrentField(state);
}

fn folderFieldIndexForType(item_type: schema.ItemType) usize {
    return switch (item_type) {
        .login => 6,
        .secure_note => 3,
        .card => 8,
        .identity => 6,
    };
}

fn folderFieldIsActive(state: *const TuiState) bool {
    if (state.form_is_category) return false;
    return state.form_active_field == folderFieldIndexForType(state.item_form_type);
}

fn syncFolderPickerFromCurrentField(state: *TuiState) void {
    const field_index = folderFieldIndexForType(state.item_form_type);
    const current_name = state.form_fields[field_index].slice();
    state.form_folder_pick_index = null;
    for (state.session.vault_v2.folders, 0..) |folder, idx| {
        if (std.mem.eql(u8, folder.name, current_name)) {
            state.form_folder_pick_index = idx;
            break;
        }
    }
}

fn moveFolderPicker(state: *TuiState, direction: i8) void {
    const folders = state.session.vault_v2.folders;
    if (folders.len == 0) {
        state.setMessage("No folders available", true);
        return;
    }

    if (state.form_folder_pick_index == null) {
        syncFolderPickerFromCurrentField(state);
    }

    var idx: usize = undefined;
    if (state.form_folder_pick_index) |current| {
        idx = if (direction >= 0)
            (current + 1) % folders.len
        else if (current == 0)
            folders.len - 1
        else
            current - 1;
    } else {
        idx = if (direction >= 0) 0 else folders.len - 1;
    }
    state.form_folder_pick_index = idx;

    const field_index = folderFieldIndexForType(state.item_form_type);
    state.form_fields[field_index].clear();
    state.form_fields[field_index].setFromSlice(folders[idx].name);
}

fn saveItemForm(state: *TuiState) !void {
    var generated_pw: ?[]const u8 = null;
    defer if (generated_pw) |pw| state.allocator.free(pw);

    var collection_ids: []const []const u8 = &.{};
    defer if (collection_ids.len > 0) state.allocator.free(collection_ids);

    var input = vault_service_v2.CreateItemInput{
        .type = state.item_form_type,
        .name = "",
    };

    switch (state.item_form_type) {
        .login => {
            const name = state.form_fields[0].slice();
            const user = state.form_fields[1].slice();
            const password_field = state.form_fields[2].slice();
            const totp = state.form_fields[3].slice();
            const url = state.form_fields[4].slice();
            const notes = state.form_fields[5].slice();
            const folder_name = state.form_fields[6].slice();
            const collections_raw = state.form_fields[7].slice();
            const org_id = state.form_fields[8].slice();

            if (name.len == 0 and user.len == 0) {
                state.setMessage("Name or user is required", true);
                return;
            }

            const resolved_folder_id = resolveFolderIdByName(state, folder_name) catch {
                state.setMessage("Folder not found", true);
                return;
            };
            collection_ids = parseCollectionIdsByName(state, collections_raw) catch {
                state.setMessage("Collection not found", true);
                return;
            };

            var login_password: ?[]const u8 = if (password_field.len > 0) password_field else null;
            if (state.form_editing_index == null and login_password == null) {
                const wl = state.wordlist orelse {
                    state.setMessage("No wordlist loaded for generation", true);
                    return;
                };
                const pw = try bip39.generateMnemonic(state.allocator, wl, "-");
                generated_pw = pw;
                login_password = pw;
            }

            input = .{
                .type = .login,
                .name = if (name.len > 0) name else user,
                .notes = notes,
                .organization_id = if (org_id.len > 0) org_id else null,
                .folder_id = resolved_folder_id,
                .collection_ids = collection_ids,
                .login_username = if (user.len > 0) user else null,
                .login_password = login_password,
                .login_totp = if (totp.len > 0) totp else null,
                .login_uri = if (url.len > 0) url else null,
            };
        },
        .secure_note => {
            const name = state.form_fields[0].slice();
            const note_type_raw = state.form_fields[1].slice();
            const notes = state.form_fields[2].slice();
            const folder_name = state.form_fields[3].slice();
            const collections_raw = state.form_fields[4].slice();
            const org_id = state.form_fields[5].slice();

            if (name.len == 0) {
                state.setMessage("Name is required", true);
                return;
            }
            const resolved_folder_id = resolveFolderIdByName(state, folder_name) catch {
                state.setMessage("Folder not found", true);
                return;
            };
            collection_ids = parseCollectionIdsByName(state, collections_raw) catch {
                state.setMessage("Collection not found", true);
                return;
            };

            input = .{
                .type = .secure_note,
                .name = name,
                .notes = notes,
                .organization_id = if (org_id.len > 0) org_id else null,
                .folder_id = resolved_folder_id,
                .collection_ids = collection_ids,
                .secure_note_type = std.fmt.parseInt(u8, note_type_raw, 10) catch 0,
            };
        },
        .card => {
            const name = state.form_fields[0].slice();
            const number = state.form_fields[1].slice();
            const brand = state.form_fields[2].slice();
            const code = state.form_fields[3].slice();
            const holder = state.form_fields[4].slice();
            const exp_month = state.form_fields[5].slice();
            const exp_year = state.form_fields[6].slice();
            const notes = state.form_fields[7].slice();
            const folder_name = state.form_fields[8].slice();
            const collections_raw = state.form_fields[9].slice();
            const org_id = state.form_fields[10].slice();

            if (name.len == 0) {
                state.setMessage("Name is required", true);
                return;
            }
            const resolved_folder_id = resolveFolderIdByName(state, folder_name) catch {
                state.setMessage("Folder not found", true);
                return;
            };
            collection_ids = parseCollectionIdsByName(state, collections_raw) catch {
                state.setMessage("Collection not found", true);
                return;
            };

            input = .{
                .type = .card,
                .name = name,
                .notes = notes,
                .organization_id = if (org_id.len > 0) org_id else null,
                .folder_id = resolved_folder_id,
                .collection_ids = collection_ids,
                .card_number = if (number.len > 0) number else null,
                .card_brand = if (brand.len > 0) brand else null,
                .card_code = if (code.len > 0) code else null,
                .card_holder = if (holder.len > 0) holder else null,
                .card_exp_month = if (exp_month.len > 0) exp_month else null,
                .card_exp_year = if (exp_year.len > 0) exp_year else null,
            };
        },
        .identity => {
            const name = state.form_fields[0].slice();
            const first_name = state.form_fields[1].slice();
            const last_name = state.form_fields[2].slice();
            const email = state.form_fields[3].slice();
            const phone = state.form_fields[4].slice();
            const notes = state.form_fields[5].slice();
            const folder_name = state.form_fields[6].slice();
            const collections_raw = state.form_fields[7].slice();
            const org_id = state.form_fields[8].slice();

            if (name.len == 0) {
                state.setMessage("Name is required", true);
                return;
            }
            const resolved_folder_id = resolveFolderIdByName(state, folder_name) catch {
                state.setMessage("Folder not found", true);
                return;
            };
            collection_ids = parseCollectionIdsByName(state, collections_raw) catch {
                state.setMessage("Collection not found", true);
                return;
            };

            input = .{
                .type = .identity,
                .name = name,
                .notes = notes,
                .organization_id = if (org_id.len > 0) org_id else null,
                .folder_id = resolved_folder_id,
                .collection_ids = collection_ids,
                .identity_first_name = if (first_name.len > 0) first_name else null,
                .identity_last_name = if (last_name.len > 0) last_name else null,
                .identity_email = if (email.len > 0) email else null,
                .identity_phone = if (phone.len > 0) phone else null,
            };
        },
    }

    if (state.form_editing_index) |idx| {
        if (idx >= state.session.vault_v2.items.len) {
            state.setMessage("Invalid item selection", true);
            return;
        }
        updateV2ItemFromForm(state, idx, input) catch {
            state.setMessage("Failed to update item", true);
            return;
        };
        state.setMessage("Item updated", false);
    } else {
        _ = vault_service_v2.createItem(
            state.session.vault_v2_allocator,
            &state.session.vault_v2,
            input,
        ) catch {
            state.setMessage("Failed to create item", true);
            return;
        };
        state.setMessage("Item created", false);
    }

    try rebuildRuntimeFromV2(state);
    state.session.dirty = true;
    try persistVault(state);
    state.screen = .item_list;
}

fn saveCategoryForm(state: *TuiState) !void {
    const name = state.form_fields[0].slice();
    if (name.len == 0) {
        state.setMessage("Name is required", true);
        return;
    }

    const allocator = state.session.vault_v2_allocator;
    if (state.form_editing_index != null) {
        const sel = selectedContainer(state) orelse {
            state.setMessage("Invalid category selection", true);
            return;
        };
        switch (sel.kind) {
            .folder => {
                const folder = &state.session.vault_v2.folders[sel.index];
                const new_name = try allocator.dupe(u8, name);
                allocator.free(folder.name);
                folder.name = new_name;
                state.setMessage("Folder updated", false);
            },
            .collection => {
                const collection = &state.session.vault_v2.collections[sel.index];
                const org_id = state.form_fields[1].slice();

                const new_name = try allocator.dupe(u8, name);
                allocator.free(collection.name);
                collection.name = new_name;

                if (collection.organizationId) |old_org| allocator.free(old_org);
                collection.organizationId = if (org_id.len > 0) try allocator.dupe(u8, org_id) else null;
                state.setMessage("Collection updated", false);
            },
        }
    } else {
        switch (state.form_container_kind) {
            .folder => {
                _ = vault_service_v2.createFolder(
                    allocator,
                    &state.session.vault_v2,
                    name,
                ) catch {
                    state.setMessage("Failed to create folder", true);
                    return;
                };
                state.setMessage("Folder created", false);
            },
            .collection => {
                const org_id = state.form_fields[1].slice();
                if (org_id.len == 0) {
                    state.setMessage("Org ID is required", true);
                    return;
                }
                _ = vault_service_v2.createCollection(
                    allocator,
                    &state.session.vault_v2,
                    org_id,
                    name,
                ) catch {
                    state.setMessage("Failed to create collection", true);
                    return;
                };
                state.setMessage("Collection created", false);
            },
        }
    }

    try rebuildRuntimeFromV2(state);
    state.session.dirty = true;
    try persistVault(state);
    state.screen = .category_list;
    const container_total = state.session.vault_v2.folders.len + state.session.vault_v2.collections.len;
    if (state.selected >= container_total and state.selected > 0) state.selected -= 1;
}

fn resolveFolderIdByName(state: *const TuiState, folder_name: []const u8) !?[]const u8 {
    if (folder_name.len == 0) return null;
    for (state.session.vault_v2.folders) |folder| {
        if (std.mem.eql(u8, folder.name, folder_name)) {
            return folder.id;
        }
    }
    return error.FolderNotFound;
}

fn parseCollectionIdsByName(state: *const TuiState, raw: []const u8) ![]const []const u8 {
    if (raw.len == 0) return &.{};

    var ids = std.ArrayList([]const u8){};
    errdefer ids.deinit(state.allocator);

    var tok = std.mem.tokenizeScalar(u8, raw, ',');
    while (tok.next()) |entry| {
        const name = std.mem.trim(u8, entry, " \t");
        if (name.len == 0) continue;

        var found: ?[]const u8 = null;
        for (state.session.vault_v2.collections) |collection| {
            if (std.mem.eql(u8, collection.name, name)) {
                found = collection.id;
                break;
            }
        }
        if (found == null) return error.CollectionNotFound;
        try ids.append(state.allocator, found.?);
    }

    return ids.toOwnedSlice(state.allocator);
}

fn updateV2ItemFromForm(
    state: *TuiState,
    item_index: usize,
    input: vault_service_v2.CreateItemInput,
) !void {
    const allocator = state.session.vault_v2_allocator;
    var item = &state.session.vault_v2.items[item_index];

    const new_name = try allocator.dupe(u8, input.name);
    allocator.free(item.name);
    item.name = new_name;

    if (item.organizationId) |v| allocator.free(v);
    item.organizationId = if (input.organization_id) |v| try allocator.dupe(u8, v) else null;

    if (item.notes) |v| allocator.free(v);
    item.notes = if (input.notes.len > 0) try allocator.dupe(u8, input.notes) else null;

    if (item.folderId) |v| allocator.free(v);
    item.folderId = if (input.folder_id) |v| try allocator.dupe(u8, v) else null;

    if (item.collectionIds) |ids| {
        for (ids) |maybe_id| {
            if (maybe_id) |id| allocator.free(id);
        }
        allocator.free(ids);
    }
    if (input.collection_ids.len > 0) {
        var ids = try allocator.alloc(?[]const u8, input.collection_ids.len);
        var i: usize = 0;
        errdefer {
            for (0..i) |j| allocator.free(ids[j].?);
            allocator.free(ids);
        }
        for (input.collection_ids, 0..) |collection_id, idx| {
            ids[idx] = try allocator.dupe(u8, collection_id);
            i += 1;
        }
        item.collectionIds = ids;
    } else {
        item.collectionIds = null;
    }

    item.type = @intFromEnum(input.type);
    switch (input.type) {
        .login => {
            if (item.login == null) item.login = .{};

            if (input.login_username) |username| {
                if (item.login.?.username) |v| allocator.free(v);
                item.login.?.username = try allocator.dupe(u8, username);
            }
            if (input.login_password) |password| {
                if (item.login.?.password) |v| allocator.free(v);
                item.login.?.password = try allocator.dupe(u8, password);
            }
            if (input.login_totp) |totp| {
                if (item.login.?.totp) |v| allocator.free(v);
                item.login.?.totp = try allocator.dupe(u8, totp);
            }
            if (input.login_uri) |uri| {
                if (item.login.?.uris) |uris| {
                    for (uris) |old_uri| {
                        if (old_uri.uri) |v| allocator.free(v);
                    }
                    allocator.free(uris);
                }
                if (uri.len > 0) {
                    var uris = try allocator.alloc(schema.LoginUri, 1);
                    uris[0] = .{
                        .uri = try allocator.dupe(u8, uri),
                        .match = null,
                    };
                    item.login.?.uris = uris;
                } else {
                    item.login.?.uris = null;
                }
            }
        },
        .secure_note => {
            if (item.secureNote == null) item.secureNote = .{};
            item.secureNote.?.type = input.secure_note_type;
        },
        .card => {
            if (item.card == null) item.card = .{};
            if (input.card_number) |number| {
                if (item.card.?.number) |v| allocator.free(v);
                item.card.?.number = try allocator.dupe(u8, number);
            }
            if (input.card_brand) |brand| {
                if (item.card.?.brand) |v| allocator.free(v);
                item.card.?.brand = try allocator.dupe(u8, brand);
            }
            if (input.card_code) |code| {
                if (item.card.?.code) |v| allocator.free(v);
                item.card.?.code = try allocator.dupe(u8, code);
            }
            if (input.card_holder) |holder| {
                if (item.card.?.cardholderName) |v| allocator.free(v);
                item.card.?.cardholderName = try allocator.dupe(u8, holder);
            }
            if (input.card_exp_month) |exp_month| {
                if (item.card.?.expMonth) |v| allocator.free(v);
                item.card.?.expMonth = try allocator.dupe(u8, exp_month);
            }
            if (input.card_exp_year) |exp_year| {
                if (item.card.?.expYear) |v| allocator.free(v);
                item.card.?.expYear = try allocator.dupe(u8, exp_year);
            }
        },
        .identity => {
            if (item.identity == null) item.identity = .{};
            if (input.identity_email) |email| {
                if (item.identity.?.email) |v| allocator.free(v);
                item.identity.?.email = try allocator.dupe(u8, email);
            }
            if (input.identity_first_name) |first_name| {
                if (item.identity.?.firstName) |v| allocator.free(v);
                item.identity.?.firstName = try allocator.dupe(u8, first_name);
            }
            if (input.identity_last_name) |last_name| {
                if (item.identity.?.lastName) |v| allocator.free(v);
                item.identity.?.lastName = try allocator.dupe(u8, last_name);
            }
            if (input.identity_phone) |phone| {
                if (item.identity.?.phone) |v| allocator.free(v);
                item.identity.?.phone = try allocator.dupe(u8, phone);
            }
        },
    }

    var now_buf: [20]u8 = undefined;
    if (item.revisionDate) |v| allocator.free(v);
    item.revisionDate = try allocator.dupe(u8, model.nowTimestamp(&now_buf));
}

fn rebuildRuntimeFromV2(state: *TuiState) !void {
    model.freeVault(state.allocator, &state.session.vault);
    state.session.vault = try storage.projectVaultV2ToRuntime(
        state.allocator,
        state.session.vault_v2,
    );
}

fn prefillItemFormFromV2(state: *TuiState, item: schema.Item) void {
    const item_type: schema.ItemType = switch (item.type) {
        2 => .secure_note,
        3 => .card,
        4 => .identity,
        else => .login,
    };
    initItemFormForType(state, item_type);

    state.form_fields[0].setFromSlice(item.name);
    switch (item_type) {
        .login => {
            if (item.login) |login| {
                if (login.username) |username| state.form_fields[1].setFromSlice(username);
                if (login.password) |password| state.form_fields[2].setFromSlice(password);
                if (login.totp) |totp| state.form_fields[3].setFromSlice(totp);
                if (login.uris) |uris| {
                    if (uris.len > 0 and uris[0].uri != null) {
                        state.form_fields[4].setFromSlice(uris[0].uri.?);
                    }
                }
            }
            if (item.notes) |notes| state.form_fields[5].setFromSlice(notes);
            if (item.organizationId) |org_id| state.form_fields[8].setFromSlice(org_id);
            fillContainerFields(state, item, 6, 7);
        },
        .secure_note => {
            if (item.secureNote) |secure_note| {
                if (secure_note.type) |note_type| {
                    var buf: [4]u8 = undefined;
                    const out = std.fmt.bufPrint(&buf, "{d}", .{note_type}) catch "";
                    state.form_fields[1].setFromSlice(out);
                }
            }
            if (item.notes) |notes| state.form_fields[2].setFromSlice(notes);
            fillContainerFields(state, item, 3, 4);
            if (item.organizationId) |org_id| state.form_fields[5].setFromSlice(org_id);
        },
        .card => {
            if (item.card) |card| {
                if (card.number) |number| state.form_fields[1].setFromSlice(number);
                if (card.brand) |brand| state.form_fields[2].setFromSlice(brand);
                if (card.code) |code| state.form_fields[3].setFromSlice(code);
                if (card.cardholderName) |holder| state.form_fields[4].setFromSlice(holder);
                if (card.expMonth) |exp_month| state.form_fields[5].setFromSlice(exp_month);
                if (card.expYear) |exp_year| state.form_fields[6].setFromSlice(exp_year);
            }
            if (item.notes) |notes| state.form_fields[7].setFromSlice(notes);
            fillContainerFields(state, item, 8, 9);
            if (item.organizationId) |org_id| state.form_fields[10].setFromSlice(org_id);
        },
        .identity => {
            if (item.identity) |identity| {
                if (identity.firstName) |first_name| state.form_fields[1].setFromSlice(first_name);
                if (identity.lastName) |last_name| state.form_fields[2].setFromSlice(last_name);
                if (identity.email) |email| state.form_fields[3].setFromSlice(email);
                if (identity.phone) |phone| state.form_fields[4].setFromSlice(phone);
            }
            if (item.notes) |notes| state.form_fields[5].setFromSlice(notes);
            fillContainerFields(state, item, 6, 7);
            if (item.organizationId) |org_id| state.form_fields[8].setFromSlice(org_id);
        },
    }
}

fn fillContainerFields(
    state: *TuiState,
    item: schema.Item,
    folder_field_index: usize,
    collection_field_index: usize,
) void {
    if (item.folderId) |folder_id| {
        for (state.session.vault_v2.folders) |folder| {
            if (std.mem.eql(u8, folder.id, folder_id)) {
                state.form_fields[folder_field_index].setFromSlice(folder.name);
                break;
            }
        }
    }

    if (item.collectionIds) |collection_ids| {
        var builder = std.ArrayList(u8){};
        defer builder.deinit(state.allocator);

        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            for (state.session.vault_v2.collections) |collection| {
                if (std.mem.eql(u8, collection.id, collection_id)) {
                    if (builder.items.len > 0) {
                        builder.appendSlice(state.allocator, ", ") catch return;
                    }
                    builder.appendSlice(state.allocator, collection.name) catch return;
                    break;
                }
            }
        }
        if (builder.items.len > 0) {
            state.form_fields[collection_field_index].setFromSlice(builder.items);
        }
    }
}

fn deleteSelectedItem(state: *TuiState) !void {
    if (state.selected >= state.session.vault_v2.items.len) {
        state.setMessage("Invalid item selection", true);
        return;
    }
    const item_id = state.session.vault_v2.items[state.selected].id;
    vault_service_v2.deleteItem(
        state.session.vault_v2_allocator,
        &state.session.vault_v2,
        item_id,
    ) catch {
        state.setMessage("Failed to delete item", true);
        return;
    };

    if (state.selected > 0) state.selected -= 1;
    try rebuildRuntimeFromV2(state);
    state.session.dirty = true;
    try persistVault(state);
    state.setMessage("Item deleted", false);
    state.screen = .item_list;
}

fn deleteSelectedCategory(state: *TuiState) !void {
    const sel = selectedContainer(state) orelse {
        state.setMessage("Invalid category selection", true);
        return;
    };
    try removeContainerAtSelection(state, sel);

    if (state.selected > 0) state.selected -= 1;
    try rebuildRuntimeFromV2(state);
    state.session.dirty = true;
    try persistVault(state);
    state.setMessage("Container deleted", false);
    state.screen = .category_list;
}

fn validateV2Relations(state: *TuiState) bool {
    var normalized = relations_v2.build(state.allocator, &state.session.vault_v2) catch |err| {
        const msg = switch (err) {
            error.UnknownFolderId => "Invalid relation: item references unknown folder",
            error.UnknownCollectionId => "Invalid relation: item references unknown collection",
            error.OrganizationMismatch => "Invalid relation: organization mismatch on collection link",
            error.DuplicateItemId => "Invalid relation: duplicate item id",
            error.DuplicateFolderId => "Invalid relation: duplicate folder id",
            error.DuplicateCollectionId => "Invalid relation: duplicate collection id",
            else => "Failed to validate vault relations",
        };
        state.setMessage(msg, true);
        return false;
    };
    normalized.deinit(state.allocator);
    return true;
}

fn persistVault(state: *TuiState) !void {
    if (!validateV2Relations(state)) return;

    storage.saveVault(
        state.allocator,
        state.session.vault,
        &state.session.key,
        &state.session.salt,
        state.session.vault_path,
    ) catch {
        state.setMessage("Failed to save vault!", true);
        return;
    };
    refreshSessionV2FromDisk(state) catch {
        state.setMessage("Saved, but failed to refresh v2 session", true);
        return;
    };
    state.session.dirty = false;
}

fn refreshSessionV2FromDisk(state: *TuiState) !void {
    const loaded = try storage.loadVaultV2WithKey(
        state.allocator,
        &state.session.key,
        state.session.vault_path,
    );

    state.session.vault_v2_arena.deinit();
    state.session.vault_v2 = loaded.vault;
    state.session.vault_v2_arena = loaded.arena;
    state.session.vault_v2_allocator = state.session.vault_v2_arena.allocator();
    state.session.salt = loaded.salt;
}

// ─── Input handling ─────────────────────────────────────────────────────────

fn handleInput(state: *TuiState, ev: KeyEvent) !void {
    state.clearMessage();

    switch (state.screen) {
        .item_list => try handleItemList(state, ev),
        .item_detail => try handleItemDetail(state, ev),
        .item_form => try handleForm(state, ev, false),
        .category_form => try handleForm(state, ev, true),
        .category_list => try handleCategoryList(state, ev),
        .confirm_delete => try handleConfirmDelete(state, ev),
        .help => {
            if (ev.key == .escape or (ev.key == .char and ev.char == 'q')) {
                state.screen = state.prev_screen;
            }
        },
    }
}

fn handleItemList(state: *TuiState, ev: KeyEvent) !void {
    const count = state.session.vault_v2.items.len;
    switch (ev.key) {
        .up => {
            if (state.selected > 0) state.selected -= 1;
        },
        .down => {
            if (count > 0 and state.selected < count - 1) state.selected += 1;
        },
        .enter => {
            if (count > 0) state.screen = .item_detail;
        },
        .char => switch (ev.char) {
            'q' => state.running = false,
            'n' => {
                initItemFormForType(state, .login);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '1' => {
                initItemFormForType(state, .login);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '2' => {
                initItemFormForType(state, .secure_note);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '3' => {
                initItemFormForType(state, .card);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '4' => {
                initItemFormForType(state, .identity);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            'e' => {
                if (count > 0) {
                    const item = state.session.vault_v2.items[state.selected];
                    state.form_editing_index = state.selected;
                    prefillItemFormFromV2(state, item);
                    state.screen = .item_form;
                }
            },
            'd' => {
                if (count > 0) {
                    const selected_item = state.session.vault_v2.items[state.selected];
                    state.delete_target_name = if (selected_item.name.len > 0) selected_item.name else "(unnamed)";
                    state.delete_is_category = false;
                    state.prev_screen = .item_list;
                    state.screen = .confirm_delete;
                }
            },
            'c' => {
                state.selected = 0;
                state.screen = .category_list;
            },
            '?' => {
                state.prev_screen = .item_list;
                state.screen = .help;
            },
            else => {},
        },
        else => {},
    }
}

fn handleItemDetail(state: *TuiState, ev: KeyEvent) !void {
    switch (ev.key) {
        .escape => state.screen = .item_list,
        .char => switch (ev.char) {
            'e' => {
                const item = state.session.vault_v2.items[state.selected];
                state.form_editing_index = state.selected;
                prefillItemFormFromV2(state, item);
                state.screen = .item_form;
            },
            'd' => {
                const selected_item = state.session.vault_v2.items[state.selected];
                state.delete_target_name = if (selected_item.name.len > 0) selected_item.name else "(unnamed)";
                state.delete_is_category = false;
                state.prev_screen = .item_detail;
                state.screen = .confirm_delete;
            },
            'p' => {
                // Toggle reveal password (just show it as a message for now)
                const pw = itemPrimarySecret(state.session.vault_v2.items[state.selected]);
                state.setMessage(pw, false);
            },
            'y' => {
                const pw = itemPrimarySecret(state.session.vault_v2.items[state.selected]);
                const copied = utils.copyToClipboard(state.allocator, pw) catch false;
                if (copied) {
                    state.setMessage("Password copied to clipboard", false);
                } else {
                    state.setMessage("Clipboard unavailable (pbcopy/wl-copy/xclip)", true);
                }
            },
            '?' => {
                state.prev_screen = .item_detail;
                state.screen = .help;
            },
            else => {},
        },
        else => {},
    }
}

fn handleCategoryList(state: *TuiState, ev: KeyEvent) !void {
    const count = state.session.vault_v2.folders.len + state.session.vault_v2.collections.len;
    switch (ev.key) {
        .escape => {
            state.selected = 0;
            state.screen = .item_list;
        },
        .up => {
            if (state.selected > 0) state.selected -= 1;
        },
        .down => {
            if (count > 0 and state.selected < count - 1) state.selected += 1;
        },
        .char => switch (ev.char) {
            'n' => {
                initContainerForm(state, .folder);
                state.form_editing_index = null;
                state.screen = .category_form;
            },
            'o' => {
                initContainerForm(state, .collection);
                state.form_editing_index = null;
                state.screen = .category_form;
            },
            'e' => {
                if (count == 0) return;
                const sel = selectedContainer(state) orelse return;
                initContainerForm(state, sel.kind);
                state.form_editing_index = state.selected;
                switch (sel.kind) {
                    .folder => {
                        state.form_fields[0].setFromSlice(state.session.vault_v2.folders[sel.index].name);
                    },
                    .collection => {
                        const collection = state.session.vault_v2.collections[sel.index];
                        state.form_fields[0].setFromSlice(collection.name);
                        if (collection.organizationId) |org_id| state.form_fields[1].setFromSlice(org_id);
                    },
                }
                state.screen = .category_form;
            },
            'd' => {
                if (count == 0) return;
                const sel = selectedContainer(state) orelse return;
                state.delete_target_name = containerDisplayName(state, sel);
                state.delete_is_category = true;
                state.prev_screen = .category_list;
                state.screen = .confirm_delete;
            },
            '?' => {
                state.prev_screen = .category_list;
                state.screen = .help;
            },
            else => {},
        },
        else => {},
    }
}

fn handleForm(state: *TuiState, ev: KeyEvent, is_category: bool) !void {
    switch (ev.key) {
        .escape => {
            state.screen = if (is_category) .category_list else .item_list;
        },
        .enter => {
            if (is_category) {
                try saveCategoryForm(state);
            } else {
                try saveItemForm(state);
            }
        },
        .tab => {
            state.form_active_field = (state.form_active_field + 1) % state.form_field_count;
        },
        .up => {
            if (!is_category and folderFieldIsActive(state)) {
                moveFolderPicker(state, -1);
            }
        },
        .down => {
            if (!is_category and folderFieldIsActive(state)) {
                moveFolderPicker(state, 1);
            }
        },
        .backspace => {
            if (!is_category and folderFieldIsActive(state)) {
                state.form_folder_pick_index = null;
            }
            state.form_fields[state.form_active_field].deleteChar();
        },
        .char => |_| {
            if (!is_category and ev.char == 7 and state.item_form_type == .login) {
                try generatePasswordInForm(state);
                return;
            }
            if (!is_category and folderFieldIsActive(state)) {
                state.form_folder_pick_index = null;
            }
            state.form_fields[state.form_active_field].appendChar(ev.char);
        },
        else => {},
    }
}

fn handleConfirmDelete(state: *TuiState, ev: KeyEvent) !void {
    switch (ev.key) {
        .escape => state.screen = state.prev_screen,
        .char => switch (ev.char) {
            'y', 'Y' => {
                if (state.delete_is_category) {
                    try deleteSelectedCategory(state);
                } else {
                    try deleteSelectedItem(state);
                }
            },
            'n', 'N' => state.screen = state.prev_screen,
            else => {},
        },
        else => {},
    }
}

// ─── Generate password via form shortcut ────────────────────────────────────

fn generatePasswordInForm(state: *TuiState) !void {
    if (state.item_form_type != .login) return;
    if (state.wordlist) |wl| {
        const pw = try bip39.generateMnemonic(state.allocator, wl, "-");
        state.form_fields[2].clear();
        state.form_fields[2].setFromSlice(pw);
        state.allocator.free(pw);
        state.setMessage("Password generated", false);
    } else {
        state.setMessage("Wordlist not loaded", true);
    }
}

fn makeTestSession(allocator: std.mem.Allocator) !VaultSession {
    var arena = std.heap.ArenaAllocator.init(allocator);
    const a = arena.allocator();
    return .{
        .vault = .{
            .version = 1,
            .items = try allocator.alloc(model.Item, 0),
            .categories = try allocator.alloc(model.Category, 0),
        },
        .vault_v2 = .{
            .version = 2,
            .encrypted = false,
            .source = .unknown,
            .folders = try a.alloc(schema.Folder, 0),
            .collections = try a.alloc(schema.Collection, 0),
            .items = try a.alloc(schema.Item, 0),
        },
        .vault_v2_arena = arena,
        .vault_v2_allocator = a,
        .key = [_]u8{0} ** crypto.KEY_LEN,
        .salt = [_]u8{0} ** crypto.SALT_LEN,
        .vault_path = try allocator.dupe(u8, "/tmp/tui-test-vault.enc"),
    };
}

test "parseCollectionIdsByName resolves names to ids" {
    const allocator = std.testing.allocator;
    var session = try makeTestSession(allocator);
    defer {
        allocator.free(session.vault_path);
        session.deinit(allocator);
    }

    const collection_id = try vault_service_v2.createCollection(
        session.vault_v2_allocator,
        &session.vault_v2,
        "org-1",
        "Engineering",
    );
    _ = collection_id;

    var state = TuiState.init(allocator, &session);
    const ids = try parseCollectionIdsByName(&state, "Engineering");
    defer if (ids.len > 0) allocator.free(ids);

    try std.testing.expectEqual(@as(usize, 1), ids.len);
    try std.testing.expectEqualStrings(session.vault_v2.collections[0].id, ids[0]);
}

test "removeContainerAtSelection deletes collection links from items" {
    const allocator = std.testing.allocator;
    var session = try makeTestSession(allocator);
    defer {
        allocator.free(session.vault_path);
        session.deinit(allocator);
    }

    const collection_id = try vault_service_v2.createCollection(
        session.vault_v2_allocator,
        &session.vault_v2,
        "org-1",
        "Engineering",
    );
    _ = try vault_service_v2.createItem(
        session.vault_v2_allocator,
        &session.vault_v2,
        .{
            .type = .secure_note,
            .name = "Shared note",
            .organization_id = "org-1",
            .collection_ids = &.{collection_id},
        },
    );
    try std.testing.expect(session.vault_v2.items[0].collectionIds != null);

    var state = TuiState.init(allocator, &session);
    state.selected = 0;
    try removeContainerAtSelection(&state, .{ .kind = .collection, .index = 0 });

    try std.testing.expectEqual(@as(usize, 0), session.vault_v2.collections.len);
    try std.testing.expect(session.vault_v2.items[0].collectionIds == null);
}

// ─── Public entry point ─────────────────────────────────────────────────────

pub fn run(allocator: std.mem.Allocator, session: *VaultSession) !void {
    var state = TuiState.init(allocator, session);

    // Load wordlist
    state.wordlist = bip39.loadWordlist(allocator, storage.getWordlistPath()) catch null;
    defer {
        if (state.wordlist) |wl| {
            bip39.freeWordlist(allocator, wl);
        }
    }

    // Enter raw mode + alternate screen
    const raw = RawMode.enable() catch {
        std.debug.print("Error: could not enable raw terminal mode.\n", .{});
        return;
    };
    defer raw.disable();

    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [8192]u8 = undefined;
    var file_writer = stdout_file.writer(&stdout_buf);
    const w = &file_writer.interface;

    try w.writeAll(Term.alt_screen_on);
    try w.writeAll(Term.cursor_hide);
    try w.flush();

    defer {
        w.writeAll(Term.cursor_show) catch {};
        w.writeAll(Term.alt_screen_off) catch {};
        w.flush() catch {};
    }

    // Main loop
    while (state.running) {
        state.refreshSize();
        try render(w, &state);

        if (readKey(raw.fd)) |ev| {
            try handleInput(&state, ev);
        }
    }
}
