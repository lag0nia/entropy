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
    mouse_left,
    mouse_move,
    enter,
    escape,
    backspace,
    clear_line,
    tab,
    shift_tab,
    char,
    unknown,
};

const KeyEvent = struct {
    key: Key,
    char: u8 = 0,
    mouse_row: u16 = 0,
    mouse_col: u16 = 0,
};

const DetailButton = enum {
    none,
    reveal,
    copy,
    generate,
};

const DetailActionButton = enum {
    none,
    edit,
    delete,
    save_field,
    cancel_back,
    reveal,
    copy,
    generate,
    help,
};

const DetailField = enum {
    name,
    user,
    password,
    totp,
    url,
    notes,
    folder,
    collections,
    org_id,
    note_type,
    number,
    brand,
    code,
    holder,
    exp_month,
    exp_year,
    first_name,
    last_name,
    email,
    phone,
};

const DetailFieldRow = struct {
    row: u16,
    field: DetailField,
};

const DetailFooterHotspot = struct {
    action: DetailActionButton,
    col_start: u16,
    col_end: u16,
};

const DetailPopoverKind = enum {
    none,
    folder,
    collections,
};

const FormPasswordButton = enum {
    none,
    reveal,
    copy,
    generate,
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
    item_hover_index: ?usize = null,
    rows: u16 = 24,
    cols: u16 = 80,
    running: bool = true,
    message: ?[]const u8 = null,
    message_is_error: bool = false,
    message_expires_at_ns: ?i128 = null,

    // Form state
    form_fields: [12]InputField = undefined,
    form_field_count: usize = 0,
    form_active_field: usize = 0,
    form_editing_index: ?usize = null, // null = creating new
    form_is_category: bool = false,
    item_form_type: schema.ItemType = .login,
    form_container_kind: ContainerKind = .folder,
    form_folder_pick_index: ?usize = null,
    form_collection_pick_index: ?usize = null,
    form_collection_selection: ?[]bool = null,
    form_hover_field: ?usize = null,
    form_field_rows: [12]u16 = [_]u16{0} ** 12,
    form_buttons_row: u16 = 0,
    form_hover_button: FormPasswordButton = .none,
    form_password_revealed: bool = false,
    detail_hover_button: DetailButton = .none,
    detail_hover_field: ?DetailField = null,
    detail_edit_field: ?DetailField = null,
    detail_edit_buffer: InputField = .{ .label = "" },
    detail_password_confirm_pending: bool = false,
    detail_password_reveal_until_ns: ?i128 = null,
    detail_folder_pick_index: ?usize = null,
    detail_collection_pick_index: ?usize = null,
    detail_collection_selection: ?[]bool = null,
    detail_field_rows: [32]DetailFieldRow = undefined,
    detail_field_row_count: usize = 0,
    detail_buttons_row: u16 = 0,
    detail_footer_row: u16 = 0,
    detail_footer_hotspots: [8]DetailFooterHotspot = undefined,
    detail_footer_hotspot_count: usize = 0,
    detail_action_hover: DetailActionButton = .none,
    detail_popover_kind: DetailPopoverKind = .none,
    detail_popover_row_start: u16 = 0,
    detail_popover_count: usize = 0,

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
        self.message_expires_at_ns = null;
    }

    fn setTimedMessage(self: *TuiState, msg: []const u8, is_error: bool, timeout_ms: u64) void {
        self.message = msg;
        self.message_is_error = is_error;
        const now = std.time.nanoTimestamp();
        self.message_expires_at_ns = now + @as(i128, @intCast(timeout_ms)) * @as(i128, std.time.ns_per_ms);
    }

    fn clearMessage(self: *TuiState) void {
        self.message = null;
        self.message_expires_at_ns = null;
    }

    fn expireMessageIfNeeded(self: *TuiState) void {
        if (self.message_expires_at_ns) |deadline| {
            if (std.time.nanoTimestamp() >= deadline) {
                self.clearMessage();
            }
        }
        if (self.detail_password_reveal_until_ns) |deadline| {
            if (std.time.nanoTimestamp() >= deadline) {
                self.detail_password_reveal_until_ns = null;
            }
        }
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

    fn clearDetailCollectionSelection(self: *TuiState) void {
        if (self.detail_collection_selection) |slice| {
            self.allocator.free(slice);
            self.detail_collection_selection = null;
        }
    }

    fn clearDetailEditState(self: *TuiState) void {
        self.detail_edit_field = null;
        self.detail_edit_buffer.clear();
        self.detail_password_confirm_pending = false;
        self.detail_folder_pick_index = null;
        self.detail_collection_pick_index = null;
        self.clearDetailCollectionSelection();
        self.detail_popover_kind = .none;
        self.detail_popover_row_start = 0;
        self.detail_popover_count = 0;
    }

    fn clearFormCollectionSelection(self: *TuiState) void {
        if (self.form_collection_selection) |slice| {
            self.allocator.free(slice);
            self.form_collection_selection = null;
        }
    }

    fn resetFormUiState(self: *TuiState) void {
        self.form_hover_field = null;
        self.form_hover_button = .none;
        self.form_buttons_row = 0;
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
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return null;
    if (n == 0) return null;

    if (n == 1) {
        return switch (buf[0]) {
            27 => .{ .key = .escape },
            13, 10 => .{ .key = .enter },
            127, 8 => .{ .key = .backspace },
            21 => .{ .key = .clear_line }, // Ctrl+U (terminal fallback)
            9 => .{ .key = .tab },
            7 => .{ .key = .char, .char = 7 }, // Ctrl+G
            20 => .{ .key = .char, .char = 20 }, // Ctrl+T
            else => |c| if (c >= 32 and c < 127)
                .{ .key = .char, .char = c }
            else
                .{ .key = .unknown },
        };
    }

    // Common encoding for Cmd/Alt+Backspace in some terminals: ESC + DEL/BS
    if (n == 2 and buf[0] == 27 and (buf[1] == 127 or buf[1] == 8)) {
        return .{ .key = .clear_line };
    }

    if (parseSgrMouse(buf[0..n])) |ev| return ev;

    // X10 mouse sequence: ESC [ M Cb Cx Cy
    if (n >= 6 and buf[0] == 27 and buf[1] == '[' and buf[2] == 'M') {
        if (buf[3] < 32 or buf[4] < 32 or buf[5] < 32) return .{ .key = .unknown };
        const cb: u8 = buf[3] - 32;
        const cx: u16 = @as(u16, buf[4] - 32);
        const cy: u16 = @as(u16, buf[5] - 32);
        const button = cb & 0x03;
        if (button == 0) {
            return .{
                .key = .mouse_left,
                .mouse_col = cx,
                .mouse_row = cy,
            };
        }
        return .{ .key = .unknown };
    }

    // Escape sequences
    if (n >= 3 and buf[0] == 27 and buf[1] == '[') {
        if (buf[2] == 'Z') return .{ .key = .shift_tab };
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

fn parseSgrMouse(seq: []const u8) ?KeyEvent {
    if (seq.len < 6) return null;
    if (!(seq[0] == 27 and seq[1] == '[' and seq[2] == '<')) return null;

    var idx: usize = 3;
    const cb = parseMouseNumber(seq, &idx) orelse return null;
    if (idx >= seq.len or seq[idx] != ';') return null;
    idx += 1;

    const cx = parseMouseNumber(seq, &idx) orelse return null;
    if (idx >= seq.len or seq[idx] != ';') return null;
    idx += 1;

    const cy = parseMouseNumber(seq, &idx) orelse return null;
    if (idx >= seq.len) return null;
    const suffix = seq[idx];
    if (suffix != 'M' and suffix != 'm') return null;

    const is_motion = (cb & 0x20) != 0;
    const button = cb & 0x03;
    if (is_motion) {
        return .{
            .key = .mouse_move,
            .mouse_col = @intCast(cx),
            .mouse_row = @intCast(cy),
        };
    }
    if (suffix == 'M' and button == 0) {
        return .{
            .key = .mouse_left,
            .mouse_col = @intCast(cx),
            .mouse_row = @intCast(cy),
        };
    }
    return .{ .key = .unknown };
}

fn parseMouseNumber(seq: []const u8, idx: *usize) ?u16 {
    if (idx.* >= seq.len) return null;
    var value: u32 = 0;
    var consumed = false;
    while (idx.* < seq.len) : (idx.* += 1) {
        const c = seq[idx.*];
        if (c < '0' or c > '9') break;
        consumed = true;
        value = value * 10 + (c - '0');
        if (value > std.math.maxInt(u16)) return null;
    }
    if (!consumed) return null;
    return @intCast(value);
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
        state.item_hover_index = null;
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
        const is_hovered = (state.item_hover_index != null and state.item_hover_index.? == i and !is_selected);

        if (is_selected) {
            try w.print("  {s}{s}{s}{s} ", .{ Color.cyan, Color.bold, Icon.arrow_right, Color.reset });
        } else if (is_hovered) {
            try w.print("  {s}>{s} ", .{ Color.bright_black, Color.reset });
        } else {
            try w.writeAll("    ");
        }

        try w.print("{s}[{s}]{s} ", .{ Color.dim, itemTypeLabel(item.type), Color.reset });

        // Name
        const name = if (item.name.len > 0) item.name else "(unnamed)";
        if (is_selected) {
            try w.print("{s}{s}{s}{s}", .{ Color.bold, Color.bright_white, name, Color.reset });
        } else if (is_hovered) {
            try w.print("{s}{s}{s}{s}", .{ Color.underline, Color.bright_white, name, Color.reset });
        } else {
            try w.print("{s}", .{name});
        }

        // Container badge
        if (resolveContainerLabel(state, item)) |label| {
            if (is_selected) {
                try w.print("  {s}[{s}]{s}", .{ Color.dim, label, Color.reset });
            } else if (is_hovered) {
                try w.print("  {s}{s}[{s}]{s}", .{ Color.dim, Color.underline, label, Color.reset });
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

fn drawItemDetail(w: *Writer, state: *TuiState) !void {
    const items = state.session.vault_v2.items;
    if (state.selected >= items.len) return;
    const item = items[state.selected];

    state.detail_field_row_count = 0;
    state.detail_popover_kind = .none;
    state.detail_popover_row_start = 0;
    state.detail_popover_count = 0;
    state.detail_buttons_row = 0;

    try w.writeAll("\n");
    try w.print("  {s}{s}Item Detail{s} {s}[{s}]{s}\n", .{
        Color.bold,
        Color.bright_white,
        Color.reset,
        Color.dim,
        itemTypeLabel(item.type),
        Color.reset,
    });
    try w.print("  {s}", .{Color.bright_black});
    var sep_i: usize = 0;
    while (sep_i < @min(state.cols -| 4, 50)) : (sep_i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    var row: u16 = 7;
    const fields = detailFieldsForItemType(item.type);
    for (fields) |field| {
        try drawDetailFieldLine(w, state, item, row, field);
        row += 1;
    }

    if (state.detail_password_confirm_pending) {
        try w.writeAll("\n");
        try w.print("  {s}Replace stored password?{s} press {s}y{s}{s} to confirm or {s}n{s}{s} to cancel\n", .{
            Color.yellow, Color.reset,
            Color.bold, Color.reset, Color.dim,
            Color.bold, Color.reset, Color.dim,
        });
        row += 2;
    }

    if (state.detail_edit_field) |field| {
        switch (field) {
            .folder => {
                row += 1;
                try drawFolderInlinePopover(w, state, row);
                row += @as(u16, @intCast(state.session.vault_v2.folders.len + 2));
            },
            .collections => {
                row += 1;
                try drawCollectionsInlinePopover(w, state, row);
                row += @as(u16, @intCast(state.session.vault_v2.collections.len + 1));
            },
            else => {},
        }
    }

    try w.writeAll("\n");
}

fn itemIndexAtMouseRow(state: *const TuiState, row: u16) ?usize {
    const items = state.session.vault_v2.items;
    if (items.len == 0) return null;

    // Header uses 2 lines, item list adds one leading blank line.
    const first_item_row: u16 = 4;
    if (row < first_item_row) return null;

    const offset: usize = @as(usize, row - first_item_row);
    if (offset >= state.visibleItems()) return null;

    const idx = state.scroll + offset;
    if (idx >= items.len) return null;
    return idx;
}

fn drawDetailButtons(w: *Writer, state: *TuiState, row: u16) !void {
    state.detail_buttons_row = row;
    const hovered = state.detail_hover_button;
    try w.writeAll("  ");
    try drawDetailButton(w, "reveal (p)", hovered == .reveal);
    try w.writeAll("  ");
    try drawDetailButton(w, "copy (y)", hovered == .copy);
    if (state.detail_edit_field != null and state.detail_edit_field.? == .password) {
        try w.writeAll("  ");
        try drawDetailButton(w, "generate (ctrl+g)", hovered == .generate);
    }
    try w.writeAll("\n");
}

fn drawDetailButton(w: *Writer, label: []const u8, hovered: bool) !void {
    if (hovered) {
        try w.print("{s}{s}[{s}]{s}", .{
            Color.cyan, Color.underline, label, Color.reset,
        });
    } else {
        try w.print("{s}[{s}]{s}", .{
            Color.dim, label, Color.reset,
        });
    }
}

fn detailButtonAtMouse(state: *const TuiState, row: u16, col: u16) DetailButton {
    if (row != state.detail_buttons_row) return .none;

    const reveal_text = "[reveal (p)]";
    const copy_text = "[copy (y)]";
    const generate_text = "[generate (ctrl+g)]";
    const reveal_start: u16 = 3;
    const reveal_end: u16 = reveal_start + @as(u16, @intCast(reveal_text.len - 1));
    const copy_start: u16 = reveal_end + 3;
    const copy_end: u16 = copy_start + @as(u16, @intCast(copy_text.len - 1));
    const generate_start: u16 = copy_end + 3;
    const generate_end: u16 = generate_start + @as(u16, @intCast(generate_text.len - 1));

    if (col >= reveal_start and col <= reveal_end) return .reveal;
    if (col >= copy_start and col <= copy_end) return .copy;
    if (state.detail_edit_field != null and state.detail_edit_field.? == .password and col >= generate_start and col <= generate_end) {
        return .generate;
    }
    return .none;
}

fn detailFooterActionAtMouse(state: *const TuiState, row: u16, col: u16) DetailActionButton {
    if (row != state.detail_footer_row) return .none;
    for (state.detail_footer_hotspots[0..state.detail_footer_hotspot_count]) |spot| {
        if (col >= spot.col_start and col <= spot.col_end) return spot.action;
    }
    return .none;
}

fn detailFieldsForItemType(item_type: u8) []const DetailField {
    return switch (item_type) {
        2 => &.{ .name, .note_type, .notes, .folder, .collections, .org_id },
        3 => &.{ .name, .number, .brand, .code, .holder, .exp_month, .exp_year, .notes, .folder, .collections, .org_id },
        4 => &.{ .name, .first_name, .last_name, .email, .phone, .notes, .folder, .collections, .org_id },
        else => &.{ .name, .user, .password, .totp, .url, .notes, .folder, .collections, .org_id },
    };
}

fn detailFieldLabel(field: DetailField) []const u8 {
    return switch (field) {
        .name => "Name",
        .user => "User",
        .password => "Password",
        .totp => "TOTP",
        .url => "URL",
        .notes => "Notes",
        .folder => "Folder",
        .collections => "Collections",
        .org_id => "Org ID",
        .note_type => "NoteType",
        .number => "Number",
        .brand => "Brand",
        .code => "Code",
        .holder => "Holder",
        .exp_month => "ExpMonth",
        .exp_year => "ExpYear",
        .first_name => "FirstName",
        .last_name => "LastName",
        .email => "Email",
        .phone => "Phone",
    };
}

fn drawDetailFieldLine(
    w: *Writer,
    state: *TuiState,
    item: schema.Item,
    row: u16,
    field: DetailField,
) !void {
    if (state.detail_field_row_count < state.detail_field_rows.len) {
        state.detail_field_rows[state.detail_field_row_count] = .{ .row = row, .field = field };
        state.detail_field_row_count += 1;
    }

    const is_editing = (state.detail_edit_field != null and state.detail_edit_field.? == field);
    const is_hovered = (state.detail_hover_field != null and state.detail_hover_field.? == field and !is_editing);

    try w.print("  {s}{s:<12}{s} ", .{
        if (is_editing) Color.bold else Color.cyan,
        detailFieldLabel(field),
        Color.reset,
    });

    if (is_editing) {
        try drawDetailEditingValue(w, state, field);
    } else {
        try drawDetailStaticValue(w, state, item, field, is_hovered);
    }
    try w.writeAll("\n");
}

fn drawDetailStaticValue(
    w: *Writer,
    state: *const TuiState,
    item: schema.Item,
    field: DetailField,
    hovered: bool,
) !void {
    if (hovered) try w.writeAll(Color.underline);
    if (hovered) try w.writeAll(Color.bright_white) else try w.writeAll(Color.reset);

    switch (field) {
        .password => {
            const pw = if (item.login) |login| login.password orelse "" else "";
            if (pw.len == 0) {
                try w.writeAll("(none)");
            } else {
                const revealed = if (state.detail_password_reveal_until_ns) |deadline|
                    std.time.nanoTimestamp() < deadline
                else
                    false;
                if (revealed) {
                    try w.writeAll(pw);
                } else {
                    for (pw) |_| try w.writeAll(Icon.dot);
                }
            }
        },
        .folder => {
            try w.writeAll(resolveFolderNameByItem(state, item) orelse "(none)");
        },
        .collections => {
            try writeCollectionNamesFromItem(w, state, item);
        },
        .name => try w.writeAll(if (item.name.len > 0) item.name else "(none)"),
        .user => try w.writeAll(if (item.login != null and item.login.?.username != null) item.login.?.username.? else "(none)"),
        .totp => try w.writeAll(if (item.login != null and item.login.?.totp != null) item.login.?.totp.? else "(none)"),
        .url => {
            if (item.login) |login| {
                if (login.uris) |uris| {
                    if (uris.len > 0 and uris[0].uri != null) {
                        try w.writeAll(uris[0].uri.?);
                    } else try w.writeAll("(none)");
                } else try w.writeAll("(none)");
            } else try w.writeAll("(none)");
        },
        .notes => try w.writeAll(item.notes orelse "(none)"),
        .org_id => try w.writeAll(item.organizationId orelse "(none)"),
        .note_type => {
            if (item.secureNote != null and item.secureNote.?.type != null) {
                try w.print("{d}", .{item.secureNote.?.type.?});
            } else {
                try w.writeAll("(none)");
            }
        },
        .number => try w.writeAll(if (item.card != null and item.card.?.number != null) item.card.?.number.? else "(none)"),
        .brand => try w.writeAll(if (item.card != null and item.card.?.brand != null) item.card.?.brand.? else "(none)"),
        .code => try w.writeAll(if (item.card != null and item.card.?.code != null) item.card.?.code.? else "(none)"),
        .holder => try w.writeAll(if (item.card != null and item.card.?.cardholderName != null) item.card.?.cardholderName.? else "(none)"),
        .exp_month => try w.writeAll(if (item.card != null and item.card.?.expMonth != null) item.card.?.expMonth.? else "(none)"),
        .exp_year => try w.writeAll(if (item.card != null and item.card.?.expYear != null) item.card.?.expYear.? else "(none)"),
        .first_name => try w.writeAll(if (item.identity != null and item.identity.?.firstName != null) item.identity.?.firstName.? else "(none)"),
        .last_name => try w.writeAll(if (item.identity != null and item.identity.?.lastName != null) item.identity.?.lastName.? else "(none)"),
        .email => try w.writeAll(if (item.identity != null and item.identity.?.email != null) item.identity.?.email.? else "(none)"),
        .phone => try w.writeAll(if (item.identity != null and item.identity.?.phone != null) item.identity.?.phone.? else "(none)"),
    }
    try w.writeAll(Color.reset);
}

fn drawDetailEditingValue(w: *Writer, state: *const TuiState, field: DetailField) !void {
    try w.writeAll(Color.underline);
    try w.writeAll(Color.bright_white);
    switch (field) {
        .folder => {
            try w.writeAll(currentDetailFolderName(state) orelse "(none)");
        },
        .collections => {
            try writeCurrentDetailCollectionNames(w, state);
        },
        .password => {
            const pw = state.detail_edit_buffer.slice();
            for (pw) |_| try w.writeAll(Icon.dot);
        },
        else => {
            try w.writeAll(state.detail_edit_buffer.slice());
        },
    }
    try w.writeAll(Color.reset);
    try w.writeAll(Color.bright_black);
    try w.writeAll("_");
    try w.writeAll(Color.reset);
}

fn drawFolderInlinePopover(w: *Writer, state: *TuiState, start_row: u16) !void {
    state.detail_popover_kind = .folder;
    state.detail_popover_row_start = start_row + 1;
    state.detail_popover_count = state.session.vault_v2.folders.len + 1;

    try w.print("  {s}Folders (Up/Down, Enter save, Esc cancel):{s}\n", .{
        Color.dim, Color.reset,
    });

    const none_selected = state.detail_folder_pick_index == null;
    if (none_selected) {
        try w.print("    {s}> [none]{s}\n", .{ Color.cyan, Color.reset });
    } else {
        try w.writeAll("      [none]\n");
    }

    for (state.session.vault_v2.folders, 0..) |folder, idx| {
        const selected = state.detail_folder_pick_index != null and state.detail_folder_pick_index.? == idx;
        if (selected) {
            try w.print("    {s}> {s}{s}{s}\n", .{ Color.cyan, Color.bold, folder.name, Color.reset });
        } else {
            try w.print("      {s}\n", .{folder.name});
        }
    }
}

fn drawCollectionsInlinePopover(w: *Writer, state: *TuiState, start_row: u16) !void {
    state.detail_popover_kind = .collections;
    state.detail_popover_row_start = start_row + 1;
    state.detail_popover_count = state.session.vault_v2.collections.len;

    try w.print("  {s}Collections (click/Up/Down, Space toggle, Enter save):{s}\n", .{
        Color.dim, Color.reset,
    });

    const selected_flags = state.detail_collection_selection orelse {
        try w.print("    {s}(none){s}\n", .{ Color.dim, Color.reset });
        return;
    };

    if (state.session.vault_v2.collections.len == 0) {
        try w.print("    {s}(no collections){s}\n", .{ Color.dim, Color.reset });
        return;
    }

    for (state.session.vault_v2.collections, 0..) |collection, idx| {
        const cursor = state.detail_collection_pick_index != null and state.detail_collection_pick_index.? == idx;
        const marked = selected_flags[idx];
        if (cursor) {
            try w.print("    {s}> [{s}] {s}{s}{s}\n", .{
                Color.cyan,
                if (marked) "x" else " ",
                Color.bold,
                collection.name,
                Color.reset,
            });
        } else {
            try w.print("      [{s}] {s}\n", .{
                if (marked) "x" else " ",
                collection.name,
            });
        }
    }
}

fn detailFieldAtMouse(state: *const TuiState, row: u16, col: u16) ?DetailField {
    if (col < 3) return null;
    for (0..state.detail_field_row_count) |i| {
        const entry = state.detail_field_rows[i];
        if (entry.row == row) return entry.field;
    }
    return null;
}

fn detailPopoverOptionAtMouse(state: *const TuiState, row: u16) ?usize {
    if (state.detail_popover_kind == .none) return null;
    if (row < state.detail_popover_row_start) return null;
    const offset = @as(usize, row - state.detail_popover_row_start);
    if (offset >= state.detail_popover_count) return null;
    return offset;
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

fn resolveFolderNameByItem(state: *const TuiState, item: schema.Item) ?[]const u8 {
    if (item.folderId) |folder_id| {
        for (state.session.vault_v2.folders) |folder| {
            if (std.mem.eql(u8, folder.id, folder_id)) return folder.name;
        }
    }
    return null;
}

fn writeCollectionNamesFromItem(w: *Writer, state: *const TuiState, item: schema.Item) !void {
    if (item.collectionIds) |collection_ids| {
        var wrote_any = false;
        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            for (state.session.vault_v2.collections) |collection| {
                if (std.mem.eql(u8, collection.id, collection_id)) {
                    if (wrote_any) try w.writeAll(", ");
                    try w.writeAll(collection.name);
                    wrote_any = true;
                    break;
                }
            }
        }
        if (wrote_any) return;
    }
    try w.writeAll("(none)");
}

fn currentDetailFolderName(state: *const TuiState) ?[]const u8 {
    if (state.detail_folder_pick_index) |idx| {
        if (idx < state.session.vault_v2.folders.len) {
            return state.session.vault_v2.folders[idx].name;
        }
    }
    return null;
}

fn writeCurrentDetailCollectionNames(w: *Writer, state: *const TuiState) !void {
    const selected = state.detail_collection_selection orelse {
        try w.writeAll("(none)");
        return;
    };
    var wrote_any = false;
    for (state.session.vault_v2.collections, 0..) |collection, idx| {
        if (!selected[idx]) continue;
        if (wrote_any) try w.writeAll(", ");
        try w.writeAll(collection.name);
        wrote_any = true;
    }
    if (!wrote_any) try w.writeAll("(none)");
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
    const creation_mode = (!state.form_is_category and state.form_editing_index == null);

    const mut_state: *TuiState = @constCast(state);
    mut_state.resetFormUiState();

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

    var row: u16 = 7;
    for (0..state.form_field_count) |i| {
        mut_state.form_field_rows[i] = row;
        row += 1;

        const field = &state.form_fields[i];
        const is_active = (i == state.form_active_field);
        const is_hover = (creation_mode and state.form_hover_field != null and state.form_hover_field.? == i and !is_active);
        const hide_password = (!state.form_is_category and state.item_form_type == .login and i == 2 and !state.form_password_revealed);

        if (is_active) {
            try w.print("  {s}{s}{s:<10}{s} ", .{ Color.bold, Color.cyan, field.label, Color.reset });
            try w.writeAll(Color.underline);
            if (hide_password) {
                for (field.slice()) |_| try w.writeAll(Icon.dot);
            } else {
                try w.writeAll(field.slice());
            }
            try w.print("{s}{s}_{s}\n", .{ Color.reset, Color.bright_black, Color.reset });
        } else {
            try w.print("  {s}{s:<10}{s} ", .{ Color.dim, field.label, Color.reset });
            if (is_hover) try w.writeAll(Color.underline);
            if (hide_password) {
                for (field.slice()) |_| try w.writeAll(Icon.dot);
                if (field.slice().len == 0) try w.writeAll("(empty)");
            } else if (field.slice().len > 0) {
                try w.writeAll(field.slice());
            } else {
                try w.writeAll("(empty)");
            }
            if (is_hover) try w.writeAll(Color.reset);
            try w.writeAll("\n");
        }
    }

    if (creation_mode and folderFieldIsActive(state)) {
        try w.writeAll("\n");
        try w.print("  {s}Folders (Up/Down, Left/Right field nav):{s}\n", .{
            Color.dim, Color.reset,
        });
        const none_selected = state.form_folder_pick_index == null;
        if (none_selected) {
            try w.print("    {s}> [none]{s}\n", .{ Color.cyan, Color.reset });
        } else {
            try w.writeAll("      [none]\n");
        }
        for (state.session.vault_v2.folders, 0..) |folder, idx| {
            const selected = state.form_folder_pick_index != null and state.form_folder_pick_index.? == idx;
            if (selected) {
                try w.print("    {s}> {s}{s}{s}\n", .{
                    Color.cyan, Color.bold, folder.name, Color.reset,
                });
            } else {
                try w.print("      {s}\n", .{folder.name});
            }
        }
    } else if (creation_mode and collectionFieldIsActive(state)) {
        try w.writeAll("\n");
        try w.print("  {s}Collections (Up/Down, Space toggle, Left/Right field nav):{s}\n", .{
            Color.dim, Color.reset,
        });
        if (state.session.vault_v2.collections.len == 0) {
            try w.print("    {s}(no collections){s}\n", .{ Color.dim, Color.reset });
        } else if (state.form_collection_selection) |selected| {
            for (state.session.vault_v2.collections, 0..) |collection, idx| {
                const cursor = state.form_collection_pick_index != null and state.form_collection_pick_index.? == idx;
                const marked = selected[idx];
                if (cursor) {
                    try w.print("    {s}> [{s}] {s}{s}{s}\n", .{
                        Color.cyan,
                        if (marked) "x" else " ",
                        Color.bold,
                        collection.name,
                        Color.reset,
                    });
                } else {
                    try w.print("      [{s}] {s}\n", .{
                        if (marked) "x" else " ",
                        collection.name,
                    });
                }
            }
        } else {
            try w.print("    {s}(none){s}\n", .{ Color.dim, Color.reset });
        }
    }

    try w.writeAll("\n");
    try drawFormPasswordButtons(w, mut_state, row + 1, creation_mode);

    if (!state.form_is_category) {
        if (state.item_form_type == .login) {
            try w.print("  {s}Tab/Shift+Tab{s}{s} next/prev  {s}Arrows{s}{s} nav/selectors  {s}Ctrl+G{s}{s} generate  {s}p{s}{s} reveal/hide  {s}y{s}{s} copy  {s}Cmd+Backspace/Ctrl+U{s}{s} clear  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.reset,
            });
        } else {
            try w.print("  {s}Tab/Shift+Tab{s}{s} next/prev  {s}Arrows{s}{s} nav/selectors  {s}Cmd+Backspace/Ctrl+U{s}{s} clear  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.bold,  Color.reset, Color.dim,
                Color.reset,
            });
        }
    } else {
        try w.print("  {s}Tab/Shift+Tab{s}{s} next/prev  {s}Arrows{s}{s} next/prev  {s}Cmd+Backspace/Ctrl+U{s}{s} clear  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
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
    try w.writeAll("    Up/Down navigate, Enter detail, mouse click open, n/1 login, 2 note, 3 card, 4 identity, e edit, d delete, c categories, q quit\n");

    try w.print("\n  {s}Item detail{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    Click any field to edit inline, Enter save field, Esc cancel field\n");
    try w.writeAll("    Password edit asks confirmation each time, Ctrl+G or [generate] creates a new one\n");
    try w.writeAll("    Folder/Collections edit uses popover selection\n");
    try w.writeAll("    p reveal password, y copy password\n");
    try w.writeAll("    Footer actions are clickable: [edit]/[delete]/[save field]/[cancel-back]/[reveal]/[copy]/[help]\n");

    try w.print("\n  {s}Item/category forms{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    Tab/Shift+Tab next/prev field, Arrows navigate, Enter save, Esc cancel\n");
    try w.writeAll("    Cmd+Backspace / Ctrl+U clear active field\n");
    try w.writeAll("    Creation form supports click-to-focus fields and folder/collections selectors\n");
    try w.writeAll("    Login creation: Ctrl+G or [generate], p [reveal/hide], y [copy]\n");
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

fn drawFooter(w: *Writer, state: *TuiState) !void {
    state.detail_footer_hotspot_count = 0;
    if (state.screen != .item_detail) state.detail_action_hover = .none;
    if (state.screen == .item_detail and state.rows >= 2) {
        const separator_row_1_based: u16 = state.rows - 1;
        try w.print("\x1b[{d};1H", .{separator_row_1_based});
    }

    try w.print("{s}", .{Color.bright_black});
    var i: usize = 0;
    while (i < state.cols) : (i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n", .{Color.reset});

    state.detail_footer_row = if (state.screen == .item_detail and state.rows > 0) state.rows - 1 else 0;

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
            var col: u16 = 1;
            try drawDetailFooterHint(w, state, &col, "e", "edit", .edit);
            try drawDetailFooterHint(w, state, &col, "d", "delete", .delete);
            try drawDetailFooterHint(w, state, &col, "Enter", "save field", .save_field);
            try drawDetailFooterHint(w, state, &col, "Esc", "cancel/back", .cancel_back);
            if (state.detail_edit_field != null and state.detail_edit_field.? == .password) {
                try drawDetailFooterHint(w, state, &col, "Ctrl+G", "generate", .generate);
            }
            try drawDetailFooterHint(w, state, &col, "p", "reveal", .reveal);
            try drawDetailFooterHint(w, state, &col, "y", "copy", .copy);
            try drawDetailFooterHint(w, state, &col, "?", "help", .help);
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

fn drawDetailFooterHint(
    w: *Writer,
    state: *TuiState,
    col_cursor: *u16,
    key: []const u8,
    desc: []const u8,
    action: DetailActionButton,
) !void {
    const visible_len: u16 = @intCast(key.len + desc.len + 3);
    const start = col_cursor.*;
    const hovered = (action != .none and state.detail_action_hover == action);
    if (action != .none and state.detail_footer_hotspot_count < state.detail_footer_hotspots.len) {
        const idx = state.detail_footer_hotspot_count;
        state.detail_footer_hotspots[idx] = .{
            .action = action,
            .col_start = start,
            .col_end = start + visible_len - 1,
        };
        state.detail_footer_hotspot_count += 1;
    }

    if (hovered) {
        try w.print(" {s}{s}{s}{s} {s}{s}{s}{s} ", .{
            Color.bg_bright_black,
            Color.cyan,
            key,
            Color.reset,
            Color.dim,
            Color.underline,
            desc,
            Color.reset,
        });
    } else {
        try drawKeyHint(w, key, desc);
    }
    col_cursor.* += visible_len;
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
    state.form_collection_pick_index = null;
    state.clearFormCollectionSelection();
    state.resetFormUiState();
    state.form_password_revealed = false;

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

fn collectionFieldIndexForType(item_type: schema.ItemType) usize {
    return switch (item_type) {
        .login => 7,
        .secure_note => 4,
        .card => 9,
        .identity => 7,
    };
}

fn collectionFieldIsActive(state: *const TuiState) bool {
    if (state.form_is_category) return false;
    return state.form_active_field == collectionFieldIndexForType(state.item_form_type);
}

fn isItemCreationForm(state: *const TuiState, is_category: bool) bool {
    return !is_category and state.screen == .item_form and state.form_editing_index == null;
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
    const field_index = folderFieldIndexForType(state.item_form_type);
    if (folders.len == 0) {
        state.form_folder_pick_index = null;
        state.form_fields[field_index].clear();
        state.setMessage("No folders available", true);
        return;
    }

    if (state.form_folder_pick_index == null) {
        syncFolderPickerFromCurrentField(state);
    }

    const max_index: i32 = @intCast(folders.len - 1);
    var pos: i32 = if (state.form_folder_pick_index) |idx| @intCast(idx) else -1;
    if (direction >= 0) {
        pos += 1;
        if (pos > max_index) pos = -1;
    } else {
        pos -= 1;
        if (pos < -1) pos = max_index;
    }

    if (pos < 0) {
        state.form_folder_pick_index = null;
        state.form_fields[field_index].clear();
    } else {
        const idx: usize = @intCast(pos);
        state.form_folder_pick_index = idx;
        state.form_fields[field_index].clear();
        state.form_fields[field_index].setFromSlice(folders[idx].name);
    }
}

fn parseFormCollectionSelectionFromField(state: *TuiState) void {
    if (state.form_collection_selection) |selected| {
        @memset(selected, false);
        const field_index = collectionFieldIndexForType(state.item_form_type);
        var tok = std.mem.tokenizeScalar(u8, state.form_fields[field_index].slice(), ',');
        while (tok.next()) |entry| {
            const name = std.mem.trim(u8, entry, " \t");
            if (name.len == 0) continue;
            for (state.session.vault_v2.collections, 0..) |collection, idx| {
                if (std.mem.eql(u8, collection.name, name)) {
                    selected[idx] = true;
                    break;
                }
            }
        }
    }
}

fn writeFormCollectionSelectionToField(state: *TuiState) void {
    const selected = state.form_collection_selection orelse return;
    const field_index = collectionFieldIndexForType(state.item_form_type);
    state.form_fields[field_index].clear();

    var builder = std.ArrayList(u8){};
    defer builder.deinit(state.allocator);

    for (state.session.vault_v2.collections, 0..) |collection, idx| {
        if (!selected[idx]) continue;
        if (builder.items.len > 0) {
            builder.appendSlice(state.allocator, ", ") catch return;
        }
        builder.appendSlice(state.allocator, collection.name) catch return;
    }
    if (builder.items.len > 0) {
        state.form_fields[field_index].setFromSlice(builder.items);
    }
}

fn ensureFormCollectionSelection(state: *TuiState) void {
    if (state.form_collection_selection == null) {
        const count = state.session.vault_v2.collections.len;
        const selected = state.allocator.alloc(bool, count) catch {
            state.setMessage("Out of memory for collections", true);
            return;
        };
        @memset(selected, false);
        state.form_collection_selection = selected;
    } else if (state.form_collection_selection.?.len != state.session.vault_v2.collections.len) {
        state.clearFormCollectionSelection();
        const count = state.session.vault_v2.collections.len;
        const selected = state.allocator.alloc(bool, count) catch {
            state.setMessage("Out of memory for collections", true);
            return;
        };
        @memset(selected, false);
        state.form_collection_selection = selected;
    }
    parseFormCollectionSelectionFromField(state);
    if (state.session.vault_v2.collections.len == 0) {
        state.form_collection_pick_index = null;
    } else if (state.form_collection_pick_index == null or state.form_collection_pick_index.? >= state.session.vault_v2.collections.len) {
        state.form_collection_pick_index = 0;
    }
}

fn moveFormCollectionPicker(state: *TuiState, direction: i8) void {
    ensureFormCollectionSelection(state);
    const count = state.session.vault_v2.collections.len;
    if (count == 0) {
        state.form_collection_pick_index = null;
        return;
    }
    if (state.form_collection_pick_index == null) {
        state.form_collection_pick_index = if (direction >= 0) 0 else count - 1;
        return;
    }
    var idx = state.form_collection_pick_index.?;
    if (direction >= 0) {
        idx = (idx + 1) % count;
    } else {
        idx = if (idx == 0) count - 1 else idx - 1;
    }
    state.form_collection_pick_index = idx;
}

fn toggleCurrentFormCollection(state: *TuiState) void {
    ensureFormCollectionSelection(state);
    const selected = state.form_collection_selection orelse return;
    const idx = state.form_collection_pick_index orelse return;
    if (idx >= selected.len) return;
    selected[idx] = !selected[idx];
    writeFormCollectionSelectionToField(state);
}

fn clearFormCollections(state: *TuiState) void {
    ensureFormCollectionSelection(state);
    if (state.form_collection_selection) |selected| @memset(selected, false);
    writeFormCollectionSelectionToField(state);
}

fn syncFormPickersForActiveField(state: *TuiState, creation_mode: bool) void {
    if (!creation_mode) return;
    if (folderFieldIsActive(state)) {
        syncFolderPickerFromCurrentField(state);
    } else if (collectionFieldIsActive(state)) {
        ensureFormCollectionSelection(state);
    }
}

fn formFieldIndexAtMouse(state: *const TuiState, row: u16, col: u16) ?usize {
    if (col < 3) return null;
    for (0..state.form_field_count) |i| {
        if (state.form_field_rows[i] == row) return i;
    }
    return null;
}

fn formPasswordButtonsVisible(state: *const TuiState, creation_mode: bool) bool {
    return creation_mode and !state.form_is_category and state.item_form_type == .login;
}

fn drawFormPasswordButtons(w: *Writer, state: *TuiState, row: u16, creation_mode: bool) !void {
    state.form_buttons_row = row;
    if (!formPasswordButtonsVisible(state, creation_mode)) return;
    const hovered = state.form_hover_button;
    try w.writeAll("  ");
    const reveal_label = if (state.form_password_revealed) "hide (p)" else "reveal (p)";
    try drawDetailButton(w, reveal_label, hovered == .reveal);
    try w.writeAll("  ");
    try drawDetailButton(w, "copy (y)", hovered == .copy);
    try w.writeAll("  ");
    try drawDetailButton(w, "generate (ctrl+g)", hovered == .generate);
    try w.writeAll("\n");
}

fn formPasswordButtonAtMouse(state: *const TuiState, row: u16, col: u16, creation_mode: bool) FormPasswordButton {
    if (!formPasswordButtonsVisible(state, creation_mode)) return .none;
    if (row != state.form_buttons_row) return .none;

    const reveal_text = if (state.form_password_revealed) "[hide (p)]" else "[reveal (p)]";
    const copy_text = "[copy (y)]";
    const generate_text = "[generate (ctrl+g)]";
    const reveal_start: u16 = 3;
    const reveal_end: u16 = reveal_start + @as(u16, @intCast(reveal_text.len - 1));
    const copy_start: u16 = reveal_end + 3;
    const copy_end: u16 = copy_start + @as(u16, @intCast(copy_text.len - 1));
    const generate_start: u16 = copy_end + 3;
    const generate_end: u16 = generate_start + @as(u16, @intCast(generate_text.len - 1));

    if (col >= reveal_start and col <= reveal_end) return .reveal;
    if (col >= copy_start and col <= copy_end) return .copy;
    if (col >= generate_start and col <= generate_end) return .generate;
    return .none;
}

fn toggleFormPasswordReveal(state: *TuiState) void {
    state.form_password_revealed = !state.form_password_revealed;
    state.setMessage(if (state.form_password_revealed) "Password visible" else "Password hidden", false);
}

fn copyFormPassword(state: *TuiState) void {
    if (state.item_form_type != .login) return;
    const pw = state.form_fields[2].slice();
    if (pw.len == 0) {
        state.setTimedMessage("Password field is empty", true, 3000);
        return;
    }
    const copied = utils.copyToClipboard(state.allocator, pw) catch false;
    if (copied) {
        state.setTimedMessage("Password copied to clipboard", false, 3000);
    } else {
        state.setTimedMessage("Clipboard unavailable (pbcopy/wl-copy/xclip)", true, 3000);
    }
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

    storage.saveVaultV2(
        state.allocator,
        state.session.vault_v2,
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

fn startDetailEditForField(state: *TuiState, field: DetailField) !void {
    if (state.selected >= state.session.vault_v2.items.len) return;
    const item = state.session.vault_v2.items[state.selected];

    if (field == .password) {
        state.clearDetailEditState();
        state.detail_password_confirm_pending = true;
        state.setMessage("Replace password? press y to confirm, n to cancel", false);
        return;
    }

    state.clearDetailEditState();
    state.detail_edit_field = field;

    switch (field) {
        .folder => syncDetailFolderPickerFromItem(state, item),
        .collections => try initDetailCollectionSelectionFromItem(state, item),
        else => loadDetailEditBufferFromItem(state, item, field),
    }
}

fn startDetailPasswordEdit(state: *TuiState) void {
    state.clearDetailEditState();
    state.detail_edit_field = .password;
    state.detail_edit_buffer.clear();
    if (state.selected < state.session.vault_v2.items.len) {
        const item = state.session.vault_v2.items[state.selected];
        if (item.login != null and item.login.?.password != null) {
            state.detail_edit_buffer.setFromSlice(item.login.?.password.?);
        }
    }
    state.setMessage("Enter new password, Enter save, Ctrl+G generate", false);
}

fn revealPasswordInline(state: *TuiState, timeout_ms: u64) void {
    const now = std.time.nanoTimestamp();
    state.detail_password_reveal_until_ns = now + @as(i128, @intCast(timeout_ms)) * @as(i128, std.time.ns_per_ms);
    state.setTimedMessage("Password revealed", false, timeout_ms);
}

fn loadDetailEditBufferFromItem(state: *TuiState, item: schema.Item, field: DetailField) void {
    state.detail_edit_buffer.clear();
    switch (field) {
        .name => state.detail_edit_buffer.setFromSlice(item.name),
        .user => if (item.login != null and item.login.?.username != null) state.detail_edit_buffer.setFromSlice(item.login.?.username.?),
        .totp => if (item.login != null and item.login.?.totp != null) state.detail_edit_buffer.setFromSlice(item.login.?.totp.?),
        .url => {
            if (item.login != null and item.login.?.uris != null and item.login.?.uris.?.len > 0 and item.login.?.uris.?[0].uri != null) {
                state.detail_edit_buffer.setFromSlice(item.login.?.uris.?[0].uri.?);
            }
        },
        .notes => if (item.notes) |notes| state.detail_edit_buffer.setFromSlice(notes),
        .org_id => if (item.organizationId) |org_id| state.detail_edit_buffer.setFromSlice(org_id),
        .note_type => {
            if (item.secureNote != null and item.secureNote.?.type != null) {
                var buf: [4]u8 = undefined;
                const out = std.fmt.bufPrint(&buf, "{d}", .{item.secureNote.?.type.?}) catch "";
                state.detail_edit_buffer.setFromSlice(out);
            }
        },
        .number => if (item.card != null and item.card.?.number != null) state.detail_edit_buffer.setFromSlice(item.card.?.number.?),
        .brand => if (item.card != null and item.card.?.brand != null) state.detail_edit_buffer.setFromSlice(item.card.?.brand.?),
        .code => if (item.card != null and item.card.?.code != null) state.detail_edit_buffer.setFromSlice(item.card.?.code.?),
        .holder => if (item.card != null and item.card.?.cardholderName != null) state.detail_edit_buffer.setFromSlice(item.card.?.cardholderName.?),
        .exp_month => if (item.card != null and item.card.?.expMonth != null) state.detail_edit_buffer.setFromSlice(item.card.?.expMonth.?),
        .exp_year => if (item.card != null and item.card.?.expYear != null) state.detail_edit_buffer.setFromSlice(item.card.?.expYear.?),
        .first_name => if (item.identity != null and item.identity.?.firstName != null) state.detail_edit_buffer.setFromSlice(item.identity.?.firstName.?),
        .last_name => if (item.identity != null and item.identity.?.lastName != null) state.detail_edit_buffer.setFromSlice(item.identity.?.lastName.?),
        .email => if (item.identity != null and item.identity.?.email != null) state.detail_edit_buffer.setFromSlice(item.identity.?.email.?),
        .phone => if (item.identity != null and item.identity.?.phone != null) state.detail_edit_buffer.setFromSlice(item.identity.?.phone.?),
        .password, .folder, .collections => {},
    }
}

fn syncDetailFolderPickerFromItem(state: *TuiState, item: schema.Item) void {
    state.detail_folder_pick_index = null;
    if (item.folderId) |folder_id| {
        for (state.session.vault_v2.folders, 0..) |folder, idx| {
            if (std.mem.eql(u8, folder.id, folder_id)) {
                state.detail_folder_pick_index = idx;
                break;
            }
        }
    }
}

fn initDetailCollectionSelectionFromItem(state: *TuiState, item: schema.Item) !void {
    state.clearDetailCollectionSelection();
    const collections = state.session.vault_v2.collections;
    var flags = try state.allocator.alloc(bool, collections.len);
    @memset(flags, false);

    if (item.collectionIds) |collection_ids| {
        for (collection_ids) |maybe_collection_id| {
            const collection_id = maybe_collection_id orelse continue;
            for (collections, 0..) |collection, idx| {
                if (std.mem.eql(u8, collection.id, collection_id)) {
                    flags[idx] = true;
                    break;
                }
            }
        }
    }
    state.detail_collection_selection = flags;

    if (collections.len == 0) {
        state.detail_collection_pick_index = null;
        return;
    }

    state.detail_collection_pick_index = 0;
    for (flags, 0..) |selected, idx| {
        if (selected) {
            state.detail_collection_pick_index = idx;
            break;
        }
    }
}

fn moveDetailFolderPicker(state: *TuiState, direction: i8) void {
    const folders = state.session.vault_v2.folders;
    if (folders.len == 0) {
        state.detail_folder_pick_index = null;
        return;
    }

    const max_index: i32 = @intCast(folders.len - 1);
    var pos: i32 = if (state.detail_folder_pick_index) |idx| @intCast(idx) else -1;
    if (direction >= 0) {
        pos += 1;
        if (pos > max_index) pos = -1;
    } else {
        pos -= 1;
        if (pos < -1) pos = max_index;
    }
    state.detail_folder_pick_index = if (pos < 0) null else @as(usize, @intCast(pos));
}

fn moveDetailCollectionPicker(state: *TuiState, direction: i8) void {
    const count = state.session.vault_v2.collections.len;
    if (count == 0) {
        state.detail_collection_pick_index = null;
        return;
    }

    if (state.detail_collection_pick_index == null) {
        state.detail_collection_pick_index = if (direction >= 0) 0 else count - 1;
        return;
    }

    var idx = state.detail_collection_pick_index.?;
    if (direction >= 0) {
        idx = (idx + 1) % count;
    } else {
        idx = if (idx == 0) count - 1 else idx - 1;
    }
    state.detail_collection_pick_index = idx;
}

fn toggleCurrentDetailCollection(state: *TuiState) void {
    const selected = state.detail_collection_selection orelse return;
    const idx = state.detail_collection_pick_index orelse return;
    if (idx >= selected.len) return;
    selected[idx] = !selected[idx];
}

fn setOptionalString(
    allocator: std.mem.Allocator,
    target: *?[]const u8,
    value: []const u8,
) !void {
    if (target.*) |old| allocator.free(old);
    target.* = if (value.len > 0) try allocator.dupe(u8, value) else null;
}

fn setFolderFromDetailSelection(state: *TuiState, item: *schema.Item) !void {
    const allocator = state.session.vault_v2_allocator;
    if (item.folderId) |old| allocator.free(old);
    if (state.detail_folder_pick_index) |idx| {
        if (idx < state.session.vault_v2.folders.len) {
            item.folderId = try allocator.dupe(u8, state.session.vault_v2.folders[idx].id);
        } else {
            item.folderId = null;
        }
    } else {
        item.folderId = null;
    }
}

fn setCollectionsFromDetailSelection(state: *TuiState, item: *schema.Item) !void {
    const allocator = state.session.vault_v2_allocator;
    if (item.collectionIds) |ids| {
        for (ids) |maybe_id| {
            if (maybe_id) |id| allocator.free(id);
        }
        allocator.free(ids);
    }

    const selected = state.detail_collection_selection orelse {
        item.collectionIds = null;
        return;
    };

    var count: usize = 0;
    for (selected) |is_selected| {
        if (is_selected) count += 1;
    }
    if (count == 0) {
        item.collectionIds = null;
        return;
    }

    var ids = try allocator.alloc(?[]const u8, count);
    var out_idx: usize = 0;
    errdefer {
        for (0..out_idx) |i| allocator.free(ids[i].?);
        allocator.free(ids);
    }
    for (selected, 0..) |is_selected, idx| {
        if (!is_selected) continue;
        ids[out_idx] = try allocator.dupe(u8, state.session.vault_v2.collections[idx].id);
        out_idx += 1;
    }
    item.collectionIds = ids;
}

fn touchItemRevision(allocator: std.mem.Allocator, item: *schema.Item) !void {
    var now_buf: [20]u8 = undefined;
    if (item.revisionDate) |old| allocator.free(old);
    item.revisionDate = try allocator.dupe(u8, model.nowTimestamp(&now_buf));
}

fn saveActiveDetailField(state: *TuiState) !bool {
    const field = state.detail_edit_field orelse return true;
    if (state.selected >= state.session.vault_v2.items.len) {
        state.setMessage("Invalid item selection", true);
        return false;
    }

    const allocator = state.session.vault_v2_allocator;
    var item = &state.session.vault_v2.items[state.selected];
    const value = state.detail_edit_buffer.slice();
    var changed = false;

    switch (field) {
        .name => {
            if (item.type == 1) {
                const username = if (item.login != null and item.login.?.username != null) item.login.?.username.? else "";
                if (value.len == 0 and username.len == 0) {
                    state.setMessage("Name or user is required", true);
                    return false;
                }
            } else if (value.len == 0) {
                state.setMessage("Name is required", true);
                return false;
            }
            const new_name = if (value.len > 0) value else "(unnamed)";
            const duped = try allocator.dupe(u8, new_name);
            allocator.free(item.name);
            item.name = duped;
            changed = true;
        },
        .user => {
            if (item.login == null) item.login = .{};
            try setOptionalString(allocator, &item.login.?.username, value);
            changed = true;
        },
        .password => {
            if (value.len == 0) {
                state.setMessage("Password unchanged (empty input)", true);
                state.clearDetailEditState();
                return true;
            }
            if (item.login == null) item.login = .{};
            try setOptionalString(allocator, &item.login.?.password, value);
            changed = true;
        },
        .totp => {
            if (item.login == null) item.login = .{};
            try setOptionalString(allocator, &item.login.?.totp, value);
            changed = true;
        },
        .url => {
            if (item.login == null) item.login = .{};
            if (item.login.?.uris) |uris| {
                for (uris) |old_uri| {
                    if (old_uri.uri) |old| allocator.free(old);
                }
                allocator.free(uris);
            }
            if (value.len > 0) {
                var uris = try allocator.alloc(schema.LoginUri, 1);
                uris[0] = .{
                    .uri = try allocator.dupe(u8, value),
                    .match = null,
                };
                item.login.?.uris = uris;
            } else {
                item.login.?.uris = null;
            }
            changed = true;
        },
        .notes => {
            try setOptionalString(allocator, &item.notes, value);
            changed = true;
        },
        .folder => {
            try setFolderFromDetailSelection(state, item);
            changed = true;
        },
        .collections => {
            try setCollectionsFromDetailSelection(state, item);
            changed = true;
        },
        .org_id => {
            try setOptionalString(allocator, &item.organizationId, value);
            changed = true;
        },
        .note_type => {
            if (item.secureNote == null) item.secureNote = .{};
            if (value.len == 0) {
                item.secureNote.?.type = null;
            } else {
                item.secureNote.?.type = std.fmt.parseInt(u8, value, 10) catch 0;
            }
            changed = true;
        },
        .number => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.number, value);
            changed = true;
        },
        .brand => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.brand, value);
            changed = true;
        },
        .code => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.code, value);
            changed = true;
        },
        .holder => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.cardholderName, value);
            changed = true;
        },
        .exp_month => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.expMonth, value);
            changed = true;
        },
        .exp_year => {
            if (item.card == null) item.card = .{};
            try setOptionalString(allocator, &item.card.?.expYear, value);
            changed = true;
        },
        .first_name => {
            if (item.identity == null) item.identity = .{};
            try setOptionalString(allocator, &item.identity.?.firstName, value);
            changed = true;
        },
        .last_name => {
            if (item.identity == null) item.identity = .{};
            try setOptionalString(allocator, &item.identity.?.lastName, value);
            changed = true;
        },
        .email => {
            if (item.identity == null) item.identity = .{};
            try setOptionalString(allocator, &item.identity.?.email, value);
            changed = true;
        },
        .phone => {
            if (item.identity == null) item.identity = .{};
            try setOptionalString(allocator, &item.identity.?.phone, value);
            changed = true;
        },
    }

    if (changed) {
        try touchItemRevision(allocator, item);
        try rebuildRuntimeFromV2(state);
        state.session.dirty = true;
        try persistVault(state);
        state.setMessage("Field updated", false);
    }
    state.clearDetailEditState();
    return true;
}

// ─── Input handling ─────────────────────────────────────────────────────────

fn handleInput(state: *TuiState, ev: KeyEvent) !void {
    state.expireMessageIfNeeded();

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
        .mouse_move => {
            state.detail_hover_button = .none;
            state.item_hover_index = itemIndexAtMouseRow(state, ev.mouse_row);
        },
        .mouse_left => {
            if (count == 0) return;
            if (itemIndexAtMouseRow(state, ev.mouse_row)) |idx| {
                state.item_hover_index = idx;
                state.selected = idx;
                state.clearDetailEditState();
                state.detail_hover_button = .none;
                state.detail_hover_field = null;
                state.screen = .item_detail;
            }
        },
        .up => {
            if (state.selected > 0) state.selected -= 1;
        },
        .down => {
            if (count > 0 and state.selected < count - 1) state.selected += 1;
        },
        .enter => {
            if (count > 0) {
                state.item_hover_index = null;
                state.clearDetailEditState();
                state.detail_hover_button = .none;
                state.detail_hover_field = null;
                state.screen = .item_detail;
            }
        },
        .char => switch (ev.char) {
            'q' => state.running = false,
            'n' => {
                state.item_hover_index = null;
                initItemFormForType(state, .login);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '1' => {
                state.item_hover_index = null;
                initItemFormForType(state, .login);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '2' => {
                state.item_hover_index = null;
                initItemFormForType(state, .secure_note);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '3' => {
                state.item_hover_index = null;
                initItemFormForType(state, .card);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            '4' => {
                state.item_hover_index = null;
                initItemFormForType(state, .identity);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            'e' => {
                if (count > 0) {
                    state.item_hover_index = null;
                    const item = state.session.vault_v2.items[state.selected];
                    state.form_editing_index = state.selected;
                    prefillItemFormFromV2(state, item);
                    state.screen = .item_form;
                }
            },
            'd' => {
                if (count > 0) {
                    state.item_hover_index = null;
                    const selected_item = state.session.vault_v2.items[state.selected];
                    state.delete_target_name = if (selected_item.name.len > 0) selected_item.name else "(unnamed)";
                    state.delete_is_category = false;
                    state.prev_screen = .item_list;
                    state.screen = .confirm_delete;
                }
            },
            'c' => {
                state.item_hover_index = null;
                state.selected = 0;
                state.screen = .category_list;
            },
            '?' => {
                state.item_hover_index = null;
                state.prev_screen = .item_list;
                state.screen = .help;
            },
            else => {},
        },
        else => {},
    }
}

fn openDetailClassicEdit(state: *TuiState) void {
    const item = state.session.vault_v2.items[state.selected];
    state.form_editing_index = state.selected;
    prefillItemFormFromV2(state, item);
    state.detail_hover_button = .none;
    state.detail_hover_field = null;
    state.detail_action_hover = .none;
    state.screen = .item_form;
}

fn openDetailDeleteConfirm(state: *TuiState) void {
    const selected_item = state.session.vault_v2.items[state.selected];
    state.delete_target_name = if (selected_item.name.len > 0) selected_item.name else "(unnamed)";
    state.delete_is_category = false;
    state.prev_screen = .item_detail;
    state.detail_hover_button = .none;
    state.detail_hover_field = null;
    state.detail_action_hover = .none;
    state.screen = .confirm_delete;
}

fn openDetailHelp(state: *TuiState) void {
    state.prev_screen = .item_detail;
    state.detail_hover_button = .none;
    state.detail_hover_field = null;
    state.detail_action_hover = .none;
    state.screen = .help;
}

fn detailCancelOrBack(state: *TuiState) void {
    if (state.detail_password_confirm_pending) {
        state.detail_password_confirm_pending = false;
        return;
    }
    if (state.detail_edit_field != null) {
        state.clearDetailEditState();
        state.setMessage("Edit canceled", false);
        return;
    }
    state.detail_hover_button = .none;
    state.detail_hover_field = null;
    state.detail_action_hover = .none;
    state.screen = .item_list;
}

fn handleItemDetail(state: *TuiState, ev: KeyEvent) !void {
    if (state.selected >= state.session.vault_v2.items.len) {
        state.screen = .item_list;
        return;
    }

    switch (ev.key) {
        .mouse_move => {
            state.detail_action_hover = detailFooterActionAtMouse(state, ev.mouse_row, ev.mouse_col);
            if (state.detail_action_hover != .none) {
                state.detail_hover_button = .none;
                state.detail_hover_field = null;
                return;
            }
            state.detail_hover_button = .none;
            state.detail_hover_field = detailFieldAtMouse(state, ev.mouse_row, ev.mouse_col);
        },
        .mouse_left => {
            if (state.detail_popover_kind != .none) {
                if (detailPopoverOptionAtMouse(state, ev.mouse_row)) |opt_idx| {
                    switch (state.detail_popover_kind) {
                        .folder => {
                            state.setTimedMessage("Use Up/Down to select folder", false, 2000);
                        },
                        .collections => {
                            if (state.detail_collection_selection) |selected| {
                                if (opt_idx < selected.len) {
                                    state.detail_collection_pick_index = opt_idx;
                                    selected[opt_idx] = !selected[opt_idx];
                                }
                            }
                        },
                        .none => {},
                    }
                    return;
                }
            }

            const menu_action = detailFooterActionAtMouse(state, ev.mouse_row, ev.mouse_col);
            if (menu_action != .none) {
                state.detail_action_hover = menu_action;
                switch (menu_action) {
                    .edit => openDetailClassicEdit(state),
                    .delete => openDetailDeleteConfirm(state),
                    .save_field => {
                        if (state.detail_edit_field != null) {
                            _ = try saveActiveDetailField(state);
                        } else {
                            state.setTimedMessage("No active field to save", true, 2000);
                        }
                    },
                    .cancel_back => detailCancelOrBack(state),
                    .reveal => {
                        if (state.detail_edit_field == null and !state.detail_password_confirm_pending) {
                            revealPasswordInline(state, 3000);
                        } else {
                            state.setTimedMessage("Finish field editing first", true, 2000);
                        }
                    },
                    .copy => {
                        if (state.detail_edit_field == null and !state.detail_password_confirm_pending) {
                            const pw = itemPrimarySecret(state.session.vault_v2.items[state.selected]);
                            const copied = utils.copyToClipboard(state.allocator, pw) catch false;
                            if (copied) {
                                state.setTimedMessage("Password copied to clipboard", false, 3000);
                            } else {
                                state.setTimedMessage("Clipboard unavailable (pbcopy/wl-copy/xclip)", true, 3000);
                            }
                        } else {
                            state.setTimedMessage("Finish field editing first", true, 2000);
                        }
                    },
                    .generate => {
                        if (state.detail_edit_field != null and state.detail_edit_field.? == .password) {
                            try generatePasswordInDetailField(state);
                        } else {
                            state.setTimedMessage("Generate is available in password edit", true, 2000);
                        }
                    },
                    .help => openDetailHelp(state),
                    .none => {},
                }
                return;
            }

            if (detailFieldAtMouse(state, ev.mouse_row, ev.mouse_col)) |clicked_field| {
                state.detail_action_hover = .none;
                if (state.detail_password_confirm_pending) {
                    state.detail_password_confirm_pending = false;
                }
                if (state.detail_edit_field) |active_field| {
                    if (active_field != clicked_field) {
                        const saved = try saveActiveDetailField(state);
                        if (!saved) return;
                    }
                }
                if (state.detail_edit_field == null or state.detail_edit_field.? != clicked_field) {
                    try startDetailEditForField(state, clicked_field);
                }
                return;
            }
        },
        .escape => {
            detailCancelOrBack(state);
        },
        .enter => {
            if (state.detail_edit_field != null) {
                _ = try saveActiveDetailField(state);
            }
        },
        .up => {
            if (state.detail_edit_field) |field| {
                switch (field) {
                    .folder => moveDetailFolderPicker(state, -1),
                    .collections => moveDetailCollectionPicker(state, -1),
                    else => {},
                }
            }
        },
        .down => {
            if (state.detail_edit_field) |field| {
                switch (field) {
                    .folder => moveDetailFolderPicker(state, 1),
                    .collections => moveDetailCollectionPicker(state, 1),
                    else => {},
                }
            }
        },
        .backspace => {
            if (state.detail_edit_field) |field| {
                switch (field) {
                    .folder, .collections => {},
                    else => state.detail_edit_buffer.deleteChar(),
                }
            }
        },
        .clear_line => {
            if (state.detail_edit_field) |field| {
                switch (field) {
                    .folder, .collections => {},
                    else => state.detail_edit_buffer.clear(),
                }
            }
        },
        .char => switch (ev.char) {
            else => {
                if (state.detail_password_confirm_pending) {
                    switch (ev.char) {
                        'y', 'Y' => startDetailPasswordEdit(state),
                        'n', 'N' => {
                            state.detail_password_confirm_pending = false;
                            state.setMessage("Password update canceled", false);
                        },
                        else => {},
                    }
                    return;
                }

                if (state.detail_edit_field) |field| {
                    if (ev.char == 7 and field == .password) {
                        try generatePasswordInDetailField(state);
                        return;
                    }
                    switch (field) {
                        .collections => if (ev.char == ' ') toggleCurrentDetailCollection(state),
                        .folder => {},
                        else => state.detail_edit_buffer.appendChar(ev.char),
                    }
                    return;
                }

                switch (ev.char) {
                    'e' => {
                        openDetailClassicEdit(state);
                    },
                    'd' => {
                        openDetailDeleteConfirm(state);
                    },
                    'p', 'P' => {
                        revealPasswordInline(state, 3000);
                    },
                    'y', 'Y' => {
                        const pw = itemPrimarySecret(state.session.vault_v2.items[state.selected]);
                        const copied = utils.copyToClipboard(state.allocator, pw) catch false;
                        if (copied) {
                            state.setTimedMessage("Password copied to clipboard", false, 3000);
                        } else {
                            state.setTimedMessage("Clipboard unavailable (pbcopy/wl-copy/xclip)", true, 3000);
                        }
                    },
                    '?' => {
                        openDetailHelp(state);
                    },
                    else => {},
                }
            },
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
    const creation_mode = isItemCreationForm(state, is_category);
    const password_field_idx: usize = if (!is_category and state.item_form_type == .login) 2 else std.math.maxInt(usize);

    if (creation_mode) {
        switch (ev.key) {
            .mouse_move => {
                state.form_hover_button = formPasswordButtonAtMouse(state, ev.mouse_row, ev.mouse_col, creation_mode);
                if (state.form_hover_button == .none) {
                    state.form_hover_field = formFieldIndexAtMouse(state, ev.mouse_row, ev.mouse_col);
                } else {
                    state.form_hover_field = null;
                }
            },
            .mouse_left => {
                const button = formPasswordButtonAtMouse(state, ev.mouse_row, ev.mouse_col, creation_mode);
                if (button != .none) {
                    state.form_hover_button = button;
                    switch (button) {
                        .reveal => toggleFormPasswordReveal(state),
                        .copy => copyFormPassword(state),
                        .generate => try generatePasswordInForm(state),
                        .none => {},
                    }
                    return;
                }

                if (formFieldIndexAtMouse(state, ev.mouse_row, ev.mouse_col)) |field_idx| {
                    if (field_idx < state.form_field_count) {
                        state.form_active_field = field_idx;
                        syncFormPickersForActiveField(state, creation_mode);
                    }
                    return;
                }
            },
            else => {},
        }
    }

    switch (ev.key) {
        .escape => {
            state.resetFormUiState();
            state.clearFormCollectionSelection();
            state.form_collection_pick_index = null;
            state.screen = if (is_category) .category_list else .item_list;
        },
        .enter => {
            if (is_category) {
                try saveCategoryForm(state);
            } else {
                try saveItemForm(state);
            }
            state.resetFormUiState();
            state.clearFormCollectionSelection();
            state.form_collection_pick_index = null;
        },
        .tab => {
            state.form_active_field = (state.form_active_field + 1) % state.form_field_count;
            syncFormPickersForActiveField(state, creation_mode);
        },
        .shift_tab => {
            state.form_active_field = if (state.form_active_field == 0)
                state.form_field_count - 1
            else
                state.form_active_field - 1;
            syncFormPickersForActiveField(state, creation_mode);
        },
        .up => {
            if (creation_mode and folderFieldIsActive(state)) {
                moveFolderPicker(state, -1);
            } else if (creation_mode and collectionFieldIsActive(state)) {
                moveFormCollectionPicker(state, -1);
            } else if (state.form_active_field > 0) {
                state.form_active_field -= 1;
                syncFormPickersForActiveField(state, creation_mode);
            }
        },
        .down => {
            if (creation_mode and folderFieldIsActive(state)) {
                moveFolderPicker(state, 1);
            } else if (creation_mode and collectionFieldIsActive(state)) {
                moveFormCollectionPicker(state, 1);
            } else {
                state.form_active_field = (state.form_active_field + 1) % state.form_field_count;
                syncFormPickersForActiveField(state, creation_mode);
            }
        },
        .left => {
            state.form_active_field = if (state.form_active_field == 0)
                state.form_field_count - 1
            else
                state.form_active_field - 1;
            syncFormPickersForActiveField(state, creation_mode);
        },
        .right => {
            state.form_active_field = (state.form_active_field + 1) % state.form_field_count;
            syncFormPickersForActiveField(state, creation_mode);
        },
        .backspace => {
            if (creation_mode and folderFieldIsActive(state)) {
                state.form_folder_pick_index = null;
                state.form_fields[folderFieldIndexForType(state.item_form_type)].clear();
            } else if (creation_mode and collectionFieldIsActive(state)) {
                clearFormCollections(state);
            } else {
                state.form_fields[state.form_active_field].deleteChar();
            }
        },
        .clear_line => {
            if (creation_mode and folderFieldIsActive(state)) {
                state.form_folder_pick_index = null;
                state.form_fields[folderFieldIndexForType(state.item_form_type)].clear();
            } else if (creation_mode and collectionFieldIsActive(state)) {
                clearFormCollections(state);
            } else {
                state.form_fields[state.form_active_field].clear();
            }
        },
        .char => |_| {
            if (!is_category and ev.char == 7 and state.item_form_type == .login) {
                try generatePasswordInForm(state);
                return;
            }
            if (!is_category and ev.char == 'p' and state.item_form_type == .login and (state.form_active_field == password_field_idx or creation_mode)) {
                if (creation_mode and state.form_active_field != password_field_idx and !folderFieldIsActive(state) and !collectionFieldIsActive(state)) {
                    // Keep text typing intact in regular text fields.
                } else {
                    toggleFormPasswordReveal(state);
                    return;
                }
            }
            if (!is_category and ev.char == 'y' and creation_mode and state.item_form_type == .login and !folderFieldIsActive(state) and !collectionFieldIsActive(state) and state.form_active_field != password_field_idx) {
                // typed as text
            } else if (!is_category and ev.char == 'y' and creation_mode and state.item_form_type == .login) {
                copyFormPassword(state);
                return;
            }
            if (!is_category and ev.char == 20 and state.item_form_type == .login) {
                toggleFormPasswordReveal(state);
                return;
            }
            if (creation_mode and collectionFieldIsActive(state)) {
                if (ev.char == ' ') toggleCurrentFormCollection(state);
                return;
            }
            if (creation_mode and folderFieldIsActive(state)) {
                state.form_folder_pick_index = null;
                return;
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

fn generatePasswordInDetailField(state: *TuiState) !void {
    if (state.detail_edit_field == null or state.detail_edit_field.? != .password) return;
    if (state.wordlist) |wl| {
        const pw = try bip39.generateMnemonic(state.allocator, wl, "-");
        defer state.allocator.free(pw);
        state.detail_edit_buffer.clear();
        state.detail_edit_buffer.setFromSlice(pw);
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
    defer state.clearDetailCollectionSelection();
    defer state.clearFormCollectionSelection();

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
    try w.writeAll(Term.enable_mouse);
    try w.flush();

    defer {
        w.writeAll(Term.disable_mouse) catch {};
        w.writeAll(Term.cursor_show) catch {};
        w.writeAll(Term.alt_screen_off) catch {};
        w.flush() catch {};
    }

    // Main loop
    while (state.running) {
        state.refreshSize();
        state.expireMessageIfNeeded();
        try render(w, &state);

        if (readKey(raw.fd)) |ev| {
            try handleInput(&state, ev);
        }
    }
}
