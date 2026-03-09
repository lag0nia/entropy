const std = @import("std");
const utils = @import("utils.zig");
const model = @import("model.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const bip39 = @import("bip39.zig");
const vault_service = @import("vault_service.zig");

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
    key: [crypto.KEY_LEN]u8,
    salt: [crypto.SALT_LEN]u8,
    vault_path: []const u8,
    dirty: bool = false,
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
    form_fields: [5]InputField = undefined,
    form_field_count: usize = 0,
    form_active_field: usize = 0,
    form_editing_index: ?usize = null, // null = creating new
    form_is_category: bool = false,

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
            return self.session.vault.categories.len;
        }
        return self.session.vault.items.len;
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
    const items = state.session.vault.items;
    const categories = state.session.vault.categories;

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
            try w.print("  {s}{s}{s} ", .{ Color.bg_bright_blue, Color.bright_white, Color.bold });
        } else {
            try w.writeAll("   ");
        }

        // Name
        const name = item.name orelse "(unnamed)";
        try w.print("{s}", .{name});

        // Category badge
        if (item.category_id) |cat_id| {
            for (categories) |cat| {
                if (std.mem.eql(u8, cat.id, cat_id)) {
                    if (is_selected) {
                        try w.print("  [{s}]", .{cat.name});
                    } else {
                        try w.print("  {s}[{s}]{s}", .{ Color.yellow, cat.name, Color.reset });
                    }
                    break;
                }
            }
        }

        // Mail (dimmed)
        if (item.mail) |mail| {
            if (is_selected) {
                try w.print("  {s}", .{mail});
            } else {
                try w.print("  {s}{s}{s}", .{ Color.dim, mail, Color.reset });
            }
        }

        if (is_selected) {
            try w.print("{s}", .{Color.reset});
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
    const items = state.session.vault.items;
    if (state.selected >= items.len) return;
    const item = items[state.selected];
    const categories = state.session.vault.categories;

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
        Color.cyan, Color.reset, item.name orelse "(none)",
    });

    // Mail
    try w.print("  {s}Mail:{s}     {s}\n", .{
        Color.cyan, Color.reset, item.mail orelse "(none)",
    });

    // Password (masked)
    try w.print("  {s}Password:{s} {s}", .{ Color.cyan, Color.reset, Color.dim });
    for (item.password) |_| {
        try w.writeAll(Icon.dot);
    }
    try w.print("{s}\n", .{Color.reset});

    // Notes
    try w.print("  {s}Notes:{s}    {s}\n", .{
        Color.cyan, Color.reset, item.notes orelse "(none)",
    });

    // Category
    var cat_name: []const u8 = "(none)";
    if (item.category_id) |cat_id| {
        for (categories) |cat| {
            if (std.mem.eql(u8, cat.id, cat_id)) {
                cat_name = cat.name;
                break;
            }
        }
    }
    try w.print("  {s}Category:{s} {s}\n", .{ Color.cyan, Color.reset, cat_name });

    try w.writeAll("\n");
    try w.print("  {s}p{s}{s} reveal password  {s}y{s}{s} copy password{s}\n", .{
        Color.bold, Color.reset, Color.dim, Color.bold, Color.reset, Color.dim, Color.reset,
    });
}

fn drawCategoryList(w: *Writer, state: *TuiState) !void {
    const categories = state.session.vault.categories;

    try w.writeAll("\n");
    try w.print("  {s}{s}Categories{s}\n", .{ Color.bold, Color.bright_white, Color.reset });
    try w.print("  {s}", .{Color.bright_black});
    var sep_i: usize = 0;
    while (sep_i < @min(state.cols -| 4, 50)) : (sep_i += 1) {
        try w.writeAll(Box.horizontal);
    }
    try w.print("{s}\n\n", .{Color.reset});

    if (categories.len == 0) {
        try w.print("  {s}No categories yet. Press {s}n{s}{s} to create one.{s}\n\n", .{
            Color.dim, Color.bold, Color.reset, Color.dim, Color.reset,
        });
        return;
    }

    for (categories, 0..) |cat, i| {
        const is_selected = (i == state.selected);
        if (is_selected) {
            try w.print("  {s}{s}{s} ", .{ Color.bg_bright_blue, Color.bright_white, Color.bold });
        } else {
            try w.writeAll("   ");
        }

        try w.print("{s}", .{cat.name});

        // Count items in this category
        var count: usize = 0;
        for (state.session.vault.items) |item| {
            if (item.category_id) |cid| {
                if (std.mem.eql(u8, cid, cat.id)) count += 1;
            }
        }

        if (is_selected) {
            try w.print("  ({d} items)", .{count});
            try w.print("{s}", .{Color.reset});
        } else {
            try w.print("  {s}({d} items){s}", .{ Color.dim, count, Color.reset });
        }
        try w.writeAll("\n");
    }
    try w.writeAll("\n");
}

fn drawForm(w: *Writer, state: *const TuiState) !void {
    const title = if (state.form_editing_index != null)
        (if (state.form_is_category) "Edit Category" else "Edit Item")
    else
        (if (state.form_is_category) "New Category" else "New Item");

    try w.writeAll("\n");
    try w.print("  {s}{s}{s}{s}\n", .{ Color.bold, Color.bright_white, title, Color.reset });
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

    try w.writeAll("\n");
    if (!state.form_is_category) {
        try w.print("  {s}Tab{s}{s} next field  {s}Ctrl+G{s}{s} generate password  {s}Enter{s}{s} save  {s}Esc{s}{s} cancel{s}\n", .{
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
            Color.bold,  Color.reset, Color.dim,
            Color.reset,
        });
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
    try w.writeAll("    Up/Down navigate, Enter detail, n new, e edit, d delete, c categories, q quit\n");

    try w.print("\n  {s}Item detail{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    p reveal password in message area, y copy password to clipboard\n");

    try w.print("\n  {s}Item/category forms{s}\n", .{ Color.cyan, Color.reset });
    try w.writeAll("    Tab next field, Enter save, Esc cancel\n");
    try w.writeAll("    Ctrl+G generate password (only item form)\n");

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
            try drawKeyHint(w, "n", "new");
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

fn initItemForm(state: *TuiState) void {
    state.form_is_category = false;
    state.form_field_count = 5;
    state.form_active_field = 0;
    state.form_fields[0] = .{ .label = "Name:" };
    state.form_fields[1] = .{ .label = "Mail:" };
    state.form_fields[2] = .{ .label = "Password:" };
    state.form_fields[3] = .{ .label = "Notes:" };
    state.form_fields[4] = .{ .label = "Category:" };
}

fn initCategoryForm(state: *TuiState) void {
    state.form_is_category = true;
    state.form_field_count = 1;
    state.form_active_field = 0;
    state.form_fields[0] = .{ .label = "Name:" };
}

fn saveItemForm(state: *TuiState) !void {
    const input = vault_service.ItemFormInput{
        .name = state.form_fields[0].slice(),
        .mail = state.form_fields[1].slice(),
        .password = state.form_fields[2].slice(),
        .notes = state.form_fields[3].slice(),
        .category_name = state.form_fields[4].slice(),
    };

    if (state.form_editing_index) |idx| {
        vault_service.updateItem(
            state.allocator,
            &state.session.vault,
            idx,
            input,
        ) catch |err| {
            switch (err) {
                error.NameOrMailRequired => state.setMessage("Name or mail is required", true),
                error.CategoryNotFound => state.setMessage("Category not found", true),
                error.ItemIndexOutOfRange => state.setMessage("Invalid item selection", true),
                else => return err,
            }
            return;
        };
        state.setMessage("Item updated", false);
    } else {
        vault_service.createItem(
            state.allocator,
            &state.session.vault,
            input,
            state.wordlist,
        ) catch |err| {
            switch (err) {
                error.NameOrMailRequired => state.setMessage("Name or mail is required", true),
                error.CategoryNotFound => state.setMessage("Category not found", true),
                error.NoWordlistLoaded => state.setMessage("No wordlist loaded for generation", true),
                else => return err,
            }
            return;
        };
        state.setMessage("Item created", false);
    }

    state.session.dirty = true;
    try persistVault(state);
    state.screen = .item_list;
}

fn saveCategoryForm(state: *TuiState) !void {
    const name = state.form_fields[0].slice();

    if (state.form_editing_index) |idx| {
        vault_service.updateCategory(
            state.allocator,
            &state.session.vault,
            idx,
            name,
        ) catch |err| {
            switch (err) {
                error.CategoryNameRequired => state.setMessage("Category name is required", true),
                error.CategoryNameAlreadyExists => state.setMessage("Category already exists", true),
                error.CategoryIndexOutOfRange => state.setMessage("Invalid category selection", true),
                else => return err,
            }
            return;
        };
        state.setMessage("Category updated", false);
    } else {
        vault_service.createCategory(
            state.allocator,
            &state.session.vault,
            name,
        ) catch |err| {
            switch (err) {
                error.CategoryNameRequired => state.setMessage("Category name is required", true),
                error.CategoryNameAlreadyExists => state.setMessage("Category already exists", true),
                else => return err,
            }
            return;
        };
        state.setMessage("Category created", false);
    }

    state.session.dirty = true;
    try persistVault(state);
    state.screen = .category_list;
    state.selected = 0;
}

fn deleteSelectedItem(state: *TuiState) !void {
    vault_service.deleteItem(
        state.allocator,
        &state.session.vault,
        state.selected,
    ) catch |err| {
        switch (err) {
            error.ItemIndexOutOfRange => state.setMessage("Invalid item selection", true),
            else => return err,
        }
        return;
    };

    if (state.selected > 0) state.selected -= 1;
    state.session.dirty = true;
    try persistVault(state);
    state.setMessage("Item deleted", false);
    state.screen = .item_list;
}

fn deleteSelectedCategory(state: *TuiState) !void {
    vault_service.deleteCategory(
        state.allocator,
        &state.session.vault,
        state.selected,
    ) catch |err| {
        switch (err) {
            error.CategoryIndexOutOfRange => state.setMessage("Invalid category selection", true),
            else => return err,
        }
        return;
    };

    if (state.selected > 0) state.selected -= 1;
    state.session.dirty = true;
    try persistVault(state);
    state.setMessage("Category deleted", false);
    state.screen = .category_list;
}

fn persistVault(state: *TuiState) !void {
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
    state.session.dirty = false;
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
    const count = state.session.vault.items.len;
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
                initItemForm(state);
                state.form_editing_index = null;
                state.screen = .item_form;
            },
            'e' => {
                if (count > 0) {
                    const item = state.session.vault.items[state.selected];
                    initItemForm(state);
                    state.form_editing_index = state.selected;
                    if (item.name) |n| state.form_fields[0].setFromSlice(n);
                    if (item.mail) |m| state.form_fields[1].setFromSlice(m);
                    state.form_fields[2].setFromSlice(item.password);
                    if (item.notes) |nt| state.form_fields[3].setFromSlice(nt);
                    // Resolve category name
                    if (item.category_id) |cid| {
                        for (state.session.vault.categories) |cat| {
                            if (std.mem.eql(u8, cat.id, cid)) {
                                state.form_fields[4].setFromSlice(cat.name);
                                break;
                            }
                        }
                    }
                    state.screen = .item_form;
                }
            },
            'd' => {
                if (count > 0) {
                    state.delete_target_name = state.session.vault.items[state.selected].name orelse "(unnamed)";
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
                const item = state.session.vault.items[state.selected];
                initItemForm(state);
                state.form_editing_index = state.selected;
                if (item.name) |n| state.form_fields[0].setFromSlice(n);
                if (item.mail) |m| state.form_fields[1].setFromSlice(m);
                state.form_fields[2].setFromSlice(item.password);
                if (item.notes) |nt| state.form_fields[3].setFromSlice(nt);
                if (item.category_id) |cid| {
                    for (state.session.vault.categories) |cat| {
                        if (std.mem.eql(u8, cat.id, cid)) {
                            state.form_fields[4].setFromSlice(cat.name);
                            break;
                        }
                    }
                }
                state.screen = .item_form;
            },
            'd' => {
                state.delete_target_name = state.session.vault.items[state.selected].name orelse "(unnamed)";
                state.delete_is_category = false;
                state.prev_screen = .item_detail;
                state.screen = .confirm_delete;
            },
            'p' => {
                // Toggle reveal password (just show it as a message for now)
                const pw = state.session.vault.items[state.selected].password;
                state.setMessage(pw, false);
            },
            'y' => {
                const pw = state.session.vault.items[state.selected].password;
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
    const count = state.session.vault.categories.len;
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
                initCategoryForm(state);
                state.form_editing_index = null;
                state.screen = .category_form;
            },
            'e' => {
                if (count > 0) {
                    initCategoryForm(state);
                    state.form_editing_index = state.selected;
                    state.form_fields[0].setFromSlice(state.session.vault.categories[state.selected].name);
                    state.screen = .category_form;
                }
            },
            'd' => {
                if (count > 0) {
                    state.delete_target_name = state.session.vault.categories[state.selected].name;
                    state.delete_is_category = true;
                    state.prev_screen = .category_list;
                    state.screen = .confirm_delete;
                }
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
        .backspace => {
            state.form_fields[state.form_active_field].deleteChar();
        },
        .char => |_| {
            if (!is_category and ev.char == 7) {
                try generatePasswordInForm(state);
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
