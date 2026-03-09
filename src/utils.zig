const std = @import("std");

/// ANSI color codes for TUI styling
pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";
    pub const underline = "\x1b[4m";

    // Foreground colors
    pub const black = "\x1b[30m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
    pub const white = "\x1b[37m";

    // Bright foreground
    pub const bright_black = "\x1b[90m";
    pub const bright_red = "\x1b[91m";
    pub const bright_green = "\x1b[92m";
    pub const bright_yellow = "\x1b[93m";
    pub const bright_blue = "\x1b[94m";
    pub const bright_magenta = "\x1b[95m";
    pub const bright_cyan = "\x1b[96m";
    pub const bright_white = "\x1b[97m";

    // Background colors
    pub const bg_black = "\x1b[40m";
    pub const bg_red = "\x1b[41m";
    pub const bg_green = "\x1b[42m";
    pub const bg_yellow = "\x1b[43m";
    pub const bg_blue = "\x1b[44m";
    pub const bg_magenta = "\x1b[45m";
    pub const bg_cyan = "\x1b[46m";
    pub const bg_white = "\x1b[47m";

    // Bright background
    pub const bg_bright_black = "\x1b[100m";
    pub const bg_bright_blue = "\x1b[104m";
    pub const bg_bright_cyan = "\x1b[106m";
};

/// Box-drawing characters (Unicode)
pub const Box = struct {
    pub const top_left = "\u{250c}"; // ┌
    pub const top_right = "\u{2510}"; // ┐
    pub const bottom_left = "\u{2514}"; // └
    pub const bottom_right = "\u{2518}"; // ┘
    pub const horizontal = "\u{2500}"; // ─
    pub const vertical = "\u{2502}"; // │
    pub const tee_right = "\u{251c}"; // ├
    pub const tee_left = "\u{2524}"; // ┤
    pub const tee_down = "\u{252c}"; // ┬
    pub const tee_up = "\u{2534}"; // ┴
    pub const cross = "\u{253c}"; // ┼

    // Double line variants
    pub const d_top_left = "\u{2554}"; // ╔
    pub const d_top_right = "\u{2557}"; // ╗
    pub const d_bottom_left = "\u{255a}"; // ╚
    pub const d_bottom_right = "\u{255d}"; // ╝
    pub const d_horizontal = "\u{2550}"; // ═
    pub const d_vertical = "\u{2551}"; // ║

    // Rounded corners
    pub const r_top_left = "\u{256d}"; // ╭
    pub const r_top_right = "\u{256e}"; // ╮
    pub const r_bottom_left = "\u{2570}"; // ╰
    pub const r_bottom_right = "\u{256f}"; // ╯
};

/// Icons using Unicode symbols
pub const Icon = struct {
    pub const lock = "\u{f023}"; //
    pub const unlock = "\u{f09c}"; //
    pub const key = "\u{2511}"; // ┑ (simple key representation)
    pub const folder = "\u{f07b}"; //
    pub const search = "\u{f002}"; //
    pub const check = "\u{2714}"; // ✔
    pub const cross_mark = "\u{2718}"; // ✘
    pub const arrow_right = "\u{25b6}"; // ▶
    pub const arrow_down = "\u{25bc}"; // ▼
    pub const dot = "\u{2022}"; // •
    pub const star = "\u{2605}"; // ★
    pub const shield = "\u{25c6}"; // ◆
};

/// Terminal control sequences
pub const Term = struct {
    pub const clear_screen = "\x1b[2J";
    pub const cursor_home = "\x1b[H";
    pub const cursor_hide = "\x1b[?25l";
    pub const cursor_show = "\x1b[?25h";
    pub const alt_screen_on = "\x1b[?1049h";
    pub const alt_screen_off = "\x1b[?1049l";
    pub const enable_mouse = "\x1b[?1000h";
    pub const disable_mouse = "\x1b[?1000l";

    /// Move cursor to row, col (1-indexed)
    pub fn moveTo(buf: []u8, row: u16, col: u16) []const u8 {
        const len = std.fmt.bufPrint(buf, "\x1b[{d};{d}H", .{ row, col }) catch return "";
        return buf[0..len.len];
    }

    /// Get terminal size via ioctl
    pub fn getSize() struct { rows: u16, cols: u16 } {
        var ws: std.posix.winsize = undefined;
        const rc = std.posix.system.ioctl(std.posix.STDOUT_FILENO, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
        if (rc == 0) {
            return .{ .rows = ws.row, .cols = ws.col };
        }
        // Fallback
        return .{ .rows = 24, .cols = 80 };
    }
};

/// Read a line of input from stdin (blocking, byte by byte)
pub fn readLine(allocator: std.mem.Allocator) !?[]u8 {
    const stdin_fd = std.fs.File.stdin().handle;

    var line: std.ArrayList(u8) = .{};
    errdefer line.deinit(allocator);

    while (true) {
        var buf: [1]u8 = undefined;
        const n = std.posix.read(stdin_fd, &buf) catch |err| switch (err) {
            else => return err,
        };
        if (n == 0) {
            // EOF
            if (line.items.len > 0) return try line.toOwnedSlice(allocator);
            return null;
        }

        if (buf[0] == '\n') {
            return try line.toOwnedSlice(allocator);
        }

        try line.append(allocator, buf[0]);
    }
}

/// Read password from stdin with echo disabled
pub fn readPassword(allocator: std.mem.Allocator, prompt: []const u8) ![]u8 {
    if (prompt.len > 0) {
        const stdout_file = std.fs.File.stdout();
        var buf: [1024]u8 = undefined;
        var fw = stdout_file.writer(&buf);
        try fw.interface.writeAll(prompt);
        try fw.interface.flush();
    }

    // Disable echo
    const stdin_fd = std.fs.File.stdin().handle;
    var termios = try std.posix.tcgetattr(stdin_fd);
    const old_lflag = termios.lflag;
    termios.lflag.ECHO = false;
    try std.posix.tcsetattr(stdin_fd, .FLUSH, termios);

    defer {
        // Restore echo
        termios.lflag = old_lflag;
        std.posix.tcsetattr(stdin_fd, .FLUSH, termios) catch {};
        // Print newline after password input
        const newline = "\n";
        _ = std.posix.write(std.fs.File.stdout().handle, newline) catch {};
    }

    return (try readLine(allocator)) orelse error.EndOfStream;
}

/// Repeat a string N times into a buffer
pub fn repeatStr(allocator: std.mem.Allocator, str: []const u8, count: usize) ![]const u8 {
    const result = try allocator.alloc(u8, str.len * count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        @memcpy(result[i * str.len .. (i + 1) * str.len], str);
    }
    return result;
}

/// Try to copy text to system clipboard. Returns false when no clipboard backend is available.
pub fn copyToClipboard(allocator: std.mem.Allocator, text: []const u8) !bool {
    if (try copyWithCommand(allocator, &.{ "pbcopy" }, text)) return true;
    if (try copyWithCommand(allocator, &.{ "wl-copy" }, text)) return true;
    if (try copyWithCommand(allocator, &.{ "xclip", "-selection", "clipboard" }, text)) return true;
    return false;
}

fn copyWithCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    text: []const u8,
) !bool {
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    errdefer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    if (child.stdin) |*stdin| {
        try stdin.writeAll(text);
        stdin.close();
        child.stdin = null;
    } else {
        return false;
    }

    const term = try child.wait();
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}
