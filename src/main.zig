const std = @import("std");
const model = @import("model.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const utils = @import("utils.zig");
const tui = @import("tui.zig");

const Color = utils.Color;
const Box = utils.Box;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize libsodium
    crypto.init() catch {
        std.debug.print("Fatal: could not initialize cryptography library.\n", .{});
        return;
    };

    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var file_writer = stdout_file.writer(&stdout_buf);
    const w = &file_writer.interface;

    // Print banner
    try printBanner(w);
    try w.flush();

    // Determine vault path
    const vault_path = storage.getVaultPath(allocator) catch {
        std.debug.print("Error: could not determine vault path.\n", .{});
        return;
    };
    defer allocator.free(vault_path);

    // Check if vault exists
    const vault_exists = blk: {
        std.fs.cwd().access(vault_path, .{}) catch break :blk false;
        break :blk true;
    };

    var session: tui.VaultSession = undefined;

    if (vault_exists) {
        // Unlock existing vault
        try w.print("{s}Enter master password: {s}", .{ Color.cyan, Color.reset });
        try w.flush();
        const password = utils.readPassword(allocator, "") catch {
            std.debug.print("Error reading password.\n", .{});
            return;
        };
        defer {
            crypto.zeroize(password);
            allocator.free(password);
        }

        try w.print("\n{s}{s} Unlocking vault...{s}\n", .{ Color.yellow, utils.Icon.shield, Color.reset });
        try w.flush();

        const loaded = storage.loadVault(allocator, password, vault_path) catch {
            try w.print("{s}{s} Wrong password or corrupted vault.{s}\n", .{
                Color.red, utils.Icon.cross_mark, Color.reset,
            });
            try w.flush();
            return;
        };
        defer crypto.zeroize(@constCast(&loaded.key));

        session = .{
            .vault = loaded.vault,
            .key = loaded.key,
            .salt = loaded.salt,
            .vault_path = vault_path,
        };
    } else {
        // Create new vault
        try w.print("\n{s}{s} No vault found. Creating a new one...{s}\n\n", .{
            Color.bright_cyan, utils.Icon.shield, Color.reset,
        });

        try w.print("{s}Choose a master password: {s}", .{ Color.cyan, Color.reset });
        try w.flush();
        const password = utils.readPassword(allocator, "") catch {
            std.debug.print("Error reading password.\n", .{});
            return;
        };
        defer {
            crypto.zeroize(password);
            allocator.free(password);
        }

        try w.print("{s}Confirm master password: {s}", .{ Color.cyan, Color.reset });
        try w.flush();
        const confirm = utils.readPassword(allocator, "") catch {
            std.debug.print("Error reading password.\n", .{});
            return;
        };
        defer {
            crypto.zeroize(confirm);
            allocator.free(confirm);
        }

        if (!std.mem.eql(u8, password, confirm)) {
            try w.print("{s}{s} Passwords do not match.{s}\n", .{
                Color.red, utils.Icon.cross_mark, Color.reset,
            });
            try w.flush();
            return;
        }

        try w.print("\n{s}{s} Deriving encryption key (this may take a moment)...{s}\n", .{
            Color.yellow, utils.Icon.shield, Color.reset,
        });
        try w.flush();

        const salt = crypto.generateSalt();
        const key = crypto.deriveKey(password, &salt) catch {
            std.debug.print("Error deriving key.\n", .{});
            return;
        };
        defer crypto.zeroize(@constCast(&key));

        // Create empty vault
        const empty_items = try allocator.alloc(model.Item, 0);
        const empty_categories = try allocator.alloc(model.Category, 0);

        const vault = model.Vault{
            .version = 1,
            .items = empty_items,
            .categories = empty_categories,
        };

        // Save vault
        storage.saveVault(allocator, vault, &key, &salt, vault_path) catch {
            std.debug.print("Error saving vault.\n", .{});
            return;
        };

        try w.print("{s}{s} Vault created at: {s}{s}\n\n", .{
            Color.green, utils.Icon.check, vault_path, Color.reset,
        });
        try w.flush();

        session = .{
            .vault = vault,
            .key = key,
            .salt = salt,
            .vault_path = vault_path,
        };
    }
    defer model.freeVault(allocator, &session.vault);
    defer crypto.zeroize(&session.key);

    try w.print("{s}{s} Vault unlocked. Launching TUI...{s}\n\n", .{
        Color.green, utils.Icon.check, Color.reset,
    });
    try w.flush();

    // Small delay so user sees the message
    std.Thread.sleep(500 * std.time.ns_per_ms);

    // Launch TUI
    tui.run(allocator, &session) catch |err| {
        std.debug.print("TUI error: {}\n", .{err});
    };
}

fn printBanner(w: *std.Io.Writer) !void {
    try w.print("\n", .{});
    try w.print("{s}{s}", .{ Color.bright_cyan, Color.bold });
    try w.print("  {s}{s}{s}{s}{s}{s}{s}\n", .{
        Box.d_top_left,   Box.d_horizontal, Box.d_horizontal, Box.d_horizontal,
        Box.d_horizontal, Box.d_horizontal, Box.d_top_right,
    });
    try w.print("  {s}     {s}   {s}enthropy{s} v0.1.0\n", .{
        Box.d_vertical, Box.d_vertical, Color.bright_white, Color.bright_cyan,
    });
    try w.print("  {s}     {s}   {s}{s}secure password manager{s}\n", .{
        Box.d_vertical, Box.d_vertical, Color.dim, Color.white, Color.bright_cyan,
    });
    try w.print("  {s}{s}{s}{s}{s}{s}{s}\n", .{
        Box.d_bottom_left, Box.d_horizontal, Box.d_horizontal,   Box.d_horizontal,
        Box.d_horizontal,  Box.d_horizontal, Box.d_bottom_right,
    });
    try w.print("{s}\n", .{Color.reset});
}

// Include all module tests
comptime {
    _ = @import("model.zig");
    _ = @import("crypto.zig");
    _ = @import("bip39.zig");
    _ = @import("storage.zig");
    _ = @import("vault_service.zig");
    _ = @import("schema_v2.zig");
    _ = @import("relations_v2.zig");
}
