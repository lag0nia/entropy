const std = @import("std");
const model = @import("model.zig");
const crypto = @import("crypto.zig");
const storage = @import("storage.zig");
const schema = @import("schema_v2.zig");
const utils = @import("utils.zig");
const tui = @import("tui.zig");
const import_bitwarden = @import("import_bitwarden.zig");

const Color = utils.Color;
const Box = utils.Box;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args_alloc = std.process.argsAlloc(allocator) catch {
        std.debug.print("Error: failed to read command-line arguments.\n", .{});
        return;
    };
    defer std.process.argsFree(allocator, args_alloc);

    const args = allocator.alloc([]const u8, args_alloc.len) catch {
        std.debug.print("Error: out of memory parsing command-line arguments.\n", .{});
        return;
    };
    defer allocator.free(args);
    for (args_alloc, 0..) |arg, i| {
        args[i] = arg;
    }

    var import_cmd: ?import_bitwarden.CliOptions = null;
    if (import_bitwarden.parseImportCommand(args)) |maybe_import| {
        if (maybe_import) |cmd| {
            const owned_file_path = allocator.dupe(u8, cmd.file_path) catch {
                std.debug.print("Error: out of memory for import file path.\n", .{});
                return;
            };
            import_cmd = .{
                .file_path = owned_file_path,
                .options = cmd.options,
            };
        }
    } else |err| {
        std.debug.print("Import argument error: {}\n", .{err});
        printImportUsage();
        return;
    }
    defer if (import_cmd) |cmd| allocator.free(cmd.file_path);

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

        var loaded_v2 = storage.loadVaultV2(allocator, password, vault_path) catch {
            try w.print("{s}{s} Wrong password or corrupted vault.{s}\n", .{
                Color.red, utils.Icon.cross_mark, Color.reset,
            });
            try w.flush();
            return;
        };
        defer loaded_v2.deinit();

        const runtime_vault = storage.projectVaultV2ToRuntime(allocator, loaded_v2.vault) catch {
            try w.print("{s}{s} Vault payload could not be projected to runtime view.{s}\n", .{
                Color.red, utils.Icon.cross_mark, Color.reset,
            });
            try w.flush();
            return;
        };

        session = .{
            .vault = runtime_vault,
            .key = loaded_v2.key,
            .salt = loaded_v2.salt,
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

        const empty_v2: schema.VaultV2 = .{
            .version = 2,
            .encrypted = false,
            .source = .unknown,
            .folders = &.{},
            .collections = &.{},
            .items = &.{},
        };

        storage.saveVaultV2(allocator, empty_v2, &key, &salt, vault_path) catch {
            std.debug.print("Error saving vault.\n", .{});
            return;
        };

        const vault = storage.projectVaultV2ToRuntime(allocator, empty_v2) catch {
            std.debug.print("Error building runtime projection.\n", .{});
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

    if (import_cmd) |cmd| {
        try w.print("{s}{s} Running Bitwarden import...{s}\n", .{
            Color.yellow, utils.Icon.shield, Color.reset,
        });
        try w.flush();

        var target: import_bitwarden.ImportTarget = .{
            .vault = &session.vault,
            .key = &session.key,
            .salt = &session.salt,
            .vault_path = session.vault_path,
        };

        const summary = import_bitwarden.importFromBitwardenJsonFile(
            allocator,
            &target,
            cmd.file_path,
            cmd.options,
        ) catch |err| {
            try w.print("{s}{s} Import failed: {}{s}\n", .{
                Color.red, utils.Icon.cross_mark, err, Color.reset,
            });
            try w.flush();
            return;
        };

        try printImportSummary(w, summary, cmd.options);
        try w.flush();
        return;
    }

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

fn printImportUsage() void {
    std.debug.print(
        \\Usage:
        \\  enthropy import bitwarden --file <path> [--mode strict|best_effort] [--dry-run] [--replace|--merge]
        \\
    , .{});
}

fn printImportSummary(
    w: *std.Io.Writer,
    summary: import_bitwarden.ImportSummary,
    options: import_bitwarden.ImportOptions,
) !void {
    const mode_label = switch (options.mode) {
        .strict => "strict",
        .best_effort => "best_effort",
    };
    const action_label = switch (options.action) {
        .replace => "replace",
        .merge => "merge",
    };

    try w.print("{s}{s} Import summary{s}\n", .{
        Color.green, utils.Icon.check, Color.reset,
    });
    try w.print("  source: {s}\n", .{@tagName(summary.source)});
    try w.print("  mode: {s}\n", .{mode_label});
    try w.print("  action: {s}\n", .{action_label});
    try w.print("  dry-run: {s}\n", .{if (options.dry_run) "true" else "false"});
    try w.print("  folders: {d}, collections: {d}\n", .{ summary.folders, summary.collections });
    try w.print(
        "  items total: {d} (login {d}, notes {d}, card {d}, identity {d})\n",
        .{
            summary.items_total,
            summary.items_login,
            summary.items_secure_note,
            summary.items_card,
            summary.items_identity,
        },
    );
    try w.print(
        "  result: imported={d} replaced={d} merged={d} kept={d} skipped={d} categories={d}\n",
        .{
            summary.imported_items,
            summary.replaced_items,
            summary.merged_items,
            summary.kept_items,
            summary.skipped_items,
            summary.imported_categories,
        },
    );
    try w.print("  warnings: {d}\n", .{summary.warning_count});

    if (options.dry_run) {
        try w.print("  {s}No changes written (dry-run).{s}\n", .{ Color.dim, Color.reset });
    } else {
        try w.print("  {s}Vault updated and saved.{s}\n", .{ Color.dim, Color.reset });
    }
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
    _ = @import("import_bitwarden.zig");
}
