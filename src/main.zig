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

    if (handleMaintenanceCommand(allocator, args) catch |err| {
        std.debug.print("Error: command failed ({})\n", .{err});
        return;
    }) {
        return;
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

        const runtime_vault = storage.projectVaultV2ToRuntime(allocator, loaded_v2.vault) catch {
            loaded_v2.deinit();
            try w.print("{s}{s} Vault payload could not be projected to runtime view.{s}\n", .{
                Color.red, utils.Icon.cross_mark, Color.reset,
            });
            try w.flush();
            return;
        };

        session = .{
            .vault = runtime_vault,
            .vault_v2 = loaded_v2.vault,
            .vault_v2_arena = loaded_v2.arena,
            .vault_v2_allocator = loaded_v2.arena.allocator(),
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

        var v2_arena = std.heap.ArenaAllocator.init(allocator);
        const v2a = v2_arena.allocator();
        const empty_v2: schema.VaultV2 = .{
            .version = 2,
            .encrypted = false,
            .source = .unknown,
            .folders = try v2a.alloc(schema.Folder, 0),
            .collections = try v2a.alloc(schema.Collection, 0),
            .items = try v2a.alloc(schema.Item, 0),
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
            .vault_v2 = empty_v2,
            .vault_v2_arena = v2_arena,
            .vault_v2_allocator = v2a,
            .key = key,
            .salt = salt,
            .vault_path = vault_path,
        };
    }
    defer session.deinit(allocator);

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

const ScriptError = error{
    ScriptNotFound,
    ScriptFailed,
};

fn handleMaintenanceCommand(allocator: std.mem.Allocator, args: []const []const u8) !bool {
    if (args.len < 2) return false;

    if (std.mem.eql(u8, args[1], "update")) {
        try runMaintenanceScript(allocator, "update.sh", args[2..]);
        return true;
    }
    if (std.mem.eql(u8, args[1], "uninstall")) {
        try runMaintenanceScript(allocator, "uninstall.sh", args[2..]);
        return true;
    }
    if (std.mem.eql(u8, args[1], "install")) {
        std.debug.print(
            "Install must run via bootstrap script:\n  curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/install.sh | bash\n",
            .{},
        );
        return true;
    }
    if (std.mem.eql(u8, args[1], "help") or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        printCliUsage();
        return true;
    }
    return false;
}

fn runMaintenanceScript(
    allocator: std.mem.Allocator,
    script_name: []const u8,
    passthrough_args: []const []const u8,
) !void {
    const script_path = try resolveScriptPath(allocator, script_name);
    defer allocator.free(script_path);

    var argv = std.ArrayList([]const u8){};
    defer argv.deinit(allocator);
    try argv.append(allocator, "bash");
    try argv.append(allocator, script_path);
    try argv.appendSlice(allocator, passthrough_args);

    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return ScriptError.ScriptFailed,
        else => return ScriptError.ScriptFailed,
    }
}

fn resolveScriptPath(allocator: std.mem.Allocator, script_name: []const u8) ![]u8 {
    const env_scripts_dir = std.process.getEnvVarOwned(allocator, "ENTROPY_SCRIPTS_DIR") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (env_scripts_dir) |dir| allocator.free(dir);

    if (env_scripts_dir) |dir| {
        const script_path = try std.fs.path.join(allocator, &.{ dir, script_name });
        if (pathExists(script_path)) return script_path;
        allocator.free(script_path);
    }

    const defaults = [_][]const u8{
        "/opt/entropy/src/scripts",
        "scripts",
    };
    for (defaults) |dir| {
        const script_path = try std.fs.path.join(allocator, &.{ dir, script_name });
        if (pathExists(script_path)) return script_path;
        allocator.free(script_path);
    }

    std.debug.print(
        "Error: could not find {s}. Looked in ENTROPY_SCRIPTS_DIR, /opt/entropy/src/scripts and ./scripts.\n",
        .{script_name},
    );
    return ScriptError.ScriptNotFound;
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
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
        \\  entropy import bitwarden --file <path> [--mode strict|best_effort] [--dry-run] [--replace|--merge]
        \\
    , .{});
}

fn printCliUsage() void {
    std.debug.print(
        \\Usage:
        \\  entropy
        \\  entropy import bitwarden --file <path> [--mode strict|best_effort] [--dry-run] [--replace|--merge]
        \\  entropy update
        \\  entropy uninstall [--purge-vault] [--remove-zig]
        \\  entropy help
        \\
        \\Notes:
        \\  - install uses bootstrap script:
        \\    curl -fsSL https://raw.githubusercontent.com/lag0nia/entropy/main/scripts/install.sh | bash
        \\  - update/uninstall run scripts from ENTROPY_SCRIPTS_DIR, /opt/entropy/src/scripts or ./scripts
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
    _ = @import("vault_service_v2.zig");
    _ = @import("schema_v2.zig");
    _ = @import("relations_v2.zig");
    _ = @import("import_bitwarden.zig");
}
