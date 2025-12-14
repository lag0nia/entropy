const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const mem = std.mem;
const meta = std.meta;

const vaxis = @import("vaxis");

const log = std.log.scoped(.main);

const ActiveSection = enum {
    top,
    mid,
    btm,
};

pub fn main() !void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.detectLeaks()) log.err("Memory leak detected!", .{});
    const alloc = gpa.allocator();

    // Get all passwords
    const passwords = try getAllPasswords(alloc) orelse &.{};
    const passwords_buf = try alloc.dupe(PasswordItem, passwords[0..]);

    var buffer: [1024]u8 = undefined;
    var tty = try vaxis.Tty.init(&buffer);
    defer tty.deinit();
    const tty_writer = tty.writer();
    var vx = try vaxis.init(alloc, .{
        .kitty_keyboard_flags = .{ .report_events = true },
    });
    defer vx.deinit(alloc, tty.writer());

    var loop: vaxis.Loop(union(enum) {
        key_press: vaxis.Key,
        winsize: vaxis.Winsize,
        mouse: vaxis.Mouse,
        table_upd,
    }) = .{ .tty = &tty, .vaxis = &vx };
    try loop.init();
    try loop.start();
    defer loop.stop();
    try vx.enterAltScreen(tty.writer());
    try vx.queryTerminal(tty.writer(), 250 * std.time.ns_per_ms);
    try vx.setMouseMode(tty.writer(), true);

    const logo =
        \\░░░░░░░█▀▀░█▄░█░▀█▀░█▀▀▄░█▀█░█▀▀▄░█░█░░░░░░
        \\░░░░░░░█▀▀░█░▀█░░█░░█▀▀▄░█░█░█▀▀░░░█░░░░░░░
        \\░░░░░░░▀▀▀░▀░░▀░░▀░░▀░░▀░▀▀▀░▀░░░░░▀░░░░░░░
    ;
    const title_logo = vaxis.Cell.Segment{
        .text = logo,
        .style = .{},
    };
    const title_info = vaxis.Cell.Segment{
        .text = "Minimalist, self-custodial password manager",
        .style = .{},
    };
    var title_segs = [_]vaxis.Cell.Segment{ title_logo, title_info };

    var cmd_input = vaxis.widgets.TextInput.init(alloc);
    defer cmd_input.deinit();

    // Colors
    const active_bg: vaxis.Cell.Color = .{ .rgb = .{ 64, 128, 255 } };
    const selected_bg: vaxis.Cell.Color = .{ .rgb = .{ 32, 64, 255 } };
    const other_bg: vaxis.Cell.Color = .{ .rgb = .{ 32, 32, 48 } };

    // Table Context
    var demo_tbl: vaxis.widgets.Table.TableContext = .{
        .active_bg = active_bg,
        .active_fg = .{ .rgb = .{ 0, 0, 0 } },
        .row_bg_1 = .{ .rgb = .{ 8, 8, 8 } },
        .selected_bg = selected_bg,
        .header_names = .{ .custom = &.{ "Service", "User" } },
        //s.header_align = .left,
        .col_indexes = .{ .by_idx = &.{ 0, 1 } },
        //.col_align = .{ .by_idx = &.{ .left, .left, .center, .center, .left } },
        //.col_align = .{ .all = .center },
        //.header_borders = true,
        //.col_borders = true,
        //.col_width = .{ .static_all = 15 },
        //.col_width = .{ .dynamic_header_len = 3 },
        //.col_width = .{ .static_individual = &.{ 10, 20, 15, 25, 15 } },
        //.col_width = .dynamic_fill,
        //.y_off = 10,
    };
    defer if (demo_tbl.sel_rows) |rows| alloc.free(rows);

    // TUI State
    var active: ActiveSection = .mid;
    var moving = false;
    var see_content = false;

    // Create an Arena Allocator for easy allocations on each Event.
    var event_arena = heap.ArenaAllocator.init(alloc);
    defer event_arena.deinit();
    while (true) {
        defer _ = event_arena.reset(.retain_capacity);
        defer tty_writer.flush() catch {};
        const event_alloc = event_arena.allocator();
        const event = loop.nextEvent();

        switch (event) {
            .mouse => |mouse| {
                if (mouse.button == vaxis.Mouse.Button.left and mouse.type == vaxis.Mouse.Type.press) {
                    const col_offset: i16 = if (see_content) 12 else 8;
                    const offset = @as(u16, @intCast(mouse.row -| col_offset));
                    demo_tbl.row = offset;
                    see_content = true;
                }
            },
            .key_press => |key| keyEvt: {
                // Close the Program
                if (key.matches('c', .{ .ctrl = true })) {
                    break;
                }
                // Refresh the Screen
                if (key.matches('l', .{ .ctrl = true })) {
                    vx.queueRefresh();
                    break :keyEvt;
                }
                // Enter Moving State
                if (key.matches('w', .{ .ctrl = true })) {
                    moving = !moving;
                    break :keyEvt;
                }
                // Command State
                if (active != .btm and
                    key.matchesAny(&.{ ':', '/', 'g', 'G' }, .{}))
                {
                    active = .btm;
                    cmd_input.clearAndFree();
                    try cmd_input.update(.{ .key_press = key });
                    break :keyEvt;
                }

                switch (active) {
                    .top => {
                        if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{}) and moving) active = .mid;
                    },
                    .mid => midEvt: {
                        if (moving) {
                            if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{})) active = .top;
                            if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{})) active = .btm;
                            break :midEvt;
                        }
                        // Change Row
                        if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{})) demo_tbl.row -|= 1;
                        if (key.matchesAny(&.{ vaxis.Key.down, 'j' }, .{})) demo_tbl.row +|= 1;
                        // Change Column
                        if (key.matchesAny(&.{ vaxis.Key.left, 'h' }, .{})) demo_tbl.col -|= 1;
                        if (key.matchesAny(&.{ vaxis.Key.right, 'l' }, .{})) demo_tbl.col +|= 1;
                        // Select/Unselect Row
                        if (key.matches(vaxis.Key.space, .{})) {
                            const rows = demo_tbl.sel_rows orelse createRows: {
                                demo_tbl.sel_rows = try alloc.alloc(u16, 1);
                                break :createRows demo_tbl.sel_rows.?;
                            };
                            var rows_list = std.ArrayList(u16).fromOwnedSlice(rows);
                            for (rows_list.items, 0..) |row, idx| {
                                if (row != demo_tbl.row) continue;
                                _ = rows_list.orderedRemove(idx);
                                break;
                            } else try rows_list.append(alloc, demo_tbl.row);
                            demo_tbl.sel_rows = try rows_list.toOwnedSlice(alloc);
                        }
                        // See Row Content
                        if (key.matches(vaxis.Key.enter, .{}) or key.matches('j', .{ .ctrl = true })) see_content = !see_content;
                    },
                    .btm => {
                        if (key.matchesAny(&.{ vaxis.Key.up, 'k' }, .{}) and moving) active = .mid
                            // Run Command and Clear Command Bar
                        else if (key.matchExact(vaxis.Key.enter, .{}) or key.matchExact('j', .{ .ctrl = true })) {
                            const cmd = try cmd_input.toOwnedSlice();
                            defer alloc.free(cmd);
                            if (mem.eql(u8, ":q", cmd) or
                                mem.eql(u8, ":quit", cmd) or
                                mem.eql(u8, ":exit", cmd)) return;
                            if (mem.eql(u8, "G", cmd)) {
                                demo_tbl.row = @intCast(passwords.len - 1);
                                active = .mid;
                            }
                            if (cmd.len >= 2 and mem.eql(u8, "gg", cmd[0..2])) {
                                const goto_row = fmt.parseInt(u16, cmd[2..], 0) catch 0;
                                demo_tbl.row = goto_row;
                                active = .mid;
                            }
                        } else try cmd_input.update(.{ .key_press = key });
                    },
                }
                moving = false;
            },
            .winsize => |ws| try vx.resize(alloc, tty.writer(), ws),
            else => {},
        }

        // Content
        seeRow: {
            if (!see_content) {
                demo_tbl.active_content_fn = null;
                demo_tbl.active_ctx = &{};
                break :seeRow;
            }
            const RowContext = struct {
                row: []const u8,
                bg: vaxis.Color,
            };
            const row_ctx = RowContext{
                .row = try fmt.allocPrint(event_alloc, "Your password is {s}", .{passwords[demo_tbl.row].password}),
                .bg = demo_tbl.active_bg,
            };
            demo_tbl.active_ctx = &row_ctx;
            demo_tbl.active_content_fn = struct {
                fn see(win: *vaxis.Window, ctx_raw: *const anyopaque) !u16 {
                    const ctx: *const RowContext = @ptrCast(@alignCast(ctx_raw));
                    win.height = 5;
                    const see_win = win.child(.{
                        .x_off = 0,
                        .y_off = 1,
                        .width = win.width,
                        .height = 4,
                    });
                    see_win.fill(.{ .style = .{ .bg = ctx.bg } });
                    const content_segs: []const vaxis.Cell.Segment = &.{
                        .{
                            .text = "- Copy to clipboard\n",
                            .style = .{ .bg = ctx.bg },
                        },
                        .{
                            .text = "- Update passsword\n",
                            .style = .{ .bg = ctx.bg },
                        },
                        .{
                            .text = "- Update item\n",
                            .style = .{ .bg = ctx.bg },
                        },
                        .{
                            .text = "- Delete item\n",
                            .style = .{ .bg = ctx.bg },
                        },
                    };
                    _ = see_win.print(content_segs, .{});
                    return see_win.height;
                }
            }.see;
            loop.postEvent(.table_upd);
        }

        // Sections
        // - Window
        const win = vx.window();
        win.clear();

        // - Top
        const top_div = 6;
        const top_bar = win.child(.{
            .x_off = 0,
            .y_off = 0,
            .width = win.width,
            .height = win.height / top_div,
        });
        for (title_segs[0..]) |*title_seg|
            title_seg.style.bg = if (active == .top) selected_bg else other_bg;
        top_bar.fill(.{ .style = .{
            .bg = if (active == .top) selected_bg else other_bg,
        } });
        const logo_bar = vaxis.widgets.alignment.center(
            top_bar,
            44,
            top_bar.height - (top_bar.height / 3),
        );
        _ = logo_bar.print(title_segs[0..], .{ .wrap = .word });

        // - Middle
        const middle_bar = win.child(.{
            .x_off = 0,
            .y_off = win.height / top_div,
            .width = win.width,
            .height = win.height - (top_bar.height + 1),
        });
        if (passwords_buf.len > 0) {
            demo_tbl.active = active == .mid;
            try vaxis.widgets.Table.drawTable(
                null,
                // event_alloc,
                middle_bar,
                //users_buf[0..],
                //user_list,
                passwords_buf,
                &demo_tbl,
            );
        }

        // - Bottom
        const bottom_bar = win.child(.{
            .x_off = 0,
            .y_off = win.height - 1,
            .width = win.width,
            .height = 1,
        });
        if (active == .btm) bottom_bar.fill(.{ .style = .{ .bg = active_bg } });
        cmd_input.draw(bottom_bar);

        // Render the screen
        try vx.render(tty_writer);
    }
}

const PasswordItem = struct { service_name: []const u8, user_id: []const u8, password: []const u8 };

pub fn getAllPasswords(allocator: std.mem.Allocator) !?[]const PasswordItem {
    const file_path = "./passwords.json";

    const pf = std.fs.cwd().openFile(file_path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };

    defer pf.close();
    const pf_data = try pf.readToEndAlloc(allocator, 16 * 1024 * 1024);

    if (std.mem.trim(u8, pf_data, " \t\n\r").len == 0) {
        return &.{};
    }

    const passwords_list = try std.json.parseFromSlice([]const PasswordItem, allocator, pf_data, .{});

    if (passwords_list.value.len == 0) {
        return &.{};
    }

    return passwords_list.value;
}
