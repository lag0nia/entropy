const std = @import("std");

const PasswordItem = struct { service_name: []const u8, user_id: []const u8, password: []const u8 };

// TODO: ARENA PATTERN
// TODO: USE trim() for retro compatibility
// TODO: Encrypt json
// TODO: Cover all json read/write checks
// TODO FIRST:  Complete program :p

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    while (true) {
        std.debug.print("----------- WELCOME TO PASSWORD MANAGER -----------\n", .{});
        std.debug.print("1. Add a new password\n", .{});
        std.debug.print("2. List all passwords\n", .{});
        std.debug.print("3. Delete a password\n", .{});
        std.debug.print("4. Exit\n", .{});

        std.debug.print("Please sir, enter your choice: ", .{});
        const user_command = try get_input(allocator);

        std.debug.print("\n\n\n", .{});

        if (std.mem.eql(u8, "1", user_command)) {
            std.debug.print("Please enter a service name: ", .{});
            const service_name = try get_input(allocator);
            std.debug.print("Please enter a user identification: ", .{});
            const user_id = try get_input(allocator);

            const password_item = PasswordItem{
                .service_name = service_name,
                .user_id = user_id,
                .password = try get_random_password(allocator, 12),
            };

            try update_passwords_list(allocator, password_item);
        } else if (std.mem.eql(u8, "2", user_command)) {
            std.debug.print("List all passwords\n\n", .{});
        } else if (std.mem.eql(u8, "3", user_command)) {
            std.debug.print("Delete a password\n\n", .{});
        } else if (std.mem.eql(u8, "4", user_command)) {
            std.debug.print("Have a good day sir :P\n\n", .{});
            break;
        } else {
            std.debug.print("Invalid input\n\n", .{});
        }
    }
}

pub fn get_input(allocator: std.mem.Allocator) ![]u8 {
    var buffer: [1024]u8 = undefined;
    var stdin = std.fs.File.stdin().reader(&buffer);

    var writer = std.io.Writer.Allocating.init(allocator);

    if (stdin.interface.streamDelimiter(&writer.writer, '\n')) |_| {
        return writer.written();
    } else |err| {
        std.debug.print("Error reading input: {}\n", .{err});
        return error.EndOfStream;
    }
}

pub fn get_random_password(allocator: std.mem.Allocator, word_number: u8) ![]const u8 {
    var btc_words_pool = try std.fs.cwd().openFile("./english.txt", .{ .mode = .read_only });
    defer btc_words_pool.close();

    const words = try btc_words_pool.readToEndAlloc(allocator, 1024 * 1024);
    var words_list = std.ArrayListUnmanaged([]const u8){};

    var it = std.mem.tokenizeScalar(u8, words, '\n');
    while (it.next()) |word| {
        try words_list.append(allocator, word);
    }

    var password_builder = std.ArrayListUnmanaged([]const u8){};

    for (0..word_number) |_| {
        const random_word = words_list.items[std.crypto.random.int(u32) % words_list.items.len];
        try password_builder.append(allocator, random_word);
    }

    const password_final = try std.mem.join(allocator, "-", password_builder.items);
    return password_final;
}

pub fn update_passwords_list(allocator: std.mem.Allocator, password_item: PasswordItem) !void {
    const file_path = "./passwords.json";
    var updated_passwords_list = std.ArrayListUnmanaged(PasswordItem){};

    {
        const password_file = std.fs.cwd().openFile(file_path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };

        if (password_file) |pf| {
            defer pf.close();

            const pf_data = try pf.readToEndAlloc(allocator, 16 * 1024 * 1024);

            if (std.mem.trim(u8, pf_data, " \t\n\r").len != 0) {
                const passwords_list = try std.json.parseFromSlice([]const PasswordItem, allocator, pf_data, .{});
                try updated_passwords_list.appendSlice(allocator, passwords_list.value);
            }
        }
    }

    try updated_passwords_list.append(allocator, password_item);

    const out_file = try std.fs.cwd().createFile(file_path, .{});
    defer out_file.close();

    var write_buffer: [4096]u8 = undefined;
    var file_writer = out_file.writer(&write_buffer);

    try std.json.Stringify.value(updated_passwords_list.items, .{ .whitespace = .indent_4 }, &file_writer.interface);
    try file_writer.interface.flush();
}
