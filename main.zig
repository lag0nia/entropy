const std = @import("std");

const PasswordItem = struct { service_name: []const u8, user_id: []const u8, password: []const u8 };

const file_path = "./passwords.json";

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
        std.debug.print("2. Get a password\n", .{});
        std.debug.print("3. Update a password\n", .{});
        std.debug.print("4. Delete a password\n", .{});
        std.debug.print("5. Export all passwords\n", .{});
        std.debug.print("6. Exit\n", .{});

        std.debug.print("Please sir, enter your choice: ", .{});
        const user_command = try getInput(allocator);

        std.debug.print("\n\n\n", .{});

        if (std.mem.eql(u8, "1", user_command)) {
            std.debug.print("Please enter a service name: ", .{});
            const service_name = try getInput(allocator);
            std.debug.print("Please enter a user identification: ", .{});
            const user_id = try getInput(allocator);

            const password_item = PasswordItem{
                .service_name = service_name,
                .user_id = user_id,
                .password = try setRandomPassword(allocator),
            };

            try updatePasswordList(allocator, password_item);
        } else if (std.mem.eql(u8, "2", user_command)) {
            try getPassword(allocator);
        } else if (std.mem.eql(u8, "3", user_command)) {
            std.debug.print("Update a password\n\n", .{});
        } else if (std.mem.eql(u8, "4", user_command)) {
            std.debug.print("Delete a password\n\n", .{});
        } else if (std.mem.eql(u8, "5", user_command)) {
            std.debug.print("Export all passwords\n\n", .{});
        } else if (std.mem.eql(u8, "6", user_command)) {
            std.debug.print("Have a good day sir :P\n\n", .{});
            break;
        } else {
            std.debug.print("Invalid input\n\n", .{});
        }
    }
}

pub fn getInput(allocator: std.mem.Allocator) ![]u8 {
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

pub fn setRandomPassword(allocator: std.mem.Allocator) ![]const u8 {
    var btc_words_pool = try std.fs.cwd().openFile("./english.txt", .{ .mode = .read_only });
    defer btc_words_pool.close();
    var entropy: [16]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&entropy);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    const first_byte = hash[0];
    const checksum = first_byte >> 4;

    var final_bits: [17]u8 = [_]u8{0} ** 17;
    @memcpy(final_bits[0..16], &entropy);
    final_bits[16] = checksum << 4;
    // from here

    const words = try btc_words_pool.readToEndAlloc(allocator, 1024 * 1024);
    var words_list = std.ArrayListUnmanaged([]const u8){};

    var it = std.mem.tokenizeScalar(u8, words, '\n');
    while (it.next()) |word| {
        try words_list.append(allocator, word);
    }

    var password_builder = std.ArrayListUnmanaged([]const u8){};

    // to complete the loop generation here based on the 132 byte number
    for (0..12) |_| {
        const random_word = words_list.items[std.crypto.random.int(u32) % words_list.items.len];
        try password_builder.append(allocator, random_word);
    }

    const password_final = try std.mem.join(allocator, "-", password_builder.items);
    return password_final;
}

pub fn updatePasswordList(allocator: std.mem.Allocator, password_item: PasswordItem) !void {
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

pub fn getPassword(allocator: std.mem.Allocator) !void {
    const pf = std.fs.cwd().openFile(file_path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("You have no passwords saved :(\n", .{});
            std.debug.print("Please add at least one with option 1\n", .{});
            return;
        },
        else => return err,
    };

    defer pf.close();
    const pf_data = try pf.readToEndAlloc(allocator, 16 * 1024 * 1024);

    if (std.mem.trim(u8, pf_data, " \t\n\r").len == 0) {
        std.debug.print("You have no passwords saved :(\n", .{});
        std.debug.print("Please add at least one with option 1\n", .{});
        return;
    }

    const passwords_list = try std.json.parseFromSlice([]const PasswordItem, allocator, pf_data, .{});

    if (passwords_list.value.len == 0) {
        std.debug.print("You have no passwords saved :(\n", .{});
        std.debug.print("Please add at least one with option 1\n", .{});
        return;
    }

    std.debug.print("\n------------------------------\n", .{});

    for (passwords_list.value) |value| {
        std.debug.print("Service name: {s}\n", .{value.service_name});
        std.debug.print("User ID: {s}\n", .{value.user_id});
        std.debug.print("\n\n---------------------\n\n", .{});
    }

    std.debug.print("Please select the item you want to get: ", .{});
    const item_index = try getInput(allocator);
    const numeric_index = try std.fmt.parseInt(usize, item_index, 10);

    std.debug.print("Your password is\n{s}\n\n", .{passwords_list.value[numeric_index].password});
}
