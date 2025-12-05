const std = @import("std");

pub fn main() !void {
    while (true) {
        std.debug.print("----------- WELCOME TO PASSWORD MANAGER -----------\n", .{});
        std.debug.print("1. Add a new password\n", .{});
        std.debug.print("2. List all passwords\n", .{});
        std.debug.print("3. Delete a password\n", .{});
        std.debug.print("4. Exit\n", .{});

        std.debug.print("Please sir, enter your choice: ", .{});

        var buffer: [100]u8 = undefined;
        var stdin_reader = std.fs.File.stdin().reader(&buffer);

        var alloc = std.heap.DebugAllocator(.{}).init;
        defer _ = alloc.deinit();
        const da = alloc.allocator();

        var allocating_writer = std.Io.Writer.Allocating.init(da);
        defer allocating_writer.deinit();
        var line: []u8 = undefined;

        while (stdin_reader.interface.streamDelimiter(&allocating_writer.writer, '\n')) |_| {
            line = allocating_writer.written();
            break;
        } else |err| {
            std.debug.print("Error reading input: {}\n", .{err});
        }

        std.debug.print("\n\n\n", .{});

        if (std.mem.eql(u8, "1", line)) {
            std.debug.print("Add a new password\n\n", .{});
        } else if (std.mem.eql(u8, "2", line)) {
            std.debug.print("List all passwords\n\n", .{});
        } else if (std.mem.eql(u8, "3", line)) {
            std.debug.print("Delete a password\n\n", .{});
        } else if (std.mem.eql(u8, "4", line)) {
            std.debug.print("Have a good day sir :P\n\n", .{});
            break;
        } else {
            std.debug.print("Invalid input\n\n", .{});
        }
    }
}
