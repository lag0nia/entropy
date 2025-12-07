const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe_name = b.option([]const u8, "exe_name", "Name of the executable") orelse "httpspec";

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("book", .{
        .root_source_file = b.path("tui.zig"),
        .target = target,
    });
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path("tui.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "book", .module = mod },
            },
        }),
    });

    const vaxis = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("vaxis", vaxis.module("vaxis"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);
}
