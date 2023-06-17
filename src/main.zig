const std = @import("std");
const repl = @import("repl.zig");

pub fn main() !void {
    const in = std.io.getStdIn();
    const out = std.io.getStdOut();

    try out.writer().writeAll("Welcome to the monkey programming language!\n");
    try repl.start(in.reader(), out.writer());
}
