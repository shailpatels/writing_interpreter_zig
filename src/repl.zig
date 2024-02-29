const std = @import("std");
const token = @import("token.zig");

const Lexer = @import("lexer.zig").Lexer;
const Parser = @import("parser.zig").Parser;

pub fn start(reader: anytype, writer: anytype) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    while (true) {
        try writer.writeAll(">> ");

        var msg_buf: [4096]u8 = undefined;
        var msg = try reader.readUntilDelimiterOrEof(&msg_buf, '\n');

        if (msg) |m| {
            var parser = Parser.init(m, allocator);
            defer parser.deinit();

            var program = parser.parseProgram();
            _ = program;
            if (parser.errors.items.len > 0) {
                printParserError(parser.errors);
                continue;
            }
        } else {
            break;
        }
    }
}

fn printParserError(errs: std.ArrayList([]const u8)) void {
    for (errs.items) |err| {
        std.log.err("{s}", .{err});
    }
}
