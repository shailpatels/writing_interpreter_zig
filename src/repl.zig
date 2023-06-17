const std = @import("std");
const token = @import("token.zig");

const Lexer = @import("lexer.zig").Lexer;

pub fn start(reader: anytype, writer: anytype) !void {
    while (true) {
        try writer.writeAll(">> ");

        var msg_buf: [4096]u8 = undefined;
        var msg = try reader.readUntilDelimiterOrEof(&msg_buf, '\n');

        if (msg) |m| {
            var lexer = Lexer.init(m);

            var tok: token.Token = undefined;
            while (true) {
                tok = lexer.nextToken();
                std.debug.print("type:'{s}', literal:'{s}'\n", .{ @tagName(tok.type), tok.literal });

                if (tok.type == .EOF) break;
            }
        } else {
            break;
        }
    }
}
