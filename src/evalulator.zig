const std = @import("std");

const Object = @import("object.zig").Object;
const Lexer = @import("lexer.zig").Lexer;
const Parser = @import("parser.zig").Parser;
const ast = @import("ast.zig");

fn Eval(_: ast.Statement) ?Object {
    return null;
}

test "eval integer expression" {
    const inputs = [_][]const u8{"5"};
    const expected = [_]i64{5};

    for (inputs, expected) |i, e| {
        const eval = testEval(i);
        try std.testing.expectEqual(e, eval.integer.value);
    }
}

fn testEval(input: []const u8) Object {
    const l = Lexer.init(input);
    var p = Parser.init(std.testing.allocator, l);
    defer p.deinit();

    const program = p.parseProgram();
    return Eval(program.statements.items[0]);
}
