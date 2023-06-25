const std = @import("std");

const Lexer = @import("lexer.zig").Lexer;
const Token = @import("token.zig").Token;
const ast = @import("ast.zig");

const Parser = struct {
    lexer: Lexer,

    current_token: Token = undefined,
    peek_token: Token = undefined,

    allocator: std.mem.Allocator,
    errors: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, l: Lexer) Parser {
        var p = Parser{
            .lexer = l,
            .allocator = allocator,
            .errors = std.ArrayList([]const u8).init(allocator),
        };

        p.nextToken();
        p.nextToken();
        return p;
    }

    pub fn deinit(self: *Parser) void {
        for (self.errors.items) |err| {
            self.allocator.free(err);
        }

        self.errors.deinit();
    }

    fn nextToken(self: *Parser) void {
        self.current_token = self.peek_token;
        self.peek_token = self.lexer.nextToken();
    }

    fn parseProgram(self: *Parser) error{OutOfMemory}!ast.Program {
        var ret = ast.Program.init(self.allocator);

        while (self.current_token.type != .EOF) {
            const statement_maybe = self.parseStatement();
            if (statement_maybe) |statement| {
                try ret.statements.append(statement);
            }

            self.nextToken();
        }

        return ret;
    }

    pub fn parseStatement(self: *Parser) ?ast.Statement {
        return switch (self.current_token.type) {
            .LET => self.parseLetStatement(),
            .RETURN => self.parseReturnStatement(),
            else => null,
        };
    }

    fn parseLetStatement(self: *Parser) ?ast.Statement {
        var statement = ast.Statement{ .let_statement = .{ .token = self.current_token, .name = undefined, .value = .{} } };
        if (!self.expectPeek(.IDENT)) {
            return null;
        }

        statement.let_statement.name = ast.Identifier{ .token = self.current_token, .value = self.current_token.literal };
        if (!self.expectPeek(.ASSIGN)) {
            return null;
        }

        while (self.current_token.type != .SEMICOLON) : (self.nextToken()) {}
        return statement;
    }

    fn parseReturnStatement(self: *Parser) ?ast.Statement {
        var statement = ast.Statement{ .return_statement = .{ .token = self.current_token, .value = .{} } };
        self.nextToken();

        while (self.current_token.type != .SEMICOLON) : (self.nextToken()) {}
        return statement;
    }

    fn expectPeek(self: *Parser, @"type": Token.Type) bool {
        if (self.peek_token.type == @"type") {
            self.nextToken();
            return true;
        } else {
            self.peekError(@"type") catch {};
            return false;
        }
    }

    fn peekError(self: *Parser, @"type": Token.Type) !void {
        const str = try std.fmt.allocPrint(self.allocator, "expected next token to be '{s}', got '{s}' instead", .{ @tagName(@"type"), @tagName(self.peek_token.type) });
        try self.errors.append(str);
    }
};

test "let statements" {
    const input =
        \\let x =  5;
        \\let y = 10;
        \\let foobar = 838383;
    ;

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();

    try checkParseError(&parser);
    try std.testing.expectEqual(@intCast(usize, 3), program.statements.items.len);
    const expected = [_][]const u8{ "x", "y", "foobar" };
    for (expected, 0..) |ident, i| {
        const actual = program.statements.items[i];

        try std.testing.expectEqualSlices(u8, "let", actual.TokenLiteral());
        try std.testing.expectEqualSlices(u8, ident, actual.let_statement.name.value);
        try std.testing.expectEqualSlices(u8, ident, actual.let_statement.name.token.literal);
    }
}

test "return statements" {
    const input =
        \\return 5;
        \\return 10;
        \\return 993322;
    ;

    var lexer = Lexer.init(input);
    var parser = Parser.init(std.testing.allocator, lexer);
    defer parser.deinit();

    var program = try parser.parseProgram();
    defer program.deinit();
    try checkParseError(&parser);

    try std.testing.expectEqual(@intCast(usize, 3), program.statements.items.len);
    for (program.statements.items) |statement| {
        try std.testing.expectEqualSlices(u8, "return", statement.TokenLiteral());
    }
}

fn checkParseError(parser: *Parser) error{ParseErrors}!void {
    if (parser.errors.items.len == 0) {
        return;
    }

    std.log.err("Parser had {d} errors\n", .{parser.errors.items.len});
    for (parser.errors.items) |msg| {
        std.log.err("{s}", .{msg});
    }
}
