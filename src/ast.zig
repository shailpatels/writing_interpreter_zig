const std = @import("std");

const Token = @import("token.zig").Token;
const Lexer = @import("lexer.zig").Lexer;

pub const Statement = union(enum) {
    let_statement: LetStatement,
    return_statement: ReturnStatement,

    pub fn TokenLiteral(self: Statement) []const u8 {
        return switch (self) {
            inline else => |tag| tag.token.literal,
        };
    }
};

pub const Program = struct {
    statements: std.ArrayList(Statement),

    pub fn init(allocator: std.mem.Allocator) Program {
        return Program{
            .statements = std.ArrayList(Statement).init(allocator),
        };
    }

    pub fn deinit(self: *Program) void {
        self.statements.deinit();
    }

    fn TokenLiteral(self: *Program) []const u8 {
        return if (self.statements > 0) self.statements[0].TokenLiteral() else "";
    }
};

pub const Identifier = struct {
    token: Token,
    value: []const u8,
};

const LetStatement = struct {
    token: Token,
    name: Identifier,
    value: Expression,
};

const ExpressionStatement = struct {
    token: Token,
    expression: Expression,
};
const Expression = struct {};

const ReturnStatement = struct {
    token: Token,
    value: Expression,
};
